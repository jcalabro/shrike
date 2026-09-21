#!/usr/bin/env python3
"""Bounded, paired remote replay comparisons; standard library only.

Example:
  python3 scripts/bench-jetstream.py --baseline shrike-cli --candidate shrike-cli-perf-N \
    --output /tmp/comparison.jsonl --pairs 12

The script is sent through SSH stdin, never installed on the server. Raw results
and an adjacent summary are written locally. Each pair contains both binaries
in a seeded random order. Bootstrap CIs resample complete pairs, preserving their
temporal association. Timings include startup and final destruction. Warmups are
excluded. Record the chosen workload and pair count before examining results.
"""

import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import resource
import shlex
import statistics
import subprocess
import sys
import threading
import time


def worker(config):
    os.chdir(config['directory'])
    os.sched_setaffinity(0, set(config['cpus']))
    os.nice(19)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    env = os.environ.copy()
    env['TOKIO_WORKER_THREADS'] = str(len(config['cpus']))
    env['GOMAXPROCS'] = str(len(config['cpus']))
    env['GOGC'] = '400'  # Match the Go CLI default; exclude inherited shell tuning.
    env.setdefault('JETSTREAM_API_KEY', 'local-benchmark')
    hashes = {key: hashlib.sha256(Path(config[key]).read_bytes()).hexdigest()
              for key in ['baseline', 'candidate']}
    print(json.dumps(dict(type='metadata', config=config, hashes=hashes,
                          environment={k: env[k] for k in
                                       ['TOKIO_WORKER_THREADS', 'GOMAXPROCS', 'GOGC']},
                          uname=list(os.uname()), load=os.getloadavg())), flush=True)
    rng = random.Random(config['seed'])
    expected = None
    for pair in range(-1, config['pairs']):
        order = ['baseline', 'candidate']
        rng.shuffle(order)
        for label in order:
            common = ['--host=localhost:8080',
                      '--after-seq='+str(config['after']), '--before-seq='+str(config['before'])]
            if config['collection']:
                common += ['--collection='+config['collection']]
            if config[label+'_kind'] == 'go':
                client = ['./'+config[label], *common, '--backfill-only', '--segment-stripes=1']
            else:
                client = ['/lib64/ld-linux-x86-64.so.2', './'+config[label], 'jetstream',
                          *common, '--insecure', '--snapshot-only', '--stats', '--json']
            command = ['timeout', '--signal=INT', '--kill-after=3s', str(config['timeout'])+'s',
                       '/usr/bin/time', '-f', '@METRIC %e %U %S %M %x %w %c %F %R %I %O',
                       'ionice', '-c', '3', *client, *config[label+'_args']]
            started = time.perf_counter()
            run_env = env.copy()
            run_env['GOMEMLIMIT'] = config[label+'_go_memory_limit']
            proc = subprocess.Popen(command, env=run_env, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
            errors = []
            def drain():
                for line in proc.stderr:
                    if len(errors) < 100:
                        errors.append(line.rstrip())
            reader = threading.Thread(target=drain)
            reader.start()
            final = None
            for line in proc.stdout:
                final = line.rstrip()
            status = proc.wait()
            reader.join()
            elapsed = time.perf_counter() - started
            metrics = [s.split()[1:] for s in errors if s.startswith('@METRIC ')]
            diagnostics = [s for s in errors if not s.startswith('@METRIC ')]
            if status or len(metrics) != 1 or diagnostics or final is None:
                raise RuntimeError(f'Failed {label} run: status={status}, diagnostics={errors}')
            if config[label+'_kind'] == 'go':
                fields = dict(re.findall(r'([a-z_]+)=([^ ]+)', final))
                def count(key):
                    return int(fields[key].replace(',', ''))
                final = dict(delivered_events=count('events'), last_processed_seq=count('last_cursor'),
                             decoded=count('decoded'), decode_errors=count('decode_errs'),
                             typed_likes='--typed-likes-client' in config[label+'_args'],
                             residual_gap=0, raw=final)
            else:
                final = json.loads(final)
            signature = (final['delivered_events'], final['last_processed_seq'], final['residual_gap'])
            if final.get('typed_likes'):
                delta = config['typed_error_delta'] if label == 'baseline' else 0
                signature += (final['decoded'] - delta, final['decode_errors'] + delta)
            if expected is None:
                expected = signature
            if signature != expected or final['residual_gap']:
                raise RuntimeError(f'Inconsistent results: {signature} versus {expected}')
            wall, user, system, rss, exit_status, voluntary, involuntary, major, minor, fs_in, fs_out = metrics[0]
            result = dict(type='run', pair=pair, label=label, wall_s=elapsed, time_wall_s=float(wall),
                          cpu_s=float(user)+float(system), rss_kib=int(rss),
                          final=final, exit_status=int(exit_status), load=os.getloadavg(),
                          voluntary_switches=int(voluntary), involuntary_switches=int(involuntary),
                          major_faults=int(major), minor_faults=int(minor),
                          filesystem_inputs=int(fs_in), filesystem_outputs=int(fs_out))
            print(json.dumps(result), flush=True)


def summarize(rows, seed):
    pairs = {}
    for row in rows:
        if row.get('type') == 'run' and row['pair'] >= 0:
            pairs.setdefault(row['pair'], {})[row['label']] = row
    if not pairs or any(len(p) != 2 for p in pairs.values()):
        raise ValueError('Missing complete measured pairs')
    ratios = [math.log(p['baseline']['wall_s']/p['candidate']['wall_s']) for p in pairs.values()]
    rng = random.Random(seed)
    bootstrap = sorted(math.exp(statistics.mean(rng.choices(ratios, k=len(ratios))))
                       for _ in range(10000))
    result = dict(pairs=len(pairs), speedup_geomean=math.exp(statistics.mean(ratios)),
                  speedup_bootstrap_95=[bootstrap[250], bootstrap[9749]])
    for label in ['baseline', 'candidate']:
        group = [p[label] for p in pairs.values()]
        result[label] = dict(wall_median=statistics.median(r['wall_s'] for r in group),
                             wall_min=min(r['wall_s'] for r in group),
                             wall_max=max(r['wall_s'] for r in group),
                             cpu_median=statistics.median(r['cpu_s'] for r in group),
                             rss_kib_median=statistics.median(r['rss_kib'] for r in group))
    return result


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--worker':
        worker(json.loads(base64.b64decode(sys.argv[2])))
        return
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host', default='root@cpu3-pop3')
    p.add_argument('--directory', default='/data/jcalabro/jetstream-1')
    p.add_argument('--baseline', required=True)
    p.add_argument('--candidate', required=True)
    p.add_argument('--baseline-kind', choices=['rust', 'go'], default='rust')
    p.add_argument('--candidate-kind', choices=['rust', 'go'], default='rust')
    p.add_argument('--baseline-go-memory-limit', default='512MiB')
    p.add_argument('--candidate-go-memory-limit', default='512MiB')
    p.add_argument('--typed-error-delta', type=int, default=0,
                   help='predeclared candidate-minus-baseline typed errors for known contract differences')
    p.add_argument('--baseline-arg', dest='baseline_args', action='append', default=[],
                   help='extra CLI argument; repeat and use = before an argument starting with --')
    p.add_argument('--candidate-arg', dest='candidate_args', action='append', default=[])
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--pairs', type=int, default=12)
    p.add_argument('--seed', type=int, default=20260921)
    p.add_argument('--cpus', default='2,3')
    p.add_argument('--after', type=int, default=0)
    p.add_argument('--before', type=int, default=20000000)
    p.add_argument('--collection', default='app.bsky.feed.like', help='empty string selects all')
    p.add_argument('--timeout', type=int, default=30)
    args = p.parse_args()
    config = vars(args).copy()
    config.pop('output'); config.pop('host')
    config['cpus'] = [int(c) for c in args.cpus.split(',')]
    for key in ['baseline', 'candidate']:
        if not re.fullmatch(r'[a-zA-Z0-9_.-]+', config[key]):
            p.error('binary names must be single path components')
    if args.pairs < 2 or args.after < 0 or args.before <= args.after or args.timeout <= 0:
        p.error('require >=2 pairs, 0 <= after < before, and a positive timeout')
    encoded = base64.b64encode(json.dumps(config).encode()).decode()
    command = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', args.host,
               shlex.join(['python3', '-B', '-', '--worker', encoded])]
    rows = []
    with args.output.open('x') as out:
        proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        proc.stdin.write(Path(__file__).read_text())
        proc.stdin.close()
        for line in proc.stdout:
            row = json.loads(line)
            rows.append(row)
            out.write(line); out.flush()
            if row['type'] == 'run':
                print(f"pair={row['pair']} {row['label']} wall={row['wall_s']} cpu={row['cpu_s']}", flush=True)
        if proc.wait():
            raise RuntimeError('Remote benchmark failed; partial results retained')
    summary = summarize(rows, args.seed)
    args.output.with_suffix('.summary.json').write_text(json.dumps(summary, indent=2)+'\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
