"""Parsing regressions for the benchmark harness; python3 -m unittest discover -s scripts."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('bench', Path(__file__).with_name('bench-jetstream.py'))
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


class Parsing(unittest.TestCase):
    def test_untyped_output_has_no_typed_counters(self):
        result = bench.parse_go_final('final elapsed=7s events=34,519,460 events_per_second=4,719,712 last_cursor=99998466', False)
        self.assertEqual(result['delivered_events'], 34519460)
        self.assertEqual(result['last_processed_seq'], 99998466)
        self.assertIsNone(result['decoded'])
        with self.assertRaises(KeyError):
            bench.parse_go_final(result['raw'], True)

    def test_typed_output_requires_and_parses_counters(self):
        result = bench.parse_go_final('final events=1,000 decoded=995 decode_errs=5 last_cursor=1234', True)
        self.assertEqual((result['decoded'], result['decode_errors']), (995, 5))

    def test_only_explicit_record_decode_errors_are_classified(self):
        for prefix in ['', 'event error: ']:
            line = prefix+'jetstream: decode record (did=did:plc:abc collection=x.y.z rkey=abc seq=69727): cbor decode: record is not an object'
            self.assertEqual(bench.go_record_error_seq(line), 69727)
        for line in ['event error: download timed out', 'jetstream: decode block 12: invalid layout',
                     '@METRIC 1 2 3', 'recoverable error: malformed event']:
            self.assertIsNone(bench.go_record_error_seq(line))


if __name__ == '__main__':
    unittest.main()
