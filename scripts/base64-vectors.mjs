#!/usr/bin/env node
// Generates differential test vectors for `$bytes` base64 decoding
// (`shrike::cbor::json`) by running the reference TypeScript
// `@atproto/lex-json` (built) over a deterministic corpus: every string of up
// to five characters over a small alphabet covering data, padding, and invalid
// characters, plus padded, unpadded, over-padded, and mutated encodings of
// random bytes. Each string is recorded with what `lexParse` makes of
// `{"$bytes": <string>}`: the decoded bytes as hex, or null when it stays a
// plain map.
//
// The reference decodes with lex-data's `fromBase64`, which on Node (no native
// `Uint8Array.fromBase64`) goes through `Buffer`. `Buffer` also takes the
// URL-safe alphabet, which shrike deliberately does not, so `-` and `_` are
// left out of the corpus.
//
// Usage:
//   node scripts/base64-vectors.mjs [out] [--seed N]
//
// ATPROTO_DIR defaults to a sibling checkout under ../../bluesky-social/. The
// output defaults to testdata/base64_ts_vectors.json; tests/lex_json.rs reads
// it.

import { execFileSync } from 'node:child_process'
import { writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const atprotoDir = resolve(process.env.ATPROTO_DIR ?? join(root, '../../bluesky-social/atproto'))

const args = process.argv.slice(2)
const flag = (name, dflt) => {
  const i = args.indexOf(name)
  if (i === -1) return dflt
  const [v] = args.splice(i, 2).slice(1)
  return Number(v)
}
const seed = flag('--seed', 1)
const out = resolve(args[0] ?? join(root, 'testdata/base64_ts_vectors.json'))

const lexJson = await import(pathToFileURL(join(atprotoDir, 'packages/lex/lex-json/dist/index.js')).href)
if (typeof Uint8Array.fromBase64 === 'function') {
  throw new Error('this Node has native Uint8Array.fromBase64; run the generator on Node 24 or older')
}

// mulberry32
let state = seed >>> 0
const rand = () => {
  state = (state + 0x6d2b79f5) >>> 0
  let t = state
  t = Math.imul(t ^ (t >>> 15), t | 1)
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296
}
const int = (n) => Math.floor(rand() * n)
const pick = (xs) => xs[int(xs.length)]

const strings = new Set()

// Exhaustive short strings. 'Q' and '/' set trailing bits that 'A' leaves
// clear; ' ' and '!' are invalid.
const ALPHABET = ['A', 'Q', '/', '=', ' ', '!']
let level = ['']
for (let len = 0; len <= 5; len++) {
  for (const s of level) strings.add(s)
  level = level.flatMap((s) => ALPHABET.map((c) => s + c))
}

// Encodings of random bytes, with their padding trimmed, kept, or extended,
// and sometimes a character replaced.
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
for (let i = 0; i < 3000; i++) {
  const bytes = Buffer.from(Array.from({ length: int(40) }, () => int(256)))
  let s = bytes.toString('base64').replace(/=+$/, '')
  s += '='.repeat(pick([0, 0, 1, 2, 3]))
  if (int(4) === 0) {
    const at = int(s.length + 1)
    s = s.slice(0, at) + pick([...B64.slice(0, 8), '=', ' ', '\n', '.']) + s.slice(at + 1)
  }
  strings.add(s)
}

const decode = (s) => {
  const v = lexJson.lexParse(JSON.stringify({ $bytes: s }))
  return v instanceof Uint8Array ? Buffer.from(v).toString('hex') : null
}
const decodeBytes = (s) => {
  const v = lexJson.lexParseJsonBytes(new TextEncoder().encode(JSON.stringify({ $bytes: s })), { strict: false })
  return v instanceof Uint8Array ? Buffer.from(v).toString('hex') : null
}

const vectors = []
let disagreements = 0
for (const s of strings) {
  const hex = decode(s)
  if (decodeBytes(s) !== hex) disagreements++
  vectors.push([s, hex])
}

const git = (dir) => execFileSync('git', ['-C', dir, 'rev-parse', 'HEAD']).toString().trim()
writeFileSync(
  out,
  JSON.stringify({
    generator: 'scripts/base64-vectors.mjs',
    atproto: git(atprotoDir),
    node: process.version,
    seed,
    vectors,
  }) + '\n',
)
const decoded = vectors.filter(([, hex]) => hex !== null).length
console.log(
  `wrote ${out}: ${vectors.length} strings (${decoded} decode to bytes); ` +
    `lexParseJsonBytes disagrees with lexParse on ${disagreements}`,
)
