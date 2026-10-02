#!/usr/bin/env node
// Generates differential test vectors for `shrike::syntax` by running the
// reference TypeScript `@atproto/syntax` (built) over a deterministic corpus:
// the interop fixtures and every string in the reference's own tests, plus
// grammar-generated and mutated values. Each value is recorded with the
// reference's verdict.
//
// Usage:
//   node scripts/syntax-vectors.mjs [out] [--scale N] [--seed N]
//
// ATPROTO_DIR defaults to a sibling checkout under ../../bluesky-social/. The
// output defaults to testdata/syntax/ts_vectors.json; tests/syntax_interop.rs
// reads it (or $SHRIKE_SYNTAX_VECTORS, for larger local runs).

import { execFileSync } from 'node:child_process'
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const atprotoDir = resolve(process.env.ATPROTO_DIR ?? join(root, '../../bluesky-social/atproto'))
const syntaxDir = join(atprotoDir, 'packages/syntax')
const interopDir = join(atprotoDir, 'interop-test-files/syntax')

const args = process.argv.slice(2)
const flag = (name, dflt) => {
  const i = args.indexOf(name)
  if (i === -1) return dflt
  const [v] = args.splice(i, 2).slice(1)
  return Number(v)
}
const scale = flag('--scale', 1)
const seed = flag('--seed', 1)
const out = resolve(args[0] ?? join(root, 'testdata/syntax/ts_vectors.json'))

const syntax = await import(pathToFileURL(join(syntaxDir, 'dist/index.js')).href)

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
const chance = (p) => rand() < p
const times = (n, f) => Array.from({ length: n }, f)

const LOWER = 'abcdefghijklmnopqrstuvwxyz'
const ALPHA = LOWER + LOWER.toUpperCase()
const DIGIT = '0123456789'
const ALNUM = ALPHA + DIGIT
const str = (chars, n) => times(n, () => pick(chars)).join('')
// Mostly the right length, sometimes one off either way.
const near = (n) => Math.max(0, n + pick([-1, 0, 0, 0, 0, 0, 1]))

const interop = (name) =>
  readFileSync(join(interopDir, name), 'utf8')
    .split('\n')
    .filter((l) => l.trim() && !l.startsWith('#'))

// Every single-quoted string literal in the reference's tests for a parser.
const testStrings = (file) =>
  [...readFileSync(join(syntaxDir, 'tests', file), 'utf8').matchAll(/'((?:[^'\\\n]|\\.)*)'/g)].map(
    (m) => m[1],
  )

// Random single-character edits and subtag-level shuffles.
const mutate = (s, chars, sep) => {
  const parts = s.split(sep)
  const at = int(s.length + 1)
  switch (int(8)) {
    case 0:
      return s.slice(0, at) + pick(chars) + s.slice(at)
    case 1:
      return s.slice(0, at) + s.slice(at + 1)
    case 2:
      return s.slice(0, at) + pick(chars) + s.slice(at + 1)
    case 3: {
      const c = s.charAt(at)
      const flipped = c === c.toLowerCase() ? c.toUpperCase() : c.toLowerCase()
      return s.slice(0, at) + flipped + s.slice(at + 1)
    }
    case 4: {
      const i = int(parts.length)
      parts.splice(i, 0, parts[int(parts.length)])
      return parts.join(sep)
    }
    case 5:
      parts.splice(int(parts.length), 1)
      return parts.join(sep)
    case 6: {
      const [i, j] = [int(parts.length), int(parts.length)]
      ;[parts[i], parts[j]] = [parts[j], parts[i]]
      return parts.join(sep)
    }
    default:
      return chance(0.5) ? s + sep : sep + s
  }
}

const corpus = (seeds, generate, mutationChars, sep, count) => {
  const values = new Set(seeds)
  for (let i = 0; i < count; i++) values.add(generate())
  const base = [...values]
  for (let i = 0; i < count; i++) {
    let v = pick(base)
    for (let n = 1 + int(3); n > 0; n--) v = mutate(v, mutationChars, sep)
    values.add(v)
  }
  return [...values]
}

const verdicts = (values, check) => {
  const valid = []
  const invalid = []
  for (const v of values) (check(v) ? valid : invalid).push(v)
  return { valid, invalid }
}

// ---------------------------------------------------------------------------
// Language tags (RFC 5646), checked with the strict `parseLanguageString` the
// lexicon `language` format uses.

const GRANDFATHERED = [
  'en-GB-oed', 'i-ami', 'i-bnn', 'i-default', 'i-enochian', 'i-hak', 'i-klingon', 'i-lux',
  'i-mingo', 'i-navajo', 'i-pwn', 'i-tao', 'i-tay', 'i-tsu', 'sgn-BE-FR', 'sgn-BE-NL',
  'sgn-CH-DE', 'art-lojban', 'cel-gaulish', 'no-bok', 'no-nyn', 'zh-guoyu', 'zh-hakka',
  'zh-min', 'zh-min-nan', 'zh-xiang',
]

const privateUse = () => [pick(['x', 'X']), ...times(near(1 + int(3)), () => str(ALNUM, near(1 + int(8))))]

const languageTag = () => {
  if (chance(0.03)) return pick(GRANDFATHERED)
  if (chance(0.05)) return privateUse().join('-')
  const parts = [chance(0.9) ? str(LOWER, 2 + int(2)) : str(ALPHA, near(2 + int(7)))]
  if (chance(0.2)) parts.push(...times(1 + int(4), () => str(ALPHA, near(3))))
  if (chance(0.4)) parts.push(str(ALPHA, near(4)))
  if (chance(0.5)) parts.push(chance(0.6) ? str(ALPHA, near(2)) : str(DIGIT, near(3)))
  if (chance(0.3)) {
    const variants = times(1 + int(3), () =>
      chance(0.6) ? str(ALNUM, near(5 + int(4))) : pick(DIGIT) + str(ALNUM, near(3)),
    )
    if (chance(0.2)) variants.push(pick(variants).toUpperCase())
    parts.push(...variants)
  }
  if (chance(0.3)) {
    const singletons = times(1 + int(3), () => pick(ALNUM))
    if (chance(0.2)) singletons.push(pick(singletons))
    for (const s of singletons) parts.push(s, ...times(near(1 + int(2)), () => str(ALNUM, near(2 + int(7)))))
  }
  if (chance(0.15)) parts.push(...privateUse())
  return parts.join('-')
}

const languageSeeds = [
  ...interop('language_syntax_valid.txt'),
  ...interop('language_syntax_invalid.txt'),
  ...interop('language_parse_invalid.txt'),
  ...testStrings('language.test.ts'),
  ...GRANDFATHERED,
  ...GRANDFATHERED.map((g) => g.toLowerCase()),
]
const language = verdicts(
  corpus(languageSeeds, languageTag, ALNUM + '-_ .', '-', 6000 * scale),
  (v) => syntax.parseLanguageString(v) !== null,
)

// ---------------------------------------------------------------------------

const git = (dir) => execFileSync('git', ['-C', dir, 'rev-parse', 'HEAD']).toString().trim()
const vectors = {
  generator: 'scripts/syntax-vectors.mjs',
  atproto: git(atprotoDir),
  seed,
  scale,
  language,
}
mkdirSync(dirname(out), { recursive: true })
writeFileSync(out, JSON.stringify(vectors) + '\n')
console.log(`wrote ${out}: language ${language.valid.length} valid, ${language.invalid.length} invalid`)
