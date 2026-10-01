#!/usr/bin/env node
// Generates differential test vectors for `shrike::oauth::scopes` by running the
// reference TypeScript `@atproto/oauth-scopes` (built) over a deterministic
// corpus: every scope string from its test suite and indigo's fixtures, plus
// grammar-generated and mutated scopes, scope sets with permission checks, and
// `include:` expansions of real and synthetic permission sets.
//
// Usage:
//   node scripts/oauth-scope-vectors.mjs [out] [--scale N] [--seed N]
//
// ATPROTO_DIR and INDIGO_DIR default to sibling checkouts under
// ../../bluesky-social/. The output defaults to
// testdata/oauth_scopes/ts_vectors.json; tests/oauth_scopes_interop.rs reads it
// (or $SHRIKE_OAUTH_SCOPE_VECTORS, for larger local runs).

import { execFileSync } from 'node:child_process'
import { readdirSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const atprotoDir = resolve(process.env.ATPROTO_DIR ?? join(root, '../../bluesky-social/atproto'))
const indigoDir = resolve(process.env.INDIGO_DIR ?? join(root, '../../bluesky-social/indigo'))
const scopesDir = join(atprotoDir, 'packages/oauth/oauth-scopes')

const args = process.argv.slice(2)
const flag = (name, dflt) => {
  const i = args.indexOf(name)
  if (i === -1) return dflt
  const [v] = args.splice(i, 2).slice(1)
  return Number(v)
}
const scale = flag('--scale', 1)
const seed = flag('--seed', 1)
const out = resolve(args[0] ?? join(root, 'testdata/oauth_scopes/ts_vectors.json'))

const s = await import(pathToFileURL(join(scopesDir, 'dist/index.js')).href)

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
const some = (xs, max) => Array.from({ length: int(max + 1) }, () => pick(xs))

const walk = (dir, pred) =>
  readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = join(dir, e.name)
    if (e.isDirectory()) return e.name === 'node_modules' ? [] : walk(p, pred)
    return pred(p) ? [p] : []
  })

// ---------------------------------------------------------------------------
// Seed corpus: reference test vectors

const seeds = new Set()
for (const file of walk(join(scopesDir, 'src'), (p) => p.endsWith('.test.ts'))) {
  for (const [, lit] of readFileSync(file, 'utf8').matchAll(/'((?:[^'\\\n]|\\.)*)'/g)) {
    if (lit.length <= 160 && !/^should |^\w+ \w+ \w+/.test(lit)) seeds.add(lit)
  }
}
const indigoData = join(indigoDir, 'atproto/auth/testdata')
for (const f of ['permission_scopes_valid.txt', 'permission_scopes_invalid.txt', 'generic_scopes_invalid.txt']) {
  for (const line of readFileSync(join(indigoData, f), 'utf8').split('\n')) {
    if (!line.startsWith('#')) seeds.add(line)
  }
}
for (const { scope } of JSON.parse(readFileSync(join(indigoData, 'generic_scopes_valid.json'), 'utf8'))) {
  seeds.add(scope)
}
for (const scope of [
  'repo:com.example.record?action=delete',
  'repo?action=delete&collection=com.example.record&collection=com.example.other',
  'rpc:com.example.query?aud=did%3Aweb%3Aapi.example.com%23frag',
  'rpc?aud=did%3Aweb%3Aapi.example.com%23frag&lxm=com.example.query&lxm=com.example.procedure',
  'blob?accept=image%2Fpng&accept=image%2Fjpeg',
  // Regressions found by larger differential runs.
  'blob:image/svg%+Bxml',
  'repo:%+B',
  'repo:com.example.foo?action=%+B',
  'blob?accept=image/svg%+Bxml',
]) {
  seeds.add(scope)
}

// ---------------------------------------------------------------------------
// Generated corpus

const RESOURCES = ['account', 'blob', 'identity', 'include', 'repo', 'rpc']
const NEAR = ['Repo', 'repos', 'rep', 'transition', 'atproto', '', 'RPC', 'blob ', 'did']
const NSIDS = [
  'com.example.foo', 'com.example.bar', 'app.bsky.feed.post', 'COM.example.foo', 'com.example.Foo',
  'com.example.calendar.event', 'com.example.calendar.listEvents', 'com.example.calendar.auth',
  'com.example.method1', 'com.example.service', 'app.bsky.feed.getFeed', 'chat.bsky.convo.getLog',
  'any.collection', 'a.b.c', 'a-b.c-d.e', 'x1.y2.z3', '9com.example.foo', 'com..example', 'com.example',
  'com.example.-bar', 'com.example.foo-bar', 'com.example.', `${'a'.repeat(63)}.b.c`, `${'a'.repeat(64)}.b.c`,
  `a.b.${'c'.repeat(63)}`, `a.b.${'c'.repeat(64)}`, `${'ab.'.repeat(105)}c`,
]
const AUDS = [
  'did:web:example.com#service_id', 'did:web:example.com', 'did:web:example.com#foo',
  'did:web:api.bsky.app#bsky_appview', 'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa#atproto_labeler',
  'did:plc:blahbla#x', 'did:plc:aaaaaaaaaaaaaaaaaaaaaaa1#x', 'did:web:localhost#x',
  'did:web:localhost%3A3000#x', 'did:web:example.com%3A443#x', 'did:web:example.com:path#x',
  'did:web:EXAMPLE.com#x', 'did:web:example.123#x', 'did:web:exa%2Fmple.com#x', 'did:web:%41.com#x',
  'did:web:a_b.com#x', 'did:web:-a.com#x', 'did:web:a..b#x', 'did:foo:bar#x', 'did:web:example.com#a#b',
  'did:web:example.com#a b', "did:web:example.com#!$&'()*+,;=:@/?", 'did:web:example.com#%2', '*', '**', '',
  'did:web:localhost%3A99999#x', 'did:web:1.2.3.4#x', 'did:web:0x1#x', 'did:web:a%3a#x',
]
const MIMES = [
  'image/png', 'IMAGE/PNG', 'image/jpeg', 'image/*', '*/*', 'text/html', 'image', 'video/*',
  'image/svg+xml', '*/png', 'image/**', 'im*age/*', 'image//png', 'image/ png', '/png', 'image/',
  'application/vnd.foo+json', 'Image/*', 'image/%',
]
const WORDS = ['email', 'repo', 'status', 'handle', '*', 'read', 'manage', 'create', 'update', 'delete', 'Email', 'invalid', '']
const KEYS = ['collection', 'action', 'lxm', 'aud', 'accept', 'attr', 'nsid', 'inheritAud', 'extra', 'Action', '']
const VALUES = [...NSIDS, ...AUDS, ...MIMES, ...WORDS, 'true', '%', '%2', '%zz', '%C3', '%E2%98%BA', 'é', '+', ' ']
const STRUCT = [':', '?', '&', '=', '%', '#', '+', '*', '/', '.', ' ', '%2', '%23', '%3A', '%25', '%2B', 'é']

const encodeSome = (v) => {
  switch (int(4)) {
    case 0: return encodeURIComponent(v)
    case 1: return v.replaceAll('#', '%23')
    default: return v
  }
}

const generated = () => {
  const resource = rand() < 0.93 ? pick(RESOURCES) : pick(NEAR)
  let scope = resource
  if (rand() < 0.8) scope += ':' + encodeSome(pick(VALUES))
  const params = some(KEYS, 3).map((k) => `${k}=${encodeSome(pick(VALUES))}`)
  if (params.length || rand() < 0.05) scope += '?' + params.join('&')
  return scope
}

// Mostly valid scopes for one resource, in positional or named form.
const SCHEMAS = {
  account: [['attr', ['email', 'repo', 'status'], 1, true], ['action', ['read', 'manage'], 2, false]],
  blob: [['accept', MIMES.slice(0, 11), 3, true]],
  identity: [['attr', ['handle', '*'], 1, true]],
  include: [['nsid', NSIDS.slice(0, 22), 1, true], ['aud', AUDS.slice(0, 13), 1, false]],
  repo: [['collection', [...NSIDS.slice(0, 22), '*'], 3, true], ['action', ['create', 'update', 'delete'], 3, false]],
  rpc: [['lxm', [...NSIDS.slice(0, 22), '*'], 3, true], ['aud', [...AUDS.slice(0, 13), '*', '*'], 1, true]],
}
const encodeValue = (v) => {
  switch (int(6)) {
    case 0: return encodeURIComponent(v)
    case 1: return encodeURIComponent(v).replaceAll('%25', '%2525')
    case 2: return v.replaceAll('#', '%23').replaceAll('+', '%2B')
    default: return v.replaceAll('#', '%23')
  }
}
const resourceScope = () => {
  const resource = pick(RESOURCES)
  let positional
  const params = []
  for (const [key, values, max, required] of SCHEMAS[resource]) {
    if (!required && rand() < 0.4) continue
    const chosen = Array.from({ length: Math.min(max, 1 + int(max)) }, () => (rand() < 0.95 ? pick(values) : pick(VALUES)))
    if (positional === undefined && key === SCHEMAS[resource][0][0] && chosen.length === 1 && rand() < 0.75) {
      positional = encodeValue(chosen[0])
    } else {
      for (const v of chosen) params.push(`${key}=${encodeValue(v)}`)
    }
  }
  if (rand() < 0.05) params.push(`${pick(KEYS)}=${encodeValue(pick(VALUES))}`)
  for (let i = params.length - 1; i > 0; i--) {
    const j = int(i + 1)
    ;[params[i], params[j]] = [params[j], params[i]]
  }
  return resource + (positional === undefined ? '' : ':' + positional) + (params.length ? '?' + params.join('&') : '')
}

const mutate = (v) => {
  let out = v
  for (let n = 1 + int(3); n > 0; n--) {
    const i = int(out.length + 1)
    switch (int(3)) {
      case 0: out = out.slice(0, i) + pick(STRUCT) + out.slice(i); break
      case 1: out = out.slice(0, i) + out.slice(i + 1); break
      default: out = out.slice(0, i) + pick(STRUCT) + out.slice(i + 1)
    }
  }
  return out
}

const corpus = new Set(seeds)
const seedList = [...seeds]
const target = corpus.size + 3000 * scale
while (corpus.size < target) {
  const r = rand()
  corpus.add(
    r < 0.55 ? resourceScope() : r < 0.75 ? generated() : mutate(pick([pick(seedList), resourceScope(), generated()])),
  )
}

// ---------------------------------------------------------------------------
// Scope vectors

const normalize = (v) => {
  try {
    return { n: s.normalizeAtprotoOauthScopeValue(v) }
  } catch {
    return { n: null, t: true }
  }
}
const parsed = (v) => {
  if (s.isStaticScopeValue(v)) return v
  for (const P of [s.AccountPermission, s.BlobPermission, s.IdentityPermission, s.IncludeScope, s.RepoPermission, s.RpcPermission]) {
    const p = P.fromString(v)
    if (p) return { ...p }
  }
  return null
}

const scopes = []
const valid = []
for (const v of corpus) {
  const entry = { s: v, ...normalize(v) }
  if (entry.n !== null) {
    entry.p = parsed(v)
    const again = normalize(entry.n)
    if (again.n !== entry.n) entry.b = true // reference output does not round trip
    valid.push(v)
  }
  scopes.push(entry)
}

// ---------------------------------------------------------------------------
// Permission checks over scope sets

const queries = []
for (const collection of ['com.example.foo', 'com.example.bar', 'app.bsky.feed.post', 'COM.example.foo', 'com.example.calendar.event', '*', 'any.collection', 'invalid']) {
  for (const action of ['create', 'update', 'delete']) queries.push({ r: 'repo', o: { collection, action } })
}
for (const aud of ['did:web:example.com#service_id', 'did:web:example.com', 'did:web:example.com#foo', 'did:web:api.bsky.app#bsky_appview', '*', 'did:plc:blahbla']) {
  for (const lxm of ['com.example.method1', 'com.example.service', 'app.bsky.feed.getFeed', 'chat.bsky.convo.getLog', '*', 'com.example.calendar.listEvents']) {
    queries.push({ r: 'rpc', o: { aud, lxm } })
  }
}
for (const mime of ['image/png', 'IMAGE/PNG', 'image/jpeg', 'image/*', '*/*', 'text/html', 'image', 'video/mp4', 'application/json', 'image/svg+xml']) {
  queries.push({ r: 'blob', o: { mime } })
}
for (const attr of ['email', 'repo', 'status']) {
  for (const action of ['read', 'manage']) queries.push({ r: 'account', o: { attr, action } })
}
for (const attr of ['handle', '*']) queries.push({ r: 'identity', o: { attr } })

const method = { repo: 'Repo', rpc: 'Rpc', blob: 'Blob', account: 'Account', identity: 'Identity' }
const needed = { repo: s.RepoPermission, rpc: s.RpcPermission, blob: s.BlobPermission, account: s.AccountPermission, identity: s.IdentityPermission }
for (const q of queries) q.n = needed[q.r].scopeNeededFor(q.o)

const checks = (perms) => queries.map((q) => (perms[`allows${method[q.r]}`](q.o) ? '1' : '0')).join('')
const matchable = valid.filter((v) => !/^include[:?]/.test(v))
const statics = ['atproto', 'transition:generic', 'transition:email', 'transition:chat.bsky']
// Values that make the reference throw are left out: one would make every
// check on the set throw.
const nonThrowing = scopes.filter((e) => !e.t).map((e) => e.s)
const sets = []
for (let i = 0; i < 600 * scale; i++) {
  const values = some([...matchable, ...matchable, ...statics, pick(nonThrowing)], 4)
  const scope = values.join(' ')
  sets.push({
    s: scope,
    strict: checks(new s.ScopePermissions(scope)),
    transition: checks(new s.ScopePermissionsTransition(scope)),
  })
}

// ---------------------------------------------------------------------------
// include: expansion

const includes = []
const realSets = walk(join(atprotoDir, 'lexicons'), (p) => p.endsWith('.json'))
  .map((p) => JSON.parse(readFileSync(p, 'utf8')))
  .filter((doc) => doc.defs?.main?.type === 'permission-set')
for (const doc of realSets) {
  for (const scope of [`include:${doc.id}`, `include:${doc.id}?aud=did:web:api.bsky.app%23bsky_appview`, `include:${doc.id}?aud=did:web:api.bsky.chat%23bsky_chat`]) {
    includes.push({ s: scope, set: doc.defs.main, scopes: s.IncludeScope.fromString(scope).toScopes(doc.defs.main) })
  }
}

const LEX_VALUES = [
  ...NSIDS.slice(0, 12), ...AUDS.slice(0, 12), ...MIMES.slice(0, 6), ...WORDS,
  1, 0, true, false, null, {}, [], ['create'], ['create', 'delete'], ['read'], ['manage'], ['image/*'],
  ['com.example.calendar.event'], ['com.example.calendar.event', 'com.example.calendar.rsvp'],
  ['com.example.calendar.listEvents'], ['com.example.calendar.event', 'app.bsky.feed.post'],
  ['com.example.calendar.sub.thing'], ['*'], [1], ['com.example.calendar.event', 2], [null],
]
const LEX_KEYS = ['collection', 'action', 'lxm', 'aud', 'accept', 'attr', 'nsid', 'inheritAud', 'inheritAud', 'extra', 'description']
const lexPermission = () => {
  const p = { type: 'permission', resource: pick(['repo', 'repo', 'rpc', 'rpc', 'rpc', 'blob', 'account', 'identity', 'include', 'other']) }
  if (p.resource === 'repo' && rand() < 0.6) p.collection = pick([['com.example.calendar.event'], ['com.example.calendar.event', 'com.example.calendar.rsvp'], ['com.example.calendar.sub.thing']])
  if (p.resource === 'rpc' && rand() < 0.6) p.lxm = pick([['com.example.calendar.listEvents'], ['com.example.calendar.a', 'com.example.calendar.b']])
  if (p.resource === 'rpc' && rand() < 0.5) {
    if (rand() < 0.6) p.inheritAud = true
    else p.aud = pick(['*', 'did:web:example.com#foo', null])
  }
  for (const k of some(LEX_KEYS, 2)) p[k] = pick(LEX_VALUES)
  return p
}
const INCLUDE_SCOPES = [
  'include:com.example.calendar.auth', 'include:com.example.calendar.auth?aud=did:web:example.com%23foo',
  'include:com.example.calendar.auth?aud=did:web:example.com#bar', 'include:com.example.auth', 'include:com.example.calendar.sub.auth',
  'include:COM.example.calendar.auth',
]
for (let i = 0; i < 300 * scale; i++) {
  const set = { type: 'permission-set', permissions: Array.from({ length: 1 + int(4) }, lexPermission) }
  const scope = pick(INCLUDE_SCOPES)
  includes.push({ s: scope, set, scopes: s.IncludeScope.fromString(scope).toScopes(set) })
}

// ---------------------------------------------------------------------------

const git = (dir) => execFileSync('git', ['-C', dir, 'rev-parse', 'HEAD']).toString().trim()
const vectors = {
  generator: 'scripts/oauth-scope-vectors.mjs',
  atproto: git(atprotoDir),
  indigo: git(indigoDir),
  seed,
  scale,
  scopes,
  queries,
  sets,
  includes,
}
mkdirSync(dirname(out), { recursive: true })
writeFileSync(out, JSON.stringify(vectors) + '\n')
const brokenCount = scopes.filter((e) => e.b).length
const throwsCount = scopes.filter((e) => e.t).length
console.log(
  `wrote ${out}: ${scopes.length} scopes (${valid.length} valid, ${throwsCount} throw, ${brokenCount} non-round-tripping), ` +
    `${sets.length} sets x ${queries.length} checks, ${includes.length} includes (${realSets.length} real sets)`,
)
