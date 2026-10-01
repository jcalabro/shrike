#!/usr/bin/env node
// Generates differential test vectors for shrike's repository writes,
// covering proofs, and multi-record proofs from the reference TypeScript
// `@atproto/repo` (built):
//
// - coveringProofs: `MST.getCoveringProof` node sets on trees of random keys.
// - commits: batches of writes applied by `Repo.formatCommit` to repos that
//   start from a full-repo CAR (`getFullRepo`), with the resulting MST root,
//   new/removed/relevant blocks, and record ops.
// - multiProofs: `getRecords` proofs for several paths, with the verdicts of
//   `verifyProofs` and `verifyRecords` on them.
//
// Usage:
//   node scripts/repo-commit-vectors.mjs [out]
//
// ATPROTO_DIR defaults to a sibling checkout under ../../bluesky-social/. The
// output defaults to testdata/repo_proofs/commit_vectors.json, which
// tests/repo_commit_interop.rs reads.

import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const atprotoDir = resolve(process.env.ATPROTO_DIR ?? join(root, '../../bluesky-social/atproto'))
const out = resolve(process.argv[2] ?? join(root, 'testdata/repo_proofs/commit_vectors.json'))

const load = (pkg) => import(pathToFileURL(join(atprotoDir, 'packages', pkg, 'dist/index.js')).href)
const repo = await load('repo')
const crypto = await load('crypto')
const { cidForLex } = await import(
  pathToFileURL(join(atprotoDir, 'packages/lex/lex-cbor/dist/index.js')).href
)
const { parseCid } = await import(
  pathToFileURL(join(atprotoDir, 'packages/lex/lex-data/dist/index.js')).href
)

const DID = 'did:plc:vectorsvectorsvectorsvec'
const OTHER_DID = 'did:plc:otherotherotherotherothe'
const COLLECTIONS = ['com.example.alpha', 'com.example.beta']
const LEAF = parseCid('bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454')

// Must match tests/repo_commit_interop.rs.
const pathFor = (i) => ({ collection: COLLECTIONS[i % 2], rkey: `r${String(i).padStart(5, '0')}` })
const recordFor = (collection, rkey, v) => ({ $type: collection, rkey, v })

const b64 = (bytes) => Buffer.from(bytes).toString('base64')
const sorted = (cids) => cids.map((c) => c.toString()).sort()

async function toBytes(iter) {
  const chunks = []
  for await (const c of iter) chunks.push(c)
  return Buffer.concat(chunks)
}

// mulberry32: a small seeded PRNG so the vectors are reproducible.
function rng(seed) {
  let a = seed >>> 0
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
  return { next, int: (n) => Math.floor(next() * n) }
}

// --- covering proofs --------------------------------------------------------

const coveringProofs = []
{
  const r = rng(7)
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789'
  const randKey = () => {
    let s = ''
    const n = 1 + r.int(8)
    for (let i = 0; i < n; i++) s += alphabet[r.int(alphabet.length)]
    return `com.example.k/${s}`
  }
  for (const size of [0, 1, 2, 5, 20, 60, 150, 300]) {
    const keys = new Set()
    while (keys.size < size) keys.add(randKey())
    let mst = await repo.MST.create(new repo.MemoryBlockstore())
    for (const k of keys) mst = await mst.add(k, LEAF)
    const probes = new Set([...keys].filter(() => r.next() < 0.3))
    for (let i = 0; i < 20; i++) probes.add(randKey())
    probes.add('com.example.k/')
    probes.add('com.example.k/~')
    const cases = []
    for (const key of [...probes].sort()) {
      cases.push({ key, proof: sorted((await mst.getCoveringProof(key)).cids()) })
    }
    coveringProofs.push({
      name: `size${size}`,
      keys: [...keys].sort(),
      root: (await mst.getPointer()).toString(),
      probes: cases,
    })
  }
}

// --- commits ------------------------------------------------------------------

async function filled(keypair, fill) {
  const storage = new repo.MemoryBlockstore()
  const writes = []
  const records = new Map()
  for (let i = 0; i < fill; i++) {
    const { collection, rkey } = pathFor(i)
    const record = recordFor(collection, rkey, 0)
    records.set(`${collection}/${rkey}`, record)
    writes.push({ action: repo.WriteOpAction.Create, collection, rkey, record })
  }
  const r = await repo.Repo.create(storage, DID, keypair, writes)
  return { storage, r, records }
}

/// A random batch of writes against `existing` paths. Mostly valid; `bad`
/// injects one invalid write.
function batch(r, fill, existing, size, bad) {
  const present = new Set(existing)
  const writes = []
  const pick = () => [...present][r.int(present.size)]
  for (let n = 0; n < size; n++) {
    const roll = r.next()
    if (roll < 0.4 || present.size === 0) {
      // A new path, sometimes one between existing keys.
      const i = fill + 1000 + r.int(9000)
      const { collection, rkey } = pathFor(i)
      const key = `${collection}/${rkey}`
      if (present.has(key)) continue
      present.add(key)
      writes.push({ action: 'create', key })
    } else if (roll < 0.7) {
      writes.push({ action: 'update', key: pick() })
    } else {
      const key = pick()
      present.delete(key)
      writes.push({ action: 'delete', key })
    }
  }
  if (bad === 'createExisting' && existing.length > 0) {
    writes.push({ action: 'create', key: existing[0] })
  } else if (bad === 'updateMissing') {
    writes.push({ action: 'update', key: `${COLLECTIONS[0]}/missing` })
  } else if (bad === 'deleteMissing') {
    writes.push({ action: 'delete', key: `${COLLECTIONS[1]}/missing` })
  }
  return writes
}

const commits = []
{
  const r = rng(42)
  const keypair = await crypto.Secp256k1Keypair.create()
  const plans = []
  for (const fill of [0, 1, 7, 40, 150]) {
    for (const size of [1, 3, 12]) plans.push({ fill, size })
  }
  plans.push({ fill: 40, size: 40 })
  plans.push({ fill: 40, size: 1, script: ['create', 'delete'] })
  plans.push({ fill: 40, size: 1, script: ['create', 'update', 'update'] })
  plans.push({ fill: 40, size: 1, script: ['deleteExisting', 'recreate'] })
  for (const bad of ['createExisting', 'updateMissing', 'deleteMissing']) {
    plans.push({ fill: 40, size: 3, bad })
  }
  plans.push({ fill: 7, size: 0 })

  for (const [n, plan] of plans.entries()) {
    const { storage, r: before, records } = await filled(keypair, plan.fill)
    const existing = [...records.keys()]
    let writes
    if (plan.script) {
      const fresh = `${COLLECTIONS[0]}/r${String(plan.fill + 500).padStart(5, '0')}`
      const old = existing[Math.floor(existing.length / 2)]
      writes = plan.script.map((step) => {
        if (step === 'create') return { action: 'create', key: fresh }
        if (step === 'update') return { action: 'update', key: fresh }
        if (step === 'delete') return { action: 'delete', key: fresh }
        if (step === 'deleteExisting') return { action: 'delete', key: old }
        return { action: 'create', key: old }
      })
    } else {
      writes = batch(r, plan.fill, existing, plan.size, plan.bad)
    }

    // Each write of a record gets content unique to its place in the batch.
    const ops = writes.map((w, i) => {
      const [collection, rkey] = w.key.split('/')
      if (w.action === 'delete') return { action: repo.WriteOpAction.Delete, collection, rkey }
      const action = w.action === 'create' ? repo.WriteOpAction.Create : repo.WriteOpAction.Update
      return { action, collection, rkey, record: recordFor(collection, rkey, i + 1) }
    })
    const car = await toBytes(repo.getFullRepo(storage, before.cid))
    const vec = {
      name: `commit${n}/fill${plan.fill}/size${writes.length}${plan.bad ? `/${plan.bad}` : ''}${plan.script ? `/${plan.script.join('-')}` : ''}`,
      car: b64(car),
      dataBefore: before.commit.data.toString(),
      writes: writes.map((w, i) => ({ ...w, v: w.action === 'delete' ? null : i + 1 })),
    }
    let commit
    try {
      commit = await before.formatCommit(ops, keypair)
    } catch {
      commits.push({ ...vec, expect: 'error' })
      continue
    }
    const after = await before.applyCommit(commit)
    const diff = await repo.DataDiff.of(after.data, before.data)
    const descripts = await repo.diffToWriteDescripts(diff)
    const oldRecordCids = new Set()
    for (const rec of records.values()) oldRecordCids.add((await cidForLex(rec)).toString())
    const commitCid = commit.cid.toString()
    const notCommit = (c) => c !== commitCid
    commits.push({
      ...vec,
      expect: {
        dataAfter: after.commit.data.toString(),
        newBlocks: sorted(commit.newBlocks.cids()).filter(notCommit),
        relevantBlocks: sorted(commit.relevantBlocks.cids()).filter(notCommit),
        removedMst: sorted(commit.removedCids.toList()).filter(
          (c) => c !== before.cid.toString() && !oldRecordCids.has(c),
        ),
        ops: descripts
          .map((d) => ({
            action: d.action,
            key: `${d.collection}/${d.rkey}`,
            cid: d.action === 'delete' ? null : d.cid.toString(),
            prev: d.action === 'create' ? null : (d.prev ?? d.cid).toString(),
          }))
          .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0)),
      },
    })
  }
}

// --- multi-record proofs ------------------------------------------------------

const multiProofs = []
{
  const r = rng(99)
  const keypair = await crypto.P256Keypair.create()
  const other = await crypto.P256Keypair.create()
  for (const fill of [0, 3, 60, 400]) {
    const { storage, r: rp, records } = await filled(keypair, fill)
    const existing = [...records.keys()]
    for (let t = 0; t < 4; t++) {
      // Paths to prove: some present, some absent.
      const paths = new Set()
      const n = 1 + r.int(6)
      for (let i = 0; i < n; i++) {
        if (existing.length > 0 && r.next() < 0.6) paths.add(existing[r.int(existing.length)])
        else paths.add(`${COLLECTIONS[r.int(2)]}/x${r.int(100000)}`)
      }
      const pathList = [...paths].map((k) => {
        const [collection, rkey] = k.split('/')
        return { collection, rkey }
      })
      const proof = await toBytes(repo.getRecords(storage, rp.cid, pathList))

      // Claims: the proven paths with true and false CIDs, plus (on odd
      // trials) a path outside the proof.
      const claims = []
      for (const { collection, rkey } of pathList) {
        const rec = records.get(`${collection}/${rkey}`)
        const cid = rec ? (await cidForLex(rec)).toString() : null
        claims.push({ key: `${collection}/${rkey}`, cid })
        claims.push({ key: `${collection}/${rkey}`, cid: cid ? null : LEAF.toString() })
      }
      if (t % 2 === 1 && existing.length > 0) {
        const k = existing[r.int(existing.length)]
        if (!paths.has(k)) claims.push({ key: k, cid: (await cidForLex(records.get(k))).toString() })
      }

      for (const [variant, did, signingKey] of [
        ['ok', DID, keypair.did()],
        ['wrong_key', DID, other.did()],
        ['wrong_did', OTHER_DID, keypair.did()],
      ]) {
        let verdict
        try {
          const res = await repo.verifyProofs(
            proof,
            claims.map((c) => {
              const [collection, rkey] = c.key.split('/')
              return { collection, rkey, cid: c.cid ? parseCid(c.cid) : null }
            }),
            did,
            signingKey,
          )
          const key = (c) => `${c.collection}/${c.rkey}/${c.cid ? c.cid.toString() : null}`
          const ok = new Set(res.verified.map(key))
          verdict = claims.map((c) => ok.has(`${c.key}/${c.cid}`))
        } catch {
          verdict = 'error'
        }
        let recs
        try {
          const found = await repo.verifyRecords(proof, did, signingKey)
          recs = []
          for (const f of found) {
            recs.push({ key: `${f.collection}/${f.rkey}`, cid: (await cidForLex(f.record)).toString() })
          }
        } catch {
          recs = 'error'
        }
        multiProofs.push({
          name: `fill${fill}/trial${t}/${variant}`,
          fill,
          did,
          signingKey,
          paths: [...paths],
          proof: b64(proof),
          claims,
          verified: verdict,
          records: recs,
        })
      }
    }
  }
}

mkdirSync(dirname(out), { recursive: true })
writeFileSync(
  out,
  JSON.stringify(
    {
      generator: 'scripts/repo-commit-vectors.mjs (@atproto/repo MST, Repo.formatCommit, getRecords, verifyProofs, verifyRecords)',
      repoDid: DID,
      collections: COLLECTIONS,
      leaf: LEAF.toString(),
      coveringProofs,
      commits,
      multiProofs,
    },
    null,
    1,
  ) + '\n',
)
console.log(
  `wrote ${coveringProofs.length} covering-proof trees, ${commits.length} commits, ${multiProofs.length} multi-proofs to ${out}`,
)
