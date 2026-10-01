#!/usr/bin/env node
// Generates differential test vectors for `shrike::repo::proof` by building
// repositories with the reference TypeScript `@atproto/repo` (built), serving
// record proofs exactly as the PDS does (`getRecords`, the
// `com.atproto.sync.getRecord` handler), and recording the reference
// verifier's (`verifyProofs`) verdict on each.
//
// Repositories hold `fill` records at deterministic keys, so the Rust side
// can rebuild the same MST and compare proof contents block for block.
//
// Usage:
//   node scripts/repo-proof-vectors.mjs [out]
//
// ATPROTO_DIR defaults to a sibling checkout under ../../bluesky-social/. The
// output defaults to testdata/repo_proofs/ts_vectors.json, which
// tests/repo_proof_interop.rs reads.

import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const atprotoDir = resolve(process.env.ATPROTO_DIR ?? join(root, '../../bluesky-social/atproto'))
const out = resolve(process.argv[2] ?? join(root, 'testdata/repo_proofs/ts_vectors.json'))

const load = (pkg) => import(pathToFileURL(join(atprotoDir, 'packages', pkg, 'dist/index.js')).href)
const repo = await load('repo')
const crypto = await load('crypto')
const { cidForLex } = await import(
  pathToFileURL(join(atprotoDir, 'packages/lex/lex-cbor/dist/index.js')).href
)

const DID = 'did:plc:vectorsvectorsvectorsvec'
const OTHER_DID = 'did:plc:otherotherotherotherothe'
const COLLECTION = 'com.atproto.lexicon.schema'

// Must match tests/repo_proof_interop.rs.
const rkeyFor = (i) => `com.example.n${String(i).padStart(4, '0')}`
const recordFor = (rkey) => ({ $type: COLLECTION, lexicon: 1, id: rkey, defs: {} })

const b64 = (bytes) => Buffer.from(bytes).toString('base64')

async function toBytes(iter) {
  const chunks = []
  for await (const c of iter) chunks.push(c)
  return Buffer.concat(chunks)
}

async function build(keypair, fill) {
  const storage = new repo.MemoryBlockstore()
  const writes = []
  for (let i = 0; i < fill; i++) {
    const rkey = rkeyFor(i)
    writes.push({
      action: repo.WriteOpAction.Create,
      collection: COLLECTION,
      rkey,
      record: recordFor(rkey),
    })
  }
  const r = await repo.Repo.create(storage, DID, keypair, writes)
  return { storage, r }
}

/// The reference verifier's verdict: the record CID, null for a proven
/// absence, or 'error' for a rejected proof.
async function verdict(proof, rkey, did, signingKey) {
  try {
    const claim = { collection: COLLECTION, rkey, cid: null }
    const res = await repo.verifyProofs(proof, [claim], did, signingKey)
    if (res.verified.length === 1) return null
    // Not absent: it must be present. Ask for the CID the proof commits to.
    const records = await repo.verifyRecords(proof, did, signingKey)
    const found = records.find((x) => x.rkey === rkey)
    return found ? (await cidForLex(found.record)).toString() : 'error'
  } catch {
    return 'error'
  }
}

const cases = []
for (const [keyType, mkKey] of [
  ['p256', () => crypto.P256Keypair.create()],
  ['k256', () => crypto.Secp256k1Keypair.create()],
]) {
  const keypair = await mkKey()
  const other = await mkKey()
  for (const fill of [0, 1, 10, 100, 500]) {
    const { storage, r } = await build(keypair, fill)
    const probes = new Set(['com.example.a', 'com.example.n0000a', 'com.example.z'])
    if (fill > 0) {
      probes.add(rkeyFor(0))
      probes.add(rkeyFor(Math.floor(fill / 2)))
      probes.add(rkeyFor(fill - 1))
    }
    for (const rkey of probes) {
      const proof = await toBytes(repo.getRecords(storage, r.cid, [{ collection: COLLECTION, rkey }]))
      const variants = [
        ['ok', DID, keypair.did()],
        ['wrong_key', DID, other.did()],
        ['wrong_did', OTHER_DID, keypair.did()],
      ]
      for (const [variant, did, signingKey] of variants) {
        cases.push({
          name: `${keyType}/fill${fill}/${rkey}/${variant}`,
          fill,
          did,
          signingKey,
          rkey,
          dataCid: r.commit.data.toString(),
          proof: b64(proof),
          expect: await verdict(proof, rkey, did, signingKey),
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
      generator: 'scripts/repo-proof-vectors.mjs (@atproto/repo getRecords + verifyProofs)',
      repoDid: DID,
      collection: COLLECTION,
      cases,
    },
    null,
    1,
  ) + '\n',
)
console.log(`wrote ${cases.length} cases to ${out}`)
