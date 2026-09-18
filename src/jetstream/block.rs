//! Bounded columnar block decode.
//!
//! A Jetstream archive block, once decompressed, is a columnar buffer: a
//! `u32` event count, then nine fixed-width columns, then five variable-length
//! blob regions (collections, DIDs, rkeys, revs, payloads) concatenated in that
//! order. This module turns that buffer into [`RawEvent`] rows.
//!
//! The layout is validated with checked arithmetic before any slice is taken:
//! the event count is capped, the fixed region must fit, and the blob regions
//! must account for the buffer exactly — no trailing and no truncation. A
//! corrupt or hostile buffer therefore yields an [`Error`], never a panic or an
//! oversized allocation.

use super::compression::{MAX_DECODED_BLOCK_BYTES, decompress_bounded};
use super::error::{Error, Result};
use super::event::Operation;
use super::filter::Kind;

/// Go's `maxBlockEventsLimit`: the maximum rows a single block may declare.
pub const MAX_BLOCK_EVENTS: usize = 1 << 18; // 262_144

/// Fixed per-event column bytes: `seq(8) + witnessed_at(8) + indexed_at(8) +
/// kind(1) + collection_len(1) + did_len(2) + rkey_len(1) + rev_len(1) +
/// payload_len(4)`.
const FIXED_PER_EVENT: usize = 8 + 8 + 8 + 1 + 1 + 2 + 1 + 1 + 4; // 34

/// The kind of a segment row. Wire codes 1..=7, matching the Jetstream
/// `segment` package.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SegmentKind {
    /// Record create.
    Create,
    /// Record update.
    Update,
    /// Record delete.
    Delete,
    /// Identity change.
    Identity,
    /// Account state change.
    Account,
    /// Repo sync marker.
    Sync,
    /// Create emitted during a resync; the client exposes it as a create.
    CreateResync,
}

impl SegmentKind {
    /// Map a wire code to a kind, rejecting `0` and anything above `7`.
    pub fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            1 => Self::Create,
            2 => Self::Update,
            3 => Self::Delete,
            4 => Self::Identity,
            5 => Self::Account,
            6 => Self::Sync,
            7 => Self::CreateResync,
            _ => return Err(Error::CorruptSegment("invalid event kind")),
        })
    }

    /// The wire code for this kind.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Create => 1,
            Self::Update => 2,
            Self::Delete => 3,
            Self::Identity => 4,
            Self::Account => 5,
            Self::Sync => 6,
            Self::CreateResync => 7,
        }
    }

    /// The public [`Kind`] this row is delivered as. Every commit-ish kind
    /// (create, update, delete, and create-resync) collapses to
    /// [`Kind::Commit`]; the three DID-level kinds map to themselves.
    pub fn public_kind(self) -> Kind {
        match self {
            Self::Create | Self::Update | Self::Delete | Self::CreateResync => Kind::Commit,
            Self::Identity => Kind::Identity,
            Self::Account => Kind::Account,
            Self::Sync => Kind::Sync,
        }
    }

    /// The commit [`Operation`] for a commit-ish kind, or `None` for a DID-level
    /// kind. `create-resync` (wire code 7) folds into [`Operation::Create`],
    /// matching the Go client.
    pub fn to_operation(self) -> Option<Operation> {
        match self {
            Self::Create | Self::CreateResync => Some(Operation::Create),
            Self::Update => Some(Operation::Update),
            Self::Delete => Some(Operation::Delete),
            Self::Identity | Self::Account | Self::Sync => None,
        }
    }
}

/// One decoded segment row, still carrying raw column bytes.
///
/// M0 keeps the string-like columns as owned bytes so the decoder is faithful
/// to the wire (it validates neither UTF-8 nor atproto syntax here; higher
/// layers do). M2 replaces the owned buffers with slices into a single shared
/// decompressed slab.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RawEvent {
    /// Jetstream sequence cursor.
    pub seq: u64,
    /// Time the event was witnessed, in unix microseconds.
    pub witnessed_at: i64,
    /// Time the event was indexed, in unix microseconds; `0` when not imported.
    pub indexed_at: i64,
    /// Row kind.
    pub kind: SegmentKind,
    /// Collection NSID bytes (empty for DID-level markers).
    pub collection: Vec<u8>,
    /// DID bytes.
    pub did: Vec<u8>,
    /// Record key bytes (empty for DID-level markers).
    pub rkey: Vec<u8>,
    /// Repo revision bytes (empty for DID-level markers).
    pub rev: Vec<u8>,
    /// Opaque payload bytes (record CBOR, upstream event CBOR, or empty).
    pub payload: Vec<u8>,
}

impl RawEvent {
    /// Display time: `indexed_at` when nonzero, else `witnessed_at`
    /// (Go `DisplayTimeUS`).
    pub fn display_time_us(&self) -> i64 {
        if self.indexed_at != 0 {
            self.indexed_at
        } else {
            self.witnessed_at
        }
    }
}

/// Decompress a raw `getBlock` zstd frame (no 8-byte length prefix) and decode
/// its rows. Segment blocks are never dictionary-compressed.
pub fn decode_block_frame(frame: &[u8]) -> Result<Vec<RawEvent>> {
    let body = decompress_bounded(frame, MAX_DECODED_BLOCK_BYTES, None)?;
    decode_block(&body)
}

/// Decode an already-decompressed columnar block body.
pub fn decode_block(body: &[u8]) -> Result<Vec<RawEvent>> {
    let n = read_u32(body, 0)? as usize;
    if n == 0 {
        // An empty block is exactly four zero bytes; anything more is corruption.
        if body.len() != 4 {
            return Err(Error::CorruptSegment("empty block has trailing bytes"));
        }
        return Ok(Vec::new());
    }
    if n > MAX_BLOCK_EVENTS {
        return Err(Error::LimitExceeded {
            what: "block events",
            value: n as u64,
            limit: MAX_BLOCK_EVENTS as u64,
        });
    }

    // Fixed region: the 4-byte count plus n * FIXED_PER_EVENT.
    let fixed = n
        .checked_mul(FIXED_PER_EVENT)
        .and_then(|v| v.checked_add(4))
        .ok_or(Error::CorruptSegment("fixed region size overflow"))?;
    if body.len() < fixed {
        return Err(Error::Truncated("block fixed columns"));
    }

    // Column base offsets within the fixed region.
    let seq_off = 4;
    let wit_off = seq_off + 8 * n;
    let idx_off = wit_off + 8 * n;
    let kind_off = idx_off + 8 * n;
    let coll_len_off = kind_off + n;
    let did_len_off = coll_len_off + n;
    let rkey_len_off = did_len_off + 2 * n;
    let rev_len_off = rkey_len_off + n;
    let plen_off = rev_len_off + n;

    // Read the length columns and accumulate blob-region sizes in u64 so the
    // sums cannot overflow on 32-bit wasm (did_len alone can reach 65535).
    let mut coll_len = Vec::with_capacity(n);
    let mut did_len = Vec::with_capacity(n);
    let mut rkey_len = Vec::with_capacity(n);
    let mut rev_len = Vec::with_capacity(n);
    let mut payload_len = Vec::with_capacity(n);
    let (mut sum_coll, mut sum_did, mut sum_rkey, mut sum_rev, mut sum_payload) =
        (0u64, 0u64, 0u64, 0u64, 0u64);
    for i in 0..n {
        let cl = body[coll_len_off + i];
        let dl = read_u16(body, did_len_off + 2 * i)?;
        let kl = body[rkey_len_off + i];
        let vl = body[rev_len_off + i];
        let pl = read_u32(body, plen_off + 4 * i)?;
        sum_coll += u64::from(cl);
        sum_did += u64::from(dl);
        sum_rkey += u64::from(kl);
        sum_rev += u64::from(vl);
        sum_payload += u64::from(pl);
        coll_len.push(cl as usize);
        did_len.push(dl as usize);
        rkey_len.push(kl as usize);
        rev_len.push(vl as usize);
        payload_len.push(pl as usize);
    }

    // The blob regions must account for the rest of the buffer exactly.
    let total_blob = sum_coll
        .checked_add(sum_did)
        .and_then(|v| v.checked_add(sum_rkey))
        .and_then(|v| v.checked_add(sum_rev))
        .and_then(|v| v.checked_add(sum_payload))
        .ok_or(Error::CorruptSegment("blob region size overflow"))?;
    let expected = (fixed as u64)
        .checked_add(total_blob)
        .ok_or(Error::CorruptSegment("block size overflow"))?;
    if expected != body.len() as u64 {
        return Err(if expected > body.len() as u64 {
            Error::Truncated("block blob regions")
        } else {
            Error::CorruptSegment("block has trailing bytes")
        });
    }

    // After the exact-fit check, all region offsets are in-bounds usizes.
    let coll_start = fixed;
    let did_start = coll_start + sum_coll as usize;
    let rkey_start = did_start + sum_did as usize;
    let rev_start = rkey_start + sum_rkey as usize;
    let payload_start = rev_start + sum_rev as usize;

    let (mut c, mut d, mut k, mut v, mut p) =
        (coll_start, did_start, rkey_start, rev_start, payload_start);
    let mut events = Vec::with_capacity(n);
    for i in 0..n {
        let event = RawEvent {
            seq: read_u64(body, seq_off + 8 * i)?,
            witnessed_at: read_i64(body, wit_off + 8 * i)?,
            indexed_at: read_i64(body, idx_off + 8 * i)?,
            kind: SegmentKind::from_u8(body[kind_off + i])?,
            collection: body[c..c + coll_len[i]].to_vec(),
            did: body[d..d + did_len[i]].to_vec(),
            rkey: body[k..k + rkey_len[i]].to_vec(),
            rev: body[v..v + rev_len[i]].to_vec(),
            payload: body[p..p + payload_len[i]].to_vec(),
        };
        c += coll_len[i];
        d += did_len[i];
        k += rkey_len[i];
        v += rev_len[i];
        p += payload_len[i];
        events.push(event);
    }
    Ok(events)
}

fn read_u16(b: &[u8], off: usize) -> Result<u16> {
    let end = off.checked_add(2).ok_or(Error::Truncated("u16 column"))?;
    let slice = b.get(off..end).ok_or(Error::Truncated("u16 column"))?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(b: &[u8], off: usize) -> Result<u32> {
    let end = off.checked_add(4).ok_or(Error::Truncated("u32 column"))?;
    let slice = b.get(off..end).ok_or(Error::Truncated("u32 column"))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64(b: &[u8], off: usize) -> Result<u64> {
    let end = off.checked_add(8).ok_or(Error::Truncated("u64 column"))?;
    let slice = b.get(off..end).ok_or(Error::Truncated("u64 column"))?;
    let mut a = [0u8; 8];
    a.copy_from_slice(slice);
    Ok(u64::from_le_bytes(a))
}

fn read_i64(b: &[u8], off: usize) -> Result<i64> {
    Ok(read_u64(b, off)? as i64)
}
