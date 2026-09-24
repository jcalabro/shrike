pub(crate) const RESERVED_HEADER_BYTES: usize = 256;
pub(crate) const BLOCK_INDEX_ENTRY_SIZE: usize = 52;

pub(crate) const DID_A: &str = "did:plc:abcdefghijklmnopqrstuvwx";
pub(crate) const RKEY: &str = "3l3qo2vuowo2b";
pub(crate) const REV: &str = "3l3qo2vutsw2b";

/// One create-commit row with a minimal (empty-map) CBOR record body.
pub(crate) fn row(seq: u64) -> Row {
    Row {
        seq,
        witnessed_at: seq as i64 * 100,
        indexed_at: 0,
        kind: 1, // create
        collection: b"app.bsky.feed.post".to_vec(),
        did: DID_A.as_bytes().to_vec(),
        rkey: RKEY.as_bytes().to_vec(),
        rev: REV.as_bytes().to_vec(),
        payload: vec![0xA0], // CBOR {}
    }
}

pub(crate) struct Row {
    pub(crate) seq: u64,
    pub(crate) witnessed_at: i64,
    pub(crate) indexed_at: i64,
    pub(crate) kind: u8,
    pub(crate) collection: Vec<u8>,
    pub(crate) did: Vec<u8>,
    pub(crate) rkey: Vec<u8>,
    pub(crate) rev: Vec<u8>,
    pub(crate) payload: Vec<u8>,
}

/// Encode the decompressed columnar body for one block.
pub(crate) fn block_body(rows: &[Row]) -> Vec<u8> {
    let n = rows.len();
    let mut b = Vec::new();
    b.extend_from_slice(&(n as u32).to_le_bytes());
    if n == 0 {
        return b;
    }
    for r in rows {
        b.extend_from_slice(&r.seq.to_le_bytes());
    }
    for r in rows {
        b.extend_from_slice(&r.witnessed_at.to_le_bytes());
    }
    for r in rows {
        b.extend_from_slice(&r.indexed_at.to_le_bytes());
    }
    for r in rows {
        b.push(r.kind);
    }
    for r in rows {
        b.push(r.collection.len() as u8);
    }
    for r in rows {
        b.extend_from_slice(&(r.did.len() as u16).to_le_bytes());
    }
    for r in rows {
        b.push(r.rkey.len() as u8);
    }
    for r in rows {
        b.push(r.rev.len() as u8);
    }
    for r in rows {
        b.extend_from_slice(&(r.payload.len() as u32).to_le_bytes());
    }
    for r in rows {
        b.extend_from_slice(&r.collection);
    }
    for r in rows {
        b.extend_from_slice(&r.did);
    }
    for r in rows {
        b.extend_from_slice(&r.rkey);
    }
    for r in rows {
        b.extend_from_slice(&r.rev);
    }
    for r in rows {
        b.extend_from_slice(&r.payload);
    }
    b
}

/// The compressed zstd frame for a single block, as `getBlock` returns it.
pub(crate) fn block_frame(rows: &[Row]) -> Vec<u8> {
    zstd::bulk::compress(&block_body(rows), 3).expect("compress block")
}

/// Assemble a complete sealed segment and return its bytes plus the lowercase
/// 16-hex checksum the plan would name for it.
pub(crate) fn seal(blocks: &[Vec<Row>]) -> (Vec<u8>, String) {
    use core::hash::Hasher;
    use twox_hash::XxHash3_64;

    let mut file = vec![0u8; RESERVED_HEADER_BYTES];
    let mut index: Vec<[u8; BLOCK_INDEX_ENTRY_SIZE]> = Vec::new();
    let mut ev_count = 0u32;
    let (mut min_seq, mut max_seq) = (u64::MAX, 0u64);
    let (mut min_w, mut max_w) = (i64::MAX, i64::MIN);

    for rows in blocks {
        let body = block_body(rows);
        let frame = zstd::bulk::compress(&body, 3).expect("compress block");
        let offset = file.len() as u64;
        file.extend_from_slice(&(frame.len() as u64).to_le_bytes());
        file.extend_from_slice(&frame);

        let (mut bmin_s, mut bmax_s) = (u64::MAX, 0u64);
        let (mut bmin_w, mut bmax_w) = (i64::MAX, i64::MIN);
        for r in rows {
            ev_count += 1;
            bmin_s = bmin_s.min(r.seq);
            bmax_s = bmax_s.max(r.seq);
            bmin_w = bmin_w.min(r.witnessed_at);
            bmax_w = bmax_w.max(r.witnessed_at);
        }
        if rows.is_empty() {
            bmin_s = 0;
            bmax_s = 0;
            bmin_w = 0;
            bmax_w = 0;
        } else {
            min_seq = min_seq.min(bmin_s);
            max_seq = max_seq.max(bmax_s);
            min_w = min_w.min(bmin_w);
            max_w = max_w.max(bmax_w);
        }

        let mut e = [0u8; BLOCK_INDEX_ENTRY_SIZE];
        e[0..8].copy_from_slice(&offset.to_le_bytes());
        e[8..12].copy_from_slice(&(frame.len() as u32).to_le_bytes());
        e[12..16].copy_from_slice(&(body.len() as u32).to_le_bytes());
        e[16..20].copy_from_slice(&(rows.len() as u32).to_le_bytes());
        e[20..28].copy_from_slice(&bmin_s.to_le_bytes());
        e[28..36].copy_from_slice(&bmax_s.to_le_bytes());
        e[36..44].copy_from_slice(&bmin_w.to_le_bytes());
        e[44..52].copy_from_slice(&bmax_w.to_le_bytes());
        index.push(e);
    }

    let footer_offset = file.len() as u64;
    for e in &index {
        file.extend_from_slice(e);
    }
    let file_len = file.len() as u64;

    if ev_count == 0 {
        min_seq = 0;
        max_seq = 0;
        min_w = 0;
        max_w = 0;
    }

    file[0..4].copy_from_slice(b"jss0");
    file[12..14].copy_from_slice(&1u16.to_le_bytes());
    file[14..18].copy_from_slice(&(blocks.len() as u32).to_le_bytes());
    file[18..22].copy_from_slice(&ev_count.to_le_bytes());
    file[22..26].copy_from_slice(&0u32.to_le_bytes());
    file[26..34].copy_from_slice(&min_seq.to_le_bytes());
    file[34..42].copy_from_slice(&max_seq.to_le_bytes());
    file[42..50].copy_from_slice(&min_w.to_le_bytes());
    file[50..58].copy_from_slice(&max_w.to_le_bytes());
    file[58..66].copy_from_slice(&footer_offset.to_le_bytes());
    file[66..74].copy_from_slice(&file_len.to_le_bytes());
    file[74..82].copy_from_slice(&file_len.to_le_bytes());
    file[82..90].copy_from_slice(&file_len.to_le_bytes());
    file[90..98].copy_from_slice(&footer_offset.to_le_bytes());

    let mut hasher = XxHash3_64::new();
    hasher.write(&file[12..RESERVED_HEADER_BYTES]);
    hasher.write(&file[footer_offset as usize..]);
    let checksum = hasher.finish();
    file[4..12].copy_from_slice(&checksum.to_le_bytes());
    (file, format!("{checksum:016x}"))
}
