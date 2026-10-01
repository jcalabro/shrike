#![no_main]
//! `Repo::load_car` must never panic on arbitrary bytes. A CAR it accepts
//! must export and load back to the same repository, and stay writable.

use libfuzzer_sys::fuzz_target;
use shrike::crypto::P256SigningKey;
use shrike::repo::{Repo, WriteOp};
use shrike::syntax::{Nsid, RecordKey};

fuzz_target!(|data: &[u8]| {
    let Ok(mut repo) = Repo::load_car(data) else {
        return;
    };
    let car = repo.export_car().expect("export a loaded repo");
    let again = Repo::load_car(&car).expect("load an exported repo");
    assert_eq!(again.head_cid(), repo.head_cid());
    assert_eq!(again.export_car().expect("export"), car);

    let key = P256SigningKey::from_bytes(&[7; 32]).expect("valid key");
    let collection = Nsid::try_from("com.example.fuzz").expect("valid NSID");
    let rkey = RecordKey::try_from("fuzz").expect("valid rkey");
    let write = WriteOp::Create {
        collection: collection.clone(),
        rkey: rkey.clone(),
        record: b"\xa0".to_vec(),
    };
    // A loaded tree may already hold the key, or be malformed in ways only
    // a write uncovers; either must be an error, not a panic.
    if repo.apply_writes(&[write], &key).is_ok() {
        assert!(repo.get(&collection, &rkey).expect("read back").is_some());
    }
});
