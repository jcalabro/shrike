#![no_main]
//! Operations on MST trees built elsewhere: any order-keeping shape, and
//! hostile trees that link a block twice, misplace a key, run too deep, or
//! lack blocks. Nothing may panic, overflow the stack, or fail internally;
//! failed operations must change nothing; and ordered trees must behave
//! like a map. See `tests/support/mst_hostile.rs`, shared with the
//! `trees_from_elsewhere_behave` property test.

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;

#[path = "../../tests/support/mst_hostile.rs"]
mod mst_hostile;

#[derive(Arbitrary, Debug)]
struct Input {
    seed: u64,
    keys: u8,
    shape: u8,
    hide: u64,
    ops: Vec<(u8, u8, bool)>,
}

fuzz_target!(|input: Input| {
    let case = mst_hostile::Case {
        seed: input.seed,
        keys: input.keys,
        shape: input.shape,
        hide: input.hide,
        ops: input.ops.into_iter().take(32).collect(),
    };
    if let Err(e) = mst_hostile::run(&case) {
        panic!("{e}");
    }
});
