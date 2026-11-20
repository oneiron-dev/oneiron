//! The sequence floor equivalence door (Engine RULING SEQ-FLOOR-SHAPE = A):
//! one log folded by its rows' own floors and by one install's arrival order
//! as before the ruling, so a test shows both agree on every row of a log
//! whose signers each sign one chain. Compiled only under
//! `--cfg oneiron_test_support`; never API.

pub use crate::authority::sequence_floor_door::{FloorEquivalence, fold_both_ways};
