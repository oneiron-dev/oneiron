//! The fold memory measurement door ([ROSTER-KEY-LOG-FLOOD] PLAN v2, step
//! one): the authority fold's phases one at a time (the rows by hash, the
//! ancestor index, every row's state, the merge, the causal floors pass, the
//! whole vault fold), so a test under a counting allocator weighs each.
//! Compiled only under `--cfg oneiron_test_support`; never API.

pub use crate::authority::fold_memory_door::{
    Folded, Index, Rows, State, States, causal_floors, fold, index, projected_bytes, rows, states,
};
