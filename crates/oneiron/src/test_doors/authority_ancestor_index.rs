//! The ancestor index equivalence door (row [ROSTER-KEY-LOG-FLOOD], PR 1):
//! one synthetic log's claimed ancestry built by the fold's run index and by
//! the per-row set index it replaced, so a test shows both give the same
//! members, counts and memory floor verdict. Compiled only under
//! `--cfg oneiron_test_support`; never API.

pub use crate::authority::ancestor_index_door::{IndexedAncestry, by_runs, by_sets};
