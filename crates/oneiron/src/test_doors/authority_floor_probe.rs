//! The floor probe equivalence door (row [ROSTER-KEY-LOG-FLOOD], PR 3): the
//! probe a floored row's voucher folds on, asked as the fold asks it now
//! (each row once, in id order, on the fold's signature verdicts) and as it
//! asked before (rounds in hash order), of every row of one log under
//! several floor maps. Compiled only under `--cfg oneiron_test_support`;
//! never API.

pub use crate::authority::floor_probe_door::{ProbeEquivalence, probe_both_ways};
