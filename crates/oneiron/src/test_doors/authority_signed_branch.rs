//! The signed-branch proofs' work door (row [REVOKE-PROOF-BRANCH-REFOLD-CUBIC]):
//! a log's whole fold with the number of row transitions its restriction
//! proofs tried, so a test shows how that work grows with the log. Compiled
//! only under `--cfg oneiron_test_support`; never API.

pub use crate::authority::signed_branch_door::fold_counting_proof_tries;
