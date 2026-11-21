//! The signed-branch proofs' work door (row [REVOKE-PROOF-BRANCH-REFOLD-CUBIC]):
//! a log's whole fold, with the number of row transitions the fold's
//! signed-branch proofs of its restrictions tried. Compiled only under
//! `--cfg oneiron_test_support`; never API.

use super::revoke_proof::PROOF_TRIES;
use super::{AuthorityFold, AuthorityLogEntry, fold_authority_log};

/// `entries`' whole fold ([`fold_authority_log`]) and how many row
/// transitions its restriction proofs tried.
pub fn fold_counting_proof_tries(entries: &[AuthorityLogEntry]) -> (AuthorityFold, u64) {
    PROOF_TRIES.with(|tries| tries.set(Some(0)));
    let fold = fold_authority_log(entries);
    let tries = PROOF_TRIES.with(|tries| tries.take()).unwrap_or_default();
    (fold, tries)
}
