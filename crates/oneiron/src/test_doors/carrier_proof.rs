//! Door for `tests/doors_read_standing_heads.rs` (FIX
//! [FOREIGN-ANCHOR-CHAIN-COUNTS-IN-EVERY-CHAIN-PREDICATES], site O2): the
//! three-state carrier proof of one install key, as a bool.
//!
//! The unit under test is the private `carrier_proof` in
//! `secret_custody::holder_export::relay` (its removed arm read every chain;
//! now the standing heads). The test folds with the public
//! [`Vault::authority_fold`] and asks this door whether the key is disproven,
//! since the [`ProofState`] it returns is crate-private.

use crate::EntityId;
use crate::authority::AuthorityFold;
use crate::secret_custody::holder_export::{ProofState, carrier_proof};

/// Whether `key` as `executor`'s install key is disproven on `fold`: the
/// authority roster names it (a roster key acts as nobody), or a head
/// `executor` stands under removed the machine.
#[must_use]
pub fn carrier_proof_disproves(fold: &AuthorityFold, executor: EntityId, key: &[u8; 32]) -> bool {
    matches!(carrier_proof(fold, executor, key), ProofState::Disproven)
}
