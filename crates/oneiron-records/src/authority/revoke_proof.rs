//! Moved from `crates/oneiron/src/authority/revoke_proof.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::authority::*;

/// A signed withdrawal that may cross rejected permissive ancestry.
pub fn restrictive_withdrawal(op: &AuthorityOp) -> bool {
    match op {
        AuthorityOp::RevokeActor { .. }
        | AuthorityOp::SlipRevoke { .. }
        | AuthorityOp::SlipConsume { .. }
        | AuthorityOp::SlipGrantRevoke { .. }
        | AuthorityOp::RemovalArchiveConsume { .. } => true,
        op => removes_machine(op),
    }
}

pub fn removes_machine(op: &AuthorityOp) -> bool {
    matches!(op, AuthorityOp::MachineProfile(profile) if profile.role == MachineRole::Removed)
}
