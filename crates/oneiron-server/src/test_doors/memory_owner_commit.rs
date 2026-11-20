//! Door for `tests/memory_verb_owner_proof_at_commit.rs` (FIX
//! MEMORY-VERB-OWNER-PROOF-NOT-REVALIDATED-AT-COMMIT, FIX
//! MEMORY-DELETE-OWNER-PROOF-NOT-REVALIDATED-AT-COMMIT): one act run at a
//! vault's next core memory `retract`, `supersede`, `delete` or
//! `hard_delete` on the owner's path, after the route admitted the owner
//! and before the vault's door opens its writer, where a revocation of the
//! owner's credential lands.

use oneiron::Vault;

use super::vault_acts::{ActPoint, run_at_next, run_waiting};

/// Runs `act` once, at the next core memory `retract`, `supersede`,
/// `delete` or `hard_delete` the owner's path runs on `vault`: after the
/// route admitted the owner, before the vault's door opens its writer.
pub fn before_next_owner_commit(vault: &Vault, act: impl FnOnce() + Send + 'static) {
    run_at_next(ActPoint::OwnerCommit, vault, act);
}

/// Runs the act waiting for `vault`'s next owner `retract`, `supersede`,
/// `delete` or `hard_delete`, if one waits.
pub(crate) fn run_before_owner_commit(vault: &Vault) {
    run_waiting(ActPoint::OwnerCommit, vault);
}
