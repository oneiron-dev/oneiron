//! Door for `tests/memory_verb_owner_proof_at_commit.rs` (FIX
//! MEMORY-VERB-OWNER-PROOF-NOT-REVALIDATED-AT-COMMIT): one act run at a
//! vault's next core memory `retract` or `supersede` on the owner's path,
//! after the route admitted the owner and before the vault's lifecycle door
//! opens its writer, where a revocation of the owner's credential lands.

use std::sync::{Mutex, PoisonError};

use oneiron::Vault;

type OwnerCommitAct = Box<dyn FnOnce() + Send>;

/// Acts waiting for a vault's next owner retract or supersede, by the
/// vault's address, so tests running side by side never take each other's
/// act.
static BEFORE_OWNER_COMMIT: Mutex<Vec<(usize, OwnerCommitAct)>> = Mutex::new(Vec::new());

/// Runs `act` once, at the next core memory `retract` or `supersede` the
/// owner's path runs on `vault`: after the route admitted the owner, before
/// the lifecycle door opens its writer.
pub fn before_next_owner_commit(vault: &Vault, act: impl FnOnce() + Send + 'static) {
    BEFORE_OWNER_COMMIT
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((std::ptr::from_ref(vault).addr(), Box::new(act)));
}

/// Runs the act waiting for `vault`'s next owner retract or supersede, if
/// one waits.
pub(crate) fn run_before_owner_commit(vault: &Vault) {
    let address = std::ptr::from_ref(vault).addr();
    let act = {
        let mut waiting = BEFORE_OWNER_COMMIT
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        waiting
            .iter()
            .position(|(waiting_on, _)| *waiting_on == address)
            .map(|index| waiting.remove(index).1)
    };
    if let Some(act) = act {
        act();
    }
}
