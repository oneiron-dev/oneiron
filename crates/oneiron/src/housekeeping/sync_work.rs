//! The sync lane's work a housekeeping pass carries: a left shared env's
//! owed body collection (FIX 2413), and the retained peer work that waits
//! for its turn (FIX 7997, 8565). A build without the `sync` feature keeps
//! no shared env and no retained peer work, so it owes none.

use crate::Vault;
use crate::error::Result;

/// When this left shared env's owed body collection is due, or `None` when
/// it owes none.
#[cfg(feature = "sync")]
pub(super) fn left_env_body_collect_due_at(vault: &Vault) -> Result<Option<u64>> {
    crate::sync::shared_leave::left_env_body_collect_due_at(vault)
}

#[cfg(not(feature = "sync"))]
pub(super) fn left_env_body_collect_due_at(_vault: &Vault) -> Result<Option<u64>> {
    Ok(None)
}

/// Runs this left shared env's owed body collection when it is due.
/// Warning-only: the pass that carries it never fails for it.
#[cfg(feature = "sync")]
pub(super) fn collect_left_env_bodies(vault: &Vault) {
    crate::sync::shared_leave::collect_left_env_bodies(vault);
}

#[cfg(not(feature = "sync"))]
pub(super) fn collect_left_env_bodies(_vault: &Vault) {}

/// Drains the retained peer work: maintenance operations take their turn
/// (FIX 8565, 8858), and federation batches past their wait end with their
/// receipt (FIX 7997). Warning-only: the pass that carries it never fails for
/// it, and what is left waits for the next pass.
#[cfg(feature = "sync")]
pub(super) fn drain_retained_sync_work(vault: &Vault) {
    if let Err(error) = crate::sync::quota::drain_retained_maintenance(vault) {
        tracing::warn!(
            kind = ?error.kind(),
            "housekeeping: retained maintenance work did not drain; it waits for the next pass"
        );
    }
    if let Err(error) = crate::sync::federation_burst::expire_retained_work(vault) {
        tracing::warn!(
            kind = ?error.kind(),
            "housekeeping: retained federation work past its wait did not end; it waits for the next pass"
        );
    }
}

#[cfg(not(feature = "sync"))]
pub(super) fn drain_retained_sync_work(_vault: &Vault) {}
