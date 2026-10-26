//! The sync lane's work a housekeeping pass carries: a left shared env's
//! owed body collection (FIX 2413). A build without the `sync` feature keeps
//! no shared env, so it owes none.

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
