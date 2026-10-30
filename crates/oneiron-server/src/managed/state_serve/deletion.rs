//! The vault's deletion as a managed host reads it (FIX 11710): the marker
//! every `Ping` reports to the supervisor, and the gate beside the reap
//! freeze that stops background passes once it is present.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use oneiron_vault_contract::PingDeletion;

use super::ManagedState;

/// The vault's deletion marker as this process reads it. A deletion is never
/// undone, so the first read that finds the marker is kept and no later one
/// is made; until then each look reads the vault again.
#[derive(Default)]
pub(super) struct DeletionMarker {
    /// The deletion, once a read found it.
    present: OnceLock<PingDeletion>,
    /// Whether the last read failed: a run of failures is logged once.
    unreadable: AtomicBool,
    /// Whether a background pass the deletion stopped has logged why.
    passes_stopped: AtomicBool,
}

impl DeletionMarker {
    /// The vault's deletion, when its marker is present. A read that fails
    /// reports none, logged once a run, and the vault serves on: here an
    /// unreadable marker stops nothing, and the binding door still judges
    /// each request on its own read.
    pub(super) fn read(&self, vault: &oneiron::Vault) -> Option<PingDeletion> {
        if let Some(deletion) = self.present.get() {
            return Some(*deletion);
        }
        match vault.shared_vault_deletion() {
            Ok(None) => {
                self.unreadable.store(false, Ordering::Relaxed);
                None
            }
            Ok(Some(deletion)) => Some(*self.present.get_or_init(|| PingDeletion {
                deleted_at: deletion.deleted_at,
                backup_retain_until: Some(deletion.backup_retain_until),
            })),
            Err(error) => {
                if !self.unreadable.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        kind = ?error.kind(),
                        reason = "vault_deletion_unread",
                        "the vault's deletion marker did not read; Ping reports none and background passes go on"
                    );
                }
                None
            }
        }
    }

    /// Whether the deletion gate stops a background pass now: once the
    /// marker is present. The first pass it stops logs why.
    pub(super) fn stops_pass(&self, vault: &oneiron::Vault) -> bool {
        if self.read(vault).is_none() {
            return false;
        }
        if !self.passes_stopped.swap(true, Ordering::Relaxed) {
            tracing::info!(
                reason = "vault_deleted",
                "background passes stop: the vault's Owners deleted it; its backup schedule and custody publication run on to let its backups go at their deadline"
            );
        }
        true
    }
}

impl ManagedState {
    /// The vault's deletion, as every `Ping` reports it (FIX 11710).
    pub(super) fn vault_deletion(&self) -> Option<PingDeletion> {
        self.admission.deletion().read(self.server.vault())
    }
}
