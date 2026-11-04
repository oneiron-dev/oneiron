//! The vault's deletion marker as a host's background passes read it (FIX
//! 11710, FIX 11979): the marker every managed `Ping` reports to the
//! supervisor, and the gate beside the reap freeze that stops background
//! passes once it is present. The managed host and the self-hosted serve
//! share it; the backup schedule and custody publication run on past it,
//! to let the vault's backups go at their deadline.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use oneiron_vault_contract::PingDeletion;

use super::housekeeping::HousekeepingAdmission;

/// The vault's deletion marker as this process reads it. A deletion is never
/// undone, so the first read that finds the marker is kept and no later one
/// is made; until then each look reads the vault again.
#[derive(Default)]
pub(crate) struct DeletionMarker {
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
    pub(crate) fn read(&self, vault: &oneiron::Vault) -> Option<PingDeletion> {
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
    pub(crate) fn stops_pass(&self, vault: &oneiron::Vault) -> bool {
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

    /// The admission of a self-hosted serve's background pass over `admit`
    /// (FIX 11979): while the vault stands what `admit` admits is held as
    /// today, and once the vault's deletion marker is present the pass is
    /// refused, logged once, as the managed host's deletion gate refuses
    /// it.
    pub(crate) fn gate(
        self: &Arc<Self>,
        vault: &Arc<oneiron::Vault>,
        admit: HousekeepingAdmission,
    ) -> HousekeepingAdmission {
        let marker = Arc::clone(self);
        let vault = Arc::clone(vault);
        Arc::new(move || {
            if marker.stops_pass(&vault) {
                None
            } else {
                admit()
            }
        })
    }
}
