//! The relay delete guard over one vault's backup holds (FIX 1488): the
//! adapter L14's relay locker delete takes ([`super::relay_hold_guard`]).
//!
//! It reads the vault's standing legal holds the way backup expiry does,
//! under the vault's writer ([`oneiron::Vault::with_backup_hold_exclusion`]),
//! and runs the delete's unlink inside that exclusion. Any standing hold
//! defers the delete until release; a vault it cannot open, a target of
//! another vault, or a hold read that fails defers it as unknown. It never
//! reports a delete it did not make.

use std::sync::Arc;

use super::relay_hold_guard::{
    RelayDeleteDeferral, RelayDeleteHoldError, RelayDeleteHoldGuard, RelayDeleteHoldOutcome,
    RelayDeleteTarget,
};

/// Opens the vault a relay locker belongs to, or `None` when it cannot be
/// opened now.
pub(crate) type RelayVaultSource = Arc<dyn Fn() -> Option<Arc<oneiron::Vault>> + Send + Sync>;

const HOLD_STATE_UNKNOWN: RelayDeleteHoldOutcome =
    RelayDeleteHoldOutcome::Deferred(RelayDeleteDeferral::HoldStateUnknown);

/// [`RelayDeleteHoldGuard`] over the holds of the vault `vault_id` names.
pub(crate) struct VaultRelayHoldGuard {
    vault_id: [u8; 32],
    vault: RelayVaultSource,
    /// What a guard whose vault does not open hands a subscriber: a counter
    /// that never moves, so the relay's own retry cadence asks again.
    idle: tokio::sync::watch::Sender<u64>,
}

impl VaultRelayHoldGuard {
    /// The guard for the locker of `vault_id`, whose vault `vault` opens.
    pub(crate) fn new(vault_id: [u8; 32], vault: RelayVaultSource) -> Self {
        Self {
            vault_id,
            vault,
            idle: tokio::sync::watch::channel(0).0,
        }
    }
}

impl RelayDeleteHoldGuard for VaultRelayHoldGuard {
    fn delete_if_released(
        &self,
        target: &RelayDeleteTarget,
        unlink: &mut dyn FnMut() -> std::io::Result<()>,
    ) -> Result<RelayDeleteHoldOutcome, RelayDeleteHoldError> {
        if target.vault_id != self.vault_id {
            return Ok(HOLD_STATE_UNKNOWN);
        }
        let Some(vault) = (self.vault)() else {
            return Ok(HOLD_STATE_UNKNOWN);
        };
        let guarded = vault.with_backup_hold_exclusion(|holds| {
            if holds.keeps_backups() {
                return Ok(RelayDeleteHoldOutcome::Deferred(
                    RelayDeleteDeferral::HeldUntilRelease,
                ));
            }
            unlink()
                .map(|()| RelayDeleteHoldOutcome::Deleted)
                .map_err(RelayDeleteHoldError::StorageIo)
        });
        match guarded {
            Ok(outcome) => outcome,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "relay delete deferred: the vault's legal holds did not read"
                );
                Ok(HOLD_STATE_UNKNOWN)
            }
        }
    }

    fn subscribe_rechecks(&self) -> tokio::sync::watch::Receiver<u64> {
        match (self.vault)() {
            Some(vault) => vault.backup_hold_rechecks(),
            None => self.idle.subscribe(),
        }
    }
}
