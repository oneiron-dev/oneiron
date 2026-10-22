//! The relay delete guard over one vault's backup holds (FIX 1488): the
//! adapter L14's relay locker delete takes ([`crate::managed::RelayDeleteHoldGuard`]).
//!
//! It reads the vault's standing legal holds the way backup expiry does,
//! under the vault's writer ([`oneiron::Vault::with_backup_hold_exclusion`]),
//! and runs the delete's unlink inside that exclusion. Any standing hold
//! defers the delete until release, with only whether the owner may see a
//! hold that stands, read in that same exclusion (FIX 9500); a vault it
//! cannot open, a target of another vault, or a hold read that fails defers
//! it as unknown. It never reports a delete it did not make.

use std::sync::Arc;

use oneiron::recovery::checkpoint::BackupHoldVisibility;
use oneiron_vault_contract::relay_delete::RelayHoldVisibility;

use crate::managed::{
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
    /// What a subscriber holds: a counter that moves with the rechecks of
    /// the vault the source opened last, and once more each time the source
    /// first resolves or is rebound to another vault, so a delete deferred
    /// while the vault did not open asks again once it does. An event, never
    /// a timer.
    rechecks: tokio::sync::watch::Sender<u64>,
    /// The vault whose rechecks [`Self::rechecks`] carries.
    followed: std::sync::Mutex<std::sync::Weak<oneiron::Vault>>,
}

impl VaultRelayHoldGuard {
    /// The guard for the locker of `vault_id`, whose vault `vault` opens.
    pub(crate) fn new(vault_id: [u8; 32], vault: RelayVaultSource) -> Self {
        Self {
            vault_id,
            vault,
            rechecks: tokio::sync::watch::channel(0).0,
            followed: std::sync::Mutex::new(std::sync::Weak::new()),
        }
    }

    /// Follows the vault the source opens now. When that is its first
    /// vault, or another one than before, the subscribers' counter moves,
    /// and from then on it carries that vault's own rechecks until the vault
    /// closes. The host calls this when it binds or rebinds the source;
    /// subscribing calls it too. Runs inside a Tokio runtime.
    pub(crate) fn source_bound(&self) {
        let Some(vault) = (self.vault)() else {
            return;
        };
        {
            let mut followed = self
                .followed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if std::ptr::eq(followed.as_ptr(), Arc::as_ptr(&vault)) {
                return;
            }
            *followed = Arc::downgrade(&vault);
        }
        let mut vault_rechecks = vault.backup_hold_rechecks();
        let rechecks = self.rechecks.clone();
        recheck(&rechecks);
        tokio::spawn(async move {
            while vault_rechecks.changed().await.is_ok() {
                recheck(&rechecks);
            }
        });
    }
}

/// Moves a recheck counter.
fn recheck(rechecks: &tokio::sync::watch::Sender<u64>) {
    rechecks.send_modify(|generation| *generation = generation.wrapping_add(1));
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
        if vault.vault_key_vault_id() != self.vault_id {
            return Ok(HOLD_STATE_UNKNOWN);
        }
        let guarded = vault.with_backup_hold_exclusion(|holds| {
            if let Some(held) = holds.held_visibility() {
                let visibility = match held {
                    BackupHoldVisibility::Visible => RelayHoldVisibility::Visible,
                    BackupHoldVisibility::SilentOnly => RelayHoldVisibility::SilentOnly,
                };
                return Ok(RelayDeleteHoldOutcome::Deferred(
                    RelayDeleteDeferral::Held { visibility },
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
        self.source_bound();
        self.rechecks.subscribe()
    }
}
