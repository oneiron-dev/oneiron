//! The owner's `secrets: on | off` switch for the write-door secret scan.
//!
//! The switch is the catalogue key `secret_scan.mode`, read inside every
//! batch write transaction. The owner changes it through `vault.settings.set`
//! (any other caller proposes). Each applied change lands its setting change
//! row and a typed event in the same transaction, and those change rows are
//! the switch's change log.

use super::ledger::{PolicyChangedEvent, put_event_in_txn};
use crate::Vault;
use crate::batch::secret_scan::{
    LiftTrigger, SecretScanMode, enqueue_lift_in_txn, secret_scan_mode_in_txn,
};
use crate::batch::setting_keys::SECRET_SCAN_MODE;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::PolicyRowScope;
use crate::setting::{EncodedValue, SettingChange, SettingMode, settings_after_in_txn};

/// Event kind on the shared owner-policy stream for a switch change.
const SECRET_SCAN_CHANGED: &str = "policy.secret_scan.changed";

/// How many setting change rows one page of the change log reads.
const CHANGE_LOG_PAGE: usize = 256;

#[doc(hidden)]
pub use oneiron_verb_wire::policy_model::owner_rows::secret_scan_switch::SecretScanReceipt;

impl Vault {
    /// The vault's `secrets` setting. On unless the owner switched it off.
    pub fn secret_scan_mode(&self) -> Result<SecretScanMode> {
        let txn = self.store.env.read_txn()?;
        secret_scan_mode_in_txn(&self.store, &txn)
    }

    /// Every change of the switch, oldest first: the setting change rows of
    /// `secret_scan.mode`, each numbered by its place among them.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn secret_scan_change_log(&self) -> Result<Vec<SecretScanReceipt>> {
        let txn = self.store.env.read_txn()?;
        let mut receipts = Vec::new();
        let mut after = None;
        loop {
            let (changes, through) =
                settings_after_in_txn(&self.store, &txn, after, CHANGE_LOG_PAGE)?;
            for change in changes
                .iter()
                .filter(|change| change.key == SECRET_SCAN_MODE.spec.name)
            {
                let revision = u64::try_from(receipts.len())
                    .ok()
                    .and_then(|count| count.checked_add(1))
                    .ok_or(Error::ArithmeticOverflow("secret scan change revision"))?;
                receipts.push(receipt_of(change, revision));
            }
            match through {
                Some(sequence) => after = Some(sequence),
                None => break,
            }
        }
        Ok(receipts)
    }
}

/// One change row of the switch as its change log shows it.
fn receipt_of(change: &SettingChange, revision: u64) -> SecretScanReceipt {
    SecretScanReceipt {
        receipt_id: change.id.to_hex(),
        revision,
        author: change.by.as_ref().map(EntityId::to_hex).unwrap_or_default(),
        mode: mode_of(change.value.as_ref()),
        previous: mode_of(change.prior.as_ref()),
        at: change.at,
    }
}

/// A row's mode: no row, or one that does not decode, reads on.
fn mode_of(value: Option<&EncodedValue>) -> SecretScanMode {
    value
        .and_then(EncodedValue::decode::<SecretScanMode>)
        .unwrap_or_default()
}

/// The `secret_scan.mode` key's hook, in the write of each applied change:
/// the `policy.secret_scan.changed` event on the owner-policy stream, named by
/// the change's id, and, when the switch goes from off back to on, a
/// historical lift run ([`Vault::start_secret_lift`]) for what was stored
/// while it was off.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn secret_scan_switched_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    change: &SettingChange,
) -> Result<()> {
    let on_now = secret_scan_mode_in_txn(&vault.store, txn)? == SecretScanMode::On;
    // A pin set over no pin covers a value row this hook does not read, which
    // may hold off.
    let was_off = change.prior.as_ref().map(|prior| mode_of(Some(prior)))
        == Some(SecretScanMode::Off)
        || (change.mode == SettingMode::Pin && change.prior.is_none());
    if on_now && was_off {
        enqueue_lift_in_txn(&vault.store, txn, LiftTrigger::Switch, change.by, change.at)?;
    }
    put_event_in_txn(
        vault,
        txn,
        &PolicyChangedEvent {
            kind: SECRET_SCAN_CHANGED.to_owned(),
            receipt_id: change.id.to_hex(),
            author: change.by.as_ref().map(EntityId::to_hex).unwrap_or_default(),
            scope: Some(PolicyRowScope::Vault),
            target: None,
            at: change.at,
        },
    )
}

#[cfg(test)]
mod tests;
