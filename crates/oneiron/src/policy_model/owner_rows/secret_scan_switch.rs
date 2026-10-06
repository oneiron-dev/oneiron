//! The owner's `secrets: on | off` switch for the write-door secret scan.
//!
//! The switch is a vault setting held in this vault's metadata, read inside
//! every batch write transaction. Only a live vault owner changes it, and each
//! change lands its receipt and a typed event in the same transaction.
use serde::{Deserialize, Serialize};

use super::ledger::{PolicyChangedEvent, put_event_in_txn};
use crate::Vault;
use crate::batch::secret_scan::{
    SecretScanMode, put_secret_scan_mode_in_txn, secret_scan_mode_in_txn,
};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, GateError, Result};
use crate::gate::PolicyRowScope;
use crate::side_table::{self, Named, SideTable};

/// Event kind on the shared owner-policy stream for a switch change.
const SECRET_SCAN_CHANGED: &str = "policy.secret_scan.changed";

/// One owner change of the switch, in revision order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretScanReceipt {
    pub receipt_id: String,
    pub revision: u64,
    /// The owner actor who switched it, as hex.
    pub author: String,
    pub mode: SecretScanMode,
    /// The mode the vault had before this change.
    pub previous: SecretScanMode,
    pub at: u64,
}

const RECEIPTS: SideTable<u64, SecretScanReceipt, Named> =
    SideTable::new(&side_table::OWNER_POLICY_SECRET_SCAN_RECEIPT);

impl Vault {
    /// The vault's `secrets` setting. On unless the owner switched it off.
    pub fn secret_scan_mode(&self) -> Result<SecretScanMode> {
        let txn = self.store.env.read_txn()?;
        secret_scan_mode_in_txn(&self.store, &txn)
    }

    /// Switches the write-door secret scan for this vault.
    ///
    /// Off skips the ingest scan on batch writes and staged sources; serve and
    /// export redaction run in both modes. Only a live vault owner may switch
    /// it (an Admin or Delegate may not, whatever grants it holds). The new
    /// mode, its receipt and a `policy.secret_scan.changed` event commit in
    /// one transaction; a call that keeps the current mode is receipted too.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] when the proof belongs to
    /// another vault, its person is no longer live, or the actor is not an
    /// owner of this vault.
    pub fn set_secret_scan_mode(
        &self,
        owner: &AuthenticatedOwner,
        mode: SecretScanMode,
        now: u64,
    ) -> Result<SecretScanReceipt> {
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        if !super::authority::owners_in_txn(self, &txn)?.contains(&owner.actor()) {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "only the vault owner switches the secret scan",
            )));
        }
        let previous = secret_scan_mode_in_txn(&self.store, &txn)?;
        let last = RECEIPTS
            .iter_rev_from(&self.store, &txn, &[])?
            .next()
            .transpose()?
            .map(|(revision, _)| revision);
        let revision = match last {
            None => 1,
            Some(revision) => revision.checked_add(1).ok_or(Error::InvariantViolation(
                "secret scan receipt revision overflow",
            ))?,
        };
        let receipt = SecretScanReceipt {
            receipt_id: self.store.clock.entity_id()?.to_hex(),
            revision,
            author: owner.actor().to_hex(),
            mode,
            previous,
            at: now,
        };
        put_secret_scan_mode_in_txn(&self.store, &mut txn, mode)?;
        RECEIPTS.put(&self.store, &mut txn, &revision, &receipt)?;
        put_event_in_txn(
            self,
            &mut txn,
            &PolicyChangedEvent {
                kind: SECRET_SCAN_CHANGED.to_owned(),
                receipt_id: receipt.receipt_id.clone(),
                author: receipt.author.clone(),
                scope: Some(PolicyRowScope::Vault),
                target: None,
                at: now,
            },
        )?;
        txn.commit()?;
        Ok(receipt)
    }

    /// Every switch change in revision order.
    pub fn secret_scan_change_log(&self) -> Result<Vec<SecretScanReceipt>> {
        let txn = self.store.env.read_txn()?;
        Ok(RECEIPTS
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, receipt)| receipt)
            .collect())
    }
}

#[cfg(test)]
mod tests;
