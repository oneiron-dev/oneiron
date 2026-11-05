use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::deletion::{DeleteReason, DeletionGateContext, GatedDeletion};
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::{EntityId, Vault};

use super::intake::ClipMetadata;
use super::retention::ClipboardRetention;

/// Which ordinary Clipboard records the owner erases. Ranges are [from, before).
/// All empties the dedicated world; it retains the role's WORLD metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ClipboardErase {
    Clip { clip: EntityId },
    Range { from: u64, before: u64 },
    All,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClipboardEraseReport {
    /// Records the native hard-delete door completed. Not a delivery receipt
    /// and not a claim that the filesystem or retained backups shrank.
    pub erased: Vec<EntityId>,
}

impl Vault {
    /// Carries out the owner's erase through the existing hard-delete door,
    /// preserving its legal holds, dependent cleanup, receipt and sweep work.
    /// No reader or writer is held across separate deletion transactions.
    pub fn erase_clipboard_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        selection: ClipboardErase,
    ) -> Result<ClipboardEraseReport> {
        let rows = {
            let txn = self.store.env.read_txn()?;
            owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
            self.clipboard_metadata_in_txn(&txn)?
        };
        let mut erased = Vec::new();
        for row in rows.into_iter().filter(|row| match selection {
            ClipboardErase::Clip { clip } => row.clip == clip,
            ClipboardErase::Range { from, before } => {
                row.copied_at >= from && row.copied_at < before
            }
            ClipboardErase::All => true,
        }) {
            if self.erase_clipboard_row(owner, row, DeleteReason::UserHardDelete, None)? {
                erased.push(row.clip);
            }
        }
        Ok(ClipboardEraseReport { erased })
    }

    pub(super) fn erase_clipboard_row(
        &self,
        owner: &AuthenticatedOwner,
        row: ClipMetadata,
        reason: DeleteReason,
        policy: Option<&ClipboardRetention>,
    ) -> Result<bool> {
        let context = {
            let txn = self.store.env.read_txn()?;
            owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
            let manifest = crate::gate::resolve_policy_manifest(&self.store, &txn)?;
            DeletionGateContext::new(
                owner.actor(),
                EdgeActorClass::Human,
                crate::store::policy_record::POLICY_SCHEMA_VERSION.to_owned(),
                manifest.read_frontier_hash()?,
            )
        };
        let reverify = |txn: &heed::RoTxn<'_>| {
            owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            if let Some(expected) = policy
                && self.clipboard_retention_in_txn(txn)? != *expected
            {
                return Err(Error::ConcurrentWrite);
            }
            Ok(())
        };
        let selected = |txn: &heed::RoTxn<'_>| {
            let Some(current) = self.clipboard_entry_in_txn(txn, row.clip)? else {
                return Err(Error::ConcurrentWrite);
            };
            if current.copied_at != row.copied_at
                || u64::try_from(current.text.len()).unwrap_or(u64::MAX) != row.text_bytes
            {
                return Err(Error::ConcurrentWrite);
            }
            Ok(())
        };
        let gate = GatedDeletion::with_pre_scrub_check(context, &reverify, &selected);
        Ok(self
            .delete_entity_with_reason_gated(&row.clip, reason, gate)?
            .existed)
    }
}
