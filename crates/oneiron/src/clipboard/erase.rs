use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::deletion::{DeleteReason, DeletionGateContext, GatedDeletion};
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::{EntityId, Vault};

use super::clipboard_world_id;
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
    /// Clip/all erasure also reaches malformed values in this exact family.
    pub fn erase_clipboard_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        selection: ClipboardErase,
    ) -> Result<ClipboardEraseReport> {
        let selected = {
            let txn = self.store.env.read_txn()?;
            owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
            match selection {
                ClipboardErase::Clip { clip } => {
                    if self.clipboard_claim_raw_in_txn(&txn, clip)?.is_some() {
                        vec![(clip, None)]
                    } else {
                        Vec::new()
                    }
                }
                ClipboardErase::Range { from, before } => self
                    .clipboard_metadata_in_txn(&txn, false)?
                    .into_iter()
                    .filter(|row| row.copied_at >= from && row.copied_at < before)
                    .map(|row| (row.clip, Some(row.copied_at)))
                    .collect(),
                ClipboardErase::All => {
                    let mut clips = Vec::new();
                    for clip in self.claims_for_subject_in_txn(&txn, &clipboard_world_id()?)? {
                        if self.clipboard_claim_raw_in_txn(&txn, clip)?.is_some() {
                            clips.push((clip, None));
                        }
                    }
                    clips
                }
            }
        };
        let mut erased = Vec::new();
        for (clip, copied_at) in selected {
            if self.erase_clipboard_id(
                owner,
                clip,
                DeleteReason::UserHardDelete,
                None,
                copied_at,
            )? {
                erased.push(clip);
            }
        }
        Ok(ClipboardEraseReport { erased })
    }

    pub(super) fn erase_clipboard_id(
        &self,
        owner: &AuthenticatedOwner,
        clip: EntityId,
        reason: DeleteReason,
        policy: Option<&ClipboardRetention>,
        copied_at: Option<u64>,
    ) -> Result<bool> {
        let context = {
            let txn = self.store.env.read_txn()?;
            let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
            let manifest = crate::gate::resolve_policy_manifest(&self.store, &txn)?;
            DeletionGateContext::new(
                actor,
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
                return Err(Error::ConcurrentWrite("Clipboard cleanup policy changed"));
            }
            Ok(())
        };
        let selected = |txn: &heed::RoTxn<'_>| {
            let Some(current) = self.clipboard_claim_raw_in_txn(txn, clip)? else {
                return Err(Error::ConcurrentWrite("Clipboard selection changed"));
            };
            if let Some(expected) = copied_at {
                let actual = current
                    .value
                    .as_map()
                    .and_then(|fields| {
                        fields
                            .iter()
                            .find(|(key, _)| key.as_str() == Some(super::intake::KEY_COPIED_AT))
                    })
                    .and_then(|(_, value)| value.as_u64());
                if actual != Some(expected) {
                    return Err(Error::ConcurrentWrite("Clipboard copy position changed"));
                }
            }
            Ok(())
        };
        let gate = GatedDeletion::with_pre_scrub_check(context, &reverify, &selected);
        Ok(self
            .delete_entity_with_reason_gated(&clip, reason, gate)?
            .existed)
    }
}
