//! Owner review and exact canonical settlement of a retained document-copy
//! lineage (FIX12419, document-only).
//!
//! [`EntityDocument::repo_copy_edit_review_as`] reads the current retained
//! lineage's recomputed held cause without bringing it current; [`EntityDocument::settle_repo_copy_edit_as`]
//! lands the owner's exact canonical replacement through the existing
//! attributed writer, carries the reviewed copy blob's marks onto the ACTUAL
//! persisted bytes, refreshes the SAME lineage, and journals the SAME durable
//! UPDATE frame. No new ledger, table, directive, `x:` authority gate,
//! presence gate, or raw held stash; the result is the actual committed frame,
//! not a remote ACK or delivery.

use super::EntityDocument;
use super::eligible;
use super::entity::journal_update_in_txn;

use crate::consent::AuthenticatedOwner;
use crate::entity_doc::SyncEdit;
use crate::error::{Error, Result, SyncProtocolValidation};
use crate::sync::selector::secret_projection::{
    RepoCopyEditReview, begin_repo_copy_settlement_in_txn, finish_repo_copy_settlement_in_txn,
    review_repo_copy_edit_in_txn,
};
use crate::{EdgeActorClass, WriteActor};

impl EntityDocument {
    /// The current owner review of this document's retained copy lineage: the
    /// source, the recomputed ruled held cause, and the lineage's retained
    /// submitted (masked) text, with the opaque revision the exact-approval
    /// token binds. `None` for no mark, an unread copy, an empty lineage, or
    /// no actual held cause (unchanged or cleanly applied), never an arbitrary
    /// force-write. Reads without bringing the lineage current, so the proposal
    /// is not overwritten. The token is NOT authority.
    ///
    /// # Errors
    /// An owner who no longer stands; [`eligible`]'s own refusal; a store,
    /// mark, copy id, or visible diff failure.
    pub fn repo_copy_edit_review_as(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<Option<RepoCopyEditReview>> {
        let txn = self.vault.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(&self.vault, &txn)?;
        eligible(&self.vault, &txn, self.id)?;
        if self.vault.get_entity_type_in_txn(&txn, &self.id)?
            == Some(crate::registry::ENTITY_TYPE_NOTE)
        {
            return Ok(None);
        }
        review_repo_copy_edit_in_txn(&self.vault, &txn, self.id)
    }

    /// Settles this document's retained copy lineage with the owner's exact
    /// canonical `replacement`, approved by `approval` from
    /// [`RepoCopyEditReview::approval_for`]. The SAME document lock and one
    /// grouped writer revalidates the owner, checks eligibility and the
    /// non-NOTE guard, recomputes the review and compares the approval BEFORE
    /// any write, then lands the replacement as the revalidated owner through
    /// the existing canonical writer (`start` 0, `delete` the reviewed source's
    /// Unicode-scalar count, `at` the vault instant), carries the reviewed copy
    /// blob's marks onto the ACTUAL persisted bytes, refreshes the SAME lineage,
    /// and journals the SAME durable UPDATE frame. The notice and the prose
    /// receipts follow only after the commit, in the existing order. An old
    /// review is stale after any state change.
    ///
    /// # Errors
    /// An owner who no longer stands; [`eligible`]'s or the non-NOTE guard's
    /// [`SyncProtocolValidation::DocumentAdmissionDenied`]; the existing
    /// [`crate::error::ArtifactError::EditProposalStale`] when no held review
    /// stands now or the approval does not match the recomputed review and
    /// exact replacement; the canonical writer's, the mark carry's, the lineage
    /// refresh's, or the journal's own failure.
    pub fn settle_repo_copy_edit_as(
        &self,
        owner: &AuthenticatedOwner,
        approval: &[u8; 32],
        replacement: &str,
    ) -> Result<Vec<u8>> {
        let _writer = self.lock()?;
        let (frame, edited) = self.vault.with_write_txn_grouped(|txn| {
            let actor_id = owner.revalidate_as_vault_owner_in_txn(&self.vault, txn)?;
            eligible(&self.vault, txn, self.id)?;
            if self.vault.get_entity_type_in_txn(txn, &self.id)?
                == Some(crate::registry::ENTITY_TYPE_NOTE)
            {
                return Err(Error::sync_protocol(
                    SyncProtocolValidation::DocumentAdmissionDenied,
                ));
            }
            let settlement = begin_repo_copy_settlement_in_txn(
                &self.vault,
                txn,
                self.id,
                approval,
                replacement,
            )?;
            let actor = WriteActor::new(actor_id, EdgeActorClass::Human);
            let at = self.vault.instant_in_txn(txn)?.secs();
            let edit = SyncEdit {
                actor,
                at,
                start: 0,
                delete: settlement.source_len(),
                insert: replacement,
            };
            let edited =
                crate::entity_doc::edit_sync_text_in_txn(&self.vault, txn, &self.id, &edit)?;
            finish_repo_copy_settlement_in_txn(&self.vault, txn, &settlement)?;
            let frame =
                journal_update_in_txn(&self.vault, txn, self.id, edited.sequence, &edited.update)?;
            Ok((frame, edited))
        })?;
        let _ = self.notices.send(frame.clone());
        edited.land(&self.vault);
        Ok(frame)
    }
}
