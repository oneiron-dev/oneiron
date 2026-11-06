//! A native output's Keep (moved out of `pending`): the waiting file lands
//! as a version forked from the head it was made against, and a deck export
//! binds the deck to it.

use super::PendingRow;
use super::output_settle::output_record;
use crate::Vault;
use crate::anchored_annotation::ReanchorSummary;
use crate::blob_artifact::{
    BlobVersionProvenance, VersionReconciliation, read_blob_artifact_head_in_txn,
};
use crate::edit_settle::codec::{RECORD, settlement_key_parts};
use crate::edit_settle::receipts::{already_settled, settlement_receipt_record};
use crate::edit_settle::records::{
    SettleConsent, SettleOutcomeKind, SettleSelectOutcome, SettledReview,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

impl Vault {
    pub(super) fn keep_native_output(
        &self,
        artifact_id: &EntityId,
        row: &PendingRow,
        consent: &SettleConsent,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<SettleSelectOutcome> {
        self.authorize_settle(consent, actor)?;
        let key = settlement_key_parts(artifact_id, &row.proposal_ref);
        let provenance = BlobVersionProvenance::AgentRun {
            run_ref: row.proposal_ref.clone(),
        };
        let (version, record, reconciliation) = self.with_write_txn_grouped(|wtxn| {
            let grant_ref = self.authorize_settle_in_txn(wtxn, consent, actor)?;
            if let Some(existing) = RECORD.get(&self.store, wtxn, &key)? {
                return Err(already_settled(&existing));
            }
            let head = read_blob_artifact_head_in_txn(&self.store, wtxn, artifact_id)?;
            // The output forks from the version it was made against; a later
            // head keeps both, as a person may keep a machine version beside
            // their own. Made against nothing, it lands on whatever head is.
            // A deck export was made against the version its deck projected
            // over, whatever head it found then (FIX 2700). An explicit fork
            // lands a fork version even against the current head; anything
            // else forks only from an older head (blind review of #4387).
            let fork_parent = row.base_version.filter(|base| {
                row.explicit_fork || head.as_ref().is_some_and(|head| head.version != *base)
            });
            let version = match &row.made_by {
                Some(made_by) => self.append_blob_artifact_version_kept_in_txn(
                    wtxn,
                    artifact_id,
                    fork_parent,
                    &row.new_bytes,
                    &provenance,
                    made_by,
                    actor,
                    occurred,
                    learned_at,
                )?,
                None => self.append_blob_artifact_version_with_engine_and_parent_in_txn(
                    wtxn,
                    artifact_id,
                    &row.new_bytes,
                    &provenance,
                    None,
                    actor,
                    occurred,
                    learned_at,
                    fork_parent,
                    None,
                )?,
            };
            if let Some(hold) = &row.deck {
                self.keep_deck_export_in_txn(
                    wtxn,
                    artifact_id,
                    hold,
                    (row.base_version, row.base_content_hash),
                    &version,
                    (actor, row.made_by.as_ref(), learned_at),
                )?;
            }
            // The head it replaced is the version an Undo restores.
            let replaced = row.base_version.and(head.as_ref().map(|head| head.version));
            let record = output_record(
                row,
                SettleOutcomeKind::Selected,
                (consent, actor),
                learned_at,
                (Some(&version), replaced),
                grant_ref,
            );
            RECORD.put(&self.store, wtxn, &key, &record)?;
            let reconciliation = VersionReconciliation::of(fork_parent, head.as_ref());
            Ok((version, record, reconciliation))
        })?;
        Ok(SettleSelectOutcome {
            stranded_proposal: None,
            version,
            reanchor: ReanchorSummary::default(),
            receipt: settlement_receipt_record(*artifact_id, &record)?,
            reconciliation,
            review: SettledReview::of(record),
        })
    }
}
