//! A native output's Keep (moved out of `pending`): the waiting file lands
//! as a version forked from the head it was made against, and a deck export
//! binds the deck to it.

use super::output_settle::output_record;
use super::{LINK, PendingBody, PendingRow};
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
use crate::federation::record_scope::BirthPosition;
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
            // The claim is born at the producer's frozen position, never at
            // the keeper's (FIX 3171).
            let version = self.append_blob_artifact_version_kept_in_txn(
                wtxn,
                artifact_id,
                fork_parent,
                &row.new_bytes,
                &provenance,
                row.made_by.as_ref(),
                actor,
                occurred,
                learned_at,
                row.producer_position(),
            )?;
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
            if let Some(stamp) = row.delta_receipt.as_deref() {
                LINK.put(&self.store, wtxn, &key, &stamp.to_owned())?;
            }
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

impl PendingRow {
    /// The position its producing run's host bound, frozen as the output was
    /// retained (FIX 3171). An edit or an unbound producer has the default.
    fn producer_position(&self) -> BirthPosition {
        match &self.body {
            PendingBody::Output {
                producer_world,
                producer_facet,
                ..
            } => BirthPosition {
                world: *producer_world,
                facet: *producer_facet,
            },
            PendingBody::SheetAnswers { .. } | PendingBody::Edit { .. } => BirthPosition::default(),
        }
    }
}
