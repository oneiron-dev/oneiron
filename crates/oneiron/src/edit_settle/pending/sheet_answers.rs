//! Paid sheet answers wait in the same pending record until byte staging succeeds.

use std::time::Instant;

use super::{MadeByReader, PENDING, PendingBody, PendingProposalView, PendingRow, admission};
use crate::edit_roundtrip::SheetAnswerWork;
use crate::edit_settle::codec::{RECORD, settlement_key_parts};
use crate::edit_settle::receipts::already_settled;
use crate::provenance::made_by::MadeBy;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Error, Result, Vault};

impl Vault {
    /// Retains actual paid decisions before attempting byte staging. No edit
    /// proposal, validation result or proposed bytes are fabricated.
    pub fn retain_sheet_answer_work_with_reads(
        &self,
        artifact: &EntityId,
        run_ref: &str,
        work: &SheetAnswerWork,
        made_by: Option<&MadeBy>,
        reader: Option<MadeByReader<'_>>,
        (actor, at): (WriteActor, u64),
        read_rows: &[EntityId],
    ) -> Result<PendingProposalView> {
        let lane = admission::retention_lane(artifact, made_by, actor.entity_ref(), reader)?;
        self.with_write_txn_grouped(|wtxn| {
            self.retain_sheet_answer_work_with_reads_in_txn(
                wtxn,
                artifact,
                run_ref,
                work,
                made_by,
                lane.as_ref(),
                (actor, at),
                read_rows,
            )
        })
    }

    /// The answered cohort commits beside its original ask stamp and history.
    pub(crate) fn retain_sheet_answer_work_with_reads_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        artifact: &EntityId,
        run_ref: &str,
        work: &SheetAnswerWork,
        made_by: Option<&MadeBy>,
        lane: Option<&crate::claim::ScopedRead<'_>>,
        (actor, at): (WriteActor, u64),
        read_rows: &[EntityId],
    ) -> Result<PendingProposalView> {
        work.bundle().ops()?;
        match (lane, made_by) {
            (Some(lane), Some(made_by)) => {
                admission::admit_made_by_in_txn(self, wtxn, lane, made_by, actor.entity_ref())?;
            }
            _ => {
                admission::retention_lane(artifact, made_by, actor.entity_ref(), None)?;
            }
        }
        let mut read_rows = read_rows.to_vec();
        read_rows.sort_unstable();
        read_rows.dedup();
        let row = PendingRow {
            proposal_ref: run_ref.to_owned(),
            retained_by: actor.entity_ref(),
            retained_by_kind: self.get_entity_type_in_txn(wtxn, &actor.entity_ref())?,
            retained_at: at,
            made_by: made_by.cloned(),
            base_version: Some(work.base_version),
            base_content_hash: Some(work.base_content_hash),
            explicit_fork: false,
            next_sheet_row: work.next_sheet_row,
            new_bytes: Vec::new(),
            new_file: None,
            body: PendingBody::SheetAnswers {
                bundle: work.bundle().clone(),
            },
            read_rows,
            deck: None,
            delta_receipt: None,
        };
        self.put_pending_in_txn(wtxn, artifact, &row, None, None)?;
        Ok(row.view(*artifact))
    }

    /// Finishes this ask's byte attempt. Expiry is an explicit retained
    /// needs-staging result, not an empty or successful proposal.
    pub(crate) fn finish_pending_sheet_answers(
        &self,
        artifact: &EntityId,
        run_ref: &str,
        deadline: Instant,
    ) -> Result<PendingProposalView> {
        match self.stage_pending_sheet_answers(artifact, run_ref, Some(deadline)) {
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::TimedOut => self
                .pending_proposal(artifact, run_ref)?
                .ok_or(Error::EntityNotFound),
            result => result,
        }
    }

    /// Stages only the retained decisions, never calls a provider, and never
    /// renews `deadline`. A later caller may supply its own new work clock.
    /// Any failure leaves the answered record intact.
    pub fn stage_pending_sheet_answers(
        &self,
        artifact: &EntityId,
        run_ref: &str,
        deadline: Option<Instant>,
    ) -> Result<PendingProposalView> {
        let row = self
            .pending_row(artifact, run_ref)?
            .ok_or(Error::EntityNotFound)?;
        let PendingBody::SheetAnswers { bundle } = &row.body else {
            return Ok(row.view(*artifact));
        };
        let proposal = self
            .stage_sheet_answers(
                artifact,
                bundle.clone(),
                run_ref,
                row.base_version
                    .ok_or(Error::CorruptedIndex("answered base version"))?,
                row.base_content_hash
                    .ok_or(Error::CorruptedIndex("answered base hash"))?,
                crate::office_body::document_resources_until(deadline),
            )?
            .ok_or(Error::CorruptedIndex("answered cohort has no values"))?;
        self.with_write_txn_grouped(|wtxn| {
            let key = settlement_key_parts(artifact, run_ref);
            if let Some(record) = RECORD.get(&self.store, wtxn, &key)? {
                return Err(already_settled(&record));
            }
            let current = PENDING
                .get(&self.store, wtxn, &key)?
                .ok_or(Error::EntityNotFound)?;
            if current != row {
                return Err(Error::InvariantViolation(
                    "answered cohort changed during staging",
                ));
            }
            let mut staged = current;
            staged.new_bytes = proposal.new_bytes;
            staged.body = PendingBody::Edit {
                format: proposal.format,
                manifest: proposal.manifest.to_msgpack()?,
                inspection: proposal.inspection,
                recalc: proposal.recalc,
                calc_engine: proposal
                    .calc_engine
                    .as_deref()
                    .map(|stamp| (stamp.engine().to_owned(), stamp.version().to_owned())),
                sheet_answers: proposal.sheet_answers.map(|bundle| *bundle),
            };
            PENDING.put(&self.store, wtxn, &key, &staged)?;
            Ok(staged.view(*artifact))
        })
    }
}
