//! A fold's receipt (ARCH-0079 #reader-forks) and a summary's memo row,
//! beside the run's fold ledger and where the run's rows are: base, or its
//! off-record room's overlay, through the route it captured at entry.
//!
//! A receipt is written with the binding of the result it describes, in the
//! checkpoint's one transaction, so neither exists without the other. It is
//! computed by the host from the jobs it names; the guest only names them.
//! The model response's correction record (FIX 4411) joins the same commit,
//! and the step's replay context joins the same transaction beside its
//! capsule (FIX 6351, `replay_capsule::context`).

use super::corrections::{committed_checkpoint, put_correction_in_txn};
use super::program_resume::{ProgramResumeCommit, join_program_resume_in_txn};
use super::records::REPLAY_RECORDS;
use super::replay_capsule::{join_step_context_in_txn, stage_step_context};
use super::routing::SessionBinding;
use crate::code_run::{
    CodeRunCorrectionCheckpoint, CodeRunCorrectionDraft, CodeRunReplayGeneration,
    CodeRunReplayRecord, ExecutorStorage, ParkedWait, StepContextCommit,
    seal_parked_code_consent_in_txn,
};
use crate::side_table::{self, Raw, SideTable};
use crate::store::result_manifest::ResultOccurrence;
use crate::{EntityId, Error, ModelId, Result, Vault};

/// One receipt per folded occurrence, keyed by its run and its occurrence.
const FOLDS: SideTable<(EntityId, EntityId), ReaderFoldReceipt, Raw> =
    SideTable::new(&side_table::CODE_RUN_READER_FOLD);

/// One row per summary made, keyed by its memo key.
pub(super) const MEMOS: SideTable<[u8; 32], SummaryMemo, Raw> =
    SideTable::new(&side_table::CODE_RUN_SUMMARY_MEMO);

pub(crate) fn code_run_summary_memo_accepts_masked(bytes: &[u8]) -> bool {
    crate::side_table::decodes::<SummaryMemo, Raw>(bytes)
}

pub(crate) use crate::store::reader_fold_receipt::{
    OccurrenceRef, ReaderFoldReceipt, ReaderSubstrateRef, ReceiptFinding, ReceiptPartial,
    ReceiptSource, ReceiptTree, SummaryMemo,
};

impl Vault {
    /// Every fold receipt run `run` holds in the base vault, by its folded
    /// occurrence.
    pub(crate) fn code_run_reader_folds_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        run: EntityId,
    ) -> Result<Vec<ReaderFoldReceipt>> {
        Ok(FOLDS
            .scan_from(&self.store, rtxn, run.as_bytes())?
            .into_iter()
            .map(|(_, receipt)| receipt)
            .collect())
    }

    /// Restores one receipt an archive carried, in the import's transaction.
    pub(crate) fn put_code_run_reader_fold_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        receipt: &ReaderFoldReceipt,
    ) -> Result<()> {
        let key = (receipt.folded.owner, receipt.folded.occurrence);
        FOLDS.put(&self.store, wtxn, &key, receipt)
    }
}

impl SessionBinding<'_> {
    /// [`ExecutorStorage::put_code_run_replay_record_with_receipts_if_generation`]
    /// on the room's route: the record compared and put, its heal tally when
    /// the turn healed, every receipt beside it and the response's
    /// correction record, in one routed transaction.
    fn put_replay_record_with_receipts(
        &self,
        record: &CodeRunReplayRecord,
        expected: Option<CodeRunReplayGeneration>,
        healed_model: Option<&ModelId>,
        receipts: &[ReaderFoldReceipt],
        correction: Option<(&CodeRunCorrectionDraft<'_>, CodeRunCorrectionCheckpoint)>,
    ) -> Result<()> {
        // The routed append fences a base row against a spawn target's erase
        // in its own writer (FIX 9180), with or without a heal.
        self.answered(|| {
            self.put_replay_routed(record, expected, healed_model, |txn, write| {
                for receipt in receipts {
                    let key = (receipt.folded.owner, receipt.folded.occurrence);
                    FOLDS.put(&write, txn, &key, receipt)?;
                }
                if let Some((draft, checkpoint)) = correction {
                    put_correction_in_txn(&write, txn, draft, Some(checkpoint))?;
                }
                Ok(())
            })
        })
    }
}

impl ExecutorStorage<'_> {
    /// The checkpoint's commit with the fold receipts its step staged: the
    /// replay append, its heal tally and every receipt in one transaction, so a receipt never exists without its
    /// binding, nor a binding without its receipt.
    ///
    /// The model response the step ran joins the same commit as its
    /// correction record (FIX 4411), naming the checkpoint `record` commits
    /// for its step; its heal tally moves exactly when the response needed a
    /// repair, once per committed turn (ONE-1929).
    ///
    /// A step that parks its run on `parked` seals the code consent wait it
    /// names in the same transaction (DOOR-079 1b), when one is bound to it,
    /// so the binding is sealed exactly when its parked step commits. A
    /// room's run binds no code consent wait, so its commit seals nothing.
    /// The step's replay `context` joins its capsule in the same
    /// transaction (FIX 6351); a room's run captures no capsule.
    pub(crate) fn put_code_run_replay_record_with_receipts_if_generation(
        &self,
        record: &CodeRunReplayRecord,
        expected: Option<CodeRunReplayGeneration>,
        correction: &CodeRunCorrectionDraft<'_>,
        receipts: &[ReaderFoldReceipt],
        parked: Option<&ParkedWait>,
        context: &StepContextCommit,
    ) -> Result<CodeRunReplayGeneration> {
        self.put_replay_record_with_receipts_and_resume(
            record,
            expected,
            Some(correction),
            receipts,
            parked,
            None,
            context,
        )
    }

    /// [`Self::put_code_run_replay_record_with_receipts_if_generation`] for
    /// one pinned entry of a turn program (DOOR-141 PR3b): its resume head
    /// and pages join the same commit, beside its frontier, and never fail
    /// it. A room's run is no program's, so its commit joins nothing.
    pub(crate) fn put_program_entry_replay_record(
        &self,
        record: &CodeRunReplayRecord,
        expected: Option<CodeRunReplayGeneration>,
        receipts: &[ReaderFoldReceipt],
        parked: Option<&ParkedWait>,
        resume: &ProgramResumeCommit,
        context: &StepContextCommit,
    ) -> Result<CodeRunReplayGeneration> {
        self.put_replay_record_with_receipts_and_resume(
            record,
            expected,
            None,
            receipts,
            parked,
            Some(resume),
            context,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "a checkpoint's commit writes every row its step staged in one transaction"
    )]
    fn put_replay_record_with_receipts_and_resume(
        &self,
        record: &CodeRunReplayRecord,
        expected: Option<CodeRunReplayGeneration>,
        correction: Option<&CodeRunCorrectionDraft<'_>>,
        receipts: &[ReaderFoldReceipt],
        parked: Option<&ParkedWait>,
        resume: Option<&ProgramResumeCommit>,
        context: &StepContextCommit,
    ) -> Result<CodeRunReplayGeneration> {
        let healed_model = correction.and_then(CodeRunCorrectionDraft::healed_model);
        let correction = correction
            .map(|draft| committed_checkpoint(record, draft).map(|checkpoint| (draft, checkpoint)))
            .transpose()?;
        match self {
            Self::Canonical(vault) => {
                // Its body instances are minted before the writer opens.
                let context = stage_step_context(vault, context);
                vault.put_code_run_replay_record_if_generation_with_heal_and(
                    record,
                    expected,
                    healed_model,
                    |wtxn| {
                        // FIX 4747: an agent run's step, whose run is its
                        // attempt's own, commits only while this machine
                        // holds the run; the fence renews its lease.
                        crate::agent_dispatch::fence_agent_run_step_in_txn(
                            vault,
                            wtxn,
                            crate::attempt_queue::AttemptId::from_bytes(record.run_id.as_bytes())?,
                        )?;
                        for receipt in receipts {
                            let key = (receipt.folded.owner, receipt.folded.occurrence);
                            FOLDS.put(&vault.store, wtxn, &key, receipt)?;
                        }
                        if let Some((draft, checkpoint)) = correction {
                            put_correction_in_txn(&vault.store, wtxn, draft, Some(checkpoint))?;
                        }
                        if let Some(parked) = parked {
                            seal_parked_code_consent_in_txn(vault, wtxn, record, parked)?;
                        }
                        // The step's replay context joins its capsule (FIX
                        // 6351), in a savepoint of its own; it never fails
                        // the commit.
                        if let Some(context) = &context {
                            join_step_context_in_txn(vault, wtxn, context);
                        }
                        // A turn program's frontier joins its checkpoint's own
                        // commit (DOOR-141 PR2); it never fails it.
                        crate::dreamer_runner::join_program_checkpoint_in_txn(vault, wtxn, record);
                        // So does a pinned entry's resume checkpoint (DOOR-141
                        // PR3b), in a savepoint of its own.
                        if let Some(resume) = resume {
                            join_program_resume_in_txn(vault, wtxn, record, resume);
                        }
                        Ok(())
                    },
                )
            }
            Self::Session(binding) => {
                REPLAY_RECORDS.encode_value(record)?;
                let next = record.generation()?;
                binding.put_replay_record_with_receipts(
                    record,
                    expected,
                    healed_model,
                    receipts,
                    correction,
                )?;
                Ok(next)
            }
        }
    }

    /// The fold receipt of `owner`'s result at `path`, if it is a fold's.
    pub(crate) fn code_run_reader_fold(
        &self,
        owner: EntityId,
        path: &str,
    ) -> Result<Option<ReaderFoldReceipt>> {
        let key = (owner, ResultOccurrence::owned(owner, path)?.id());
        self.reader_read(|txn, dbs| FOLDS.get(&dbs, txn, &key))
    }

    /// The summary memo key `memo` names, if one was made.
    pub(crate) fn code_run_summary_memo(&self, memo: &[u8; 32]) -> Result<Option<SummaryMemo>> {
        self.reader_read(|txn, dbs| MEMOS.get(&dbs, txn, memo))
    }
}
