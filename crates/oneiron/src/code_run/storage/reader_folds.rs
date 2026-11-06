//! A fold's receipt (ARCH-0079 #reader-forks) and a summary's memo row,
//! beside the run's fold ledger and where the run's rows are: base, or its
//! off-record room's overlay, through the route it captured at entry.
//!
//! A receipt is written with the binding of the result it describes, in the
//! checkpoint's one transaction, so neither exists without the other. It is
//! computed by the host from the jobs it names; the guest only names them.

use super::program_resume::{ProgramResumeCommit, join_program_resume_in_txn};
use super::records::REPLAY_RECORDS;
use super::routing::SessionBinding;
use crate::code_run::{
    CodeRunReplayGeneration, CodeRunReplayRecord, ExecutorStorage, ParkedWait,
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
    /// the turn healed, and every receipt beside it, in one routed
    /// transaction.
    fn put_replay_record_with_receipts(
        &self,
        record: &CodeRunReplayRecord,
        expected: Option<CodeRunReplayGeneration>,
        healed_model: Option<&ModelId>,
        receipts: &[ReaderFoldReceipt],
    ) -> Result<()> {
        // The routed append fences a base row against a spawn target's erase
        // in its own writer (FIX 9180), with or without a heal.
        self.answered(|| {
            self.put_replay_routed(record, expected, healed_model, |txn, write| {
                for receipt in receipts {
                    let key = (receipt.folded.owner, receipt.folded.occurrence);
                    FOLDS.put(&write, txn, &key, receipt)?;
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
    /// A step that parks its run on `parked` seals the code consent wait it
    /// names in the same transaction (DOOR-079 1b), when one is bound to it,
    /// so the binding is sealed exactly when its parked step commits. A
    /// room's run binds no code consent wait, so its commit seals nothing.
    pub(crate) fn put_code_run_replay_record_with_receipts_if_generation(
        &self,
        record: &CodeRunReplayRecord,
        expected: Option<CodeRunReplayGeneration>,
        healed_model: Option<&ModelId>,
        receipts: &[ReaderFoldReceipt],
        parked: Option<&ParkedWait>,
    ) -> Result<CodeRunReplayGeneration> {
        self.put_replay_record_with_receipts_and_resume(
            record,
            expected,
            healed_model,
            receipts,
            parked,
            None,
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
    ) -> Result<CodeRunReplayGeneration> {
        self.put_replay_record_with_receipts_and_resume(
            record,
            expected,
            None,
            receipts,
            parked,
            Some(resume),
        )
    }

    fn put_replay_record_with_receipts_and_resume(
        &self,
        record: &CodeRunReplayRecord,
        expected: Option<CodeRunReplayGeneration>,
        healed_model: Option<&ModelId>,
        receipts: &[ReaderFoldReceipt],
        parked: Option<&ParkedWait>,
        resume: Option<&ProgramResumeCommit>,
    ) -> Result<CodeRunReplayGeneration> {
        match self {
            Self::Canonical(vault) => vault.put_code_run_replay_record_if_generation_with_heal_and(
                record,
                expected,
                healed_model,
                |wtxn| {
                    for receipt in receipts {
                        let key = (receipt.folded.owner, receipt.folded.occurrence);
                        FOLDS.put(&vault.store, wtxn, &key, receipt)?;
                    }
                    if let Some(parked) = parked {
                        seal_parked_code_consent_in_txn(vault, wtxn, record, parked)?;
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
            ),
            Self::Session(_) if receipts.is_empty() => self
                .put_code_run_replay_record_if_generation_with_heal(record, expected, healed_model),
            Self::Session(binding) => {
                REPLAY_RECORDS.encode_value(record)?;
                let next = record.generation()?;
                binding.put_replay_record_with_receipts(
                    record,
                    expected,
                    healed_model,
                    receipts,
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
