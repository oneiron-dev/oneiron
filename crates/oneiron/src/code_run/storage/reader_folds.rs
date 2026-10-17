//! A fold's receipt (ARCH-0079 #reader-forks) and a summary's memo row,
//! beside the run's fold ledger and where the run's rows are: base, or its
//! off-record room's overlay, through the route it captured at entry.
//!
//! A receipt is written with the binding of the result it describes, in the
//! checkpoint's one transaction, so neither exists without the other. It is
//! computed by the host from the jobs it names; the guest only names them.

use serde::{Deserialize, Serialize};

use super::records::{REPLAY_RECORDS, replay_generation_matches};
use super::routing::SessionBinding;
use crate::code_run::{
    CodeRunReplayGeneration, CodeRunReplayRecord, ExecutorStorage, ResultOccurrence,
};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::{EntityId, Error, ModelId, Result, Vault};

/// One receipt per folded occurrence, keyed by its run and its occurrence.
const FOLDS: SideTable<(EntityId, EntityId), ReaderFoldReceipt, Raw> =
    SideTable::new(&side_table::CODE_RUN_READER_FOLD);

/// One row per summary made, keyed by its memo key.
pub(super) const MEMOS: SideTable<[u8; 32], SummaryMemo, Raw> =
    SideTable::new(&side_table::CODE_RUN_SUMMARY_MEMO);

/// One result occurrence as a receipt names it: its id, the run that holds
/// it, its path in that run's record and its body's handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OccurrenceRef {
    pub(crate) occurrence: EntityId,
    pub(crate) owner: EntityId,
    pub(crate) path: String,
    pub(crate) handle: String,
}

impl OccurrenceRef {
    pub(crate) fn new(owner: EntityId, path: &str, handle: &str) -> Result<Self> {
        Ok(Self {
            occurrence: ResultOccurrence::owned(owner, path)?.id(),
            owner,
            path: path.to_owned(),
            handle: handle.to_owned(),
        })
    }
}

/// The source a fold read: its occurrence and the range of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReceiptSource {
    pub(crate) occurrence: OccurrenceRef,
    pub(crate) range: (u64, u64),
}

/// One reader job a fold named: its task, its finding (none for a job that
/// left none), its state, why it settled short, and the range it read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReceiptFinding {
    pub(crate) task: EntityId,
    pub(crate) occurrence: Option<OccurrenceRef>,
    pub(crate) state: String,
    pub(crate) reason: Option<String>,
    pub(crate) range: (u64, u64),
}

/// A child that settled short, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReceiptPartial {
    pub(crate) task: EntityId,
    pub(crate) reason: String,
}

/// One summary of a fold's tree and the results it summarized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReceiptTree {
    pub(crate) summary: OccurrenceRef,
    pub(crate) inputs: Vec<OccurrenceRef>,
}

/// What a folded result rests on: the source it was read from and the
/// findings it was folded from. It is not
/// `EdgeProvenanceClaimBody.substrate_ref` (provenance/codec.rs), which
/// names the MODEL that produced a write; nothing here reaches that field or
/// its gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReaderSubstrateRef {
    pub(crate) source: OccurrenceRef,
    pub(crate) findings: Vec<OccurrenceRef>,
}

/// A fold's receipt: the folded result, the source and range it read, each
/// job it named, the byte ranges read, unread and read short, the children's
/// cutoff, the recipe it folded by, its summary tree, every occurrence whose
/// taint the folded body inherits, and what it rests on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReaderFoldReceipt {
    pub(crate) folded: OccurrenceRef,
    pub(crate) source: ReceiptSource,
    pub(crate) findings: Vec<ReceiptFinding>,
    pub(crate) read: Vec<(u64, u64)>,
    pub(crate) unread: Vec<(u64, u64)>,
    pub(crate) partial: Vec<ReceiptPartial>,
    pub(crate) cutoff_unix_ms: u64,
    pub(crate) recipe: Option<serde_json::Value>,
    pub(crate) tree: Vec<ReceiptTree>,
    pub(crate) taint: Vec<OccurrenceRef>,
    pub(crate) substrate_ref: ReaderSubstrateRef,
}

impl ReaderFoldReceipt {
    /// What the folded result's card says of it: the ranges read, unread
    /// and read short, and how many jobs it named.
    pub(crate) fn card(&self) -> serde_json::Value {
        serde_json::json!({
            "read": self.read,
            "unread": self.unread,
            "partial": self.partial,
            "children": self.findings.len(),
        })
    }

    /// The receipt of a withheld folded occurrence as an export carries it:
    /// its marker and its refs, no range, reason or recipe.
    pub(crate) fn refs_only(&self) -> serde_json::Value {
        let refs = |items: &mut dyn Iterator<Item = &OccurrenceRef>| {
            items
                .map(|item| item.occurrence.to_hex())
                .collect::<Vec<_>>()
        };
        serde_json::json!({
            "folded": self.folded.occurrence.to_hex(),
            "source": self.source.occurrence.occurrence.to_hex(),
            "findings": refs(&mut self.findings.iter().filter_map(|f| f.occurrence.as_ref())),
            "taint": refs(&mut self.taint.iter()),
        })
    }
}

/// A summary made: its task, and its text's occurrence in the job's run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SummaryMemo {
    pub(crate) task: EntityId,
    pub(crate) owner: EntityId,
    pub(crate) path: String,
    pub(crate) handle: String,
}

macro_rules! json_row {
    ($row:ty, $what:literal) => {
        impl RawValue for $row {
            fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
                serde_json::to_vec(self).map_err(|_| Error::CorruptedIndex($what).into())
            }

            fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
                serde_json::from_slice(bytes).map_err(|_| Error::CorruptedIndex($what).into())
            }
        }
    };
}

json_row!(ReaderFoldReceipt, "code-run reader fold receipt");
json_row!(SummaryMemo, "code-run summary memo");

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
    /// on the room's route: the record compared and put, and every receipt
    /// beside it, in one routed transaction. The room keeps no heal tally
    /// for this turn.
    fn put_replay_record_with_receipts(
        &self,
        record: &CodeRunReplayRecord,
        expected: Option<CodeRunReplayGeneration>,
        receipts: &[ReaderFoldReceipt],
    ) -> Result<()> {
        self.answered(|| {
            self.session
                .routed_side_txn(&self.route, |txn, read, write| {
                    let current = REPLAY_RECORDS.get(&read, &*txn, &record.run_id)?;
                    replay_generation_matches(current.as_ref(), expected)?;
                    REPLAY_RECORDS.put(&write, txn, &record.run_id, record)?;
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
    /// replay append (and, on the canonical vault, its heal tally) and every
    /// receipt in one transaction, so a receipt never exists without its
    /// binding, nor a binding without its receipt.
    pub(crate) fn put_code_run_replay_record_with_receipts_if_generation(
        &self,
        record: &CodeRunReplayRecord,
        expected: Option<CodeRunReplayGeneration>,
        healed_model: Option<&ModelId>,
        receipts: &[ReaderFoldReceipt],
    ) -> Result<CodeRunReplayGeneration> {
        if receipts.is_empty() {
            return self.put_code_run_replay_record_if_generation_with_heal(
                record,
                expected,
                healed_model,
            );
        }
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
                    Ok(())
                },
            ),
            Self::Session(binding) => {
                REPLAY_RECORDS.encode_value(record)?;
                let next = record.generation()?;
                binding.put_replay_record_with_receipts(record, expected, receipts)?;
                Ok(next)
            }
        }
    }

    /// The fold receipt run `owner` holds for its occurrence `folded`.
    pub(crate) fn code_run_reader_fold(
        &self,
        owner: EntityId,
        folded: EntityId,
    ) -> Result<Option<ReaderFoldReceipt>> {
        self.reader_read(|txn, dbs| FOLDS.get(&dbs, txn, &(owner, folded)))
    }

    /// The summary memo key `memo` names, if one was made.
    pub(crate) fn code_run_summary_memo(&self, memo: &[u8; 32]) -> Result<Option<SummaryMemo>> {
        self.reader_read(|txn, dbs| MEMOS.get(&dbs, txn, memo))
    }
}
