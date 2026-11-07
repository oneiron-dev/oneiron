//! A continuation's compaction at its cut (FIX 4198).
//!
//! A step start captures its run's epoch coverage rows and fold ledger in
//! the start's own writer, kept inside the prefix the start holds
//! ([`StartCompaction`]). The start's body carries the capture, so the
//! start's digest binds it. A continuation seeds its child from that capture
//! in the writer that puts the child's replay row: each epoch becomes an
//! alias of the source's row, and the ledger lands again as the child's.
//! From the source's ledger as it stands then, the seed reads only the
//! folds' words. Nothing is minted, billed or receipted again. The coverage
//! and fold modules keep their own codecs and write rules.
//!
//! The capture keeps no epoch's digest, so no start body holds a hash of a
//! summary's words (FIX 928). The seed takes each digest from the source's
//! own row, which a withdrawal clears, and an alias whose summary is
//! withdrawn keeps none. A withdrawal then changes no start body and no
//! start digest that a continuation or its child's frozen seed binds.
//!
//! The capture keeps no fold's words either: no summary and no note (FIX
//! 18694). The start-body codec writes none, so no start body holds a
//! fold's prose, and an erase of a record a fold came from has nothing there
//! to retire. This closes FIX 18694 for start bodies. The seed takes each
//! fold's words from the source's own ledger in the seed's writer
//! ([`StartCompaction::with_source_words_in_txn`]). An erase of any of the
//! fold's records takes them from that ledger in the erasing writer, so a
//! withdrawn fold is inherited with none. No start body is rewritten, so no
//! start digest changes.
//!
//! After a failed step, the copied row holds that step's calls, but the
//! capture is the earlier start's (FIX 18695). The fold verbs those calls
//! made are not inherited, and their recorded answers stay as history. So
//! the child's ledger gives out handles past the highest one a copied mark,
//! compact ask or unfold answer names. No fold or mark is added for those
//! handles. A clean cut copies no call past its start and is unchanged.

use std::collections::BTreeSet;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::super::compaction::{
    CodeRunCompactionCoverage, coverage_rows_in_txn, put_coverage_aliases_in_txn,
};
use super::super::folds::{base_code_run_folds_in_txn, seed_code_run_folds_in_txn};
use crate::code_run::payload::decode_self_dispatch_outcome;
use crate::code_run::support::{expect_map, invalid_code_run_replay, map_get, str_value};
use crate::code_run::{CodeRunBridgeCall, CodeRunReplayRecord, SelfDispatchOutcome, SelfEffect};
use crate::compaction::{
    FoldCompactAsked, FoldLedger, FoldMarked, FoldRecord, FoldReply, FoldUnfolded, SelfFoldCall,
    parse_fold_handle,
};
use crate::store::Store;
use crate::{EntityId, Error, Result, Vault};

/// A run's compaction as it stood at one step start (FIX 4198): its epoch
/// coverage rows and its fold ledger, inside the prefix the start holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StartCompaction {
    /// The run's epoch coverage rows, in epoch order, from epoch 1, each
    /// without its digest (FIX 928).
    coverage: Vec<CodeRunCompactionCoverage>,
    /// The run's fold ledger: its handles, `last`, marks, unfolds and
    /// compact ask as they stood. Each fold keeps its span, sources, byline
    /// and references, but no words and no receipt ([`captured_fold`], FIX
    /// 18694). The codec writes none, whatever the ledger holds. A seed
    /// takes the words from the source's own ledger.
    #[serde(serialize_with = "serialize_captured_ledger")]
    folds: FoldLedger,
}

impl StartCompaction {
    /// The compaction of `prefix`'s run as `txn` holds it, kept inside
    /// `prefix` (FIX 4198). A step start reads it in its own writer. No
    /// fold keeps its words or its receipt (FIX 18694), and no epoch keeps
    /// its digest (FIX 928).
    ///
    /// # Errors
    ///
    /// Storage errors, and a coverage row or ledger that does not decode.
    pub(crate) fn captured_in_txn(
        store: &Store,
        txn: &heed::RoTxn<'_>,
        prefix: &CodeRunReplayRecord,
    ) -> Result<Self> {
        let folds = captured_ledger(base_code_run_folds_in_txn(store, txn, prefix.run_id)?);
        let coverage = coverage_rows_in_txn(store, txn, prefix.run_id)?
            .into_iter()
            .map(CodeRunCompactionCoverage::without_digest)
            .collect();
        Ok(Self { coverage, folds }.kept_inside(prefix))
    }

    /// What of this lies inside `prefix`, a copied prefix row (FIX 4198):
    /// the epochs that chain from epoch 1 with their spans and calls inside
    /// it, the folds with their spans inside it, and the unfolds of those
    /// folds made by its end. A span that crosses the cut is dropped, never
    /// clipped. The ledger's `last`, marks and compact ask stay as they stood.
    pub(crate) fn kept_inside(mut self, prefix: &CodeRunReplayRecord) -> Self {
        let steps = prefix.step_checkpoints.len() as u64;
        let calls = prefix.bridge_calls.len() as u64;
        let mut coverage = std::mem::take(&mut self.coverage);
        coverage.sort_unstable_by_key(CodeRunCompactionCoverage::epoch);
        for row in coverage {
            if row.last() >= steps || row.calls() > calls || !row.continues(self.coverage.last()) {
                break;
            }
            self.coverage.push(row);
        }
        let FoldLedger { folds, unfolds, .. } = &mut self.folds;
        folds.retain(|fold| fold.through < steps);
        unfolds.retain(|unfold| {
            unfold.at <= steps && folds.iter().any(|fold| fold.fold == unfold.fold)
        });
        self
    }

    /// This, with its ledger numbered past every fold handle that a
    /// recorded answer of `prefix`'s calls from `bridge_start` on names
    /// (FIX 18695). After a failed step, `prefix` holds that step's calls,
    /// but this capture is the earlier start's. The child keeps those calls'
    /// answers as history, so `last` moves to the highest handle a mark, a
    /// compact ask or an unfold answered. The child's next mark then never
    /// reuses one. No fold or mark is added for those handles. A clean cut
    /// copies no call past its start, so it is unchanged.
    ///
    /// # Errors
    ///
    /// A fold verb's recorded call, answer or handle that does not decode.
    pub(crate) fn numbered_past_copied_calls(
        mut self,
        prefix: &CodeRunReplayRecord,
        bridge_start: u64,
    ) -> Result<Self> {
        let copied = usize::try_from(bridge_start)
            .ok()
            .and_then(|start| prefix.bridge_calls.get(start..))
            .unwrap_or_default();
        for call in copied {
            self.folds.last = self.folds.last.max(answered_fold_bound(call)?);
        }
        Ok(self)
    }

    /// Whether all of this lies inside `prefix` (FIX 4198).
    fn lies_inside(&self, prefix: &CodeRunReplayRecord) -> bool {
        self.clone().kept_inside(prefix) == *self
    }

    /// What a seed of this keeps, by id alone (FIX 4198).
    pub(crate) fn inherited(&self) -> InheritedCompaction {
        InheritedCompaction {
            summaries: self
                .coverage
                .iter()
                .map(CodeRunCompactionCoverage::summary_id)
                .collect(),
            folds: self.folds.folds.iter().map(|fold| fold.fold).collect(),
            last: self.folds.last,
        }
    }

    /// This capture with each fold's words as `source`'s own base ledger
    /// holds them in `txn`, the seed's writer (FIX 4198, FIX 18694). A start
    /// carries no fold's words. An erase of any record a fold came from
    /// takes them from that ledger in the erasing writer, and this read
    /// withholds them once any is withdrawn. So a withdrawn fold comes back
    /// with none, never with words it had before. `None` when that ledger
    /// holds no fold of a captured fold's handle.
    ///
    /// # Errors
    ///
    /// Storage errors, a ledger that does not decode, and an invariant
    /// error for a fold that the ledger holds otherwise than this capture
    /// but for its words.
    pub(crate) fn with_source_words_in_txn(
        mut self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        source: EntityId,
    ) -> Result<Option<Self>> {
        let live = base_code_run_folds_in_txn(&vault.store, txn, source)?;
        for fold in &mut self.folds.folds {
            let Some(held) = live.fold(fold.fold) else {
                return Ok(None);
            };
            if captured_fold(held) != captured_fold(fold) {
                return Err(Error::InvariantViolation(
                    "an inherited fold is not its source's",
                ));
            }
            fold.summary.clone_from(&held.summary);
            fold.note.clone_from(&held.note);
        }
        Ok(Some(self))
    }
}

/// `fold` as a step start captures it (FIX 4198, FIX 18694): its handle,
/// span, sources, byline and references, with no words (no summary and no
/// note) and no receipt. The run that ran the fold keeps its receipt, and
/// the run's own ledger keeps its words.
fn captured_fold(fold: &FoldRecord) -> FoldRecord {
    FoldRecord {
        summary: None,
        note: None,
        execution: None,
        ..fold.clone()
    }
}

/// `ledger` with each fold as [`captured_fold`] leaves it (FIX 18694).
fn captured_ledger(mut ledger: FoldLedger) -> FoldLedger {
    for fold in &mut ledger.folds {
        *fold = captured_fold(fold);
    }
    ledger
}

/// The start-body codec of a captured ledger (FIX 18694): each fold
/// without its words or receipt, whatever `ledger` holds. No start body
/// then holds a fold's prose.
fn serialize_captured_ledger<S: serde::Serializer>(
    ledger: &FoldLedger,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    captured_ledger(ledger.clone()).serialize(serializer)
}

/// What a continuation's seed inherited of its source's compaction, by id
/// alone (FIX 4198): the summary each aliased epoch binds, each fold's
/// number and the ledger's `last`, which is past every handle a copied
/// answer names (FIX 18695). The child's frozen seed keeps it, so a reopen
/// finds the seed in place without the source's start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct InheritedCompaction {
    summaries: Vec<EntityId>,
    folds: Vec<u64>,
    last: u64,
}

impl InheritedCompaction {
    /// Whether `child` still holds this seed, as `txn` reads it (FIX 4198):
    /// an alias of each summary, each fold, and a ledger numbered at least
    /// as far. The child's later epochs and folds are its own.
    ///
    /// # Errors
    ///
    /// Storage errors, and a coverage row or ledger that does not decode.
    pub(crate) fn held_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        child: EntityId,
    ) -> Result<bool> {
        let aliases: BTreeSet<EntityId> = coverage_rows_in_txn(&vault.store, txn, child)?
            .iter()
            .map(CodeRunCompactionCoverage::summary_id)
            .collect();
        let ledger = base_code_run_folds_in_txn(&vault.store, txn, child)?;
        Ok(ledger.last >= self.last
            && self
                .summaries
                .iter()
                .all(|summary| aliases.contains(summary))
            && self.folds.iter().all(|fold| ledger.fold(*fold).is_some()))
    }
}

/// Seeds `child`'s compaction from `compaction`, which its source's proved
/// start captured, in the writer that puts the child's replay row (FIX
/// 4198). Each epoch becomes an alias that changes only its run, with the
/// digest the source's own row holds now: none once its summary is
/// withdrawn (FIX 928). The ledger lands as the child's through the fold
/// module's own landing, each fold with the words
/// [`StartCompaction::with_source_words_in_txn`] read in this writer (FIX
/// 18694). The capture must lie inside `child`'s copied prefix.
///
/// # Errors
///
/// Storage errors. [`Error::ConcurrentWrite`] for a child that holds
/// coverage or a ledger already; an invariant error for a capture past the
/// prefix, a captured epoch the source's row does not match, or a coverage
/// chain that does not continue.
pub(super) fn seed_continuation_compaction_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    source: EntityId,
    child: &CodeRunReplayRecord,
    compaction: &StartCompaction,
) -> Result<()> {
    if !compaction.lies_inside(child) {
        return Err(Error::InvariantViolation(
            "a continuation's compaction lies past its copied prefix",
        ));
    }
    put_coverage_aliases_in_txn(
        &vault.store,
        txn,
        source,
        child.run_id,
        &compaction.coverage,
    )?;
    seed_code_run_folds_in_txn(
        &vault.store,
        txn,
        source,
        child.run_id,
        compaction.folds.clone(),
    )
}

/// The highest fold handle that `call`'s recorded answer names, or 0 (FIX
/// 18695): a mark's new handle, a compact ask's pending marks, or an
/// unfold's fold. A call of another effect, an answer that is not a fold
/// answer, a read verb's answer and the ledger's refusal name none. A
/// refusal's text is never read.
///
/// # Errors
///
/// A fold answer whose recorded call, typed answer or handle does not
/// decode.
fn answered_fold_bound(call: &CodeRunBridgeCall) -> Result<u64> {
    if call.effect != SelfEffect::Fold {
        return Ok(0);
    }
    let Ok(SelfDispatchOutcome::Fold(answer)) = decode_self_dispatch_outcome(&call.outcome) else {
        return Ok(0);
    };
    let request = expect_map(&call.request, "fold request must be a map")?;
    let verb: SelfFoldCall = serde_json::from_str(str_value(map_get(request, "call")?)?)
        .map_err(|_| undecoded_fold_answer())?;
    let handles = match verb {
        SelfFoldCall::Mark { .. } => {
            fold_answer::<FoldMarked>(answer.as_ref())?.map(|marked| vec![marked.fold])
        }
        SelfFoldCall::Compact { .. } => {
            fold_answer::<FoldCompactAsked>(answer.as_ref())?.map(|asked| asked.pending)
        }
        SelfFoldCall::Unfold { .. } => {
            fold_answer::<FoldUnfolded>(answer.as_ref())?.map(|unfolded| vec![unfolded.fold])
        }
        SelfFoldCall::List | SelfFoldCall::Describe { .. } => None,
    };
    handles
        .unwrap_or_default()
        .iter()
        .try_fold(0, |bound, handle| {
            parse_fold_handle(handle)
                .map(|fold| bound.max(fold))
                .map_err(|_| undecoded_fold_answer())
        })
}

/// A fold verb's typed answer in `answer`, the JSON its call recorded, or
/// `None` for the ledger's refusal, which gave out no handle.
///
/// # Errors
///
/// An answer that decodes as neither.
fn fold_answer<T: DeserializeOwned>(answer: &str) -> Result<Option<T>> {
    match serde_json::from_str::<FoldReply<T>>(answer) {
        Ok(FoldReply::Answer(answer)) => Ok(Some(answer)),
        Ok(FoldReply::Refused { .. }) => Ok(None),
        Err(_) => Err(undecoded_fold_answer()),
    }
}

/// The storage error for a copied fold call that does not decode.
fn undecoded_fold_answer() -> Error {
    invalid_code_run_replay("a copied fold answer does not decode")
}
