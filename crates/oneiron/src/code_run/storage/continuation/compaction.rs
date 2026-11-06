//! A continuation's compaction at its cut (FIX 4198).
//!
//! A step start captures its run's epoch coverage rows and fold ledger in
//! the start's own writer, kept inside the prefix the start holds
//! ([`StartCompaction`]). The start's body carries the capture, so the
//! start's digest binds it. A continuation seeds its child from that capture
//! in the writer that puts the child's replay row: each epoch becomes an
//! alias of the source's row, and the ledger lands again as the child's. It
//! never reads the source's ledger as it stands later. Nothing is minted,
//! billed or receipted again. The coverage and fold modules keep their own
//! codecs and write rules.
//!
//! The capture keeps no epoch's digest, so no start body holds a hash of a
//! summary's words (FIX 928). The seed takes each digest from the source's
//! own row, which a withdrawal clears, and an alias whose summary is
//! withdrawn keeps none. A withdrawal then changes no start body and no
//! start digest that a continuation or its child's frozen seed binds.
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
    FoldCompactAsked, FoldLedger, FoldMarked, FoldReply, FoldUnfolded, SelfFoldCall,
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
    /// compact ask as they stood. No fold keeps its receipt here: the run
    /// that ran it keeps that.
    folds: FoldLedger,
}

impl StartCompaction {
    /// The compaction of `prefix`'s run as `txn` holds it, kept inside
    /// `prefix` (FIX 4198). A step start reads it in its own writer. A fold
    /// that a withdrawn record reached keeps no words, and no epoch keeps
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
        let mut folds = base_code_run_folds_in_txn(store, txn, prefix.run_id)?;
        for fold in &mut folds.folds {
            fold.execution = None;
        }
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

    /// Whether a captured fold keeps its words (FIX 4198). A start that
    /// holds one travels in a checkpoint as parts, so its rest names the
    /// words' owners.
    pub(crate) fn keeps_words(&self) -> bool {
        self.folds.folds.iter().any(|fold| fold.summary.is_some())
    }

    /// Who owns the words the captured folds keep (FIX 4198): the byline of
    /// each fold that keeps its words, and every record they came from. The
    /// start's owner walk names them, so an erase of any reaches its rest.
    pub(crate) fn word_owners(&self) -> impl Iterator<Item = EntityId> + '_ {
        self.folds
            .folds
            .iter()
            .filter(|fold| fold.summary.is_some())
            .flat_map(|fold| std::iter::once(fold.actor).chain(fold.sources.iter().copied()))
    }
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
/// module's own landing. The capture must lie inside `child`'s copied
/// prefix.
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
            fold_answer::<FoldMarked>(&answer)?.map(|marked| vec![marked.fold])
        }
        SelfFoldCall::Compact { .. } => {
            fold_answer::<FoldCompactAsked>(&answer)?.map(|asked| asked.pending)
        }
        SelfFoldCall::Unfold { .. } => {
            fold_answer::<FoldUnfolded>(&answer)?.map(|unfolded| vec![unfolded.fold])
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
