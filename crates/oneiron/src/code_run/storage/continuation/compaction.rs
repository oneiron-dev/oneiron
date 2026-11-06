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

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::super::compaction::{
    CodeRunCompactionCoverage, coverage_rows_in_txn, put_coverage_aliases_in_txn,
};
use super::super::folds::{base_code_run_folds_in_txn, seed_code_run_folds_in_txn};
use crate::code_run::CodeRunReplayRecord;
use crate::compaction::FoldLedger;
use crate::store::Store;
use crate::{EntityId, Error, Result, Vault};

/// A run's compaction as it stood at one step start (FIX 4198): its epoch
/// coverage rows and its fold ledger, inside the prefix the start holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StartCompaction {
    /// The run's epoch coverage rows, in epoch order, from epoch 1.
    coverage: Vec<CodeRunCompactionCoverage>,
    /// The run's fold ledger: its handles, `last`, marks, unfolds and
    /// compact ask as they stood. No fold keeps its receipt here: the run
    /// that ran it keeps that.
    folds: FoldLedger,
}

impl StartCompaction {
    /// The compaction of `prefix`'s run as `txn` holds it, kept inside
    /// `prefix` (FIX 4198). A step start reads it in its own writer. A fold
    /// that a withdrawn record reached keeps no words.
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
        let coverage = coverage_rows_in_txn(store, txn, prefix.run_id)?;
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
/// number and the ledger's `last`. The child's frozen seed keeps it, so a
/// reopen finds the seed in place without the source's start.
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
/// 4198). Each epoch becomes an alias that changes only its run. The ledger
/// lands as the child's through the fold module's own landing. The capture
/// must lie inside `child`'s copied prefix.
///
/// # Errors
///
/// Storage errors. [`Error::ConcurrentWrite`] for a child that holds
/// coverage or a ledger already; an invariant error for a capture past the
/// prefix, or a coverage chain that does not continue.
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
    put_coverage_aliases_in_txn(&vault.store, txn, child.run_id, &compaction.coverage)?;
    seed_code_run_folds_in_txn(
        &vault.store,
        txn,
        source,
        child.run_id,
        compaction.folds.clone(),
    )
}
