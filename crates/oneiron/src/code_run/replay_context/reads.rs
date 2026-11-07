//! What a captured step's result reads saw of reader state (FIX 6352): the
//! reader binding its run read under, whether a reader child's job was live
//! at each read of its source, a parent's settled findings at each lookup of
//! a handle that named none of its own results, the fold receipt each whole
//! result's card carried, and the verdict the door's row check gave each
//! read of another run's result. These rows belong to other runs and change
//! while the step runs, so the step's host keeps each answer as the read saw
//! it, at the bridge position the read was at. A shadow arm reads these
//! answers, never the rows as they are later.
//!
//! Some answers are final once seen: a settled child's finding stays
//! selected, and a job that is no longer live is never live again. So a
//! final answer seen before a position holds there, an answer that is not
//! final and was seen after a position held before it, and reads at one
//! position that agree hold at it. Nothing else is established. A row
//! check's verdict is never final: the door's caller and the rows it
//! withholds change.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::code_run::dispatcher::{delegated_input, delegated_occurrence_input};
use crate::code_run::{
    DelegatedSource, OccurrenceRef, ReaderFindingRef, ReaderFoldReceipt, ReaderRoute,
};
use crate::engine_executor::JsResultRef;

/// The reader binding a reader child's run reads under, as its host held it
/// from the step's start: its job's task, the generation its runner claimed
/// it at, its run and route, the source its parent delegated and, for a
/// scoped child, the inputs it was lent, by name. It holds no dispatcher,
/// door, credential or port of the parent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CapturedReaderChild {
    pub(crate) task: EntityId,
    pub(crate) generation: u32,
    pub(crate) run: EntityId,
    pub(crate) route: ReaderRoute,
    pub(crate) source: DelegatedSource,
    pub(crate) inputs: Option<BTreeMap<String, DelegatedSource>>,
}

impl CapturedReaderChild {
    /// The input `reference` names, by its name (`by_name`) or its handle,
    /// with the name it is read by, as the live binding resolves it.
    pub(crate) fn delegated(
        &self,
        by_name: bool,
        reference: &str,
    ) -> Option<(&str, &DelegatedSource)> {
        delegated_input(&self.source, self.inputs.as_ref(), by_name, reference)
    }

    /// The input an `occurrence:<hex>` ref names, with the name it is read
    /// by, as the live binding resolves it.
    pub(crate) fn delegated_occurrence(&self, wanted: &str) -> Option<(&str, &DelegatedSource)> {
        delegated_occurrence_input(&self.source, self.inputs.as_ref(), wanted)
    }

    /// Every source a read of the child can name: a scoped child's lent
    /// inputs, or a read child's one source.
    pub(crate) fn sources(&self) -> Vec<&DelegatedSource> {
        match &self.inputs {
            Some(inputs) => inputs.values().collect(),
            None => vec![&self.source],
        }
    }
}

/// One settled finding a parent's finding index selects: its child's task,
/// the finding, and each reference that selects it (its exact occurrence
/// ref and, while its child is that handle's first reporter, its content
/// handle).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SelectedFinding {
    pub(crate) task: EntityId,
    pub(crate) finding: ReaderFindingRef,
    pub(crate) references: Vec<String>,
}

/// A parent's settled findings as one read of its finding index selects
/// them: each Done or Partial child of the parent whose finding a reference
/// selects, and the child cutoff the parent's row records. A lookup of any
/// reference reads from it the answer the index gave in that read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReaderFindingSelection {
    pub(crate) findings: Vec<SelectedFinding>,
    pub(crate) cutoff_unix_ms: Option<u64>,
}

impl ReaderFindingSelection {
    /// The settled finding `reference` selects, if any.
    pub(crate) fn select(&self, reference: &str) -> Option<&SelectedFinding> {
        self.findings
            .iter()
            .find(|held| held.references.iter().any(|named| named == reference))
    }
}

/// One answer a step's reads saw, from the first to the last bridge
/// position they saw it at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ObservedAnswer<T> {
    pub(crate) first_at: u64,
    pub(crate) last_at: u64,
    pub(crate) answer: T,
}

/// The fold receipt the card of one whole result carried when the step's
/// guest described it: the result, by its occurrence and handle, and the
/// receipt, `None` when the card carried none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CapturedFoldCard {
    pub(crate) folded: OccurrenceRef,
    pub(crate) receipt: Option<ReaderFoldReceipt>,
}

/// The verdict the door's row check gave one read of another run's result
/// (FIX 6352): the rows it was served from may reach the door's caller,
/// they stay on this device, or the door refused the read with the code it
/// named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RetainedReadVerdict {
    Admitted,
    Withheld,
    Refused(String),
}

impl RetainedReadVerdict {
    /// The verdict a row check's answer gives: `Ok(withheld)`, or the code
    /// of the refusal the door named.
    pub(crate) fn of(answer: std::result::Result<bool, &str>) -> Self {
        match answer {
            Ok(false) => Self::Admitted,
            Ok(true) => Self::Withheld,
            Err(code) => Self::Refused(code.to_owned()),
        }
    }
}

/// One read of another run's result (a delegated source or a settled
/// finding) as the door's row check answered it: the bridge position the
/// read was at, the reference it was made by, whether the check counted the
/// run's callable rows beside its verb rows, and the verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RetainedReadAdmission {
    pub(crate) at: u64,
    pub(crate) reference: JsResultRef,
    pub(crate) callable: bool,
    pub(crate) verdict: RetainedReadVerdict,
}

/// What one step's result reads saw of reader state (FIX 6352), each list
/// in the order the reads saw it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReaderReadCapture {
    /// The reader binding the step's run read under; `None` when the run is
    /// no reader child.
    pub(crate) child: Option<CapturedReaderChild>,
    /// Whether the child's job was live, at each read of its source.
    pub(crate) job_live: Vec<ObservedAnswer<bool>>,
    /// The parent's settled findings, at each lookup of a handle that named
    /// none of the run's own results.
    pub(crate) findings: Vec<ObservedAnswer<ReaderFindingSelection>>,
    /// The fold receipt, or none, the card of each whole result carried.
    pub(crate) fold_cards: Vec<CapturedFoldCard>,
    /// The row check's verdict, at each read of another run's result that
    /// reached it; a read seen again with the same verdict at the same
    /// position is kept once.
    pub(crate) retained_reads: Vec<RetainedReadAdmission>,
}

impl ReaderReadCapture {
    /// A capture of no read yet, for a run that reads under `child`.
    pub(crate) const fn new(child: Option<CapturedReaderChild>) -> Self {
        Self {
            child,
            job_live: Vec::new(),
            findings: Vec::new(),
            fold_cards: Vec::new(),
            retained_reads: Vec::new(),
        }
    }

    /// Keeps the row check's `verdict` on a read of another run's result by
    /// `reference` at bridge position `at`, under the run's callable rows
    /// when `callable`.
    pub(crate) fn observe_retained_read(
        &mut self,
        at: u64,
        reference: &JsResultRef,
        callable: bool,
        verdict: RetainedReadVerdict,
    ) {
        let read = RetainedReadAdmission {
            at,
            reference: reference.clone(),
            callable,
            verdict,
        };
        let kept = self
            .retained_reads
            .iter()
            .rev()
            .take_while(|held| held.at == at)
            .any(|held| *held == read);
        if !kept {
            self.retained_reads.push(read);
        }
    }

    /// Keeps whether the child's job read live at bridge position `at`.
    pub(crate) fn observe_job_live(&mut self, at: u64, live: bool) {
        observe(&mut self.job_live, at, live);
    }

    /// Keeps the parent's settled findings as a lookup at bridge position
    /// `at` read them.
    pub(crate) fn observe_findings(&mut self, at: u64, selection: ReaderFindingSelection) {
        observe(&mut self.findings, at, selection);
    }

    /// Keeps the receipt the card of the whole result `folded` carried, or
    /// that it carried none. A card kept before is not kept again.
    pub(crate) fn keep_fold_card(
        &mut self,
        folded: OccurrenceRef,
        receipt: Option<&ReaderFoldReceipt>,
    ) {
        let card = CapturedFoldCard {
            folded,
            receipt: receipt.cloned(),
        };
        if !self.fold_cards.contains(&card) {
            self.fold_cards.push(card);
        }
    }

    /// Whether every read it keeps is one of step `run`'s: its child binding
    /// is for `run`, and each answer and each row check's verdict was seen
    /// inside the step's window, from `bridge_start` to `bridge_end`, in
    /// order.
    pub(crate) fn held_within(&self, run: EntityId, bridge_start: u64, bridge_end: u64) -> bool {
        self.child.as_ref().is_none_or(|child| child.run == run)
            && seen_in_order(&self.job_live, bridge_start, bridge_end)
            && seen_in_order(&self.findings, bridge_start, bridge_end)
            && self
                .retained_reads
                .iter()
                .try_fold(bridge_start, |from, held| {
                    (from <= held.at && held.at <= bridge_end).then_some(held.at)
                })
                .is_some()
    }

    /// The verdict the row check gave the reads of another run's result by
    /// `reference` at bridge position `cut`, under the run's callable rows
    /// when `callable` (FIX 6352): `None` unless reads at `cut` kept one and
    /// every verdict kept there agrees.
    pub(crate) fn retained_read_at(
        &self,
        reference: &JsResultRef,
        callable: bool,
        cut: u64,
    ) -> Option<&RetainedReadVerdict> {
        let mut verdicts = self
            .retained_reads
            .iter()
            .filter(|held| {
                held.at == cut && held.callable == callable && held.reference == *reference
            })
            .map(|held| &held.verdict);
        let first = verdicts.next()?;
        verdicts.all(|verdict| verdict == first).then_some(first)
    }

    /// Whether the child's job was live at bridge position `cut`: `None`
    /// when the reads kept establish neither.
    pub(crate) fn job_live_at(&self, cut: u64) -> Option<bool> {
        let seen = self
            .job_live
            .iter()
            .map(|seen| (seen.first_at, seen.last_at, seen.answer));
        established_at(seen, cut, |live| !*live)
    }

    /// The settled finding `reference` selected at bridge position `cut`:
    /// `Some(None)` when it selected none, `None` when the lookups kept
    /// establish neither.
    pub(crate) fn finding_at(&self, reference: &str, cut: u64) -> Option<Option<&SelectedFinding>> {
        let seen = self
            .findings
            .iter()
            .map(|seen| (seen.first_at, seen.last_at, seen.answer.select(reference)));
        established_at(seen, cut, Option::is_some)
    }
}

/// Whether each answer in `seen` was seen from `bridge_start` to
/// `bridge_end`, its first position not before its last, and none before the
/// answer ahead of it.
fn seen_in_order<T>(seen: &[ObservedAnswer<T>], bridge_start: u64, bridge_end: u64) -> bool {
    let mut from = bridge_start;
    seen.iter().all(|seen| {
        let fits =
            from <= seen.first_at && seen.first_at <= seen.last_at && seen.last_at <= bridge_end;
        from = seen.last_at;
        fits
    })
}

/// Keeps `answer`, seen at `at`, after the answers `observed` holds: the
/// last answer seen again extends to `at`, and any other is a new one.
fn observe<T: PartialEq>(observed: &mut Vec<ObservedAnswer<T>>, at: u64, answer: T) {
    match observed.last_mut() {
        Some(last) if last.answer == answer => last.last_at = at,
        _ => observed.push(ObservedAnswer {
            first_at: at,
            last_at: at,
            answer,
        }),
    }
}

/// The answer the reads `seen` establish at bridge position `cut`, each
/// answer with the first and last position it was seen at, where `settled`
/// says an answer is final once seen: a final answer seen before the cut, an
/// answer that is not final seen after it, else the one answer every read at
/// the cut saw. `None` when they establish none.
fn established_at<T: Copy + PartialEq>(
    seen: impl Iterator<Item = (u64, u64, T)>,
    cut: u64,
    settled: impl Fn(&T) -> bool,
) -> Option<T> {
    let mut at_cut = None;
    let mut agree = true;
    for (first, last, answer) in seen {
        if (settled(&answer) && first < cut) || (!settled(&answer) && last > cut) {
            return Some(answer);
        }
        if first <= cut && cut <= last {
            agree &= at_cut.is_none_or(|held| held == answer);
            at_cut = Some(answer);
        }
    }
    at_cut.filter(|_| agree)
}
