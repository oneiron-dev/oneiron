//! The engine's single bound settlement ask and shared page splitting.
//!
//! `oneiron_dreamer::conflict_settle` owns the rule loop over whole asks,
//! pages and rounds. The engine builds each ask and runs it for bound
//! `ai.verdict`, with model rungs reading call-local labels. The shared
//! splitter also serves extraction, identity and merge decisions. Every
//! row rides whole; a singleton wider than the state bound is measured at
//! `limits.maintenance_text_bytes`, never cut.

use super::decision_projection::SettleAsk;
use super::{ConflictSettleDecisions, DISMISS, HOLD_BOTH, KEEP_PREFIX};
use crate::dreamer_consolidation::call_labels::{CallLabelMap, LabelKind, LabelledRungs};
use crate::error::Result;
use crate::limit_ask::EngineLimit;
use crate::llm::decision::TypedDecision;
use crate::model_decision::{MAX_DECISION_STATE_BYTES, Reversibility};
use crate::{EntityId, Vault};

/// `value`'s serialized length.
pub(in crate::dreamer_consolidation) fn json_len(value: &serde_json::Value) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len())
}

/// Measures a decision state at `limits.maintenance_text_bytes` before it
/// goes whole: past the row it asks, and the state is never cut.
pub(in crate::dreamer_consolidation) fn measure_state(vault: &Vault, state: &serde_json::Value) {
    let _ = vault.measure_limit(EngineLimit::MaintenanceTextBytes, json_len(state) as u64);
}

/// `entries` in pages, in their own order. A page takes the next entry while
/// the bytes it `adds` beside what the page holds keep the page within the
/// ladder's state bound beside `frame`, and `admits` lets it in; an entry no
/// page holds beside others opens a page of its own. It splits, never caps:
/// every entry lands on exactly one page, and no entries is one empty page.
pub(in crate::dreamer_consolidation) fn split_pages<T: Copy>(
    frame: usize,
    entries: &[T],
    adds: impl Fn(&[T], T) -> usize,
    admits: impl Fn(&[T], T) -> bool,
) -> Vec<Vec<T>> {
    let mut pages = Vec::new();
    let mut page: Vec<T> = Vec::new();
    let mut bytes = frame;
    for &entry in entries {
        let mut added = adds(&page, entry);
        if !page.is_empty()
            && (bytes.saturating_add(added) > MAX_DECISION_STATE_BYTES || !admits(&page, entry))
        {
            pages.push(std::mem::take(&mut page));
            bytes = frame;
            added = adds(&page, entry);
        }
        page.push(entry);
        bytes = bytes.saturating_add(added);
    }
    if !page.is_empty() || pages.is_empty() {
        pages.push(page);
    }
    pages
}

/// What one page of a settlement answered, short of leaving it parked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PageAnswer {
    Keep(EntityId),
    HoldBoth,
    Dismiss,
}

impl PageAnswer {
    /// The answer as a call shows it: a Keep by the member's label there, or
    /// `keep` when the call does not show that member.
    pub(super) fn shown(self, labels: &CallLabelMap) -> String {
        match self {
            Self::Keep(id) => labels.label(LabelKind::Claim, id).map_or_else(
                || "keep".to_owned(),
                |label| format!("{KEEP_PREFIX}{label}"),
            ),
            Self::HoldBoth => HOLD_BOTH.to_owned(),
            Self::Dismiss => DISMISS.to_owned(),
        }
    }
}

/// Runs one settlement ask with each model rung reading call-local labels.
/// The question, answer and receipt stay canonical (FIX 7506). The state is
/// measured whole before the call. The ladder uses the ask's principal,
/// dial, bands and deadline with outbound-effect reversibility over the
/// conflict's evidence.
pub(crate) fn run_ask(
    decisions: &ConflictSettleDecisions<'_>,
    vault: &Vault,
    ask: &SettleAsk,
    evidence: &[EntityId],
) -> Result<TypedDecision> {
    measure_state(vault, &ask.state);
    let rungs = LabelledRungs::of(&decisions.ladder, &ask.labels);
    let ladder = rungs.ladder(&decisions.ladder);
    ladder.run(
        &ask.question,
        decisions.principal,
        evidence,
        &ask.state,
        decisions.dial,
        &decisions.bands,
        Reversibility::OutboundEffect,
        decisions.deadline,
    )
}
