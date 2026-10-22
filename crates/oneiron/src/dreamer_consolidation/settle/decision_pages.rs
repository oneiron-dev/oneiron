//! A parked conflict's settlement in pages (Rule 5, FIX 7636, FIX 7637).
//! Every keepable member and retained alternative is offered, and every
//! value rides whole: nothing is dropped or cut for room. A conflict whose
//! whole ask fits the ladder's state bound with at most
//! [`MAX_KEEP_OPTIONS`] keep options is asked once, as before. Any other is
//! split into pages in its own order, each one ask of its own, and the
//! pages' answers aggregate to one outcome:
//!
//! - a page that escalates, abstains or answers outside its options leaves
//!   the conflict parked, as one escalating ask does;
//! - every page holding both is hold both, every page dismissing is dismiss;
//! - otherwise one final ask chooses among hold both, dismiss, escalate and
//!   a Keep of each member a page kept, those members whole and each page's
//!   answer beside them, and its answer is the outcome. Past
//!   [`MAX_KEEP_OPTIONS`] kept members that round pages again, by count.
//!
//! The split itself is shared: a Dreamer decision pack whose state does not
//! fit one call pages its rows the same way (`executor`). A page wider than
//! the bound (one row wider than a page) is measured at
//! `limits.maintenance_text_bytes` and goes whole.

use super::decision_projection::{AskPart, SettleAsk, SettleRow, settle_rows, state_bytes};
use super::{
    ConflictSettleDecisions, ConflictSettlement, DISMISS, HOLD_BOTH, KEEP_PREFIX, MAX_KEEP_OPTIONS,
    OpenConflict,
};
use crate::dreamer_consolidation::call_labels::{CallLabelMap, LabelKind, LabelledRungs};
use crate::error::Result;
use crate::limit_ask::EngineLimit;
use crate::llm::decision::{DecisionAnswer, MAX_DECISION_STATE_BYTES, Reversibility};
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
pub(super) enum PageAnswer {
    Keep(EntityId),
    HoldBoth,
    Dismiss,
}

impl PageAnswer {
    fn of(settlement: ConflictSettlement) -> Self {
        match settlement {
            ConflictSettlement::Keep(id) | ConflictSettlement::ApproveAndKeep(id) => Self::Keep(id),
            ConflictSettlement::HoldBoth => Self::HoldBoth,
            ConflictSettlement::Dismiss => Self::Dismiss,
        }
    }

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

/// How many of `rows` a Keep may name.
fn keeps(rows: &[&SettleRow]) -> usize {
    rows.iter().filter(|row| row.keep).count()
}

/// Whether a page holding `page` takes `row` beside it: past
/// [`MAX_KEEP_OPTIONS`] keep options a keepable row opens the next page.
fn admits(page: &[&SettleRow], row: &SettleRow) -> bool {
    !row.keep || keeps(page) < MAX_KEEP_OPTIONS
}

/// Rules on `conflict` through `decisions`, in pages when one ask does not
/// hold it (the module's rule): `None` when it stays parked.
pub(super) fn rule(
    decisions: &ConflictSettleDecisions<'_>,
    vault: &Vault,
    conflict: &OpenConflict,
) -> Result<Option<ConflictSettlement>> {
    let rows = settle_rows(vault, conflict)?;
    let mut evidence = vec![conflict.marker];
    evidence.extend(conflict.members.iter().copied());
    let mut asked: Vec<&SettleRow> = rows.iter().collect();
    let mut before: Vec<PageAnswer> = Vec::new();
    let mut round = 0;
    loop {
        let whole = AskPart {
            at: None,
            before: &[],
        };
        let pages = if round > 0 {
            split_pages(0, &asked, |_, _| 0, admits)
        } else if keeps(&asked) <= MAX_KEEP_OPTIONS
            && state_bytes(conflict, &asked, &whole) <= MAX_DECISION_STATE_BYTES
        {
            vec![std::mem::take(&mut asked)]
        } else {
            let paged = AskPart {
                at: Some((0, 0, 2)),
                before: &[],
            };
            let frame = state_bytes(conflict, &[], &paged);
            split_pages(
                frame,
                &asked,
                |_, row| row.bytes().saturating_add(1),
                admits,
            )
        };
        let paged = pages.len() > 1 || round > 0;
        let mut answers = Vec::with_capacity(pages.len());
        for (page, page_rows) in pages.iter().enumerate() {
            let part = AskPart {
                at: paged.then_some((round, page, pages.len())),
                before: &before,
            };
            let ask = SettleAsk::over(conflict, &decisions.wording, page_rows, &part)?;
            let Some(settlement) = run(decisions, vault, &ask, &evidence)? else {
                return Ok(None);
            };
            if pages.len() == 1 {
                return Ok(Some(settlement));
            }
            answers.push(PageAnswer::of(settlement));
        }
        if answers.iter().all(|answer| *answer == PageAnswer::HoldBoth) {
            return Ok(Some(ConflictSettlement::HoldBoth));
        }
        if answers.iter().all(|answer| *answer == PageAnswer::Dismiss) {
            return Ok(Some(ConflictSettlement::Dismiss));
        }
        asked = answers
            .iter()
            .filter_map(|answer| match answer {
                PageAnswer::Keep(id) => rows.iter().find(|row| row.id == *id),
                PageAnswer::HoldBoth | PageAnswer::Dismiss => None,
            })
            .collect();
        before = answers;
        round += 1;
    }
}

/// One settlement ask through the ladder, each model rung reading the ask's
/// own labels; the question, its answer and the settlement stay canonical
/// (FIX 7506). Keeping one closes the others, so a cut abstains rather than
/// taking a held answer.
fn run(
    decisions: &ConflictSettleDecisions<'_>,
    vault: &Vault,
    ask: &SettleAsk,
    evidence: &[EntityId],
) -> Result<Option<ConflictSettlement>> {
    measure_state(vault, &ask.state);
    let rungs = LabelledRungs::of(&decisions.ladder, &ask.labels);
    let ladder = rungs.ladder(&decisions.ladder);
    let decision = ladder.run(
        &ask.question,
        decisions.principal,
        evidence,
        &ask.state,
        decisions.dial,
        &decisions.bands,
        Reversibility::OutboundEffect,
        decisions.deadline,
    )?;
    let DecisionAnswer::Choice(answer) = &decision.answer else {
        return Ok(None);
    };
    Ok(ask.settlement(answer))
}
