//! A solved run's span as evidence keeps it (CUA E8a; DESIGN-2 "The
//! Coach"): the checks the caller names are read on the open page now,
//! under the seat the call holds, and the span of the session's history
//! that reached the page is drafted through the one draft `library.draft`
//! takes, never past a press ([`SOLVED_PAST_PRESS`]). The copy it gives is
//! the durable draft: no secret slot's argument and no handle's text.
//!
//! A span is solved only when the caller named a check, every check met on
//! the page now, the span holds steps, and none of them is a press: a press
//! in it means the page the checks read is the one the press left, not the
//! one before it. What kept a span from being solved is named
//! ([`SolvedSnapshotGap`]); it is never taken for solved.

use super::BrowserSession;
use super::trail::Event;
use crate::library::durable_draft;
use crate::{
    BrowserDriver, BrowserError, DraftGapKind, DraftInput, DraftOutput, ExpectInput, SecretParam,
};

/// Whether a solved run's draft goes past a press (CUA E8a, CALLS row):
/// never. A caller's own `library.draft` keeps its explicit `past_press`.
pub const SOLVED_PAST_PRESS: bool = false;

/// What kept a span from being solved (CUA E8a).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SolvedSnapshotGap {
    /// The call named no check, so nothing shows the page solved.
    NoChecks,
    /// The check at index `check` did not meet on the page.
    CheckUnmet { check: usize },
    /// The check at index `check` could not be read on the page.
    CheckUnread { check: usize, error: String },
    /// The span holds no steps.
    EmptySpan,
    /// A press-class step falls in the span: its class, or none for a
    /// control no class names.
    PressInSpan { effect_class: Option<String> },
    /// The span's site or origin is unknown.
    NoSite,
}

/// A span of the session's history whose checks were read on the page
/// that span reached (CUA E8a).
#[derive(Clone, Debug)]
pub struct CapturedSolvedSpan {
    /// The span drafted, as evidence keeps it: no secret slot's argument
    /// and no handle's text.
    pub draft: DraftOutput,
    /// Each secret slot the draft names, by name and kind.
    pub secret_slots: Vec<SecretParam>,
    /// The checks as a program keeps them (the draft's postcondition).
    pub checks: Vec<ExpectInput>,
    /// Whether the draft replays as it is: complete, every parameter bound.
    pub replay_ready: bool,
    /// Why the span is not solved; none when it is.
    pub gap: Option<SolvedSnapshotGap>,
}

impl CapturedSolvedSpan {
    /// Whether every check met on the page the span reached, with no press
    /// in the span.
    #[must_use]
    pub fn solved(&self) -> bool {
        self.gap.is_none()
    }
}

impl BrowserSession {
    /// The latest entry of the session's history, by its `seq`: a span
    /// that starts after it holds only what comes later.
    #[must_use]
    pub fn history_mark(&self) -> Option<u64> {
        self.trail.last().map(|event| match event {
            Event::Effect(receipt) => receipt.seq,
            Event::Stop(marker) => marker.seq,
        })
    }

    /// The end a solved capture whose span starts after `after_seq`
    /// takes at the last granted press (FIX 10511): the history seq that
    /// press began after, so the span ends before it. None where no
    /// press was granted in this span, or its mark is the span's own
    /// start.
    #[must_use]
    pub fn pre_press_through(&self, after_seq: Option<u64>) -> Option<u64> {
        self.pre_press
            .filter(|through| *through > after_seq.unwrap_or(0))
    }

    /// Reads `input`'s checks on the open page and drafts the span of the
    /// history that reached it, as solved-run evidence keeps it (CUA E8a).
    /// The draft never goes past a press ([`SOLVED_PAST_PRESS`]).
    ///
    /// # Errors
    ///
    /// No live page, or a span bound that names no entry of the history.
    pub fn snapshot_solved_run(
        &mut self,
        mut input: DraftInput,
    ) -> Result<CapturedSolvedSpan, BrowserError> {
        input.past_press = SOLVED_PAST_PRESS;
        let mut gap = input
            .postcondition
            .is_empty()
            .then_some(SolvedSnapshotGap::NoChecks);
        for (check, expect) in input.postcondition.iter().enumerate() {
            let unmet = match self.live()?.expect(expect.clone()) {
                Ok(read) if read.met => None,
                Ok(_) => Some(SolvedSnapshotGap::CheckUnmet { check }),
                Err(error) => Some(SolvedSnapshotGap::CheckUnread {
                    check,
                    error: error.to_string(),
                }),
            };
            gap = gap.or(unmet);
        }
        let url = self.live()?.url()?;
        let steps = self.draft_steps();
        let (draft, secret) = self.draft_over_with_secrets(input, &steps, url)?;
        let gap = gap.or_else(|| span_gap(&draft));
        let durable = durable_draft(draft, secret);
        Ok(CapturedSolvedSpan {
            checks: durable.draft.proposal.postcondition.clone(),
            draft: durable.draft,
            secret_slots: durable.secret_slots,
            replay_ready: durable.replay_ready,
            gap,
        })
    }
}

/// What keeps `draft`'s span from being a solved one (CUA E8a, CALLS row
/// `solved_gap`): no steps, a press in it, or no site or origin.
fn span_gap(draft: &DraftOutput) -> Option<SolvedSnapshotGap> {
    if draft.after_seq == draft.through_seq {
        return Some(SolvedSnapshotGap::EmptySpan);
    }
    for gap in &draft.gaps {
        match &gap.gap {
            DraftGapKind::PrePress { effect_class } => {
                return Some(SolvedSnapshotGap::PressInSpan {
                    effect_class: Some(effect_class.clone()),
                });
            }
            DraftGapKind::UnknownPress => {
                return Some(SolvedSnapshotGap::PressInSpan { effect_class: None });
            }
            _ => {}
        }
    }
    if draft.site.is_none() || draft.origin.is_none() {
        return Some(SolvedSnapshotGap::NoSite);
    }
    None
}
