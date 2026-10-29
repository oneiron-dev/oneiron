//! The calls of an Arc composed in parts (FIX 7509 PR3): one input shape
//! for all of them, so one frame counts for each, and what each call shows
//! by label.
//!
//! A part with room for every claim beside its lines is one `compose` call
//! over its lines, the TURNs read in their place, every claim and the words
//! of each TURN it opened. Otherwise each review cell (a range of claims or
//! of opened words) is one `review` call beside the part's lines: its lines
//! are observations, each citing the TURNs it came from, and no cell is
//! skipped. The part then composes over its lines and every observation,
//! in `compose` calls over an exhaustive partition of them. Every call
//! keeps the editor text null: no part is written from an earlier Arc.
//!
//! A TURN a call shows only by a sitting's line, or an observation, is cited
//! as that line or observation came from it (FIX 8289): whole, or by the
//! slices it recorded, which a reply's line citing the TURN inherits.

use super::super::call_labels::LabelKind;
use super::super::residency::{residency_deferral, waits_on_residency};
use super::super::step_charge::StepChargeTally;
use super::super::support::invalid_consolidation;
use super::arc_children::ArcRun;
use super::arc_chunks::{MemberText, member};
use super::arc_evidence::ArcView;
use super::arc_output::{
    ArcCitation, ArcCitationContext, ChildReply, Inherited, child_output, inherit,
};
use super::output::reply_text;
use super::window::framed_tokens;
use super::{ScopeSummaryExecutor, compose_again};
use crate::EntityId;
use crate::dreamer_runner::DreamerParkCause;
use crate::dreamer_wake::{DreamerAttemptExecution, WakeAttemptContext};
use crate::error::{Error, Result};
use crate::llm::{
    DurableStepContext, DurableStepError, LlmResponse, StepOutcome, call_as_step_checked,
};
use crate::scope_summary::{
    ArcLineRef, ArcRange, ArcStepRef, MemberKind, ScopeSummaryPlan, SummaryLineSpan,
};
use std::collections::{BTreeMap, BTreeSet};

/// A call writing a part's lines.
pub(super) const KIND_COMPOSE: &str = "compose";
/// A call reviewing a part's lines against one cell.
pub(super) const KIND_REVIEW: &str = "review";

/// Where a call sits: its kind, its part of the Arc's parts, and its cell
/// or compose part of that part's, each 1-based.
pub(super) struct CallShape {
    pub(super) kind: &'static str,
    pub(super) child: u64,
    pub(super) children: u64,
    pub(super) part: u64,
    pub(super) parts: u64,
}

/// What one call shows, by input field.
#[derive(Default)]
pub(super) struct CallFields {
    lines: String,
    turns: String,
    claims: String,
    opened: String,
    observations: String,
}

/// The input one call reads: the declaration's purpose and `keep`, no
/// editor text, where the call sits, and what it shows.
pub(super) fn call_input(
    plan: &ScopeSummaryPlan,
    shape: &CallShape,
    fields: &CallFields,
) -> Result<String> {
    serde_json::to_string(&serde_json::json!({
        "purpose": plan.purpose,
        "keep": plan.keep,
        "editor_text": null,
        "call": {
            "kind": shape.kind,
            "child": shape.child,
            "children": shape.children,
            "part": shape.part,
            "parts": shape.parts,
        },
        "lines": fields.lines,
        "turns": fields.turns,
        "claims": fields.claims,
        "opened": fields.opened,
        "observations": fields.observations,
    }))
    .map_err(|_| invalid_consolidation("summary input encoding"))
}

/// The tokens every call's frame costs at most: its instruction, its
/// output contract and its input with nothing shown, at the widest numbers
/// and kind it can carry.
pub(super) fn frame_tokens(
    plan: &ScopeSummaryPlan,
    instruction: &str,
    schema: &serde_json::Value,
) -> Result<u64> {
    let mut frame = 0;
    for kind in [KIND_COMPOSE, KIND_REVIEW] {
        let shape = CallShape {
            kind,
            child: u64::MAX,
            children: u64::MAX,
            part: u64::MAX,
            parts: u64::MAX,
        };
        let user = call_input(plan, &shape, &CallFields::default())?;
        frame = frame.max(framed_tokens(instruction, &user, schema)?);
    }
    Ok(frame)
}

/// One observation a review wrote: its words, the TURNs it cites and the
/// slices of those it cites in part (FIX 8289).
pub(super) struct Observation {
    pub(super) text: String,
    pub(super) turn_refs: Vec<String>,
    pub(super) source_spans: Vec<SummaryLineSpan>,
}

/// How a call shows `observation`: a line with its `T` refs.
pub(super) fn show_observation(view: &ArcView, observation: &Observation) -> Result<String> {
    let mut refs = Vec::with_capacity(observation.turn_refs.len());
    for turn in &observation.turn_refs {
        let label = view
            .labels
            .label(LabelKind::Turn, EntityId::from_hex(turn)?)
            .ok_or_else(|| invalid_consolidation("an arc's turn has no label"))?;
        refs.push(label.to_string());
    }
    Ok(format!("- {} [{}]\n", observation.text, refs.join(", ")))
}

/// One call's showing, as it is built.
pub(super) struct CallBuilder<'m> {
    members: &'m [MemberText],
    view: &'m ArcView,
    fields: CallFields,
    /// The ranges of each TURN member the call shows the words of.
    shown: BTreeMap<u32, Vec<(u64, u64)>>,
    /// Each TURN the call shows by a line's or an observation's refs, as
    /// those cite it (FIX 8289).
    cited: BTreeMap<EntityId, Inherited>,
}

impl<'m> CallBuilder<'m> {
    pub(super) fn new(members: &'m [MemberText], view: &'m ArcView) -> Self {
        Self {
            members,
            view,
            fields: CallFields::default(),
            shown: BTreeMap::new(),
            cited: BTreeMap::new(),
        }
    }
}

impl CallBuilder<'_> {
    /// Shows the part's own `ranges`: its lines, and the TURNs read in their
    /// place.
    pub(super) fn group(&mut self, ranges: &[ArcRange]) -> Result<()> {
        for range in ranges {
            let member = member(self.members, range.member)?;
            let shown = member.render(range.start, range.end)?;
            match member.member.kind {
                MemberKind::Line { .. } => {
                    self.fields.lines.push_str(&shown);
                    for turn in &member.turns {
                        inherit(&mut self.cited, *turn, &member.spans);
                    }
                }
                MemberKind::Fallback { .. } => {
                    self.fields.turns.push_str(&shown);
                    self.words(range);
                }
                _ => return Err(invalid_consolidation("an arc's part owns no such member")),
            }
        }
        Ok(())
    }

    /// Shows `ranges` of claims and opened TURNs.
    pub(super) fn context(&mut self, ranges: &[ArcRange]) -> Result<()> {
        for range in ranges {
            let member = member(self.members, range.member)?;
            let shown = member.render(range.start, range.end)?;
            match member.member.kind {
                MemberKind::Claim { .. } => self.fields.claims.push_str(&shown),
                MemberKind::Fallback { .. } | MemberKind::Opened { .. } => {
                    self.fields.opened.push_str(&shown);
                    self.words(range);
                }
                _ => return Err(invalid_consolidation("an arc's cell reads no such member")),
            }
        }
        Ok(())
    }

    /// Shows each of `ids` whole, in order.
    pub(super) fn whole(&mut self, ids: &[u32]) -> Result<()> {
        let mut ranges = Vec::with_capacity(ids.len());
        for id in ids {
            ranges.push(ArcRange {
                member: *id,
                start: 0,
                end: member(self.members, *id)?.member.len,
            });
        }
        self.context(&ranges)
    }

    /// Shows `observations`, each a line with its refs.
    pub(super) fn observations(&mut self, observations: &[&Observation]) -> Result<()> {
        for observation in observations {
            self.fields
                .observations
                .push_str(&show_observation(self.view, observation)?);
            for turn in &observation.turn_refs {
                inherit(
                    &mut self.cited,
                    EntityId::from_hex(turn)?,
                    &observation.source_spans,
                );
            }
        }
        Ok(())
    }

    fn words(&mut self, range: &ArcRange) {
        self.shown
            .entry(range.member)
            .or_default()
            .push((range.start, range.end));
    }

    /// What the call shows: its fields, what its labels may name, and the
    /// TURNs whose every word it shows. A TURN cited whole, or shown whole,
    /// is cited whole; one shown or cited in part, by every slice so shown.
    pub(super) fn finish(self) -> Result<(CallFields, ArcCitationContext, BTreeSet<EntityId>)> {
        let mut cited = self.cited;
        let mut whole = BTreeSet::new();
        for (index, mut ranges) in self.shown {
            let member = member(self.members, index)?;
            let [turn] = member.turns.as_slice() else {
                return Err(invalid_consolidation("an arc's turn member names no turn"));
            };
            ranges.sort_unstable();
            if covers(&ranges, member.member.len) {
                cited.insert(*turn, None);
                whole.insert(*turn);
                continue;
            }
            let held = cited.entry(*turn).or_insert_with(|| Some(Vec::new()));
            let Some(held) = held else {
                continue;
            };
            for (start, end) in ranges {
                for span in spans(self.view, *turn, start, end) {
                    if !held.contains(&span) {
                        held.push(span);
                    }
                }
            }
        }
        let context = ArcCitationContext {
            labels: self.view.labels.clone(),
            shown: cited
                .into_iter()
                .map(|(turn, held)| {
                    let source_spans = held.unwrap_or_default();
                    (turn, ArcCitation { source_spans })
                })
                .collect(),
        };
        Ok((self.fields, context, whole))
    }
}

/// Whether sorted `ranges` cover `0..len` with no gap.
fn covers(ranges: &[(u64, u64)], len: u64) -> bool {
    let mut at = 0;
    for (start, end) in ranges {
        if *start > at {
            return false;
        }
        at = at.max(*end);
    }
    at >= len
}

/// The exact slices bytes `start..end` of `turn`'s words hold: MESSAGE-local,
/// or TURN-local for inline text. None when they hold no MESSAGE's words.
fn spans(view: &ArcView, turn: EntityId, start: u64, end: u64) -> Vec<SummaryLineSpan> {
    let Some(text) = view.texts.get(&turn) else {
        return Vec::new();
    };
    let (start, end) = (start as usize, end as usize);
    if text.projection().is_empty() {
        return vec![SummaryLineSpan {
            turn: turn.to_hex(),
            message: None,
            start,
            end,
        }];
    }
    match text.spans(Some((start, end))) {
        Ok(spans) => spans
            .into_iter()
            .map(|span| SummaryLineSpan {
                turn: turn.to_hex(),
                message: Some(span.message.to_hex()),
                start: span.start,
                end: span.end,
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// One call's checked reply, or the attempt's exit.
pub(super) enum Called {
    Reply(ChildReply, ArcStepRef),
    Exit(DreamerAttemptExecution),
}

impl<E> ScopeSummaryExecutor<'_, E> {
    /// Asks one call of a part, inside its durable step, and reads its reply
    /// through the part contract.
    pub(super) async fn child_call(
        &self,
        run: &mut ArcRun<'_>,
        ctx: &WakeAttemptContext<'_>,
        step_ctx: &DurableStepContext<'_>,
        user: String,
        context: ArcCitationContext,
        opened: BTreeSet<EntityId>,
    ) -> Result<Called> {
        // The pace, the deadline: the rest is kept for the next wake.
        if run.calls >= run.limit || ctx.deadline.expired() {
            return Ok(Called::Exit(run.charges.checkpoint()));
        }
        let mut request = self.summary_request(
            ctx.vault,
            run.evidence,
            run.schema.clone(),
            run.instruction,
            user,
        )?;
        context.labels.bind_request(&mut request, None);
        let model = request.model.as_str().to_owned();
        let step_hash = request
            .canonical_hash()
            .map_err(|_| invalid_consolidation("summary request did not hash"))?;
        let check_context = context.clone();
        let check_opened = opened.clone();
        let check_covers = run.covers.clone();
        let check = move |response: &LlmResponse| {
            child_output(response, &check_context, &check_opened, &check_covers)
                .map(drop)
                .map_err(str::to_owned)
        };
        let outcome =
            call_as_step_checked(step_ctx, self.backend, self.guard, request, &check).await;
        let charges = &mut run.charges;
        let response = match outcome {
            Ok(StepOutcome::Finished {
                response, memoized, ..
            }) => {
                if !memoized {
                    run.calls = run.calls.saturating_add(1);
                }
                if let Err(error) = charges.record_terminal(
                    ctx.vault,
                    step_ctx.attempt_id,
                    step_hash,
                    &response.usage,
                ) {
                    return Ok(Called::Exit(charges.park_on_error(&error)));
                }
                response
            }
            Ok(StepOutcome::Trapped { .. }) => {
                return Ok(Called::Exit(charges.park_for(
                    "durable step trapped for resume",
                    DreamerParkCause::Signal,
                )));
            }
            Err(DurableStepError::SpentFinalizeRefused { usage }) => {
                charges.record_usage(&usage);
                return Ok(Called::Exit(charges.checkpoint()));
            }
            Err(DurableStepError::DeadlineHardCut) => {
                return Ok(Called::Exit(charges.checkpoint()));
            }
            Err(DurableStepError::FinalizeRefused) => {
                return Ok(Called::Exit(charges.park_for(
                    "wake pass finalize window",
                    DreamerParkCause::Checkpoint,
                )));
            }
            Err(DurableStepError::Engine(error)) => {
                return Ok(Called::Exit(charges.park_on_error(&error)));
            }
            Err(other @ DurableStepError::SpentSchemaValidation { .. }) => {
                if let DurableStepError::SpentSchemaValidation { usage, .. } = &other {
                    charges.record_usage(usage);
                }
                return Ok(Called::Exit(
                    charges.park_for(&other.to_string(), DreamerParkCause::Retry),
                ));
            }
            Err(other) => {
                return Ok(Called::Exit(
                    charges.park_for(&other.to_string(), DreamerParkCause::of_step(&other)),
                ));
            }
        };
        let reply = match child_output(&response, &context, &opened, &run.covers) {
            Ok(reply) => reply,
            Err(reason) => {
                return Ok(Called::Exit(
                    run.charges.park_for(reason, DreamerParkCause::Retry),
                ));
            }
        };
        let step = ArcStepRef {
            attempt: *step_ctx.attempt_id.as_bytes(),
            step: step_hash,
            model,
            reply: *blake3::hash(reply_text(&response).as_bytes()).as_bytes(),
            lines: reply
                .lines
                .iter()
                .map(|line| ArcLineRef {
                    text: *blake3::hash(line.text.as_bytes()).as_bytes(),
                    turn_refs: line.turn_refs.clone(),
                    source_spans: line.source_spans.clone(),
                })
                .collect(),
        };
        Ok(Called::Reply(reply, step))
    }
}

/// The attempt's exit when a read or write of the Arc's work does not
/// hold: its sources moved, a source waits on residency, or the error parks.
pub(super) fn store_exit(
    error: &Error,
    charges: &StepChargeTally,
    now_ms: u64,
) -> DreamerAttemptExecution {
    match error {
        Error::ConcurrentWrite(_) => compose_again(charges, now_ms),
        error if waits_on_residency(error) => {
            residency_deferral(now_ms, charges.units, charges.step_hashes.clone())
        }
        error => charges.park_on_error(error),
    }
}
