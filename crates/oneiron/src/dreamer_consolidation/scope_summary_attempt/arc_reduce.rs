//! The Arc assembled from its parts (FIX 7509 PR3): no model call, an
//! ordered and lossless assembly. Once every part is done, each part's
//! checked lines follow in source order, each with its own TURN refs and
//! slices; the ranges are counted again over the text so joined, and every
//! distinct keep is kept, in order.
//!
//! The rows hold no prose. A part's words are read back from its settled
//! steps, through the Dreamer's own lane, and must be the reply the part
//! checked: the model and purpose it was asked of, its reply's digest, and
//! each line's digest. A step that does not read so stops the assembly.

use super::super::residency::{residency_deferral, waits_on_residency};
use super::arc_children::ArcRun;
use super::arc_output::{ArcLines, arc_wire};
use super::arc_review::{Observation, store_exit};
use super::output::reply_text;
use super::{ScopeSummaryExecutor, compose_again};
use crate::attempt_queue::AttemptId;
use crate::dreamer_consolidation::support::invalid_consolidation;
use crate::dreamer_runner::DreamerParkCause;
use crate::dreamer_wake::{DreamerAttemptExecution, WakeAttemptContext};
use crate::error::{Error, Result};
use crate::llm::{CallerSettledStep, settled_step_for_caller};
use crate::memory::Memory;
use crate::scope_summary::{
    ArcChildRow, ArcReduceRow, ArcStepRef, ComposedSummary, SummaryLineSources, result_digest,
};
use std::collections::{BTreeMap, BTreeSet};

/// The purpose every summary call is asked under, as a step records it.
const SUMMARY_STEP_PURPOSE: &str = "extraction";

/// A checked step's words as read back: each line's, and its keep.
struct Materialised {
    texts: Vec<String>,
    keep: String,
}

/// What assembling the parts came to.
pub(super) enum Assembly {
    Lines(ArcLines),
    /// A part's step did not read back as checked.
    Unread,
    /// No part wrote a line.
    Empty,
}

/// `step`'s words, read on `memory`'s lane; `None` when it does not read
/// back as the step the part checked.
fn materialise(memory: &Memory<'_>, step: &ArcStepRef) -> Result<Option<Materialised>> {
    let attempt = AttemptId::from_bytes(&step.attempt)?;
    let settled = settled_step_for_caller(memory, attempt, step.step)
        .map_err(|_| invalid_consolidation("an arc part's step did not read"))?;
    let Some(CallerSettledStep::Readable(view)) = settled else {
        return Ok(None);
    };
    if view.model.as_str() != step.model
        || view.purpose != SUMMARY_STEP_PURPOSE
        || blake3::hash(reply_text(&view.response).as_bytes()).as_bytes() != &step.reply
    {
        return Ok(None);
    }
    let Ok(wire) = arc_wire(&view.response) else {
        return Ok(None);
    };
    if wire.lines.len() != step.lines.len() {
        return Ok(None);
    }
    let mut texts = Vec::with_capacity(step.lines.len());
    for (line, held) in wire.lines.iter().zip(&step.lines) {
        let words = line.text.trim();
        if blake3::hash(words.as_bytes()).as_bytes() != &held.text {
            return Ok(None);
        }
        texts.push(words.to_owned());
    }
    Ok(Some(Materialised {
        texts,
        keep: wire.keep,
    }))
}

/// Every observation `reviewed` wrote, in cell order; `None` when a review
/// does not read back.
pub(super) fn observations(
    memory: &Memory<'_>,
    reviewed: &[ArcStepRef],
) -> Result<Option<Vec<Observation>>> {
    let mut observations = Vec::new();
    for step in reviewed {
        let Some(read) = materialise(memory, step)? else {
            return Ok(None);
        };
        for (text, line) in read.texts.into_iter().zip(&step.lines) {
            observations.push(Observation {
                text,
                turn_refs: line.turn_refs.clone(),
            });
        }
    }
    Ok(Some(observations))
}

/// The Arc `steps` (every part's checked lines, in source order) assemble
/// to.
pub(super) fn assemble(memory: &Memory<'_>, steps: &[&ArcStepRef]) -> Result<Assembly> {
    let mut text = String::new();
    let mut scalars = 0_usize;
    let mut line_sources = Vec::new();
    let mut keeps = Vec::new();
    let mut kept = BTreeSet::new();
    for step in steps {
        let Some(read) = materialise(memory, step)? else {
            return Ok(Assembly::Unread);
        };
        for (words, line) in read.texts.iter().zip(&step.lines) {
            if !text.is_empty() {
                text.push('\n');
                scalars += 1;
            }
            let output_start = scalars;
            text.push_str(words);
            scalars += words.chars().count();
            line_sources.push(SummaryLineSources {
                output_start,
                output_end: scalars,
                turn_refs: line.turn_refs.clone(),
                source_spans: line.source_spans.clone(),
            });
        }
        if !read.keep.trim().is_empty() && kept.insert(read.keep.clone()) {
            keeps.push(read.keep);
        }
    }
    if text.is_empty() {
        return Ok(Assembly::Empty);
    }
    Ok(Assembly::Lines(ArcLines {
        text,
        keep: keeps.join("\n"),
        line_sources,
    }))
}

impl<E> ScopeSummaryExecutor<'_, E> {
    /// Assembles every part's lines and lands the Arc through the landing
    /// fence, its generation's completion proven there.
    pub(super) fn land_arc_work(
        &self,
        ctx: &WakeAttemptContext<'_>,
        attempt_id: AttemptId,
        run: ArcRun<'_>,
        rows: &BTreeMap<u32, ArcChildRow>,
        (params_hash, memo): ([u8; 32], [u8; 32]),
    ) -> Result<DreamerAttemptExecution> {
        if ctx.deadline.expired() {
            return Ok(run.charges.checkpoint());
        }
        let mut steps = Vec::new();
        for child in &run.manifest.children {
            let Some(row) = rows.get(&child.id) else {
                return Err(invalid_consolidation("an arc's part has no record"));
            };
            steps.extend(row.composed.iter());
        }
        let memory = ctx
            .vault
            .memory(self.actor.entity_ref(), self.actor.actor_class());
        let lines = match assemble(&memory, &steps) {
            Ok(Assembly::Lines(lines)) => lines,
            Ok(Assembly::Unread) => {
                return Ok(run
                    .charges
                    .park_for("an arc part's step did not read", DreamerParkCause::Retry));
            }
            Ok(Assembly::Empty) => {
                return Ok(run
                    .charges
                    .park_for("the model wrote an empty arc", DreamerParkCause::Retry));
            }
            Err(error) => return Ok(run.charges.park_on_error(&error)),
        };
        let reduce = ArcReduceRow {
            digest: result_digest(&lines.text, &lines.keep, &lines.line_sources),
            lines: lines.line_sources.len() as u64,
        };
        if let Err(error) = ctx
            .vault
            .save_arc_work(&run.work, None, &[], None, Some(&reduce))
        {
            return Ok(store_exit(&error, &run.charges, ctx.now_ms));
        }
        let composed = ComposedSummary {
            text: &lines.text,
            keep: &lines.keep,
            params_hash,
            instruction: run.instruction,
            model: self.model.as_str(),
            covers: run.evidence.covers.clone(),
            messages: run.evidence.messages.clone(),
            memo,
            line_sources: Some(lines.line_sources),
            arc_work: Some(run.work),
        };
        // The landing fence reads every pin again and proves the generation
        // complete before anything is minted.
        match ctx.vault.land_composed_scope_summary(
            attempt_id,
            run.plan,
            run.evidence,
            &composed,
            self.actor,
        ) {
            Ok(_) => Ok(DreamerAttemptExecution::Completed {
                completed_units: run.charges.units,
            }),
            Err(Error::ConcurrentWrite(_)) => Ok(compose_again(&run.charges, ctx.now_ms)),
            Err(error) if waits_on_residency(&error) => {
                Ok(residency_deferral(ctx.now_ms, run.charges.units))
            }
            Err(error) => Ok(run
                .charges
                .park(&format!("summary landing refused: {error}"))),
        }
    }
}
