//! The Arc assembled from its parts (FIX 7509 PR3): no model call, an
//! ordered and lossless assembly; only the optional synopsis
//! ([`super::arc_synopsis`], off by default) asks one more. Once every
//! part is done, each part's checked lines follow in source order, its
//! compose pieces merged first ([`super::arc_part_merge`], FIX 8285), each
//! line with its own TURN refs and slices; the ranges are counted again
//! over the text so joined, and every distinct keep is kept, in order.
//!
//! The rows hold no prose. A part's words are read back from its settled
//! steps, through the Dreamer's own lane, and must be the reply the part
//! checked: the model and purpose it was asked of, its reply's digest, and
//! each line's digest. A step that does not read so is named, part and
//! step (FIX 8288): only that part's step ref and those after it are
//! cleared and the part is composed again, every other part as it stands.

use super::super::residency::{residency_deferral, waits_on_residency};
use super::arc_children::ArcRun;
use super::arc_output::{ArcLines, arc_wire};
use super::arc_part_merge::{PartLine, merge_part};
use super::arc_review::{Observation, store_exit};
use super::arc_synopsis::{ARC_SYNOPSIS, Synopsis};
use super::output::reply_text;
use super::{ScopeSummaryExecutor, compose_again};
use crate::attempt_queue::AttemptId;
use crate::dreamer_consolidation::support::invalid_consolidation;
use crate::dreamer_runner::DreamerParkCause;
use crate::dreamer_wake::{DreamerAttemptExecution, WakeAttemptContext};
use crate::error::{Error, Result};
use crate::llm::{CallerSettledStep, DurableStepContext, settled_step_for_caller};
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
    /// Part `part`'s compose step at `step` did not read back as checked.
    Unread {
        part: u32,
        step: usize,
    },
    /// No part wrote a line.
    Empty,
}

/// What landing an Arc composed in parts came to.
pub(super) enum Landing {
    /// The attempt's exit: landed, owed, parked or deferred.
    Exit(DreamerAttemptExecution),
    /// Part `part`'s compose step at `step` did not read back: it composes
    /// again from that step (FIX 8288).
    Recompose { part: u32, step: usize },
}

/// What reading a part's reviews back came to.
pub(super) enum Observed {
    /// Every observation, in cell order.
    All(Vec<Observation>),
    /// The review at this index did not read back as checked.
    Unread(usize),
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

/// Every observation `reviewed` wrote, in cell order, each with the TURNs
/// and the slices it cites (FIX 8289); or the first review that does not
/// read back.
pub(super) fn observations(memory: &Memory<'_>, reviewed: &[ArcStepRef]) -> Result<Observed> {
    let mut observations = Vec::new();
    for (index, step) in reviewed.iter().enumerate() {
        let Some(read) = materialise(memory, step)? else {
            return Ok(Observed::Unread(index));
        };
        for (text, line) in read.texts.into_iter().zip(&step.lines) {
            observations.push(Observation {
                text,
                turn_refs: line.turn_refs.clone(),
                source_spans: line.source_spans.clone(),
            });
        }
    }
    Ok(Observed::All(observations))
}

/// The Arc `parts` (each part's id and checked compose steps, in source
/// order) assemble to: each part's pieces merged, then its lines.
pub(super) fn assemble(memory: &Memory<'_>, parts: &[(u32, &[ArcStepRef])]) -> Result<Assembly> {
    let mut text = String::new();
    let mut scalars = 0_usize;
    let mut line_sources = Vec::new();
    let mut keeps = Vec::new();
    let mut kept = BTreeSet::new();
    for (part, steps) in parts {
        let mut pieces = Vec::new();
        for (index, step) in steps.iter().enumerate() {
            let Some(read) = materialise(memory, step)? else {
                return Ok(Assembly::Unread {
                    part: *part,
                    step: index,
                });
            };
            for (words, line) in read.texts.into_iter().zip(&step.lines) {
                pieces.push(PartLine {
                    text: words,
                    turn_refs: line.turn_refs.clone(),
                    source_spans: line.source_spans.clone(),
                });
            }
            if !read.keep.trim().is_empty() && kept.insert(read.keep.clone()) {
                keeps.push(read.keep);
            }
        }
        for line in merge_part(pieces) {
            if !text.is_empty() {
                text.push('\n');
                scalars += 1;
            }
            let output_start = scalars;
            text.push_str(&line.text);
            scalars += line.text.chars().count();
            line_sources.push(SummaryLineSources {
                output_start,
                output_end: scalars,
                turn_refs: line.turn_refs,
                source_spans: line.source_spans,
            });
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
    /// Assembles every part's lines, led by their synopsis when it is on,
    /// and lands the Arc through the landing fence, its generation's
    /// completion proven there; or names the part whose step did not read
    /// back, to compose again.
    pub(super) async fn land_arc_work(
        &self,
        ctx: &WakeAttemptContext<'_>,
        step_ctx: &DurableStepContext<'_>,
        attempt_id: AttemptId,
        run: &mut ArcRun<'_>,
        rows: &BTreeMap<u32, ArcChildRow>,
        (params_hash, memo): ([u8; 32], [u8; 32]),
    ) -> Result<Landing> {
        if ctx.deadline.expired() {
            return Ok(Landing::Exit(run.charges.checkpoint()));
        }
        let mut parts = Vec::with_capacity(run.manifest.children.len());
        for child in &run.manifest.children {
            let Some(row) = rows.get(&child.id) else {
                return Err(invalid_consolidation("an arc's part has no record"));
            };
            parts.push((child.id, row.composed.as_slice()));
        }
        let assembled = {
            let memory = ctx
                .vault
                .memory(self.actor.entity_ref(), self.actor.actor_class());
            assemble(&memory, &parts)
        };
        let lines = match assembled {
            Ok(Assembly::Lines(lines)) => lines,
            Ok(Assembly::Unread { part, step }) => return Ok(Landing::Recompose { part, step }),
            Ok(Assembly::Empty) => {
                return Ok(Landing::Exit(run.charges.park_for(
                    "the model wrote an empty arc",
                    DreamerParkCause::Retry,
                )));
            }
            Err(error) => return Ok(Landing::Exit(run.charges.park_on_error(&error))),
        };
        let lines = if ARC_SYNOPSIS {
            match self.lead_with_synopsis(run, ctx, step_ctx, lines).await? {
                Synopsis::Lines(lines) => lines,
                Synopsis::Exit(exit) => return Ok(Landing::Exit(exit)),
            }
        } else {
            lines
        };
        // The text lands in durable names, never its calls' labels (FIX
        // 10359); the reduce digest is the landed text's.
        let lines = super::durable_labels::durable_arc(lines, run.view);
        let reduce = ArcReduceRow {
            digest: result_digest(&lines.text, &lines.keep, &lines.line_sources),
            lines: lines.line_sources.len() as u64,
        };
        if let Err(error) = ctx
            .vault
            .save_arc_work(&run.work, None, &[], None, Some(&reduce))
        {
            return Ok(Landing::Exit(store_exit(&error, &run.charges, ctx.now_ms)));
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
        let exit = match ctx.vault.land_composed_scope_summary(
            attempt_id,
            run.plan,
            run.evidence,
            &composed,
            self.actor,
        ) {
            Ok(_) => DreamerAttemptExecution::Completed {
                completed_units: run.charges.units,
                step_hashes: run.charges.step_hashes.clone(),
            },
            Err(Error::ConcurrentWrite(_)) => compose_again(&run.charges, ctx.now_ms),
            Err(error) if waits_on_residency(&error) => residency_deferral(
                ctx.now_ms,
                run.charges.units,
                run.charges.step_hashes.clone(),
            ),
            Err(error) => run
                .charges
                .park(&format!("summary landing refused: {error}")),
        };
        Ok(Landing::Exit(exit))
    }
}
