//! The Arc's optional synopsis (FIX 8290, Engine 02:3x): once its parts'
//! lines are assembled, one more call reads them, each as an observation
//! with the TURNs it cites, and writes a shorter narrative of the whole
//! Arc. Its lines lead the Arc's text; every assembled line follows as it
//! was, so nothing the parts wrote is lost. Off by default
//! ([`ARC_SYNOPSIS`]): the default path makes no call beyond the parts'.
//!
//! The call reads the host's summary instruction as every Arc call does,
//! with its kind `synopsis`. Lines that do not fit one call, a reply that
//! writes no line or one that asks a TURN opened land the Arc as assembled.

use super::ScopeSummaryExecutor;
use super::arc_children::ArcRun;
use super::arc_output::ArcLines;
use super::arc_review::{CallBuilder, CallShape, Called, Observation, call_input};
use super::window::framed_tokens;
use crate::dreamer_wake::{DreamerAttemptExecution, WakeAttemptContext};
use crate::error::Result;
use crate::llm::DurableStepContext;
use crate::scope_summary::SummaryLineSources;

/// Whether an Arc composed in parts asks one synopsis call over its
/// assembled lines before it lands (FIX 8290). Off: an Arc is its parts'
/// lines, assembled, with no further model call.
pub(super) const ARC_SYNOPSIS: bool = false;
/// The call writing an Arc's synopsis.
const KIND_SYNOPSIS: &str = "synopsis";

/// What the synopsis step came to.
pub(super) enum Synopsis {
    /// The Arc's lines to land: the synopsis's first, when it wrote one.
    Lines(ArcLines),
    /// The attempt's exit.
    Exit(DreamerAttemptExecution),
}

impl<E> ScopeSummaryExecutor<'_, E> {
    /// Asks the synopsis of `lines`, the Arc's assembled lines, and leads
    /// them with it.
    pub(super) async fn lead_with_synopsis(
        &self,
        run: &mut ArcRun<'_>,
        ctx: &WakeAttemptContext<'_>,
        step_ctx: &DurableStepContext<'_>,
        lines: ArcLines,
    ) -> Result<Synopsis> {
        // Lines join with one newline and never hold one.
        let observed: Vec<Observation> = lines
            .text
            .split('\n')
            .zip(&lines.line_sources)
            .map(|(text, source)| Observation {
                text: text.to_owned(),
                turn_refs: source.turn_refs.clone(),
                source_spans: source.source_spans.clone(),
            })
            .collect();
        let mut call = CallBuilder::new(&run.members, run.view);
        call.observations(&observed.iter().collect::<Vec<_>>())?;
        let (fields, context, whole) = call.finish()?;
        let shape = CallShape {
            kind: KIND_SYNOPSIS,
            child: 1,
            children: 1,
            part: 1,
            parts: 1,
        };
        let user = call_input(run.plan, &shape, &fields)?;
        if framed_tokens(run.instruction, &user, &run.schema)? > run.manifest.pins.window {
            tracing::info!(
                lines = lines.line_sources.len(),
                "an arc lands without a synopsis: its lines exceed one call"
            );
            return Ok(Synopsis::Lines(lines));
        }
        let reply = match self
            .child_call(run, ctx, step_ctx, user, context, whole)
            .await?
        {
            Called::Reply(reply, _) => reply,
            Called::Exit(exit) => return Ok(Synopsis::Exit(exit)),
        };
        if reply.lines.is_empty() || !reply.open.is_empty() {
            tracing::info!(
                opened = reply.open.len(),
                "an arc lands without a synopsis: its call wrote no line"
            );
            return Ok(Synopsis::Lines(lines));
        }
        let mut text = String::new();
        let mut scalars = 0_usize;
        let mut line_sources = Vec::with_capacity(reply.lines.len() + lines.line_sources.len());
        for line in reply.lines {
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
        text.push('\n');
        let shift = scalars + 1;
        text.push_str(&lines.text);
        line_sources.extend(
            lines
                .line_sources
                .into_iter()
                .map(|source| SummaryLineSources {
                    output_start: source.output_start + shift,
                    output_end: source.output_end + shift,
                    ..source
                }),
        );
        Ok(Synopsis::Lines(ArcLines {
            text,
            keep: lines.keep,
            line_sources,
        }))
    }
}
