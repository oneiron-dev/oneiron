//! A sitting too big for one call on its model (FIX 7509 P7b, Rule 5). Its
//! TURNs are paged to the window the host counts for the model: each page is
//! a call of its own over raw TURN text, never an earlier page's output, a
//! prior body or a page's keep, and the lines of every page land as one
//! summary over the sitting's full evidence.
//!
//! Packing is deterministic from the evidence and the window. TURNs fill a
//! page in order; one that fits no empty page is cut into parts, each sized
//! to an empty page and cited by a label of its own: runs of whole MESSAGEs
//! first, and a MESSAGE (or inline text) alone too big for a page at
//! characters. Every MESSAGE byte lands in exactly one part; the `"\n"`
//! between two parts is not sent again. No source, byte or page count bounds
//! it: the one park on size names a window that holds no character.

use super::output::{self, PageRef};
use super::{ScopeSummaryEvidence, ScopeSummaryExecutor, compose_again};
use crate::dreamer_consolidation::residency::{residency_deferral, waits_on_residency};
use crate::dreamer_consolidation::step_charge::StepChargeTally;
use crate::dreamer_consolidation::support::invalid_consolidation;
use crate::dreamer_consolidation::turn_text::TurnText;
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerParkCause};
use crate::dreamer_wake::{DreamerAttemptExecution, WakeAttemptContext};
use crate::error::{Error, Result};
use crate::llm::{
    DurableStepContext, DurableStepError, LlmResponse, StepOutcome, call_as_step_checked,
};
use crate::scope_summary::{ComposedSummary, ScopeSummaryPlan, SummaryLineSpan};
use crate::{EntityId, Vault};
use std::collections::BTreeMap;

/// The identity a paged sitting's composition is known by.
const PAGES_DOMAIN: &str = "oneiron:session-summary-pages:v1";

impl<E> ScopeSummaryExecutor<'_, E> {
    /// The tokens one call's input may fill on the model: the host's count,
    /// else the vault's own row for the model, its context less the output
    /// it reserves where that is below it, as the host counts. `None` when
    /// neither is known: a zero context, or a row that did not read.
    pub(super) fn session_window(&self, vault: &Vault) -> Option<u64> {
        if let Some(window) = self.window_tokens.filter(|window| *window > 0) {
            return Some(window);
        }
        let row = match vault.model_registry_row(&self.model) {
            Ok(row) => row?,
            Err(error) => {
                tracing::warn!(
                    model = %self.model,
                    %error,
                    "a session summary's model row did not read; its window is unknown"
                );
                return None;
            }
        };
        let context = row.catalog.context_window_tokens;
        if context == 0 {
            return None;
        }
        let output = row
            .catalog
            .max_output_tokens
            .filter(|output| *output < context)
            .unwrap_or(0);
        Some(context - output)
    }

    /// Composes a sitting too big for one call on `window` (FIX 7509 P7b):
    /// the standing composition under the paged identity first, then every
    /// page in order from the first, each a durable step a resume replays
    /// from its memo with no second call, and the lines of all of them
    /// landing as one body through the landing fence over the full evidence.
    pub(super) async fn compose_pages(
        &self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
        plan: &ScopeSummaryPlan,
        evidence: &ScopeSummaryEvidence,
        instruction: &str,
        window: u64,
    ) -> Result<DreamerAttemptExecution> {
        let attempt_id = attempt.status.attempt.id;
        let (Some(session), Some(first)) = (plan.session, evidence.covers.first().copied()) else {
            return Err(invalid_consolidation(
                "only a sitting with text pages its turns",
            ));
        };
        let schema = output::session_schema();
        let params = serde_json::to_vec(&(
            instruction,
            self.model.as_str(),
            &schema,
            PAGES_DOMAIN,
            window,
        ))
        .map_err(|_| invalid_consolidation("summary policy did not encode"))?;
        let params_hash = *blake3::hash(&params).as_bytes();
        let memo = plan.composition_memo(evidence, &params_hash)?;
        // The same paged composition already stands: no page is asked again.
        match ctx.vault.reuse_composed_scope_summary(
            attempt_id,
            plan,
            evidence,
            &first,
            &memo,
            &params_hash,
        ) {
            Ok(true) => return Ok(DreamerAttemptExecution::Completed { completed_units: 0 }),
            Ok(false) => {}
            Err(error) if waits_on_residency(&error) => {
                return Ok(residency_deferral(ctx.now_ms, 0));
            }
            Err(error) => return Err(error),
        }
        let sources = blake3::Hash::from_bytes(evidence.fingerprint()?).to_hex();
        // A page's frame is counted at the widest numbers it can carry.
        let frame = framed_tokens(
            instruction,
            &page_input(plan, "", u64::MAX, u64::MAX, &session, sources.as_str())?,
            &schema,
        )?;
        let pages = match window.checked_sub(frame) {
            Some(room) => pages(evidence, room)?,
            None => None,
        };
        let Some(pages) = pages else {
            return Ok(DreamerAttemptExecution::Park {
                reason: format!(
                    "session summary page does not fit: window_tokens={window} frame_tokens={frame}"
                ),
                cause: DreamerParkCause::Retry,
            });
        };
        let count = pages.len() as u64;
        let mut steps = Vec::with_capacity(pages.len());
        for (index, page) in (1_u64..).zip(pages) {
            let user = page_input(
                plan,
                &page.records,
                index,
                count,
                &session,
                sources.as_str(),
            )?;
            let request =
                self.summary_request(ctx.vault, evidence, schema.clone(), instruction, user)?;
            let step_hash = request
                .canonical_hash()
                .map_err(|_| invalid_consolidation("summary request did not hash"))?;
            steps.push((request, step_hash, page.labels));
        }
        // A sitting's summary is in no conversation: its steps are about the
        // first TURN it reads, as its one call's step is.
        let subject = match &plan.scope {
            Some(scope) => scope.conversation,
            None => first,
        };
        let step_ctx = DurableStepContext {
            vault: ctx.vault,
            attempt_id,
            run_id: attempt.status.attempt.run_id.clone(),
            envelope_actor: self.actor,
            subject,
            deadline: Some(ctx.deadline),
            now_ms: ctx.now_ms,
        };
        // Every exit once a page may have been paid carries the tally.
        let mut charges = StepChargeTally::default();
        let mut replies = Vec::with_capacity(steps.len());
        for (request, step_hash, labels) in steps {
            if ctx.deadline.expired() {
                return Ok(charges.checkpoint());
            }
            // Each page answers to the page contract inside its step.
            let check_labels = labels.clone();
            let check = move |response: &LlmResponse| {
                output::paged_output(response, &check_labels)
                    .map(drop)
                    .map_err(str::to_owned)
            };
            let outcome =
                call_as_step_checked(&step_ctx, self.backend, self.guard, request, &check).await;
            let response = match outcome {
                Ok(StepOutcome::Finished { response, .. }) => {
                    if let Err(error) =
                        charges.record_terminal(ctx.vault, attempt_id, step_hash, &response.usage)
                    {
                        return Ok(charges.park_on_error(&error));
                    }
                    response
                }
                Ok(StepOutcome::Trapped { .. }) => {
                    return Ok(charges
                        .park_for("durable step trapped for resume", DreamerParkCause::Signal));
                }
                Err(DurableStepError::SpentFinalizeRefused { usage }) => {
                    charges.record_usage(&usage);
                    return Ok(charges.checkpoint());
                }
                Err(DurableStepError::DeadlineHardCut) => return Ok(charges.checkpoint()),
                Err(DurableStepError::FinalizeRefused) => {
                    return Ok(
                        charges.park_for("wake pass finalize window", DreamerParkCause::Checkpoint)
                    );
                }
                Err(DurableStepError::Engine(error)) => return Ok(charges.park_on_error(&error)),
                Err(other @ DurableStepError::SpentSchemaValidation { .. }) => {
                    if let DurableStepError::SpentSchemaValidation { usage, .. } = &other {
                        charges.record_usage(usage);
                    }
                    return Ok(charges.park_for(&other.to_string(), DreamerParkCause::Retry));
                }
                Err(other) => {
                    return Ok(
                        charges.park_for(&other.to_string(), DreamerParkCause::of_step(&other))
                    );
                }
            };
            // The step's check already admitted this reply; its lines are read
            // through the same parse.
            match output::paged_output(&response, &labels) {
                Ok(page) => replies.push(page),
                Err(reason) => return Ok(charges.park_for(reason, DreamerParkCause::Retry)),
            }
        }
        if ctx.deadline.expired() {
            return Ok(charges.checkpoint());
        }
        let composition = match output::assemble(replies) {
            Ok(composition) => composition,
            Err(reason) => return Ok(charges.park_for(reason, DreamerParkCause::Retry)),
        };
        let composed = ComposedSummary {
            text: &composition.text,
            keep: &composition.keep,
            params_hash,
            instruction,
            model: self.model.as_str(),
            covers: evidence.covers.clone(),
            messages: evidence.messages.clone(),
            memo,
            line_sources: Some(composition.line_sources),
        };
        // The landing fence reads the whole evidence again, every page's
        // sources with it.
        match ctx
            .vault
            .land_composed_scope_summary(attempt_id, plan, evidence, &composed, self.actor)
        {
            Ok(_) => Ok(DreamerAttemptExecution::Completed {
                completed_units: charges.units,
            }),
            Err(Error::ConcurrentWrite(_)) => Ok(compose_again(&charges, ctx.now_ms)),
            Err(error) if waits_on_residency(&error) => {
                Ok(residency_deferral(ctx.now_ms, charges.units))
            }
            Err(error) => Ok(charges.park(&format!("summary landing refused: {error}"))),
        }
    }
}

/// The tokens a call costs as framed: its instruction, its input as sent
/// and its output contract, each counted as a resident's window counts.
pub(super) fn framed_tokens(
    instruction: &str,
    user: &str,
    schema: &serde_json::Value,
) -> Result<u64> {
    let schema = serde_json::to_string(schema)
        .map_err(|_| invalid_consolidation("summary policy did not encode"))?;
    Ok([instruction, user, schema.as_str()]
        .into_iter()
        .map(tokens)
        .sum())
}

/// The input one page's call reads: the declaration's purpose and `keep`,
/// no editor text, the page's records, and where the page sits: its 1-based
/// `index` of `count`, its sitting and its sources' digest, so a changed
/// pin is a new step.
fn page_input(
    plan: &ScopeSummaryPlan,
    records: &str,
    index: u64,
    count: u64,
    session: &EntityId,
    sources: &str,
) -> Result<String> {
    serde_json::to_string(&serde_json::json!({
        "purpose": plan.purpose,
        "keep": plan.keep,
        "editor_text": null,
        "records": records,
        "page": {
            "index": index,
            "count": count,
            "session": session.to_hex(),
            "sources": sources,
        },
    }))
    .map_err(|_| invalid_consolidation("summary input encoding"))
}

/// One page of a sitting: the records it shows, what each label it shows
/// stands for, and the tokens its records cost.
#[derive(Default)]
struct Page {
    records: String,
    labels: BTreeMap<String, PageRef>,
    cost: u64,
}

/// A whole TURN or one part of it, as a page shows it.
struct Unit {
    label: String,
    rendered: String,
    cost: u64,
    cites: PageRef,
}

/// The sitting's pages in order, each holding `room` tokens of records at
/// most, or `None` when a part of one character fits no page. A unit that
/// does not fit closes a page that holds any and goes on an empty one.
fn pages(evidence: &ScopeSummaryEvidence, room: u64) -> Result<Option<Vec<Page>>> {
    let mut pages = Vec::new();
    let mut page = Page::default();
    for (index, (turn, text)) in evidence.turns.iter().enumerate() {
        let Some(words) = text.text() else {
            continue;
        };
        let label = output::turn_label(index);
        let rendered = render(&label, words);
        let cost = escaped_cost(&rendered)?;
        let units = if cost <= room {
            vec![Unit {
                label,
                rendered,
                cost,
                cites: PageRef {
                    turn: *turn,
                    spans: Vec::new(),
                },
            }]
        } else {
            let Some(parts) = parts(&label, *turn, text, words, room)? else {
                return Ok(None);
            };
            parts
        };
        for unit in units {
            if !page.labels.is_empty() && page.cost.saturating_add(unit.cost) > room {
                pages.push(std::mem::take(&mut page));
            }
            page.records.push_str(&unit.rendered);
            page.cost = page.cost.saturating_add(unit.cost);
            page.labels.insert(unit.label, unit.cites);
        }
    }
    if !page.labels.is_empty() {
        pages.push(page);
    }
    Ok(Some(pages))
}

/// The parts of the TURN `label` names, which fits no empty page, in order,
/// each sized to fit one: runs of whole MESSAGEs, and a MESSAGE alone too
/// big for a page (or inline text) cut at characters. `None` when not even
/// one character's part fits.
fn parts(
    label: &str,
    turn: EntityId,
    text: &TurnText,
    words: &str,
    room: u64,
) -> Result<Option<Vec<Unit>>> {
    let inline = text.projection().is_empty();
    let messages = if inline {
        vec![(0, words.len())]
    } else {
        message_ranges(text, words)?
    };
    let mut parts = Vec::new();
    let mut next = 0;
    while let Some(&(start, _)) = messages.get(next) {
        let part_label = format!("{label}.p{}", parts.len() + 1);
        let run = longest_fit(messages.len() - next, |run| {
            fits(&part_label, &words[start..messages[next + run - 1].1], room)
        })?;
        if run > 0 {
            let end = messages[next + run - 1].1;
            parts.push(part(part_label, turn, text, inline, words, (start, end))?);
            next += run;
            continue;
        }
        // One MESSAGE alone fits no empty page: it is cut at characters.
        let (mut at, end) = messages[next];
        while at < end {
            let part_label = format!("{label}.p{}", parts.len() + 1);
            let bytes = longest_fit(end - at, |bytes| {
                let cut = words.floor_char_boundary(at + bytes);
                // A prefix short of one character holds none, so fits.
                Ok(cut == at || fits(&part_label, &words[at..cut], room)?)
            })?;
            let cut = words.floor_char_boundary(at + bytes);
            if cut == at {
                return Ok(None);
            }
            parts.push(part(part_label, turn, text, inline, words, (at, cut))?);
            at = cut;
        }
        next += 1;
    }
    Ok((!parts.is_empty()).then_some(parts))
}

/// One part of `turn` showing `range` of its text under `label`, with the
/// exact slices it holds: MESSAGE-local, or TURN-local for inline text.
fn part(
    label: String,
    turn: EntityId,
    text: &TurnText,
    inline: bool,
    words: &str,
    (start, end): (usize, usize),
) -> Result<Unit> {
    let rendered = render(&label, &words[start..end]);
    let cost = escaped_cost(&rendered)?;
    let spans = if inline {
        vec![SummaryLineSpan {
            turn: turn.to_hex(),
            message: None,
            start,
            end,
        }]
    } else {
        text.spans(Some((start, end)))?
            .into_iter()
            .map(|span| SummaryLineSpan {
                turn: turn.to_hex(),
                message: Some(span.message.to_hex()),
                start: span.start,
                end: span.end,
            })
            .collect()
    };
    Ok(Unit {
        label,
        rendered,
        cost,
        cites: PageRef { turn, spans },
    })
}

/// Each MESSAGE of a projected TURN that holds words, as its byte range in
/// the TURN's text, in projection order: from each MESSAGE's whole span and
/// the `"\n"` that joins one MESSAGE to the next. An empty MESSAGE holds
/// none.
fn message_ranges(text: &TurnText, words: &str) -> Result<Vec<(usize, usize)>> {
    let lengths: BTreeMap<EntityId, usize> = text
        .spans(None)?
        .into_iter()
        .map(|span| (span.message, span.end - span.start))
        .collect();
    let mut ranges = Vec::new();
    let mut offset = 0_usize;
    for (index, message) in text.projection().into_iter().enumerate() {
        if index != 0 {
            offset += 1;
        }
        let len = lengths.get(&message).copied().unwrap_or(0);
        if len != 0 {
            ranges.push((offset, offset + len));
        }
        offset += len;
    }
    if offset != words.len() {
        return Err(invalid_consolidation(
            "a projected turn's messages do not tile its text",
        ));
    }
    Ok(ranges)
}

/// The largest `n` in `1..=max` that `fits`, or 0 when 1 does not: doubling
/// from 1 to the first `n` that does not fit, then halving the gap below it.
fn longest_fit(max: usize, mut fits: impl FnMut(usize) -> Result<bool>) -> Result<usize> {
    let (mut good, mut bad) = (0, max.saturating_add(1));
    let mut probe = 1;
    while probe < bad {
        if fits(probe)? {
            good = probe;
            probe = if probe == max {
                bad
            } else {
                probe.saturating_mul(2).min(max)
            };
        } else {
            bad = probe;
        }
    }
    while bad - good > 1 {
        let mid = good + (bad - good) / 2;
        if fits(mid)? {
            good = mid;
        } else {
            bad = mid;
        }
    }
    Ok(good)
}

/// Whether `slice`, shown under `label`, fits `room` tokens.
fn fits(label: &str, slice: &str, room: u64) -> Result<bool> {
    Ok(escaped_cost(&render(label, slice))? <= room)
}

/// How a page shows `words` under `label`: as a sitting's one call shows a
/// TURN, `[label] words` and a newline.
fn render(label: &str, words: &str) -> String {
    format!("[{label}] {words}\n")
}

/// The tokens `rendered` costs where a page carries it, inside its JSON
/// `records` string: counted over its escaping, without the quotes.
fn escaped_cost(rendered: &str) -> Result<u64> {
    let escaped = serde_json::to_string(rendered)
        .map_err(|_| invalid_consolidation("summary input encoding"))?;
    let inner = escaped
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(&escaped);
    Ok(tokens(inner))
}

/// The tokens `text` counts, as a resident's window counts them.
fn tokens(text: &str) -> u64 {
    crate::count_context_pack_tokens(text) as u64
}
