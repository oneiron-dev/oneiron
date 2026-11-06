//! Core half of `compaction::gate`: its store-layer items live in `oneiron_store::compaction::gate` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::compaction::gate::*;

use super::driver::{CompactionProduct, CompactionRequest, CompactionWindowMessage};
use crate::tokenizer::count_context_pack_tokens;
use oneiron_model::llm::FinishReason;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// What a compaction backend reads, as one JSON document: the span to cover
/// (`from`, `through`), the summary's token ceiling, the lines it must keep
/// word for word, what the agent asked it to keep (`note`, or null), the
/// check the last try failed, and the window's messages.
/// The host's prompt explains these keys; no prose lives here.
#[must_use]
pub fn compaction_request_input(
    request: &CompactionRequest,
    retry: Option<CompactionCheck>,
) -> Value {
    input_document(
        request.turn_start,
        &request.window,
        &request.pins,
        request.note.as_deref(),
        request.summary_token_budget,
        retry,
    )
}

fn input_document(
    turn_start: u64,
    window: &[CompactionWindowMessage],
    pins: &[String],
    note: Option<&str>,
    summary_token_budget: u64,
    retry: Option<CompactionCheck>,
) -> Value {
    serde_json::json!({
        "from": turn_start,
        "through": window.last().map_or(turn_start, |message| message.turn),
        "max_summary_tokens": summary_token_budget,
        "pins": pins,
        "note": note,
        "retry": retry.map(CompactionCheck::as_str),
        "steps": window.iter().map(step_frame).collect::<Vec<_>>(),
    })
}

fn step_frame(message: &CompactionWindowMessage) -> Value {
    serde_json::json!({"step": message.turn, "text": message.content})
}

/// The tokens [`compaction_request_input`] renders for `window` from
/// `turn_start` with `pins` and `note`, on its costliest try (whichever
/// retry it names), counted as a backend counts its input. The retry's name
/// sits between fixed keys, so the costliest is found on an empty input.
pub(crate) fn compaction_input_tokens(
    turn_start: u64,
    window: &[CompactionWindowMessage],
    pins: &[String],
    note: Option<&str>,
    summary_token_budget: u64,
) -> u64 {
    let render =
        |window: &[CompactionWindowMessage], pins: &[String], retry: Option<CompactionCheck>| {
            count_context_pack_tokens(
                &input_document(turn_start, window, pins, note, summary_token_budget, retry)
                    .to_string(),
            ) as u64
        };
    let retry = [
        None,
        Some(CompactionCheck::NaturalStop),
        Some(CompactionCheck::Schema),
        Some(CompactionCheck::Size),
        Some(CompactionCheck::Pins),
        Some(CompactionCheck::Degeneracy),
        Some(CompactionCheck::Coverage),
    ]
    .into_iter()
    .max_by_key(|retry| render(&[], &[], *retry))
    .flatten();
    render(window, pins, retry)
}

/// The tokens one step adds to [`compaction_request_input`]: its JSON frame,
/// escapes included, and the comma that joins it to the step before.
pub(crate) fn compaction_step_input_tokens(message: &CompactionWindowMessage) -> u64 {
    count_context_pack_tokens(&step_frame(message).to_string()) as u64 + 1
}

/// A summary that passed all six checks against its sealed request.
///
/// Private fields and no public constructor: holding one is proof the gate
/// ran on exactly this request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatedCompaction {
    pub(super) request: CompactionRequest,
    pub(super) product: CompactionProduct,
    /// The summary's vector, embedded in its pass for a room's mint
    /// (`embed_for_room`); `None` anywhere else.
    pub(super) vector: Option<super::epoch_vector::EpochVector>,
}

impl GatedCompaction {
    /// The request the gate judged.
    #[must_use]
    pub const fn request(&self) -> &CompactionRequest {
        &self.request
    }

    /// The accepted summary prose.
    #[must_use]
    pub fn summary_text(&self) -> &str {
        &self.product.summary_text
    }

    /// Test fixtures for the mint mechanics, which judge no reply.
    #[cfg(test)]
    pub(crate) fn ungated_for_test(
        request: &CompactionRequest,
        product: CompactionProduct,
    ) -> Self {
        Self {
            request: request.clone(),
            product,
            vector: None,
        }
    }
}

/// Runs the six checks over `product`, the backend's whole reply to
/// `request`, and returns the accepted summary or the first check it failed.
pub fn gate_compaction(
    request: &CompactionRequest,
    product: &CompactionProduct,
    policy: &CompactionGatePolicy,
) -> Result<GatedCompaction, CompactionGateFailure> {
    if product.finish != FinishReason::Stop {
        return Err(fail(
            CompactionCheck::NaturalStop,
            "the reply did not end on a natural stop",
        ));
    }
    let (from, through, summary) = parse_reply(&product.summary_text)?;

    let summary_tokens = count_context_pack_tokens(&summary) as u64;
    let window_tokens: u64 = request
        .window
        .iter()
        .map(|message| count_context_pack_tokens(&message.content) as u64)
        .sum();
    if summary_tokens >= window_tokens {
        return Err(fail(
            CompactionCheck::Size,
            "the summary is not smaller than its window",
        ));
    }
    if summary_tokens < policy.floor_tokens {
        return Err(fail(
            CompactionCheck::Size,
            "the summary is below the floor",
        ));
    }
    if summary_tokens > request.summary_token_budget {
        return Err(fail(
            CompactionCheck::Size,
            "the summary exceeds its token budget",
        ));
    }

    if request
        .pins
        .iter()
        .any(|pin| !summary.contains(pin.as_str()))
    {
        return Err(fail(CompactionCheck::Pins, "a verbatim pin is missing"));
    }

    screen_degeneracy(&summary, policy)?;

    let last = request
        .window
        .last()
        .map(|message| message.turn)
        .ok_or(fail(CompactionCheck::Coverage, "the window is empty"))?;
    if from != request.turn_start || through != last {
        return Err(fail(
            CompactionCheck::Coverage,
            "the summary's span is not the requested span",
        ));
    }
    if request
        .watermark
        .turn
        .is_some_and(|watermark| last > watermark)
    {
        return Err(fail(
            CompactionCheck::Coverage,
            "the window runs past the watermark",
        ));
    }

    Ok(GatedCompaction {
        request: request.clone(),
        product: CompactionProduct {
            summary_text: summary,
            finish: product.finish.clone(),
            latency: product.latency,
        },
        vector: None,
    })
}
