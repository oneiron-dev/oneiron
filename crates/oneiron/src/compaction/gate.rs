//! The deterministic pre-swap gate (agent-runtime-v1 §d7).
//!
//! A summary replaces real history only after six transport-level checks, in
//! this order: a natural stop, its requested schema, a size band, every
//! verbatim pin, the degeneracy screens, and coverage that stops at the
//! watermark. Every check fails closed and names itself, so a retry can tell
//! the backend what failed. Only [`gate_compaction`] builds a
//! [`GatedCompaction`], and an executor swap takes nothing else.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::FinishReason;
use crate::tokenizer::count_context_pack_tokens;

use super::driver::{CompactionProduct, CompactionRequest, CompactionWindowMessage};

/// The JSON schema a compaction backend is asked to answer in. The gate's
/// schema check reads exactly these three keys and nothing else.
#[must_use]
pub fn compaction_reply_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["from", "through", "summary"],
        "properties": {
            "from": {"type": "integer", "minimum": 0},
            "through": {"type": "integer", "minimum": 0},
            "summary": {"type": "string"},
        },
    })
}

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

/// The tokens one more pin adds to [`compaction_request_input`]: the pin as
/// a JSON string, escapes included, and the comma that joins it.
pub(crate) fn compaction_pin_input_tokens(pin: &str) -> u64 {
    count_context_pack_tokens(&Value::from(pin).to_string()) as u64 + 1
}

/// The tokens one step adds to [`compaction_request_input`]: its JSON frame,
/// escapes included, and the comma that joins it to the step before.
pub(crate) fn compaction_step_input_tokens(message: &CompactionWindowMessage) -> u64 {
    count_context_pack_tokens(&step_frame(message).to_string()) as u64 + 1
}

/// One pre-swap check, in gate order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompactionCheck {
    /// The reply ended on a natural stop, not a truncation or a filter.
    NaturalStop,
    /// The reply is the requested schema, exactly.
    Schema,
    /// The summary is smaller than its window, within its budget and above
    /// the floor.
    Size,
    /// Every verbatim pin occurs in the summary word for word.
    Pins,
    /// The summary clears the degeneracy screens.
    Degeneracy,
    /// The summary covers the requested span and nothing past the watermark.
    Coverage,
}

impl CompactionCheck {
    /// The stable name a retry and a report carry.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NaturalStop => "natural_stop",
            Self::Schema => "schema",
            Self::Size => "size",
            Self::Pins => "pins",
            Self::Degeneracy => "degeneracy",
            Self::Coverage => "coverage",
        }
    }
}

/// Host policy for the gate. The defaults are a starting point, not law:
/// a host overrides them from its own config.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CompactionGatePolicy {
    /// Tries one pass makes before the session keeps its raw window.
    pub tries: u32,
    /// The fewest tokens an accepted summary carries.
    pub floor_tokens: u64,
    /// Above this share of repeated non-blank lines a summary is degenerate.
    pub max_repeated_line_share: f64,
    /// A token run repeated back to back this many times is a loop.
    pub max_consecutive_repeats: usize,
    /// Below this share of distinct tokens (over at least
    /// [`Self::distinct_min_tokens`] tokens) a summary is degenerate.
    pub min_distinct_token_share: f64,
    pub distinct_min_tokens: usize,
}

impl Default for CompactionGatePolicy {
    fn default() -> Self {
        Self {
            tries: 3,
            floor_tokens: 16,
            max_repeated_line_share: 0.5,
            max_consecutive_repeats: 4,
            min_distinct_token_share: 0.2,
            distinct_min_tokens: 40,
        }
    }
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

/// The check a reply failed, and why, in words a log can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactionGateFailure {
    pub check: CompactionCheck,
    pub detail: &'static str,
}

impl std::fmt::Display for CompactionGateFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.check.as_str(), self.detail)
    }
}

fn fail(check: CompactionCheck, detail: &'static str) -> CompactionGateFailure {
    CompactionGateFailure { check, detail }
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

/// Strict: one JSON object with exactly `from`, `through` and `summary`.
fn parse_reply(reply: &str) -> Result<(u64, u64, String), CompactionGateFailure> {
    let schema = |detail| fail(CompactionCheck::Schema, detail);
    let value: Value = serde_json::from_str(reply.trim())
        .map_err(|_| schema("the reply is not one JSON value"))?;
    let Value::Object(map) = value else {
        return Err(schema("the reply is not a JSON object"));
    };
    if map.len() != 3 {
        return Err(schema("the reply carries keys outside the schema"));
    }
    let from = map
        .get("from")
        .and_then(Value::as_u64)
        .ok_or(schema("`from` is not an unsigned integer"))?;
    let through = map
        .get("through")
        .and_then(Value::as_u64)
        .ok_or(schema("`through` is not an unsigned integer"))?;
    let summary = map
        .get("summary")
        .and_then(Value::as_str)
        .ok_or(schema("`summary` is not a string"))?;
    if summary.trim().is_empty() {
        return Err(schema("`summary` is blank"));
    }
    Ok((from, through, summary.to_owned()))
}

fn screen_degeneracy(
    summary: &str,
    policy: &CompactionGatePolicy,
) -> Result<(), CompactionGateFailure> {
    let degenerate = |detail| Err(fail(CompactionCheck::Degeneracy, detail));
    let lines: Vec<&str> = summary
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    if lines.len() > 1 {
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for line in &lines {
            *counts.entry(line).or_default() += 1;
        }
        let repeated: usize = counts.values().filter(|count| **count > 1).sum();
        if repeated as f64 / lines.len() as f64 > policy.max_repeated_line_share {
            return degenerate("most lines repeat");
        }
    }
    let words: Vec<&str> = summary.split_whitespace().collect();
    if has_consecutive_loop(&words, policy.max_consecutive_repeats) {
        return degenerate("a run of words repeats back to back");
    }
    if words.len() >= policy.distinct_min_tokens {
        let distinct = words.iter().collect::<BTreeSet<_>>().len();
        if (distinct as f64 / words.len() as f64) < policy.min_distinct_token_share {
            return degenerate("too few distinct words");
        }
    }
    Ok(())
}

/// True when some run of 1..=8 words occurs `repeats` times back to back.
fn has_consecutive_loop(words: &[&str], repeats: usize) -> bool {
    if repeats < 2 {
        return false;
    }
    for width in 1..=8_usize {
        let span = width * repeats;
        if span > words.len() {
            break;
        }
        for start in 0..=words.len() - span {
            let first = &words[start..start + width];
            if (1..repeats).all(|k| &words[start + k * width..start + (k + 1) * width] == first) {
                return true;
            }
        }
    }
    false
}

/// Why compaction did not run (agent-runtime-v1 §d7): four causes that look
/// alike from outside, so a negative is always typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactionSuppression {
    /// The backend's credentials were refused.
    Auth,
    /// The backend's meter admits no more spend.
    NoCredit,
    /// This turn's pass ended without an accepted swap. `check` names the
    /// gate check the last try failed, when the gate was reached. The next
    /// turn may try again.
    TurnScoped { check: Option<CompactionCheck> },
    /// Compaction is off for this session, for the stated reason.
    Sticky { why: CompactionOff },
}

impl CompactionSuppression {
    /// The stable name a report carries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::NoCredit => "no_credit",
            Self::TurnScoped { .. } => "turn_scoped",
            Self::Sticky { .. } => "sticky",
        }
    }
}

/// Why a session's compaction is off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactionOff {
    /// The host configures no model at all.
    NoModels,
    /// The host's config turns compaction off.
    Disabled,
    /// The prompt package holds no compaction prompt.
    NoPrompt,
    /// No configured seat serves the compaction role.
    NoSeat,
    /// The compaction seat leaves less input room than a run's window, so
    /// a sealed window could not reach it whole.
    SeatTooSmall,
    /// The host's backend failed in a way no retry fixes.
    BackendFailed,
    /// The run lives in a room whose stretch keeps no summary of its own: an
    /// anonymous room retains nothing, and a room already on record when the
    /// run entered writes through its saver, which no epoch mint reaches. Its
    /// window stays raw. A run in an off-record room compacts into the room's
    /// overlay instead.
    OffRecordRun,
    /// The run's agent profile gives its window to its own harness, which
    /// compacts it: Oneiron never compacts it twice.
    HarnessCompacts,
}

impl CompactionOff {
    /// The stable name a report carries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoModels => "no_model_configured",
            Self::Disabled => "disabled",
            Self::NoPrompt => "no_compaction_prompt",
            Self::NoSeat => "no_compaction_seat",
            Self::SeatTooSmall => "compaction_seat_too_small",
            Self::BackendFailed => "backend_failed",
            Self::OffRecordRun => "off_record_run",
            Self::HarnessCompacts => "harness_compacts",
        }
    }
}

/// A backend's typed refusal: nothing was produced, and this is why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactionRefusal {
    pub suppression: CompactionSuppression,
    /// Operator-facing detail for the refusal's receiver; never shown to the
    /// model. Logs carry only `suppression`: the detail can quote a provider's
    /// error body.
    pub detail: String,
}
