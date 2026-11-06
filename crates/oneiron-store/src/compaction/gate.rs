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

use oneiron_base::tokenizer::count_context_pack_tokens;
use oneiron_model::llm::FinishReason;

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

/// The tokens one more pin adds to [`compaction_request_input`]: the pin as
/// a JSON string, escapes included, and the comma that joins it.
pub fn compaction_pin_input_tokens(pin: &str) -> u64 {
    count_context_pack_tokens(&Value::from(pin).to_string()) as u64 + 1
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

pub fn fail(check: CompactionCheck, detail: &'static str) -> CompactionGateFailure {
    CompactionGateFailure { check, detail }
}

/// Strict: one JSON object with exactly `from`, `through` and `summary`.
pub fn parse_reply(reply: &str) -> Result<(u64, u64, String), CompactionGateFailure> {
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

pub fn screen_degeneracy(
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
    /// The pass bills a room payer the vault's owners must first approve
    /// (FIX 3740): it waits on their ask, across turns, and the run's next
    /// breakpoint after their yes tries again. Nothing was spent.
    PayerNeeded,
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
            Self::PayerNeeded => "payer_needed",
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
