//! ONE-1816 [BK-05] booking constraint seam.
//!
//! This module is the lane-head home for every booking seam type:
//! [`EventTypeKey`], [`BookingError`], [`ConstraintObject`], [`SolveRequest`],
//! [`RankedSlot`], [`SolveResult`], [`SlotOracle`], and [`SlotMask`]. ONE-1823
//! plugs a real solver into [`SlotOracle`] without moving or redefining any type
//! declared here.
//!
//! The shape of the front is: bounded free text is parsed ONCE into a
//! deterministic, serializable [`ConstraintObject`], and only that object
//! reaches [`SlotOracle::solve`]. Free text is structurally absent from
//! [`SolveRequest`] — there is no text field to carry it.

use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, Instant};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Value as JsonValue, json};

use crate::entity_id::EntityId;
use crate::llm::decision::catalogue::BOOKING_OFF_TOPIC;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionDial, DecisionRung,
    GeneratedDecisions, GeneratedMiss, GeneratedRung, GeneratedStep, HeldLadder, ProviderPin,
    Reversibility,
};
use crate::llm::{
    BudgetLease, CallClass, CallEnvelope, CallPurpose, ContentPart, DeterministicFallback,
    LlmBackend, LlmMessage, LlmMessageRole, LlmRequest, ModelId, ModelLocality, ResponseFormat,
    TierPrecedence,
};
use crate::retrieval_depth::RetrievalDeadline;
use crate::temporal::TimeRange;

mod parse;

pub use self::parse::parse_constraint_with_backend;

#[doc(hidden)]
pub use oneiron_verb_wire::booking::constraint::{
    BookingError, CONSTRAINT_SCHEMA_VERSION, ConstraintObject, ConstraintWeekday, EventTypeKey,
    LocalMinuteWindow, RankedSlot,
};
#[doc(hidden)]
use oneiron_verb_wire::booking::constraint::{MINUTES_PER_DAY, is_strictly_ascending};

/// Hard ceiling on the caller-configured input bound. The dial is
/// [`ConstraintParseConfig::max_input_bytes`]; this only stops a config from
/// disabling the bound entirely.
const MAX_INPUT_BYTES_CEILING: usize = 4096;

/// Output bound on the parse call. The parser emits one small JSON object.
const MAX_OUTPUT_TOKENS: u32 = 256;

/// Booking-specific [`CallPurpose::Other`] name. The host policy binds this
/// purpose to its cheap tier; no provider or model id is hard-coded here.
pub const CONSTRAINT_PARSE_CALL_PURPOSE: &str = "booking_constraint_parse";

/// Name of the deterministic fallback that runs when the parse tier is
/// unavailable. Validation stays deterministic; the solver always is.
const CONSTRAINT_PARSE_FALLBACK: &str = "booking_constraint_deterministic_reject";

/// The booking front's typed question; a yes ends the turn with a deflect.
const OFF_TOPIC_QUESTION: &str = "Is the text something other than a scheduling preference?";

/// The time one shipped off-topic read may take.
const OFF_TOPIC_BUDGET: Duration = Duration::from_secs(30);

// -------------------------------------------------------------------------
// TimeRange wire adapter
//
// `crate::temporal::TimeRange` is the ONE time range import path for booking,
// and it deliberately carries no serde derives. The seam owns its own
// serialization, so the adapter lives here rather than widening the shared
// temporal type.
// -------------------------------------------------------------------------

#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct TimeRangeWire {
    start: u64,
    end: u64,
}

impl From<&TimeRange> for TimeRangeWire {
    fn from(value: &TimeRange) -> Self {
        Self {
            start: value.start,
            end: value.end,
        }
    }
}

impl From<TimeRangeWire> for TimeRange {
    fn from(value: TimeRangeWire) -> Self {
        Self {
            start: value.start,
            end: value.end,
        }
    }
}

mod time_range_serde {
    use super::{Deserialize, Deserializer, Serialize, Serializer, TimeRange, TimeRangeWire};

    pub(super) fn serialize<S: Serializer>(
        value: &TimeRange,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        TimeRangeWire::from(value).serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<TimeRange, D::Error> {
        TimeRangeWire::deserialize(deserializer).map(TimeRange::from)
    }
}

/// What one bounded parse pass concluded. `OffTopic` is a terminal disposition:
/// it yields one structured deflect, never a second turn. It is the off-topic
/// question's answer through the host's ladder; a constraint is the extraction
/// an on-topic turn's parse returns.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "disposition", rename_all = "snake_case")]
pub enum ConstraintParseDisposition {
    Constraint {
        object: ConstraintObject,
        visitor_tz_override: Option<String>,
    },
    OffTopic,
}

// -------------------------------------------------------------------------
// Solver seam
// -------------------------------------------------------------------------

/// What the oracle is asked. There is no free-text field, by construction.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SolveRequest {
    pub event_type: EventTypeKey,
    #[serde(with = "time_range_serde")]
    pub window: TimeRange,
    pub constraint: Option<ConstraintObject>,
    pub visitor_tz: String,
}

/// Exact host choice made by routing for one half-open slot. This travels to
/// confirmation, not to the public availability mask.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SlotHostBinding {
    pub start_utc: u64,
    pub end_utc: u64,
    /// One host for Either, every participating host for Both; canonical hex.
    pub host_refs: Vec<String>,
    /// IANA zone per host, in the same order as `host_refs`. This travels
    /// with the solver choice into confirmation, not the public slot mask.
    pub host_zones: Vec<String>,
}

/// What the oracle returned. Host bindings belong to this solve, never to a
/// later configuration lookup. Confirmation refuses a slot without a binding.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SolveResult {
    pub slots: Vec<RankedSlot>,
    pub flex_used: bool,
    pub host_bindings: Vec<SlotHostBinding>,
}

/// The final availability mask shape, settled from day one. There is no
/// artifact wrapper and no migration path: no consumer ships before it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SlotMask {
    pub event_type: EventTypeKey,
    pub window_start_utc: u64,
    /// Half-open `[window_start_utc, window_end_utc)`.
    pub window_end_utc: u64,
    pub slots: Vec<RankedSlot>,
    pub flex_used: bool,
}

/// The deterministic chooser of times and their exact host bindings. Production
/// wiring selects the implementation; confirmation consumes the same result.
///
/// `Send + Sync` matches [`LlmBackend`]: a `&dyn SlotOracle` is held across the
/// parse await in `run_constraint_turn`, so without them the turn future is not
/// `Send` and ONE-1819's server handlers cannot call this front at all.
pub trait SlotOracle: Send + Sync {
    fn solve(&self, req: &SolveRequest) -> Result<SolveResult, BookingError>;

    /// Takes the rows this oracle's solves have read so far, leaving the set
    /// empty: what a lifecycle writer that solved through it lists as its
    /// read set (FIX 5483). An oracle that lists nothing returns none.
    fn take_read_rows(&self) -> Vec<crate::EntityId> {
        Vec::new()
    }

    /// [`Self::solve`] for moving an existing booking, whose own place must
    /// not count against its move, as a confirm's own hold never blocks that
    /// confirm. An oracle that counts no bookings just solves.
    fn solve_moving(
        &self,
        req: &SolveRequest,
        _moving: crate::EntityId,
    ) -> Result<SolveResult, BookingError> {
        self.solve(req)
    }

    /// Re-solves for the existing booking `moving`, kept on `hosts`.
    fn solve_bound(
        &self,
        req: &SolveRequest,
        hosts: &[String],
        moving: crate::EntityId,
    ) -> Result<SolveResult, BookingError> {
        let mut result = self.solve_moving(req, moving)?;
        result
            .host_bindings
            .retain(|binding| binding.host_refs == hosts);
        result.slots.retain(|slot| {
            result.host_bindings.iter().any(|binding| {
                binding.start_utc == slot.start_utc && binding.end_utc == slot.end_utc
            })
        });
        Ok(result)
    }
}

// -------------------------------------------------------------------------
// Bounded parse pass
// -------------------------------------------------------------------------

/// The parse dial. `model` and `locality` are the host's cheap seat as the
/// vault's live model policy admitted it; `tier` is that admission's tier
/// precedence, carried on each call's envelope.
pub struct ConstraintParseConfig {
    pub model: ModelId,
    pub locality: ModelLocality,
    pub tier: TierPrecedence,
    pub max_input_bytes: usize,
    pub decisions: BookingDecisions,
}

/// The host's ladder for the off-topic question, the principal it asks for, the
/// dial and learned bands it routes under, and the time one read may take. The
/// parse tier's read sits at the dial's first rung, in place of that slot's
/// provider.
#[derive(Clone)]
pub struct BookingDecisions {
    pub ladder: HeldLadder,
    pub principal: EntityId,
    pub dial: DecisionDial,
    pub bands: DecisionBandPolicy,
    pub budget: Duration,
}

impl BookingDecisions {
    /// An unstaffed ladder for `principal`: the parse tier's read, at the
    /// system-one rung, is the one rung, and every band starts in shadow.
    #[must_use]
    pub fn shipped(principal: EntityId) -> Self {
        Self {
            ladder: HeldLadder::unstaffed(),
            principal,
            dial: DecisionDial {
                first: DecisionRung::SystemOne,
                ceiling: DecisionRung::SystemOne,
                band: DecisionBand::default(),
            },
            bands: DecisionBandPolicy::default(),
            budget: OFF_TOPIC_BUDGET,
        }
    }
}

impl ConstraintParseConfig {
    fn validate(&self) -> Result<(), BookingError> {
        if self.max_input_bytes == 0 || self.max_input_bytes > MAX_INPUT_BYTES_CEILING {
            return Err(BookingError::InvalidConfig(format!(
                "constraint parse max input bytes must be within 1..={MAX_INPUT_BYTES_CEILING}"
            )));
        }
        if self.tier.resolved().as_str().trim().is_empty() {
            return Err(BookingError::InvalidConfig(
                "constraint parse tier does not resolve to a configured cheap tier".to_owned(),
            ));
        }
        Ok(())
    }
}

/// One bounded parse input. `now_utc` anchors relative phrasing; the free text
/// is consumed here and never propagates past the disposition.
pub struct ConstraintParseRequest {
    pub free_text: String,
    pub detected_visitor_tz: String,
    pub now_utc: u64,
}

/// Per-session dials. Caller-supplied values, not a new approval wall.
pub struct ConstraintSessionCaps {
    pub max_turns: u16,
    pub max_model_calls: u16,
}

/// Per-session counters. Admission is checked BEFORE an LLM request is built or
/// sent, and before the oracle is called.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstraintSessionState {
    pub turns_used: u16,
    pub model_calls_used: u16,
}

impl ConstraintSessionState {
    pub fn admit_turn(&mut self, caps: &ConstraintSessionCaps) -> Result<(), BookingError> {
        self.turns_used = admit(self.turns_used, caps.max_turns)?;
        Ok(())
    }

    pub fn admit_model_call(&mut self, caps: &ConstraintSessionCaps) -> Result<(), BookingError> {
        self.model_calls_used = admit(self.model_calls_used, caps.max_model_calls)?;
        Ok(())
    }
}

fn admit(used: u16, cap: u16) -> Result<u16, BookingError> {
    used.checked_add(1)
        .filter(|next| *next <= cap)
        .ok_or(BookingError::SessionCapExhausted)
}

/// An IANA-shaped identifier: nonempty, of any length (ABC row 75), and
/// restricted to the characters zone names use. Anything else fails closed.
pub(super) fn validate_visitor_tz(value: &str) -> Result<(), BookingError> {
    if value.is_empty() {
        return Err(BookingError::InvalidConstraint(
            "visitor timezone must not be empty".to_owned(),
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-' | b'+'))
    {
        return Err(BookingError::InvalidConstraint(
            "visitor timezone must be an IANA-shaped identifier".to_owned(),
        ));
    }
    Ok(())
}
