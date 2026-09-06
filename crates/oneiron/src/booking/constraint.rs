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

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Value as JsonValue, json};

use crate::llm::{
    BudgetLease, CallClass, CallEnvelope, CallPurpose, ContentPart, DeterministicFallback,
    LlmBackend, LlmMessage, LlmMessageRole, LlmRequest, ModelId, ModelLocality, ResponseFormat,
    TierPrecedence,
};
use crate::temporal::TimeRange;

/// Wire version of [`ConstraintObject`]. A payload carrying any other version
/// fails closed rather than being coerced.
pub const CONSTRAINT_SCHEMA_VERSION: u16 = 1;

/// Exclusive upper bound for a local-minute-of-day.
const MINUTES_PER_DAY: u16 = 1440;

/// Hard ceiling on the caller-configured input bound. The dial is
/// [`ConstraintParseConfig::max_input_bytes`]; this only stops a config from
/// disabling the bound entirely.
const MAX_INPUT_BYTES_CEILING: usize = 4096;

/// Output bound on the parse call. The parser emits one small JSON object.
const MAX_OUTPUT_TOKENS: u32 = 256;

/// Bound on how many local windows a single parse may produce.
const MAX_LOCAL_TIME_WINDOWS: usize = 8;

/// Bound on an IANA timezone identifier.
const MAX_VISITOR_TZ_BYTES: usize = 64;

/// Booking-specific [`CallPurpose::Other`] name. The host policy binds this
/// purpose to its cheap tier; no provider or model id is hard-coded here.
pub const CONSTRAINT_PARSE_CALL_PURPOSE: &str = "booking_constraint_parse";

/// Name of the deterministic fallback that runs when the parse tier is
/// unavailable. Validation stays deterministic; the solver always is.
const CONSTRAINT_PARSE_FALLBACK: &str = "booking_constraint_deterministic_reject";

/// Routing namespace for the model id derived from the resolved tier. The
/// concrete provider/model is chosen by host policy behind the tier ref, so
/// only this namespace is constant.
const CONSTRAINT_TIER_PROVIDER: &str = "tier";

/// Host-configured event type. Configuration for the type (duration, pool,
/// flex policy) is ONE-1823's `EventTypeConfig`; the key alone lives here.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(transparent)]
pub struct EventTypeKey(pub String);

/// Booking error taxonomy. `Display` and `std::error::Error` are implemented
/// by hand so the derive list stays exactly the seam's five traits.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum BookingError {
    /// Host configuration is missing or unusable — including an unresolvable
    /// parse tier. Never a silent fallback to an ungoverned model.
    InvalidConfig(String),
    /// A normalized constraint failed validation or canonical ordering.
    InvalidConstraint(String),
    /// The bounded parse pass failed or returned an unusable payload.
    ConstraintParse(String),
    /// The per-session turn or model-call dial is spent.
    SessionCapExhausted,
    /// The oracle refused or failed to solve.
    SlotOracle(String),
    /// Surface assembly (lens atoms, controls, card) failed.
    Surface(String),
}

impl fmt::Display for BookingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(detail) => write!(f, "booking invalid config: {detail}"),
            Self::InvalidConstraint(detail) => write!(f, "booking invalid constraint: {detail}"),
            Self::ConstraintParse(detail) => write!(f, "booking constraint parse failed: {detail}"),
            Self::SessionCapExhausted => f.write_str("booking session cap exhausted"),
            Self::SlotOracle(detail) => write!(f, "booking slot oracle failed: {detail}"),
            Self::Surface(detail) => write!(f, "booking surface assembly failed: {detail}"),
        }
    }
}

impl std::error::Error for BookingError {}

// -------------------------------------------------------------------------
// TimeRange wire adapter
//
// `crate::temporal::TimeRange` is the ONE time range import path for booking,
// and it deliberately carries no serde derives. The seam owns its own
// serialization, so the adapter lives here rather than widening the shared
// temporal type.
// -------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
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

mod opt_time_range_serde {
    use super::{Deserialize, Deserializer, Serialize, Serializer, TimeRange, TimeRangeWire};

    pub(super) fn serialize<S: Serializer>(
        value: &Option<TimeRange>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value
            .as_ref()
            .map(TimeRangeWire::from)
            .serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<TimeRange>, D::Error> {
        Ok(Option::<TimeRangeWire>::deserialize(deserializer)?.map(TimeRange::from))
    }
}

// -------------------------------------------------------------------------
// Normalized constraint
// -------------------------------------------------------------------------

/// Weekday axis of a normalized constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintWeekday {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}

/// Half-open local-minute-of-day window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LocalMinuteWindow {
    /// Inclusive, `0..1440`.
    pub start_minute: u16,
    /// Exclusive, `start < end <= 1440`.
    pub end_minute: u16,
}

/// The deterministic, serializable constraint. This is pure data: it holds no
/// source text and no model explanation, so free text cannot ride it into a
/// solve. An empty weekday or window vector means "no restriction on that
/// axis".
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConstraintObject {
    pub schema_version: u16,
    #[serde(default)]
    pub weekdays: Vec<ConstraintWeekday>,
    #[serde(default)]
    pub local_time_windows: Vec<LocalMinuteWindow>,
    #[serde(with = "opt_time_range_serde")]
    pub utc_window: Option<TimeRange>,
    pub allow_flex_pool: bool,
}

impl ConstraintObject {
    /// Sort and de-duplicate every axis, then validate. Two semantically
    /// identical payloads that differ only in weekday/window order canonicalize
    /// to the same value, and therefore to the same bytes and hash.
    pub fn canonicalize(mut self) -> Result<Self, BookingError> {
        self.weekdays.sort_unstable();
        self.weekdays.dedup();
        self.local_time_windows.sort_unstable();
        self.local_time_windows.dedup();
        self.validate()?;
        Ok(self)
    }

    /// Fail closed on an unsupported schema version, an out-of-bounds minute
    /// window, an inverted UTC window, an over-long vector, or a vector that is
    /// not in canonical (strictly ascending) order.
    pub fn validate(&self) -> Result<(), BookingError> {
        if self.schema_version != CONSTRAINT_SCHEMA_VERSION {
            return Err(BookingError::InvalidConstraint(format!(
                "constraint schema version must be {CONSTRAINT_SCHEMA_VERSION}, got {}",
                self.schema_version
            )));
        }
        if self.local_time_windows.len() > MAX_LOCAL_TIME_WINDOWS {
            return Err(BookingError::InvalidConstraint(format!(
                "constraint carries at most {MAX_LOCAL_TIME_WINDOWS} local time windows"
            )));
        }
        for window in &self.local_time_windows {
            if window.start_minute >= window.end_minute || window.end_minute > MINUTES_PER_DAY {
                return Err(BookingError::InvalidConstraint(format!(
                    "local minute window must satisfy 0 <= start < end <= {MINUTES_PER_DAY}"
                )));
            }
        }
        if let Some(window) = &self.utc_window
            && window.start >= window.end
        {
            return Err(BookingError::InvalidConstraint(
                "utc window must satisfy start < end".to_owned(),
            ));
        }
        if !is_strictly_ascending(&self.weekdays) {
            return Err(BookingError::InvalidConstraint(
                "constraint weekdays must be sorted and de-duplicated".to_owned(),
            ));
        }
        if !is_strictly_ascending(&self.local_time_windows) {
            return Err(BookingError::InvalidConstraint(
                "constraint local time windows must be sorted and de-duplicated".to_owned(),
            ));
        }
        Ok(())
    }

    /// Canonical JSON bytes. Validation runs first, so a non-canonical object
    /// can never produce bytes: field order is the declaration order and every
    /// vector is proven strictly ascending.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BookingError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| {
            BookingError::InvalidConstraint(format!("constraint serialization failed: {error}"))
        })
    }

    /// BLAKE3 over [`Self::canonical_bytes`].
    pub fn canonical_hash(&self) -> Result<[u8; 32], BookingError> {
        Ok(*blake3::hash(&self.canonical_bytes()?).as_bytes())
    }
}

fn is_strictly_ascending<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

/// What one bounded parse pass concluded. `OffTopic` is a terminal disposition:
/// it yields one structured deflect, never a second turn.
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

/// One slot the oracle chose. UTC times are the oracle's; no caller rewrites,
/// rounds, or invents them.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RankedSlot {
    pub start_utc: u64,
    pub end_utc: u64,
    pub rank: f32,
}

/// Exact host choice made by routing for one half-open slot. This travels to
/// confirmation, not to the public availability mask.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SlotHostBinding {
    pub start_utc: u64,
    pub end_utc: u64,
    /// One host for Either, every participating host for Both; canonical hex.
    pub host_refs: Vec<String>,
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
}

// -------------------------------------------------------------------------
// Bounded parse pass
// -------------------------------------------------------------------------

/// The parse dial. `tier` is resolved by the existing model-policy precedence
/// and must point at the host's cheap tier.
pub struct ConstraintParseConfig {
    pub tier: TierPrecedence,
    pub max_input_bytes: usize,
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

    /// The model id is derived from the RESOLVED tier ref, never hard-coded:
    /// host policy owns which concrete model sits behind the tier.
    fn model_id(&self) -> Result<ModelId, BookingError> {
        let tier = sanitize_model_id_segment(self.tier.resolved().as_str());
        ModelId::new(format!("{CONSTRAINT_TIER_PROVIDER}/{tier}@configured")).map_err(|error| {
            BookingError::InvalidConfig(format!(
                "constraint parse tier does not resolve to a usable model id: {error}"
            ))
        })
    }
}

fn sanitize_model_id_segment(value: &str) -> String {
    let sanitized = value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_') {
                byte as char
            } else {
                '.'
            }
        })
        .collect::<String>()
        .trim_matches('.')
        .to_owned();
    if sanitized.is_empty() {
        "configured".to_owned()
    } else {
        sanitized
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

/// Parse bounded free text into a disposition with one zero-temperature,
/// JSON-schema, tool-free model call.
///
/// The caller has already admitted the model call: this function does not touch
/// session state.
pub async fn parse_constraint_with_backend(
    backend: &dyn LlmBackend,
    lease: &BudgetLease,
    request: &ConstraintParseRequest,
    config: &ConstraintParseConfig,
) -> Result<ConstraintParseDisposition, BookingError> {
    config.validate()?;
    let free_text = request.free_text.trim();
    if free_text.is_empty() {
        return Err(BookingError::InvalidConstraint(
            "constraint free text must not be empty".to_owned(),
        ));
    }
    if free_text.len() > config.max_input_bytes {
        return Err(BookingError::InvalidConstraint(format!(
            "constraint free text exceeds the configured bound of {} bytes",
            config.max_input_bytes
        )));
    }
    validate_visitor_tz(&request.detected_visitor_tz)?;

    let response = backend
        .generate(
            constraint_parse_llm_request(request, config, free_text)?,
            lease,
        )
        .await
        .map_err(|error| BookingError::ConstraintParse(error.to_string()))?;

    let disposition: ConstraintParseDisposition =
        serde_json::from_str(&response_text(&response.message)).map_err(|error| {
            BookingError::ConstraintParse(format!("parser payload is not a disposition: {error}"))
        })?;

    match disposition {
        ConstraintParseDisposition::OffTopic => Ok(ConstraintParseDisposition::OffTopic),
        ConstraintParseDisposition::Constraint {
            object,
            visitor_tz_override,
        } => {
            // A timezone override is the only free-form string the parser may
            // emit. Validating it as an identifier is what stops the original
            // sentence from riding into the solve request.
            if let Some(tz) = &visitor_tz_override {
                validate_visitor_tz(tz)?;
            }
            Ok(ConstraintParseDisposition::Constraint {
                object: object.canonicalize()?,
                visitor_tz_override,
            })
        }
    }
}

/// An IANA-shaped identifier: bounded, and restricted to the characters zone
/// names use. Anything else fails closed.
pub(crate) fn validate_visitor_tz(value: &str) -> Result<(), BookingError> {
    if value.is_empty() || value.len() > MAX_VISITOR_TZ_BYTES {
        return Err(BookingError::InvalidConstraint(format!(
            "visitor timezone must be 1..={MAX_VISITOR_TZ_BYTES} bytes"
        )));
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

fn response_text(message: &LlmMessage) -> String {
    message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

fn constraint_parse_llm_request(
    request: &ConstraintParseRequest,
    config: &ConstraintParseConfig,
    free_text: &str,
) -> Result<LlmRequest, BookingError> {
    // `params` is copied verbatim into the provider request body, so only
    // provider-supported generation parameters belong here.
    // `config.max_input_bytes` is local admission state: it is enforced before
    // this request is built and never sent.
    let mut params = BTreeMap::new();
    params.insert("temperature".to_owned(), json!(0));
    params.insert("max_output_tokens".to_owned(), json!(MAX_OUTPUT_TOKENS));

    Ok(LlmRequest {
        model: config.model_id()?,
        envelope: CallEnvelope {
            purpose: CallPurpose::Other {
                name: CONSTRAINT_PARSE_CALL_PURPOSE.to_owned(),
            },
            class: CallClass::Durable {
                fallback: DeterministicFallback {
                    name: CONSTRAINT_PARSE_FALLBACK.to_owned(),
                    config: None,
                },
            },
            tier: config.tier.clone(),
            response_format: ResponseFormat::Json {
                schema: constraint_response_schema(),
            },
            locality: ModelLocality::ThirdParty,
        },
        messages: vec![
            LlmMessage {
                role: LlmMessageRole::System,
                content: vec![ContentPart::Text {
                    text: constraint_system_prompt(),
                }],
            },
            LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text {
                    text: constraint_user_section(request, free_text),
                }],
            },
        ],
        // The capability boundary: the model parses scheduling constraints and
        // nothing else. No tools, ever.
        tools: Vec::new(),
        params,
        provider_options: BTreeMap::new(),
    })
}

/// Machine-facing instruction for the parser. This never reaches a visitor —
/// all visible copy is host-supplied configuration.
fn constraint_system_prompt() -> String {
    [
        "You are the Oneiron booking constraint parser, a system voice independent of any persona.",
        "Convert the scheduling preference into the JSON schema and return nothing else.",
        "Return disposition=off_topic when the text is not a scheduling preference.",
        "Never copy the input text, an explanation, or any other field into the output.",
        "You do not choose times, hold, confirm, or cancel anything.",
    ]
    .join("\n")
}

fn constraint_user_section(request: &ConstraintParseRequest, free_text: &str) -> String {
    format!(
        "schema_version={CONSTRAINT_SCHEMA_VERSION}\nvisitor_tz={}\nnow_utc={}\ntext={free_text}",
        request.detected_visitor_tz, request.now_utc
    )
}

fn constraint_response_schema() -> JsonValue {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["disposition"],
        "properties": {
            "disposition": { "enum": ["constraint", "off_topic"] },
            "visitor_tz_override": { "type": ["string", "null"], "maxLength": MAX_VISITOR_TZ_BYTES },
            "object": {
                "type": "object",
                "additionalProperties": false,
                "required": ["schema_version", "utc_window", "allow_flex_pool"],
                "properties": {
                    "schema_version": { "const": CONSTRAINT_SCHEMA_VERSION },
                    "weekdays": {
                        "type": "array",
                        "maxItems": 7,
                        "items": {
                            "enum": [
                                "monday", "tuesday", "wednesday", "thursday",
                                "friday", "saturday", "sunday",
                            ]
                        }
                    },
                    "local_time_windows": {
                        "type": "array",
                        "maxItems": MAX_LOCAL_TIME_WINDOWS,
                        "items": {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["start_minute", "end_minute"],
                            "properties": {
                                "start_minute": { "type": "integer", "minimum": 0, "maximum": MINUTES_PER_DAY },
                                "end_minute": { "type": "integer", "minimum": 0, "maximum": MINUTES_PER_DAY },
                            }
                        }
                    },
                    "utc_window": {
                        "type": ["object", "null"],
                        "additionalProperties": false,
                        "required": ["start", "end"],
                        "properties": {
                            "start": { "type": "integer", "minimum": 0 },
                            "end": { "type": "integer", "minimum": 0 },
                        }
                    },
                    "allow_flex_pool": { "type": "boolean" },
                }
            }
        }
    })
}

// -------------------------------------------------------------------------
// Fixture oracle
//
// Plain `#[cfg(test)]`, deliberately NOT behind the `test-hooks` or
// `test-support` features. This fixture is the mechanism that lets ONE-1816
// land before ONE-1823's real solver exists.
// -------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod fixture {
    use std::sync::Mutex;

    use super::{BookingError, RankedSlot, SlotOracle, SolveRequest, SolveResult};

    /// Returns configured slots and records every request it was asked. It
    /// cannot accept or retain free text: [`SolveRequest`] has no such field.
    /// The recorder is a `Mutex` because [`SlotOracle`] is shareable.
    pub(crate) struct FixtureSlotOracle {
        result: SolveResult,
        seen: Mutex<Vec<SolveRequest>>,
    }

    impl FixtureSlotOracle {
        pub(crate) fn with_slots(slots: Vec<RankedSlot>, flex_used: bool) -> Self {
            Self {
                result: SolveResult {
                    slots,
                    flex_used,
                    host_bindings: Vec::new(),
                },
                seen: Mutex::new(Vec::new()),
            }
        }

        pub(crate) fn seen(&self) -> Vec<SolveRequest> {
            self.seen.lock().expect("recorded solve requests").clone()
        }
    }

    impl SlotOracle for FixtureSlotOracle {
        fn solve(&self, req: &SolveRequest) -> Result<SolveResult, BookingError> {
            self.seen
                .lock()
                .expect("recorded solve requests")
                .push(req.clone());
            Ok(self.result.clone())
        }
    }
}
