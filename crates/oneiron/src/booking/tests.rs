//! ONE-1816 [BK-05] constraint-front oracles.
//!
//! Deterministic fakes only: no live network and no live model. The fixture
//! `SlotOracle` lives beside the seam in `constraint.rs` under plain
//! `#[cfg(test)]` — neither the `test-hooks` nor the `test-support` feature is
//! referenced anywhere in this lane.

use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use serde_json::{Value as JsonValue, json};

use crate::lens::{ButtonControl, GeneratedUiCard, LensAtom, SelfUiControl};
use crate::llm::{
    BudgetLease, CallPurpose, ContentPart, FatalLlmError, FinishReason, LlmBackend,
    LlmGenerateFuture, LlmInputUsage, LlmMessage, LlmMessageRole, LlmOutputUsage, LlmRequest,
    LlmResponse, LlmStreamResult, LlmUsage, ModelTierRef, ResponseFormat, TierPrecedence,
};
use crate::temporal::TimeRange;

use super::agent_front::{
    BOOKING_SLOT_BUTTON_ACTION, ConstraintContinuation, ConstraintFrontCopy,
    ConstraintFrontOutcome, ConstraintTurnRequest, run_constraint_turn,
};
use super::constraint::fixture::FixtureSlotOracle;
use super::constraint::{
    BookingError, CONSTRAINT_PARSE_CALL_PURPOSE, CONSTRAINT_SCHEMA_VERSION, ConstraintObject,
    ConstraintParseConfig, ConstraintParseDisposition, ConstraintParseRequest,
    ConstraintSessionCaps, ConstraintSessionState, ConstraintWeekday, EventTypeKey,
    LocalMinuteWindow, RankedSlot, SlotMask, SlotOracle, SolveRequest,
    parse_constraint_with_backend,
};

// -------------------------------------------------------------------------
// Fakes
// -------------------------------------------------------------------------

/// Records every request it is handed and replays one scripted body.
struct RecordingBackend {
    body: String,
    seen: Mutex<Vec<LlmRequest>>,
}

impl RecordingBackend {
    fn new(body: impl Into<String>) -> Self {
        Self {
            body: body.into(),
            seen: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> usize {
        self.seen.lock().expect("recorded calls").len()
    }

    fn last(&self) -> LlmRequest {
        self.seen
            .lock()
            .expect("recorded calls")
            .last()
            .cloned()
            .expect("a recorded call")
    }
}

impl LlmBackend for RecordingBackend {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.seen.lock().expect("recorded calls").push(request);
        let body = self.body.clone();
        Box::pin(async move {
            Ok(LlmResponse {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content: vec![ContentPart::Text { text: body }],
                },
                usage: LlmUsage {
                    input: LlmInputUsage::default(),
                    output: LlmOutputUsage::default(),
                    raw_provider: JsonValue::Null,
                },
                finish_reason: FinishReason::Stop,
            })
        })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    match Pin::new(&mut future).poll(&mut cx) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("test future unexpectedly pending"),
    }
}

fn noop_waker() -> Waker {
    unsafe fn clone(_: *const ()) -> RawWaker {
        raw_waker()
    }
    unsafe fn wake(_: *const ()) {}
    unsafe fn wake_by_ref(_: *const ()) {}
    unsafe fn drop(_: *const ()) {}

    fn raw_waker() -> RawWaker {
        RawWaker::new(
            std::ptr::null(),
            &RawWakerVTable::new(clone, wake, wake_by_ref, drop),
        )
    }

    // SAFETY: the noop waker never dereferences the null data pointer.
    unsafe { Waker::from_raw(raw_waker()) }
}

// -------------------------------------------------------------------------
// Builders
// -------------------------------------------------------------------------

const VISITOR_SENTENCE: &str = "any weekday afternoon works, ideally after lunch";

fn cheap_tier() -> TierPrecedence {
    TierPrecedence {
        per_call: None,
        vault_policy: Some(ModelTierRef("host-cheap-tier".to_owned())),
        purpose_default: None,
        global_default: ModelTierRef("host-global-tier".to_owned()),
    }
}

fn parse_config() -> ConstraintParseConfig {
    ConstraintParseConfig {
        tier: cheap_tier(),
        max_input_bytes: 512,
    }
}

fn caps() -> ConstraintSessionCaps {
    ConstraintSessionCaps {
        max_turns: 2,
        max_model_calls: 2,
    }
}

fn copy() -> ConstraintFrontCopy {
    ConstraintFrontCopy {
        speaker: "host-configured-speaker".to_owned(),
        slots_line: "host-configured-slots-line".to_owned(),
        no_fit_line: "host-configured-no-fit-line".to_owned(),
        off_topic_line: "host-configured-off-topic-line".to_owned(),
    }
}

fn lease() -> BudgetLease {
    BudgetLease::for_test("booking-constraint-lease")
}

fn window() -> TimeRange {
    TimeRange {
        start: 1_800_000_000,
        end: 1_800_600_000,
    }
}

fn event_type() -> EventTypeKey {
    EventTypeKey("intro-call".to_owned())
}

fn canonical_object() -> ConstraintObject {
    ConstraintObject {
        schema_version: CONSTRAINT_SCHEMA_VERSION,
        weekdays: vec![ConstraintWeekday::Monday, ConstraintWeekday::Wednesday],
        local_time_windows: vec![LocalMinuteWindow {
            start_minute: 780,
            end_minute: 1020,
        }],
        utc_window: None,
        allow_flex_pool: false,
    }
}

fn constraint_payload(weekdays: &[&str], windows: &[(u16, u16)]) -> String {
    let windows = windows
        .iter()
        .map(|(start, end)| json!({ "start_minute": start, "end_minute": end }))
        .collect::<Vec<_>>();
    json!({
        "disposition": "constraint",
        "object": {
            "schema_version": CONSTRAINT_SCHEMA_VERSION,
            "weekdays": weekdays,
            "local_time_windows": windows,
            "utc_window": null,
            "allow_flex_pool": false,
        },
        "visitor_tz_override": null,
    })
    .to_string()
}

fn slot(start_utc: u64, rank: f32) -> RankedSlot {
    RankedSlot {
        start_utc,
        end_utc: start_utc + 1800,
        rank,
    }
}

fn turn_request() -> ConstraintTurnRequest {
    ConstraintTurnRequest {
        session_ref: "sess-1816".to_owned(),
        event_type: event_type(),
        window: window(),
        detected_visitor_tz: "Europe/Warsaw".to_owned(),
        free_text: VISITOR_SENTENCE.to_owned(),
    }
}

fn run_turn(
    oracle: &dyn SlotOracle,
    backend: &dyn LlmBackend,
    state: &mut ConstraintSessionState,
) -> Result<ConstraintFrontOutcome, BookingError> {
    block_on_ready(run_constraint_turn(
        oracle,
        backend,
        &lease(),
        &parse_config(),
        &caps(),
        state,
        &copy(),
        turn_request(),
    ))
}

fn parsed_object(backend: &RecordingBackend) -> ConstraintObject {
    match block_on_ready(parse_constraint_with_backend(
        backend,
        &lease(),
        &ConstraintParseRequest {
            free_text: VISITOR_SENTENCE.to_owned(),
            detected_visitor_tz: "Europe/Warsaw".to_owned(),
            now_utc: 1_800_000_000,
        },
        &parse_config(),
    ))
    .expect("parse succeeds")
    {
        ConstraintParseDisposition::Constraint { object, .. } => object,
        ConstraintParseDisposition::OffTopic => panic!("expected a constraint disposition"),
    }
}

/// Buttons in document order. Children are pushed in reverse so the stack pops
/// them left-to-right — the order the card actually renders.
fn buttons(card: &GeneratedUiCard) -> Vec<ButtonControl> {
    let mut found = Vec::new();
    let mut stack = vec![card.tree.root()];
    while let Some(node) = stack.pop() {
        if let LensAtom::SelfUi(SelfUiControl::Button(control)) = &node.atom {
            found.push(control.clone());
        }
        for child in node.children.iter().rev() {
            stack.push(child);
        }
    }
    found
}

fn voice_lines(card: &GeneratedUiCard) -> usize {
    let mut count = 0;
    let mut stack = vec![card.tree.root()];
    while let Some(node) = stack.pop() {
        if matches!(node.atom, LensAtom::VoiceLine(_)) {
            count += 1;
        }
        for child in &node.children {
            stack.push(child);
        }
    }
    count
}

/// Every source file this ticket owns, with comment lines stripped: these
/// assertions are about what the lane CODE does, never about its prose.
fn lane_sources() -> [String; 3] {
    [
        include_str!("constraint.rs"),
        include_str!("agent_front.rs"),
        include_str!("mod.rs"),
    ]
    .map(|source| {
        source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    })
}

// -------------------------------------------------------------------------
// Oracles
// -------------------------------------------------------------------------

/// Every seam type resolves from `crate::booking::constraint` alone, and
/// `booking/mod.rs` re-exports without defining anything.
#[test]
fn booking_constraint_seam_compiles_from_constraint_home() {
    use crate::booking::constraint::{
        BookingError as SeamError, ConstraintObject as SeamObject, EventTypeKey as SeamKey,
        RankedSlot as SeamSlot, SlotMask as SeamMask, SlotOracle as SeamOracle,
        SolveRequest as SeamRequest, SolveResult as SeamResult,
    };

    // Each seam data type round-trips through serde, clones, debugs, and
    // compares — the exact five-trait derive contract.
    fn assert_seam<T>(value: &T)
    where
        T: serde::Serialize + serde::de::DeserializeOwned + Clone + std::fmt::Debug + PartialEq,
    {
        let bytes = serde_json::to_vec(value).expect("seam type serializes");
        let restored: T = serde_json::from_slice(&bytes).expect("seam type deserializes");
        assert_eq!(
            &restored,
            &value.clone(),
            "seam type round-trips: {value:?}"
        );
    }

    // The trait is object-safe and lives here, so ONE-1823 can implement it
    // without touching this file.
    fn takes_oracle(_: &dyn SeamOracle) {}

    let object = canonical_object();
    let request = SeamRequest {
        event_type: SeamKey("intro-call".to_owned()),
        window: window(),
        constraint: Some(object.clone()),
        visitor_tz: "Europe/Warsaw".to_owned(),
    };
    let ranked = SeamSlot {
        start_utc: 10,
        end_utc: 20,
        rank: 0.5,
    };
    let result = SeamResult {
        slots: vec![ranked.clone()],
        flex_used: false,
    };
    let mask = SeamMask {
        event_type: SeamKey("intro-call".to_owned()),
        window_start_utc: 10,
        window_end_utc: 20,
        slots: vec![ranked.clone()],
        flex_used: false,
    };

    assert_seam(&SeamError::SessionCapExhausted);
    assert_seam(&SeamKey("intro-call".to_owned()));
    assert_seam::<SeamObject>(&object);
    assert_seam(&request);
    assert_seam(&ranked);
    assert_seam(&result);
    assert_seam(&mask);

    // `BookingError` carries Display and std::error::Error from hand-written
    // impls, not from the derive list.
    let dynamic: &dyn std::error::Error = &SeamError::SessionCapExhausted;
    assert!(!dynamic.to_string().is_empty());

    takes_oracle(&FixtureSlotOracle::with_slots(Vec::new(), false));

    // mod.rs is declarations and re-exports only.
    let source = &lane_sources()[2];
    for definition in ["struct ", "enum ", "trait ", "impl ", "fn ", "type "] {
        assert!(
            !source.contains(definition),
            "booking/mod.rs must not define `{definition}`"
        );
    }
}

/// The mask shape is final: exactly five fields, half-open window, no artifact
/// wrapper and no migration path.
#[test]
fn booking_constraint_slot_mask_schema_is_final() {
    let mask = SlotMask {
        event_type: event_type(),
        window_start_utc: window().start,
        window_end_utc: window().end,
        slots: vec![slot(1_800_003_600, 1.0)],
        flex_used: true,
    };
    let value = serde_json::to_value(&mask).expect("mask serializes");
    let object = value.as_object().expect("mask is a JSON object");
    let mut keys = object.keys().cloned().collect::<Vec<_>>();
    keys.sort();
    assert_eq!(
        keys,
        vec![
            "event_type".to_owned(),
            "flex_used".to_owned(),
            "slots".to_owned(),
            "window_end_utc".to_owned(),
            "window_start_utc".to_owned(),
        ]
    );

    // Half-open [start, end): the rendered slot sits inside the window.
    assert!(mask.window_start_utc <= mask.slots[0].start_utc);
    assert!(mask.slots[0].end_utc <= mask.window_end_utc);

    // No artifact type and no migration path exists anywhere in the lane.
    for source in lane_sources() {
        assert!(!source.contains("SlotMaskArtifact"));
        assert!(!source.contains("migrate"));
    }
}

/// Order-insensitive payloads canonicalize to identical bytes and hashes;
/// unknown fields, bad minutes, inverted UTC windows, and wrong schema versions
/// all fail closed.
#[test]
fn booking_constraint_canonical_round_trip() {
    let backend_a = RecordingBackend::new(constraint_payload(
        &["wednesday", "monday", "monday"],
        &[(780, 1020), (540, 720), (780, 1020)],
    ));
    let backend_b = RecordingBackend::new(constraint_payload(
        &["monday", "wednesday"],
        &[(540, 720), (780, 1020)],
    ));

    let first = parsed_object(&backend_a);
    let second = parsed_object(&backend_b);

    assert_eq!(first, second, "semantically identical payloads converge");
    assert_eq!(
        first.canonical_bytes().expect("canonical bytes"),
        second.canonical_bytes().expect("canonical bytes"),
    );
    assert_eq!(
        first.canonical_hash().expect("canonical hash"),
        second.canonical_hash().expect("canonical hash"),
    );
    // De-duplication actually happened.
    assert_eq!(first.weekdays.len(), 2);
    assert_eq!(first.local_time_windows.len(), 2);

    // Unknown fields fail closed at the wire — including an explanation field.
    let unknown = json!({
        "schema_version": CONSTRAINT_SCHEMA_VERSION,
        "weekdays": [],
        "local_time_windows": [],
        "utc_window": null,
        "allow_flex_pool": false,
        "explanation": "the visitor said afternoons",
    });
    assert!(serde_json::from_value::<ConstraintObject>(unknown).is_err());

    // Invalid minute bounds fail closed.
    for (start_minute, end_minute) in [(1020u16, 780u16), (600, 600), (0, 1441)] {
        let object = ConstraintObject {
            local_time_windows: vec![LocalMinuteWindow {
                start_minute,
                end_minute,
            }],
            ..canonical_object()
        };
        assert!(
            matches!(
                object.canonicalize(),
                Err(BookingError::InvalidConstraint(_))
            ),
            "minute window {start_minute}..{end_minute} must fail closed"
        );
    }

    // An inverted UTC window fails closed.
    let inverted = ConstraintObject {
        utc_window: Some(TimeRange {
            start: 200,
            end: 100,
        }),
        ..canonical_object()
    };
    assert!(matches!(
        inverted.canonicalize(),
        Err(BookingError::InvalidConstraint(_))
    ));

    // An unsupported schema version fails closed.
    let stale = ConstraintObject {
        schema_version: CONSTRAINT_SCHEMA_VERSION + 1,
        ..canonical_object()
    };
    assert!(matches!(
        stale.canonicalize(),
        Err(BookingError::InvalidConstraint(_))
    ));

    // A non-canonical object cannot produce bytes at all.
    let unsorted = ConstraintObject {
        weekdays: vec![ConstraintWeekday::Wednesday, ConstraintWeekday::Monday],
        ..canonical_object()
    };
    assert!(unsorted.canonical_bytes().is_err());
}

/// The parse call is zero-temperature, JSON-schema, tool-free, bounded, on the
/// caller's cheap tier, and carries no hard-coded provider or model id.
#[test]
fn booking_constraint_fake_llm_request_is_bounded() {
    let backend = RecordingBackend::new(constraint_payload(&["monday"], &[(780, 1020)]));
    let _ = parsed_object(&backend);
    let request = backend.last();

    assert_eq!(request.params.get("temperature"), Some(&json!(0)));
    assert!(request.params.contains_key("max_output_tokens"));
    assert_eq!(
        request.params.get("max_input_bytes"),
        Some(&json!(parse_config().max_input_bytes)),
    );
    assert!(request.tools.is_empty(), "the parser gets no tools");
    assert!(matches!(
        request.envelope.response_format,
        ResponseFormat::Json { .. }
    ));
    assert_eq!(
        request.envelope.purpose,
        CallPurpose::Other {
            name: CONSTRAINT_PARSE_CALL_PURPOSE.to_owned()
        },
    );
    // The caller's cheap tier rides through untouched.
    assert_eq!(request.envelope.tier, cheap_tier());
    assert_eq!(request.envelope.tier.resolved().as_str(), "host-cheap-tier");
    // The model id is DERIVED from the resolved tier, never hard-coded.
    assert_eq!(request.model.name(), "host-cheap-tier");
    for source in lane_sources() {
        for vendor in ["openai/", "anthropic", "gpt-", "claude", "openrouter"] {
            assert!(
                !source.contains(vendor),
                "no provider/model id may be hard-coded: {vendor}"
            );
        }
    }

    // An unresolvable tier is InvalidConfig, never a silent fallback to an
    // expensive or ungoverned model.
    let blank = ConstraintParseConfig {
        tier: TierPrecedence {
            per_call: None,
            vault_policy: None,
            purpose_default: None,
            global_default: ModelTierRef("   ".to_owned()),
        },
        max_input_bytes: 512,
    };
    let calls_before = backend.calls();
    assert!(matches!(
        block_on_ready(parse_constraint_with_backend(
            &backend,
            &lease(),
            &ConstraintParseRequest {
                free_text: VISITOR_SENTENCE.to_owned(),
                detected_visitor_tz: "Europe/Warsaw".to_owned(),
                now_utc: 1,
            },
            &blank,
        )),
        Err(BookingError::InvalidConfig(_))
    ));

    // Input past the configured bound is refused before the backend is called.
    assert!(matches!(
        block_on_ready(parse_constraint_with_backend(
            &backend,
            &lease(),
            &ConstraintParseRequest {
                free_text: "x".repeat(parse_config().max_input_bytes + 1),
                detected_visitor_tz: "Europe/Warsaw".to_owned(),
                now_utc: 1,
            },
            &parse_config(),
        )),
        Err(BookingError::InvalidConstraint(_))
    ));
    assert_eq!(
        backend.calls(),
        calls_before,
        "a rejected config or over-long input never reaches the backend"
    );
}

/// The oracle sees only structured data. The visitor's sentence appears in no
/// solve request and in no continuation serialization.
#[test]
fn booking_constraint_free_text_never_reaches_oracle() {
    let oracle = FixtureSlotOracle::with_slots(vec![slot(1_800_003_600, 1.0)], false);
    let backend = RecordingBackend::new(constraint_payload(&["monday"], &[(780, 1020)]));
    let mut state = ConstraintSessionState::default();
    run_turn(&oracle, &backend, &mut state).expect("turn succeeds");

    let seen = oracle.seen();
    assert_eq!(seen.len(), 1);
    let request = &seen[0];
    assert_eq!(request.event_type, event_type());
    assert_eq!(request.window, window());
    assert_eq!(request.visitor_tz, "Europe/Warsaw");
    assert!(request.constraint.is_some());

    let serialized = serde_json::to_string(request).expect("solve request serializes");
    assert!(
        !serialized.contains("lunch") && !serialized.contains(VISITOR_SENTENCE),
        "the original sentence must be absent from the solve request: {serialized}"
    );
    // The whole payload is the four structured fields and nothing else.
    let value: JsonValue = serde_json::from_str(&serialized).expect("solve request is JSON");
    let mut keys = value
        .as_object()
        .expect("solve request is an object")
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    keys.sort();
    assert_eq!(
        keys,
        vec![
            "constraint".to_owned(),
            "event_type".to_owned(),
            "visitor_tz".to_owned(),
            "window".to_owned(),
        ]
    );

    // A parser that tries to smuggle the sentence through the one free-form
    // string it may emit is refused before the solve.
    let smuggler = RecordingBackend::new(
        json!({
            "disposition": "constraint",
            "object": {
                "schema_version": CONSTRAINT_SCHEMA_VERSION,
                "weekdays": [],
                "local_time_windows": [],
                "utc_window": null,
                "allow_flex_pool": false,
            },
            "visitor_tz_override": VISITOR_SENTENCE,
        })
        .to_string(),
    );
    let mut fresh = ConstraintSessionState::default();
    let clean = FixtureSlotOracle::with_slots(vec![slot(1_800_003_600, 1.0)], false);
    assert!(matches!(
        run_turn(&clean, &smuggler, &mut fresh),
        Err(BookingError::InvalidConstraint(_))
    ));
    assert!(clean.seen().is_empty(), "a smuggled tz never reaches solve");
}

/// Identical normalized requests produce identical results, and the fixture is
/// compiled by plain `#[cfg(test)]` with no feature gate.
#[test]
fn booking_constraint_fixture_oracle_is_deterministic() {
    let oracle = FixtureSlotOracle::with_slots(
        vec![slot(1_800_003_600, 0.9), slot(1_800_007_200, 0.4)],
        true,
    );
    let request = SolveRequest {
        event_type: event_type(),
        window: window(),
        constraint: Some(canonical_object()),
        visitor_tz: "Europe/Warsaw".to_owned(),
    };
    let first = oracle.solve(&request).expect("first solve");
    let second = oracle.solve(&request).expect("second solve");
    assert_eq!(first, second);
    assert!(first.flex_used);

    // The fixture is gated by plain `#[cfg(test)]` alone.
    let seam = include_str!("constraint.rs");
    assert!(seam.contains("#[cfg(test)]\npub(crate) mod fixture"));
    // No `cfg(feature = ...)` of ANY kind exists in the lane, so neither
    // `test-hooks` nor `test-support` can be referenced by construction. One
    // TimeRange import path, and no mutable vault receiver.
    for source in lane_sources() {
        assert!(!source.contains("feature = "), "no cargo feature gate");
        assert!(!source.contains("test-hooks"));
        assert!(!source.contains("test-support"));
        assert!(!source.contains("&mut Vault"));
        if source.contains("TimeRange") {
            assert!(source.contains("use crate::temporal::TimeRange;"));
        }
    }
    // ONE-1823's solver does not exist yet: these oracles run without it.
    assert!(
        !std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/booking/solver.rs"
        ))
        .exists()
    );
}

/// The front forwards the parsed object and renders the oracle's own UTC
/// integers — it never invents, rewrites, or rounds a time.
#[test]
fn booking_constraint_mask_intersection_is_oracle_owned() {
    let slots = vec![slot(1_800_003_600, 0.9), slot(1_800_007_200, 0.4)];
    let oracle = FixtureSlotOracle::with_slots(slots.clone(), true);
    let backend = RecordingBackend::new(constraint_payload(&["monday"], &[(780, 1020)]));
    let mut state = ConstraintSessionState::default();

    let ConstraintFrontOutcome::Slots(reply) =
        run_turn(&oracle, &backend, &mut state).expect("turn")
    else {
        panic!("expected slots");
    };

    // flex_used and every slot survive untouched.
    assert!(reply.solve_result.flex_used);
    assert_eq!(reply.solve_result.slots, slots);

    // The rendered buttons carry the oracle's exact epoch integers.
    let rendered = buttons(&reply.card);
    assert_eq!(rendered.len(), slots.len());
    for (control, expected) in rendered.iter().zip(&slots) {
        assert_eq!(
            control.label.as_str(),
            format!("{}-{}", expected.start_utc, expected.end_utc),
        );
    }

    // The oracle received the canonicalized object the parser produced.
    let seen = oracle.seen();
    let forwarded = seen[0].constraint.as_ref().expect("constraint forwarded");
    forwarded.validate().expect("forwarded object is canonical");
}

/// 0 slots continues by email, 1..=3 render exactly that many buttons, and more
/// than 3 truncates to the top-ranked 3 without inventing anything.
#[test]
fn booking_constraint_reply_shape_is_one_voice_two_or_three_buttons() {
    for count in 1usize..=3 {
        let slots = (0..count)
            .map(|index| {
                slot(
                    1_800_003_600 + index as u64 * 1800,
                    1.0 - index as f32 * 0.1,
                )
            })
            .collect::<Vec<_>>();
        let oracle = FixtureSlotOracle::with_slots(slots.clone(), false);
        let backend = RecordingBackend::new(constraint_payload(&["monday"], &[(780, 1020)]));
        let mut state = ConstraintSessionState::default();
        let ConstraintFrontOutcome::Slots(reply) =
            run_turn(&oracle, &backend, &mut state).expect("turn")
        else {
            panic!("expected slots for {count}");
        };
        assert_eq!(voice_lines(&reply.card), 1, "exactly one voice line");
        // A single slot renders one button: the front never duplicates or
        // invents a second one to reach a nicer shape.
        assert_eq!(buttons(&reply.card).len(), count);
    }

    // Five slots truncate to the top-ranked three, in the oracle's own order.
    let slots = vec![
        slot(1_800_000_100, 0.10),
        slot(1_800_000_200, 0.90),
        slot(1_800_000_300, 0.50),
        slot(1_800_000_400, 0.95),
        slot(1_800_000_500, 0.20),
    ];
    let oracle = FixtureSlotOracle::with_slots(slots.clone(), false);
    let backend = RecordingBackend::new(constraint_payload(&["monday"], &[(780, 1020)]));
    let mut state = ConstraintSessionState::default();
    let ConstraintFrontOutcome::Slots(reply) =
        run_turn(&oracle, &backend, &mut state).expect("turn")
    else {
        panic!("expected slots");
    };
    let labels = buttons(&reply.card)
        .iter()
        .map(|control| control.label.as_str().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        labels,
        vec![
            "1800000200-1800002000".to_owned(),
            "1800000300-1800002100".to_owned(),
            "1800000400-1800002200".to_owned(),
        ],
        "top-ranked three, in the oracle's order"
    );
    // The full result is still reported; truncation is presentational only.
    assert_eq!(reply.solve_result.slots, slots);

    // Zero slots is a continuation, not an empty card.
    let empty = FixtureSlotOracle::with_slots(Vec::new(), false);
    let backend = RecordingBackend::new(constraint_payload(&["monday"], &[(780, 1020)]));
    let mut state = ConstraintSessionState::default();
    assert!(matches!(
        run_turn(&empty, &backend, &mut state).expect("turn"),
        ConstraintFrontOutcome::ContinueByEmail(_)
    ));
}

/// Every proposed slot rides `BOOKING_SLOT_BUTTON_ACTION`, and nothing else on
/// any surface can encode a hold, confirm, or commit.
#[test]
fn booking_constraint_commit_is_button_only() {
    let slots = vec![slot(1_800_003_600, 0.9), slot(1_800_007_200, 0.4)];
    let oracle = FixtureSlotOracle::with_slots(slots, false);
    let backend = RecordingBackend::new(constraint_payload(&["monday"], &[(780, 1020)]));
    let mut state = ConstraintSessionState::default();
    let ConstraintFrontOutcome::Slots(reply) =
        run_turn(&oracle, &backend, &mut state).expect("turn")
    else {
        panic!("expected slots");
    };

    let rendered = buttons(&reply.card);
    assert_eq!(rendered.len(), 2);
    for control in rendered {
        assert_eq!(control.action.command.as_str(), BOOKING_SLOT_BUTTON_ACTION);
    }

    // The card offers buttons and nothing else interactive: no text input can
    // carry a commit.
    let mut stack = vec![reply.card.tree.root()];
    while let Some(node) = stack.pop() {
        if let LensAtom::SelfUi(control) = &node.atom {
            assert!(
                matches!(control, SelfUiControl::Button(_)),
                "the only control on a booking card is a button"
            );
        }
        for child in &node.children {
            stack.push(child);
        }
    }

    // No lifecycle verb exists anywhere in the lane: proposing is the ceiling.
    for source in lane_sources() {
        for verb in [
            "fn hold",
            "fn confirm",
            "fn commit",
            "fn cancel",
            "fn reschedule",
        ] {
            assert!(
                !source.contains(verb),
                "no lifecycle verb in this lane: {verb}"
            );
        }
    }
}

/// An exhausted session returns `SessionCapExhausted` before the backend or the
/// oracle is touched.
#[test]
fn booking_constraint_caps_stop_before_backend() {
    let oracle = FixtureSlotOracle::with_slots(vec![slot(1_800_003_600, 1.0)], false);
    let backend = RecordingBackend::new(constraint_payload(&["monday"], &[(780, 1020)]));
    let mut state = ConstraintSessionState {
        turns_used: caps().max_turns,
        model_calls_used: 0,
    };
    assert!(matches!(
        run_turn(&oracle, &backend, &mut state),
        Err(BookingError::SessionCapExhausted)
    ));
    assert_eq!(backend.calls(), 0, "no model call on an exhausted session");
    assert!(oracle.seen().is_empty(), "no solve on an exhausted session");

    // The model-call dial is independent of the turn dial.
    let mut spent_calls = ConstraintSessionState {
        turns_used: 0,
        model_calls_used: caps().max_model_calls,
    };
    assert!(matches!(
        run_turn(&oracle, &backend, &mut spent_calls),
        Err(BookingError::SessionCapExhausted)
    ));
    assert_eq!(backend.calls(), 0);

    // Caps stay caller-supplied dials: a fresh session admits the same turn.
    let mut fresh = ConstraintSessionState::default();
    assert!(run_turn(&oracle, &backend, &mut fresh).is_ok());
    assert_eq!(fresh.turns_used, 1);
    assert_eq!(fresh.model_calls_used, 1);
}

/// Off-topic yields exactly one structured deflect: no solve, no controls, no
/// second turn.
#[test]
fn booking_constraint_off_topic_is_one_deflect() {
    let oracle = FixtureSlotOracle::with_slots(vec![slot(1_800_003_600, 1.0)], false);
    let backend = RecordingBackend::new(json!({ "disposition": "off_topic" }).to_string());
    let mut state = ConstraintSessionState::default();

    let ConstraintFrontOutcome::Deflect(deflect) =
        run_turn(&oracle, &backend, &mut state).expect("turn")
    else {
        panic!("expected a deflect");
    };

    assert_eq!(voice_lines(&deflect.card), 1);
    assert!(
        buttons(&deflect.card).is_empty(),
        "a deflect carries no control, so it can carry no action"
    );
    assert!(
        oracle.seen().is_empty(),
        "off-topic never reaches the solver"
    );
    assert_eq!(backend.calls(), 1, "exactly one parse pass, no second turn");
    // The deflect line is the host's configured copy, verbatim.
    let rendered = serde_json::to_string(&deflect.card).expect("card serializes");
    assert!(rendered.contains(&copy().off_topic_line));
}

/// The rung-2 continuation round-trips the exact canonical object, visitor TZ,
/// event type, and session reference — and carries no raw free text.
#[test]
fn booking_constraint_email_continuation_carries_same_object() {
    let oracle = FixtureSlotOracle::with_slots(Vec::new(), false);
    let backend = RecordingBackend::new(constraint_payload(
        &["wednesday", "monday"],
        &[(780, 1020), (540, 720)],
    ));
    let mut state = ConstraintSessionState::default();

    let ConstraintFrontOutcome::ContinueByEmail(continuation) =
        run_turn(&oracle, &backend, &mut state).expect("turn")
    else {
        panic!("expected a continuation");
    };

    assert_eq!(continuation.event_type, event_type());
    assert_eq!(continuation.visitor_tz, "Europe/Warsaw");
    assert_eq!(continuation.session_ref, "sess-1816");

    // The envelope's object is the same one the oracle was handed.
    let solved = oracle.seen();
    let forwarded = solved[0].constraint.as_ref().expect("constraint forwarded");
    assert_eq!(&continuation.constraint, forwarded);
    assert_eq!(
        continuation.constraint.canonical_hash().expect("hash"),
        forwarded.canonical_hash().expect("hash"),
    );

    let encoded = serde_json::to_string(&continuation).expect("continuation serializes");
    assert!(!encoded.contains("lunch") && !encoded.contains(VISITOR_SENTENCE));

    // It survives a wire round-trip unchanged.
    let restored: ConstraintContinuation =
        serde_json::from_str(&encoded).expect("continuation deserializes");
    assert_eq!(restored, continuation);
    restored.constraint.validate().expect("still canonical");
}
