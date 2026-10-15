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

use crate::llm::{
    BudgetLease, ContentPart, FatalLlmError, FinishReason, LlmBackend, LlmGenerateFuture,
    LlmInputUsage, LlmMessage, LlmMessageRole, LlmOutputUsage, LlmRequest, LlmResponse,
    LlmStreamResult, LlmUsage, ModelTierRef, TierPrecedence,
};
use crate::temporal::TimeRange;

use super::constraint::{
    BookingError, CONSTRAINT_SCHEMA_VERSION, ConstraintObject, ConstraintParseConfig,
    ConstraintParseDisposition, ConstraintParseRequest, ConstraintWeekday, LocalMinuteWindow,
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
        per_seat: None,
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

fn lease() -> BudgetLease {
    BudgetLease::for_test("booking-constraint-lease")
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

// -------------------------------------------------------------------------
// Oracles
// -------------------------------------------------------------------------

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
