//! ONE-1817 [BK-06] booking anti-abuse route guards.
//!
//! The HTTP adapter over `oneiron::booking::anti_abuse`. The later BK-04 /
//! BK-08 slot-list, hold, and book handlers call `enforce_*` BEFORE touching
//! the solver or lifecycle, and use the response-cache helpers when they
//! serve a listing; enforcement never moves below the route layer. Guards
//! thread `State<Arc<SyncServer>>` and fail as `crate::error::ApiError` —
//! no invented request state and no new server field: rows, counters, and
//! the cache all persist through `server.vault` under the booking-only meta
//! prefix owned by the engine.
//!
//! Behavioural law comes from the engine:
//! - honeypot and too-fast submissions leave as `SilentOk`, an HTTP 200
//!   shape indistinguishable from ordinary success, with no booking-side
//!   write and no revealing log;
//! - rate blocks are logged with hashed request keys only and surface as
//!   `RetryAfter` so the route can emit `Retry-After`;
//! - invalid email evidence prompts a correction rather than hard-blocking;
//! - borderline traffic is quarantined into a durable pending-review record
//!   and accepted, never silently deleted.

use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use oneiron::booking::EventTypeKey;
use oneiron::booking::anti_abuse::{
    BookingAbuseVerdict, BookingAntiAbuseRuleRow, BookingQuarantineAdmission, BookingRateDecision,
    BookingRequestFacts, admit_quarantine_submission, applicable_booking_anti_abuse_rules,
    book_rate_knobs, evaluate_booking_book_request, evaluate_booking_hold_request,
    evaluate_booking_slot_list_request, hold_rate_knobs, observe_book_request,
    observe_hold_request, observe_slot_list_request, read_slot_list_cache,
    server_submission_fingerprint, slot_list_rate_knobs, write_slot_list_cache,
};
use oneiron::{EntityId, Vault};

use crate::error::ApiError;
use crate::server::SyncServer;

/// The hashed identity behind one rate bucket. With an email available the
/// engine keys the book window on the IP+email pair, so two people behind
/// one corporate NAT keep independent budgets; raw addresses never cross
/// into persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BookingRateKey {
    pub ip_hash: [u8; 32],
    pub email_hash: Option<[u8; 32]>,
}

/// How a guard call disposes of the request. Route handlers translate:
/// `SilentOk` answers exactly like an ordinary 200, `RetryAfter` carries the
/// `Retry-After` hint, `PromptCorrection` is a 200-class correction body,
/// and `QuarantineAndAccept` accepts while routing to owner review.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BookingHttpDisposition {
    Continue,
    SilentOk,
    RetryAfter { seconds: u64 },
    PromptCorrection { body: String },
    QuarantineAndAccept,
}

fn now_secs() -> std::result::Result<u64, ApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ApiError::internal_server_error("booking anti-abuse clock unavailable"))
}

fn engine_error(error: oneiron::booking::BookingError) -> ApiError {
    tracing::error!(error = %error, "booking anti-abuse engine error");
    ApiError::internal_server_error("booking anti-abuse failure")
}

fn correction_body(field: &'static str, message: &str) -> String {
    serde_json::json!({
        "ok": false,
        "action": "correct",
        "field": field,
        "message": message,
    })
    .to_string()
}

fn hex_prefix(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(8);
    for byte in &bytes[..4] {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0F)]));
    }
    out
}

fn log_rate_block(endpoint: &'static str, ip_hash: &[u8; 32], retry_after_secs: u64) {
    tracing::info!(
        endpoint = endpoint,
        ip = hex_prefix(ip_hash),
        retry_after_secs = retry_after_secs,
        "booking anti-abuse rate block"
    );
}

/// Loads every row that governs this request: the page-wide stack PLUS the
/// named event type's exact stack. A page-wide owner configuration must
/// keep applying when a request carries an event type, so the adapter never
/// loads by exact scope alone.
fn load_rows(
    vault: &Vault,
    facts: &BookingRequestFacts,
) -> std::result::Result<Vec<BookingAntiAbuseRuleRow>, ApiError> {
    applicable_booking_anti_abuse_rules(vault, &facts.page_ref, &facts.event_type)
        .map_err(engine_error)
}

/// Maps an engine verdict onto the public disposition. Returns `None` for
/// `Allow` so the caller can move on to its endpoint-specific counter.
/// `SilentHttp200Reject` performs no write and emits no request-bound log:
/// from the outside the answer is just 200.
fn disposition_from_verdict(
    endpoint: &'static str,
    facts: &BookingRequestFacts,
    verdict: BookingAbuseVerdict,
) -> std::result::Result<Option<BookingHttpDisposition>, ApiError> {
    match verdict {
        BookingAbuseVerdict::Allow => Ok(None),
        BookingAbuseVerdict::SilentHttp200Reject => Ok(Some(BookingHttpDisposition::SilentOk)),
        BookingAbuseVerdict::PromptCorrection { field, message } => {
            Ok(Some(BookingHttpDisposition::PromptCorrection {
                body: correction_body(field, &message),
            }))
        }
        BookingAbuseVerdict::RateLimited { retry_after_secs } => {
            log_rate_block(endpoint, &facts.ip_hash, retry_after_secs);
            Ok(Some(BookingHttpDisposition::RetryAfter {
                seconds: retry_after_secs,
            }))
        }
        BookingAbuseVerdict::Quarantine { .. } => {
            // Book admission owns quarantine's duplicate/quota/write transaction.
            Err(ApiError::internal_server_error(
                "quarantine requires book admission",
            ))
        }
    }
}

/// Slot-list guard: silent bot rejects, then the per-IP minute window, with
/// the response cache discharging requests before any quota is spent.
///
/// # Errors
///
/// [`ApiError`] internal-server on engine or storage failure.
pub(crate) async fn enforce_slot_list(
    State(server): State<Arc<SyncServer>>,
    facts: BookingRequestFacts,
) -> std::result::Result<BookingHttpDisposition, ApiError> {
    let vault = &server.vault;
    let rows = load_rows(vault, &facts)?;
    let Some((per_minute_per_ip, _)) =
        slot_list_rate_knobs(&rows, &facts.page_ref, &facts.event_type)
    else {
        return Ok(BookingHttpDisposition::Continue);
    };
    let now = now_secs()?;
    // A fresh cached listing answers without spending quota; the handler
    // serves the body through `cached_slot_list_body`.
    if read_slot_list_cache(vault, &facts.page_ref, facts.event_type.as_ref(), now)
        .map_err(engine_error)?
        .is_some()
    {
        return Ok(BookingHttpDisposition::Continue);
    }
    match observe_slot_list_request(vault, &facts.ip_hash, per_minute_per_ip, now)
        .map_err(engine_error)?
    {
        BookingRateDecision::Allowed => {
            let verdict = evaluate_booking_slot_list_request(&rows, &facts);
            if let Some(disposition) = disposition_from_verdict("slot-list", &facts, verdict)? {
                return Ok(disposition);
            }
            Ok(BookingHttpDisposition::Continue)
        }
        BookingRateDecision::Exceeded { retry_after_secs } => {
            log_rate_block("slot-list", &facts.ip_hash, retry_after_secs);
            Ok(BookingHttpDisposition::RetryAfter {
                seconds: retry_after_secs,
            })
        }
    }
}

/// Hold guard: silent bot rejects, the one-active-hold-per-session verdict
/// from the engine, then the per-IP minute window.
///
/// # Errors
///
/// [`ApiError`] internal-server on engine or storage failure.
pub(crate) async fn enforce_hold(
    State(server): State<Arc<SyncServer>>,
    facts: BookingRequestFacts,
) -> std::result::Result<BookingHttpDisposition, ApiError> {
    let vault = &server.vault;
    let rows = load_rows(vault, &facts)?;
    let verdict = evaluate_booking_hold_request(&rows, &facts);
    if let Some(disposition) = disposition_from_verdict("hold", &facts, verdict)? {
        return Ok(disposition);
    }
    if let Some((max_active_per_session, _)) =
        hold_rate_knobs(&rows, &facts.page_ref, &facts.event_type)
        && facts.active_holds_for_session >= max_active_per_session
    {
        return Ok(BookingHttpDisposition::RetryAfter { seconds: 60 });
    }
    let Some((_, per_minute_per_ip)) = hold_rate_knobs(&rows, &facts.page_ref, &facts.event_type)
    else {
        return Ok(BookingHttpDisposition::Continue);
    };
    match observe_hold_request(vault, &facts.ip_hash, per_minute_per_ip, now_secs()?)
        .map_err(engine_error)?
    {
        BookingRateDecision::Allowed => Ok(BookingHttpDisposition::Continue),
        BookingRateDecision::Exceeded { retry_after_secs } => {
            log_rate_block("hold", &facts.ip_hash, retry_after_secs);
            Ok(BookingHttpDisposition::RetryAfter {
                seconds: retry_after_secs,
            })
        }
    }
}

/// Book guard: silent bot rejects, the active-future-booking verdict from
/// the engine, then the minute window keyed on the combined IP+email pair
/// whenever an email is available.
///
/// # Errors
///
/// [`ApiError`] internal-server on engine or storage failure.
pub(crate) async fn enforce_book(
    State(server): State<Arc<SyncServer>>,
    mut facts: BookingRequestFacts,
) -> std::result::Result<BookingHttpDisposition, ApiError> {
    // This is the trusted production admission boundary: never honour a
    // fingerprint supplied by the transport.
    facts.submission_fingerprint = server_submission_fingerprint(&facts);
    let vault = &server.vault;
    let rows = load_rows(vault, &facts)?;
    let verdict = evaluate_booking_book_request(&rows, &facts);
    let is_quarantine = matches!(verdict, BookingAbuseVerdict::Quarantine { .. });
    let per_minute_per_ip = match book_rate_knobs(&rows, &facts.page_ref, &facts.event_type) {
        Some((per_minute_per_ip, _)) => per_minute_per_ip,
        // Quarantine is a write path, so it must always consume a bounded
        // bucket even when the owner has not configured BookRate.
        None if is_quarantine => NonZeroU32::new(1).expect("one is non-zero"),
        None => {
            return disposition_from_verdict("book", &facts, verdict)
                .map(|disposition| disposition.unwrap_or(BookingHttpDisposition::Continue));
        }
    };
    let key = BookingRateKey {
        ip_hash: facts.ip_hash,
        email_hash: facts.email_hash,
    };
    if !is_quarantine {
        if let Some(disposition) = disposition_from_verdict("book", &facts, verdict.clone())? {
            return Ok(disposition);
        }
    }
    if let BookingAbuseVerdict::Quarantine { reason } = &verdict {
        // This one engine door serializes exact-retry lookup, aggregate quota,
        // and first durable quarantine write.
        match admit_quarantine_submission(vault, &facts, reason, per_minute_per_ip, now_secs()?)
            .map_err(engine_error)?
        {
            BookingQuarantineAdmission::Accepted(receipt) => {
                tracing::info!(
                    endpoint = "book",
                    claim_ref = %receipt.claim_ref,
                    "booking anti-abuse quarantine accepted"
                );
                return Ok(BookingHttpDisposition::QuarantineAndAccept);
            }
            BookingQuarantineAdmission::RateLimited { retry_after_secs } => {
                log_rate_block("book", &facts.ip_hash, retry_after_secs);
                return Ok(BookingHttpDisposition::RetryAfter {
                    seconds: retry_after_secs,
                });
            }
        }
    }
    // A non-quarantine request consumes its identity confirmation bucket.
    match observe_book_request(
        vault,
        &key.ip_hash,
        key.email_hash.as_ref(),
        per_minute_per_ip,
        now_secs()?,
    )
    .map_err(engine_error)?
    {
        BookingRateDecision::Allowed => Ok(BookingHttpDisposition::Continue),
        BookingRateDecision::Exceeded { retry_after_secs } => {
            log_rate_block("book", &facts.ip_hash, retry_after_secs);
            Ok(BookingHttpDisposition::RetryAfter {
                seconds: retry_after_secs,
            })
        }
    }
}

/// A fresh cached slot-list body for one scope, if one is stored. Handlers
/// consult this after `enforce_slot_list` reports `Continue`.
///
/// # Errors
///
/// [`ApiError`] internal-server on engine or storage failure.
pub(crate) fn cached_slot_list_body(
    server: &SyncServer,
    page_ref: &EntityId,
    event_type: Option<&EventTypeKey>,
) -> std::result::Result<Option<Vec<u8>>, ApiError> {
    read_slot_list_cache(&server.vault, page_ref, event_type, now_secs()?).map_err(engine_error)
}

/// Stores one slot-list response under the governing rule's cache TTL.
/// Returns `false` when no slot-list rule is seeded for the scope — nothing
/// is cached rather than an invented TTL.
///
/// # Errors
///
/// [`ApiError`] internal-server on engine or storage failure.
pub(crate) fn remember_slot_list_body(
    server: &SyncServer,
    page_ref: &EntityId,
    event_type: Option<&EventTypeKey>,
    body: &[u8],
) -> std::result::Result<bool, ApiError> {
    let rows = applicable_booking_anti_abuse_rules(&server.vault, page_ref, &event_type.cloned())
        .map_err(engine_error)?;
    let Some((_, cache_ttl_secs)) = slot_list_rate_knobs(&rows, page_ref, &event_type.cloned())
    else {
        return Ok(false);
    };
    write_slot_list_cache(
        &server.vault,
        page_ref,
        event_type,
        body,
        cache_ttl_secs,
        now_secs()?,
    )
    .map_err(engine_error)?;
    Ok(true)
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use oneiron::booking::anti_abuse::{
        BookingAntiAbuseOwnerConfig, BookingRuleScope, apply_rule_amendment,
        booking_anti_abuse_rules, booking_email_hash, booking_ip_hash, booking_session_hash,
        default_booking_anti_abuse_rows,
    };
    use oneiron::booking::config::{
        BOOKING_EVENT_TYPE_PREDICATE, BOOKING_EVENT_TYPE_SCHEMA_VERSION,
        BookingEventTypeClaimValue, DEFAULT_INTRO_DURATION_MIN, DEFAULT_MIN_NOTICE_SECS,
        EventTypeConfig, HostAvailabilityConfig, RoutingMode, WeeklyWallWindow,
        encode_event_type_claim_value,
    };
    use oneiron::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
    use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};

    const PAGE_BYTE: u8 = 0x61;
    const OTHER_PAGE_BYTE: u8 = 0x62;

    fn test_server() -> (tempfile::TempDir, Arc<SyncServer>) {
        let dir = tempfile::tempdir().expect("temp vault dir");
        let vault = Arc::new(
            oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).expect("open vault"),
        );
        let server = Arc::new(
            SyncServer::new(vault, crate::config::SyncServerConfig::default())
                .expect("sync server"),
        );
        (dir, server)
    }

    fn page() -> EntityId {
        EntityId::from_bytes([PAGE_BYTE; 16]).expect("page id")
    }

    fn other_page() -> EntityId {
        EntityId::from_bytes([OTHER_PAGE_BYTE; 16]).expect("other page id")
    }

    fn event() -> EventTypeKey {
        EventTypeKey("intro-call".to_owned())
    }

    fn nz16(value: u16) -> NonZeroU16 {
        match NonZeroU16::new(value) {
            Some(nz) => nz,
            None => panic!("fixture must be non-zero"),
        }
    }

    fn nz32(value: u32) -> NonZeroU32 {
        match NonZeroU32::new(value) {
            Some(nz) => nz,
            None => panic!("fixture must be non-zero"),
        }
    }

    fn nz64(value: u64) -> NonZeroU64 {
        match NonZeroU64::new(value) {
            Some(nz) => nz,
            None => panic!("fixture must be non-zero"),
        }
    }

    /// The ratified owner-supplied stack, mirroring the engine fixtures.
    fn owner_config() -> BookingAntiAbuseOwnerConfig {
        BookingAntiAbuseOwnerConfig {
            min_intake_chars: nz16(10),
            normal_notice_secs: nz64(86_400),
            high_value_notice_secs: nz64(172_800),
            min_submit_millis: nz64(1_500),
            slot_list_per_minute_per_ip: nz32(120),
            slot_list_cache_ttl_secs: nz64(45),
            book_per_minute_per_ip: nz32(10),
            max_active_future_per_email: 1,
            max_active_holds_per_session: 1,
            hold_per_minute_per_ip: nz32(30),
            tentative_confirm_ttl_secs: nz64(900),
        }
    }

    fn install_defaults(server: &SyncServer) {
        install_defaults_scoped(server, Some(event()));
    }

    fn install_live_booking_config(server: &SyncServer, event_type: EventTypeKey) {
        let config = BookingEventTypeClaimValue {
            schema_version: BOOKING_EVENT_TYPE_SCHEMA_VERSION,
            page_ref: page(),
            config: EventTypeConfig {
                key: event_type,
                duration_min: DEFAULT_INTRO_DURATION_MIN,
                slot_step_min: 30,
                pre_buffer_min: 0,
                post_buffer_min: 0,
                min_notice_secs: DEFAULT_MIN_NOTICE_SECS,
                booking_window_secs: 86_400,
                daily_cap: None,
                weekly_cap: None,
                routing: RoutingMode::Either,
                hosts: vec![HostAvailabilityConfig {
                    host_ref: EntityId::from_bytes([0x63; 16]).expect("host fixture id"),
                    calendar_refs: vec![
                        EntityId::from_bytes([0x64; 16]).expect("calendar fixture id"),
                    ],
                    host_tz: "UTC".to_owned(),
                    working_hours: vec![WeeklyWallWindow {
                        weekday: 0,
                        start_minute: 0,
                        end_minute: 60,
                    }],
                    preferred_hours: Vec::new(),
                }],
                flex_windows: Vec::new(),
            },
        };
        let body = ClaimBody::new(
            BOOKING_EVENT_TYPE_PREDICATE,
            ClaimSubject::Entity(page()),
            encode_event_type_claim_value(&config).expect("config value"),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        server
            .vault
            .put_claim(
                &EntityId::from_bytes([0x65; 16]).expect("config fixture id"),
                &body,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
            )
            .expect("live booking config");
    }

    fn install_defaults_scoped(server: &SyncServer, event_type: Option<EventTypeKey>) {
        // The quarantine path mints its pending-review claim with the page
        // as the subject through the ordinary claim door, so the fixture
        // page exists the way a published booking page does.
        server
            .vault
            .put_entity(
                &page(),
                oneiron::registry::ENTITY_TYPE_EVENT,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                b"booking page fixture",
            )
            .expect("page entity");
        install_live_booking_config(server, event_type.clone().unwrap_or_else(event));
        let rows = default_booking_anti_abuse_rows(page(), event_type, &owner_config())
            .expect("seed rows");
        for row in rows {
            apply_rule_amendment(&server.vault, 0, row, None).expect("install row");
        }
    }

    fn facts() -> BookingRequestFacts {
        BookingRequestFacts {
            page_ref: page(),
            event_type: Some(event()),
            ip_hash: booking_ip_hash("198.51.100.23"),
            email_hash: Some(booking_email_hash("ada@example.org")),
            session_hash: Some(booking_session_hash("sess-fixture")),
            started_at_millis: 4_000_000,
            submitted_at_millis: 4_000_000 + 4_000,
            submission_fingerprint: [0xA5; 32],
            selected_slot_hash: [0xB1; 32],
            intake_content_hash: [0xC2; 32],
            honeypot_nonempty: false,
            intake_chars: 32,
            active_future_bookings_for_email: 0,
            active_holds_for_session: 0,
            email: None,
        }
    }

    #[tokio::test]
    async fn honeypot_and_fast_submit_are_silent_200_without_writes() {
        let (_dir, server) = test_server();
        install_defaults(&server);

        let mut honeypot = facts();
        honeypot.honeypot_nonempty = true;
        let mut fast = facts();
        fast.submitted_at_millis = fast.started_at_millis + 30;

        let first = enforce_book(State(server.clone()), honeypot.clone())
            .await
            .expect("honeypot guard answers");
        let second = enforce_book(State(server.clone()), fast.clone())
            .await
            .expect("floor guard answers");
        assert_eq!(first, BookingHttpDisposition::SilentOk);
        assert_eq!(
            first, second,
            "both bot signals must be one indistinguishable 200 shape"
        );
        let third = enforce_book(State(server.clone()), honeypot)
            .await
            .expect("repeat honeypot");
        let fourth = enforce_book(State(server.clone()), fast)
            .await
            .expect("repeat fast");
        assert_eq!(third, fourth);
        assert_eq!(third, first);

        // No booking-side write: the same IP still holds its entire 10/min
        // book budget, so none of the four silent rejections spent a token.
        let mut legit = facts();
        legit.honeypot_nonempty = false;
        for _ in 0..10 {
            let disposition = enforce_book(State(server.clone()), legit.clone())
                .await
                .expect("legit book");
            assert_eq!(disposition, BookingHttpDisposition::Continue);
        }
        let eleventh = enforce_book(State(server.clone()), legit)
            .await
            .expect("budget exhaustion");
        assert!(
            matches!(eleventh, BookingHttpDisposition::RetryAfter { .. }),
            "the live counter proves the budget is exactly ten and the silent calls spent none: {eleventh:?}"
        );

        // And no rule churn: the ten seeded rows are all that exists.
        let rows = booking_anti_abuse_rules(
            &server.vault,
            &BookingRuleScope {
                page_ref: page(),
                event_type: Some(event()),
            },
        )
        .expect("rows");
        assert_eq!(rows.len(), 10);
    }

    #[tokio::test]
    async fn slot_list_ignores_default_form_timestamps_but_spends_its_ip_quota() {
        let (_dir, server) = test_server();
        install_defaults(&server);

        // Listing has no form submission. The ordinary zero defaults must not
        // accidentally trip the book-only submit-floor rule.
        let mut listing = facts();
        listing.started_at_millis = 0;
        listing.submitted_at_millis = 0;
        listing.email_hash = None;

        let first = enforce_slot_list(State(server.clone()), listing.clone())
            .await
            .expect("ordinary slot list");
        assert_eq!(first, BookingHttpDisposition::Continue);
        assert_ne!(first, BookingHttpDisposition::SilentOk);

        for _ in 0..119 {
            assert_eq!(
                enforce_slot_list(State(server.clone()), listing.clone())
                    .await
                    .expect("slot-list quota"),
                BookingHttpDisposition::Continue
            );
        }
        let exhausted = enforce_slot_list(State(server.clone()), listing)
            .await
            .expect("slot-list exhaustion");
        assert!(
            matches!(exhausted, BookingHttpDisposition::RetryAfter { .. }),
            "an ordinary listing consumes the endpoint quota: {exhausted:?}"
        );
    }

    #[tokio::test]
    async fn slot_list_limit_is_ip_scoped_and_cache_is_30_to_60_seconds() {
        let (_dir, server) = test_server();
        install_defaults(&server);

        let mut ip_one = facts();
        ip_one.ip_hash = booking_ip_hash("203.0.113.60");
        ip_one.email_hash = None;
        // 120 allowed, the 121st limited — in ONE sixty-second window.
        for _ in 0..120 {
            let disposition = enforce_slot_list(State(server.clone()), ip_one.clone())
                .await
                .expect("slot list");
            assert_eq!(disposition, BookingHttpDisposition::Continue);
        }
        let limited = enforce_slot_list(State(server.clone()), ip_one.clone())
            .await
            .expect("limit answer");
        let BookingHttpDisposition::RetryAfter { seconds } = limited else {
            panic!("the 121st listing must be rate limited: {limited:?}");
        };
        assert!((1..=60).contains(&seconds), "Retry-After inside the window");

        // The limit is IP-scoped: a fresh address keeps its own budget.
        let mut ip_two = facts();
        ip_two.ip_hash = booking_ip_hash("203.0.113.61");
        ip_two.email_hash = None;
        let disposition = enforce_slot_list(State(server.clone()), ip_two)
            .await
            .expect("fresh ip");
        assert_eq!(disposition, BookingHttpDisposition::Continue);

        // The response cache discharges requests without spending quota —
        // which is exactly how a page can survive the 120/min envelope.
        let body = b"{\"slots\":[1,2,3]}".to_vec();
        assert!(
            remember_slot_list_body(&server, &page(), Some(&event()), &body).expect("cache write"),
            "the slot-list rule supplies the cache TTL"
        );
        assert_eq!(
            cached_slot_list_body(&server, &page(), Some(&event())).expect("cache read"),
            Some(body.clone())
        );
        // The spent IP keeps answering from cache — no quota movement.
        let cached = enforce_slot_list(State(server.clone()), ip_one.clone())
            .await
            .expect("cached answer");
        assert_eq!(cached, BookingHttpDisposition::Continue);

        // The cache is scope-keyed: another page is a miss, not a leak.
        assert_eq!(
            cached_slot_list_body(&server, &other_page(), Some(&event())).expect("other page"),
            None
        );

        // The window itself: the rule's TTL sits inside the ratified band,
        // and out-of-band writes refuse at the engine door (engine-side test
        // covers 29s/61s); here the adapter accepts only the rule's TTL.
        let rows = booking_anti_abuse_rules(
            &server.vault,
            &BookingRuleScope {
                page_ref: page(),
                event_type: Some(event()),
            },
        )
        .expect("rows");
        let (rate, ttl) = slot_list_rate_knobs(&rows, &page(), &Some(event())).expect("slot knobs");
        assert_eq!(rate.get(), 120);
        assert!(
            (30..=60).contains(&ttl.get()),
            "cache window inside the ratified 30-60s band"
        );
        assert_eq!(ttl.get(), 45, "the owner-configured TTL is what applied");
    }

    #[tokio::test]
    async fn book_limit_uses_combined_ip_email_key() {
        let (_dir, server) = test_server();
        install_defaults(&server);

        // One corporate NAT address, two distinct people behind it.
        let nat_ip = booking_ip_hash("192.0.2.10");
        let mut alice = facts();
        alice.ip_hash = nat_ip;
        alice.email_hash = Some(booking_email_hash("alice@example.org"));
        let mut bob = facts();
        bob.ip_hash = nat_ip;
        bob.email_hash = Some(booking_email_hash("bob@example.org"));

        // Ten Alice bookings pass; the eleventh Alice booking limits.
        for _ in 0..10 {
            let disposition = enforce_book(State(server.clone()), alice.clone())
                .await
                .expect("alice book");
            assert_eq!(disposition, BookingHttpDisposition::Continue);
        }
        let limited = enforce_book(State(server.clone()), alice.clone())
            .await
            .expect("alice limit");
        assert!(
            matches!(limited, BookingHttpDisposition::RetryAfter { .. }),
            "ten alice bookings exhaust her combined IP+email bucket: {limited:?}"
        );

        // Bob behind the SAME NAT keeps an independent bucket: the combined
        // key never collapses two people onto one minute budget.
        let bob_first = enforce_book(State(server.clone()), bob.clone())
            .await
            .expect("bob book");
        assert_eq!(bob_first, BookingHttpDisposition::Continue);

        // The per-email active-future quota is likewise per person: Alice at
        // her cap is asked to correct, Bob under his cap proceeds.
        let mut alice_capped = alice.clone();
        alice_capped.active_future_bookings_for_email = 1;
        alice_capped.email_hash = alice.email_hash;
        let capped = enforce_book(State(server.clone()), alice_capped)
            .await
            .expect("alice cap");
        let BookingHttpDisposition::PromptCorrection { body } = capped else {
            panic!("Alice at her email cap prompts a correction: {capped:?}");
        };
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("correction json");
        assert_eq!(parsed["field"], "email");

        let bob_open = enforce_book(State(server.clone()), bob)
            .await
            .expect("bob under cap");
        assert_eq!(bob_open, BookingHttpDisposition::Continue);
    }

    #[tokio::test]
    async fn hold_limit_enforces_one_active_per_session_and_ip_cap() {
        let (_dir, server) = test_server();
        install_defaults(&server);

        // One active hold per session: a session already squatting retries.
        let mut squatting = facts();
        squatting.active_holds_for_session = 1;
        let session_ip = squatting.ip_hash;
        let blocked = enforce_hold(State(server.clone()), squatting)
            .await
            .expect("session cap");
        assert_eq!(
            blocked,
            BookingHttpDisposition::RetryAfter { seconds: 60 },
            "the session squatter retries, never a hard denial"
        );

        // The verdict path spent no per-IP budget: thirty more holds from
        // that same address still pass inside the window.
        let mut free = facts();
        free.ip_hash = session_ip;
        free.active_holds_for_session = 0;
        for _ in 0..30 {
            let disposition = enforce_hold(State(server.clone()), free.clone())
                .await
                .expect("hold");
            assert_eq!(disposition, BookingHttpDisposition::Continue);
        }
        let limited = enforce_hold(State(server.clone()), free)
            .await
            .expect("ip cap");
        assert!(
            matches!(limited, BookingHttpDisposition::RetryAfter { .. }),
            "the configured per-IP hold cap binds: {limited:?}"
        );

        // The cap is per IP: another address is untouched.
        let mut elsewhere = facts();
        elsewhere.ip_hash = booking_ip_hash("203.0.113.200");
        elsewhere.active_holds_for_session = 0;
        let disposition = enforce_hold(State(server.clone()), elsewhere)
            .await
            .expect("fresh ip");
        assert_eq!(disposition, BookingHttpDisposition::Continue);
    }

    #[tokio::test]
    async fn quarantine_without_book_rate_is_scope_bounded_despite_rotating_identities() {
        let (_dir, server) = test_server();
        server
            .vault
            .put_entity(
                &page(),
                oneiron::registry::ENTITY_TYPE_EVENT,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                b"booking page fixture",
            )
            .expect("page entity");
        install_live_booking_config(&server, event());
        for row in default_booking_anti_abuse_rows(page(), None, &owner_config())
            .expect("seed rows")
            .into_iter()
            .filter(|row| {
                !matches!(
                    row.rule,
                    oneiron::booking::anti_abuse::BookingAntiAbuseRule::BookRate { .. }
                )
            })
        {
            apply_rule_amendment(&server.vault, 0, row, None).expect("install partial row");
        }
        let mut first = facts();
        first.email = Some(oneiron::booking::anti_abuse::EmailValidationEvidence {
            syntax_valid: true,
            mx_present: Some(false),
            disposable_domain: true,
        });
        assert_eq!(
            enforce_book(State(server.clone()), first.clone())
                .await
                .expect("first guard"),
            BookingHttpDisposition::QuarantineAndAccept
        );
        // Replay is accepted before quota consumption, despite a transport
        // placeholder/timing change; it cannot starve the page-wide budget.
        let mut retry = first.clone();
        retry.submission_fingerprint = [0xD3; 32];
        retry.started_at_millis = 0;
        retry.submitted_at_millis = u64::MAX;
        assert_eq!(
            enforce_book(State(server.clone()), retry)
                .await
                .expect("retry guard"),
            BookingHttpDisposition::QuarantineAndAccept
        );
        for attempt in 1..4_u8 {
            let mut request = facts();
            request.event_type = Some(EventTypeKey(format!("attacker-event-{attempt}")));
            request.ip_hash = booking_ip_hash(&format!("198.51.100.{attempt}"));
            request.email_hash = Some(booking_email_hash(&format!("rotate-{attempt}@example.org")));
            request.selected_slot_hash = [attempt; 32];
            request.intake_content_hash = [attempt.wrapping_add(10); 32];
            request.email = Some(oneiron::booking::anti_abuse::EmailValidationEvidence {
                syntax_valid: true,
                mx_present: Some(false),
                disposable_domain: true,
            });
            let disposition = enforce_book(State(server.clone()), request)
                .await
                .expect("guard");
            assert!(
                matches!(disposition, BookingHttpDisposition::RetryAfter { .. }),
                "rotating identity and event string cannot bypass the page-wide quarantine budget"
            );
        }
        let decisions = server.vault.gate_decisions(10).expect("decisions");
        assert_eq!(
            decisions.len(),
            1,
            "the aggregate budget bounds decision growth"
        );
        let quarantine_claims = server
            .vault
            .claims_for_subject(&page())
            .expect("claims")
            .into_iter()
            .map(|claim_id| {
                server
                    .vault
                    .get_claim(&claim_id)
                    .expect("claim")
                    .expect("claim body")
            })
            .filter(|claim| claim.predicate == "booking.submission_quarantine")
            .count();
        assert_eq!(
            quarantine_claims, 1,
            "the aggregate budget bounds quarantine claim growth"
        );
        assert_eq!(
            server
                .vault
                .store
                .pending_gate_consents(10)
                .expect("pending rows")
                .len(),
            1,
            "the aggregate budget bounds pending growth and an exact retry adds no row"
        );
        assert!(
            decisions[0].claim_id.is_some(),
            "the sole decision still binds exactly one pending-review claim"
        );
    }

    #[tokio::test]
    async fn server_boundary_replaces_transport_fingerprint_and_ignores_timestamp_only_retry() {
        let (_dir, server) = test_server();
        install_defaults(&server);
        let mut first = facts();
        first.submission_fingerprint = [1; 32];
        first.email = Some(oneiron::booking::anti_abuse::EmailValidationEvidence {
            syntax_valid: true,
            mx_present: Some(false),
            disposable_domain: true,
        });
        assert_eq!(
            enforce_book(State(server.clone()), first.clone())
                .await
                .expect("first"),
            BookingHttpDisposition::QuarantineAndAccept
        );
        let mut retry = first.clone();
        retry.submission_fingerprint = [2; 32];
        retry.started_at_millis = 0;
        retry.submitted_at_millis = u64::MAX;
        let _ = enforce_book(State(server.clone()), retry)
            .await
            .expect("retry guard");
        assert_eq!(
            server.vault.gate_decisions(10).expect("decisions").len(),
            1,
            "transport fingerprint and timestamps cannot fork a trusted submission identity"
        );
        let mut distinct = first;
        distinct.intake_content_hash = [0xE4; 32];
        // Same form shape and identity, but canonical intake differs.
        assert_eq!(
            enforce_book(State(server.clone()), distinct)
                .await
                .expect("distinct guard"),
            BookingHttpDisposition::QuarantineAndAccept
        );
        assert_eq!(server.vault.gate_decisions(10).expect("decisions").len(), 2);
        assert_eq!(
            server
                .vault
                .store
                .pending_gate_consents(10)
                .expect("pending")
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn server_adapters_thread_state_and_api_error_for_slot_list_hold_and_book() {
        // Every guard threads `State<Arc<SyncServer>>`, loads its rows and
        // counters from that one state, and returns `Result<_, ApiError>` —
        // the assertions below exercise each adapter's verdict, counter,
        // cache, and quarantine wiring through nothing but `server`.
        let (_dir, server) = test_server();
        install_defaults(&server);

        // Structurally: no invented request-state facade exists in this
        // adapter's source.
        let src = include_str!("booking_anti_abuse.rs");
        // Built at runtime so the scan does not see its own needles.
        for token in [["Api", "State"].concat(), ["App", "State"].concat()] {
            assert!(
                !src.contains(&token),
                "the adapter threads SyncServer alone; found {token}"
            );
        }

        let good = facts();
        for call in ["slot", "hold", "book"] {
            let disposition = match call {
                "slot" => enforce_slot_list(State(server.clone()), good.clone())
                    .await
                    .expect("slot adapter"),
                "hold" => enforce_hold(State(server.clone()), good.clone())
                    .await
                    .expect("hold adapter"),
                _ => enforce_book(State(server.clone()), good.clone())
                    .await
                    .expect("book adapter"),
            };
            // The slot/hold calls above consumed one unit of each window, so
            // all three adapters demonstrably share the seeded rows.
            assert_eq!(
                disposition,
                BookingHttpDisposition::Continue,
                "{call} adapter must continue a clean request"
            );
        }

        // A correctable verdict maps onto the correction disposition.
        let mut short_intake = facts();
        short_intake.intake_chars = 0;
        let prompted = enforce_book(State(server.clone()), short_intake)
            .await
            .expect("prompt adapter");
        let BookingHttpDisposition::PromptCorrection { body } = prompted else {
            panic!("intake correction prompts: {prompted:?}");
        };
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("correction json");
        assert_eq!(parsed["field"], "intake");

        // Hold creation does not evaluate submit-form honeypot fields.
        let mut bot = facts();
        bot.honeypot_nonempty = true;
        let disposition = enforce_hold(State(server.clone()), bot)
            .await
            .expect("hold adapter");
        assert_eq!(disposition, BookingHttpDisposition::Continue);

        // Borderline traffic quarantines through the adapter and is accepted.
        let mut borderline = facts();
        borderline.email_hash = Some(booking_email_hash("sketchy@example.net"));
        borderline.email = Some(oneiron::booking::anti_abuse::EmailValidationEvidence {
            syntax_valid: true,
            mx_present: Some(false),
            disposable_domain: true,
        });
        let quarantined = enforce_book(State(server.clone()), borderline)
            .await
            .expect("quarantine adapter");
        assert_eq!(quarantined, BookingHttpDisposition::QuarantineAndAccept);
    }

    #[tokio::test]
    async fn page_wide_rows_govern_event_typed_requests() {
        let (_dir, server) = test_server();
        // Only page-wide (`event_type: None`) rows exist; no event-scoped
        // stack is ever installed.
        install_defaults_scoped(&server, None);

        // A request naming an event type still answers to the page-wide
        // intake control...
        let mut typed = facts();
        typed.intake_chars = 0;
        let prompted = enforce_book(State(server.clone()), typed)
            .await
            .expect("page-wide intake governs");
        let BookingHttpDisposition::PromptCorrection { body } = prompted else {
            panic!("the page-wide intake rule must govern an event-typed request: {prompted:?}");
        };
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("correction json");
        assert_eq!(parsed["field"], "intake");

        // ...and to the page-wide slot-list rate knob: 120 pass, the 121st
        // event-typed listing is limited exactly as if the stack had been
        // seeded event-scoped.
        let good = facts();
        for _ in 0..120 {
            let disposition = enforce_slot_list(State(server.clone()), good.clone())
                .await
                .expect("slot list");
            assert_eq!(disposition, BookingHttpDisposition::Continue);
        }
        let limited = enforce_slot_list(State(server.clone()), good)
            .await
            .expect("slot-list limit");
        assert!(
            matches!(limited, BookingHttpDisposition::RetryAfter { .. }),
            "the page-wide 120/min slot-list row governs event-typed traffic: {limited:?}"
        );

        // The cache helper resolves the page-wide TTL for the same typed
        // scope as well.
        let body = b"{\"slots\":[]}".to_vec();
        assert!(
            remember_slot_list_body(&server, &page(), Some(&event()), &body).expect("cache write"),
            "the page-wide slot-list row supplies the cache TTL"
        );
        assert_eq!(
            cached_slot_list_body(&server, &page(), Some(&event())).expect("cache read"),
            Some(body)
        );
    }
}
