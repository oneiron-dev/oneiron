//! Shared fixtures for tests that enter the real public router.

use super::*;
pub(super) use axum::body::{Body, to_bytes};
pub(super) use axum::http::Request;
pub(super) use oneiron::EdgeActorClass;
pub(super) use oneiron::booking::anti_abuse::{
    BookingAntiAbuseRule, BookingAntiAbuseRuleRow, BookingRateDecision, BookingRuleScope,
    apply_rule_amendment, booking_ip_hash, booking_rule_row_id, observe_hold_request,
};
pub(super) use oneiron::booking::{
    BOOKING_EVENT_TYPE_PREDICATE, BOOKING_EVENT_TYPE_SCHEMA_VERSION, BOOKING_PUBLIC_PAGE_PREDICATE,
    BOOKING_PUBLIC_PAGE_SCHEMA_VERSION, BOOKING_VERBS, BookingEventTypeClaimValue,
    ConstraintFieldConfig, DEFAULT_HOLD_TTL_SECS, EventTypeCard, EventTypeConfig, EventTypeKey,
    HostAvailabilityConfig, MAX_CHECKOUT_HOLD_TTL_SECS, PublicBookingAvailability, RankedSlot,
    RoutingMode, ThemeTokens, WeeklyWallWindow, encode_event_type_claim_value,
    issue_checkout_lease,
};
pub(super) use oneiron::memory::ClaimInput;
pub(super) use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, DreamerHomeNodeCandidate,
    DreamerRunnerStore, TimeRange,
};
pub(super) use serde_json::{Value, json};
pub(super) use std::num::NonZeroU32;
pub(super) use tower::ServiceExt;

pub(super) struct Fixture {
    _dir: tempfile::TempDir,
    pub(super) server: Arc<SyncServer>,
    pub(super) page: EntityId,
    pub(super) token: String,
}

pub(super) fn id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("fixture id")
}

impl Fixture {
    pub(super) fn new() -> Self {
        let fixture = Self::unpublished();
        fixture.publish_page(fixture.page, true, 1, now_secs().expect("clock") + 86_400);
        fixture
    }

    pub(super) fn unpublished() -> Self {
        let dir = tempfile::tempdir().expect("temp vault");
        let vault =
            Arc::new(Vault::open(dir.path(), oneiron::VaultConfig::device()).expect("vault"));
        let server = Arc::new(
            SyncServer::new(
                vault,
                crate::config::SyncServerConfig {
                    auth_secret: Some("owner-fixture-secret".to_owned()),
                    allow_unauthenticated: false,
                    lease_vault_id: 9,
                    ..Default::default()
                },
            )
            .expect("server"),
        );
        DreamerRunnerStore::new(&server.vault)
            .elect_home_node(&[DreamerHomeNodeCandidate::always_on_local(9)], 1)
            .expect("home node");
        let page = id(0x71);
        let fixture = Self {
            _dir: dir,
            server,
            page,
            token: booking_page_token(page),
        };
        fixture.configure_page(page, id(0x72));
        fixture
            .server
            .vault
            .put_entity(
                &id(0x77),
                oneiron::registry::ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"fixture owner",
            )
            .expect("owner");
        fixture
    }

    pub(super) fn configure_page(&self, page: EntityId, claim_id: EntityId) {
        self.server
            .vault
            .put_entity(
                &page,
                oneiron::registry::ENTITY_TYPE_ASSET,
                TimeRange { start: 1, end: 1 },
                1,
                b"fixture booking page",
            )
            .expect("page");
        let config = EventTypeConfig {
            key: EventTypeKey("intro".to_owned()),
            duration_min: 30,
            slot_step_min: 30,
            pre_buffer_min: 0,
            post_buffer_min: 0,
            min_notice_secs: 0,
            booking_window_secs: 7 * 86_400,
            daily_cap: None,
            weekly_cap: None,
            routing: RoutingMode::Either,
            hosts: vec![HostAvailabilityConfig {
                host_ref: id(0x73),
                calendar_refs: vec![id(0x74)],
                host_tz: "UTC".to_owned(),
                working_hours: (0..7)
                    .map(|weekday| WeeklyWallWindow {
                        weekday,
                        start_minute: 0,
                        end_minute: 1_440,
                    })
                    .collect(),
                preferred_hours: Vec::new(),
            }],
            flex_windows: Vec::new(),
        };
        let value = encode_event_type_claim_value(&BookingEventTypeClaimValue {
            schema_version: BOOKING_EVENT_TYPE_SCHEMA_VERSION,
            page_ref: page,
            config,
        })
        .expect("config");
        self.server
            .vault
            .put_claim(
                &claim_id,
                &ClaimBody::new(
                    BOOKING_EVENT_TYPE_PREDICATE,
                    ClaimSubject::Entity(page),
                    value,
                    1.0,
                    ClaimApprovalStatus::Auto,
                    ClaimLifecycleStatus::Active,
                ),
                TimeRange { start: 1, end: 1 },
                1,
            )
            .expect("config claim");
    }

    pub(super) fn publish_page(
        &self,
        page: EntityId,
        published: bool,
        from: u64,
        until: u64,
    ) -> String {
        let input = publication_input(page, published, from, until);
        let receipt = self
            .server
            .vault
            .memory(id(0x77), EdgeActorClass::Human)
            .claim_upsert(&input)
            .expect("normal owner publication write");
        assert_eq!(receipt.approval, "auto");
        receipt.claim_short_id
    }

    pub(super) async fn slots(&self) -> Vec<RankedSlot> {
        let response = self
            .route(
                "GET",
                &format!("/public/booking/{}", self.token),
                Value::Null,
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_inline(&response);
        let value: Value = serde_json::from_slice(&bytes(response).await).expect("page JSON");
        let model: BookingPageModel =
            serde_json::from_value(value["model"].clone()).expect("model");
        let oneiron::booking::RungProjection::Slots(mask) = model.slots else {
            panic!("slots only")
        };
        mask.slots
    }

    pub(super) async fn route(&self, method: &str, path: &str, body: Value) -> Response {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header(CONTENT_TYPE, "application/json")
            // A hostile header is always present; every quota assertion below
            // must still charge the real peer, not this supplied address.
            .header("x-forwarded-for", "198.51.100.7, 192.0.2.1")
            .extension(ConnectInfo(
                "127.0.0.1:43123".parse::<SocketAddr>().expect("peer"),
            ))
            .body(Body::from(serde_json::to_vec(&body).expect("body")))
            .expect("request");
        crate::build_app(self.server.clone())
            .oneshot(request)
            .await
            .expect("response")
    }

    // This helper only serializes a typed request into the actual public router.
    // Capability resolution, peer extraction, admission and lifecycle all run.
    pub(super) async fn dispatch(
        &self,
        verb: &str,
        request: BookingOperationRequest,
    ) -> Result<BookingOperationResponse, StatusCode> {
        self.dispatch_at(&self.token, verb, request).await
    }

    pub(super) async fn dispatch_at(
        &self,
        token: &str,
        verb: &str,
        request: BookingOperationRequest,
    ) -> Result<BookingOperationResponse, StatusCode> {
        let response = self
            .route(
                "POST",
                &format!("/public/booking/{token}/verbs/{verb}"),
                serde_json::to_value(request).expect("typed request"),
            )
            .await;
        assert_inline(&response);
        if response.status() != StatusCode::OK {
            return Err(response.status());
        }
        Ok(serde_json::from_slice(&bytes(response).await).expect("typed operation response"))
    }
}

pub(super) fn publication_input(
    page: EntityId,
    published: bool,
    from: u64,
    until: u64,
) -> ClaimInput {
    let publication = BookingPagePublication {
        schema_version: BOOKING_PUBLIC_PAGE_SCHEMA_VERSION,
        published,
        owner_display: "Fixture host".to_owned(),
        event_types: vec![EventTypeCard {
            key: EventTypeKey("intro".to_owned()),
            title: "Fixture event".to_owned(),
            duration_min: 30,
            description: "Fixture description".to_owned(),
        }],
        constraint_field: ConstraintFieldConfig {
            enabled: true,
            placeholder: "Fixture constraint".to_owned(),
        },
        theme: ThemeTokens(json!({"unknown-owner-bag": {"nested": [null, "</script>", 7]}})),
        initial_availability: PublicBookingAvailability {
            event_type: EventTypeKey("intro".to_owned()),
            start_after_secs: 86_400,
            window_secs: 86_400,
            visitor_tz: "UTC".to_owned(),
        },
    };
    ClaimInput {
        id: None,
        predicate: BOOKING_PUBLIC_PAGE_PREDICATE.to_owned(),
        subject_ref: page.to_hex(),
        value: serde_json::to_value(publication).expect("presentation"),
        confidence: 1.0,
        source: "user_stated".to_owned(),
        world_ref: None,
        scope: None,
        valid_from: Some(from),
        valid_to: Some(until),
        occurred_at: None,
        learned_at: None,
        salience: None,
    }
}

pub(super) fn selected(slot: &RankedSlot) -> SelectedSlot {
    SelectedSlot {
        start_utc: slot.start_utc,
        end_utc: slot.end_utc,
    }
}

pub(super) fn hold(
    slot: SelectedSlot,
    session: &str,
    lease: Option<String>,
) -> BookingOperationRequest {
    BookingOperationRequest::Book(BookingBookInput::Hold(BookingHoldInput {
        event_type: EventTypeKey("intro".to_owned()),
        selected_slot: slot,
        visitor_tz: "UTC".to_owned(),
        constraint: None,
        session_ref: session.to_owned(),
        checkout_lease_token: lease,
        idempotency_key: format!("hold-{session}"),
    }))
}

pub(super) fn confirm(token: String, session: &str) -> BookingOperationRequest {
    BookingOperationRequest::Book(BookingBookInput::Confirm(BookingConfirmInput {
        hold_token: token,
        booker_email: "visitor@example.test".to_owned(),
        intake: Vec::new(),
        session_ref: session.to_owned(),
        idempotency_key: format!("confirm-{session}"),
    }))
}

pub(super) fn reschedule(token: String, slot: SelectedSlot, key: &str) -> BookingOperationRequest {
    BookingOperationRequest::Reschedule(BookingRescheduleInput {
        reschedule_token: token,
        selected_slot: slot,
        visitor_tz: "UTC".to_owned(),
        idempotency_key: key.to_owned(),
    })
}

pub(super) fn cancel(token: String, key: &str) -> BookingOperationRequest {
    BookingOperationRequest::Cancel(BookingCancelInput {
        cancel_token: token,
        idempotency_key: key.to_owned(),
    })
}

pub(super) fn availability() -> BookingOperationRequest {
    BookingOperationRequest::Availability(BookingAvailabilityInput {
        event_type: EventTypeKey("intro".to_owned()),
        window: TimeRange { start: 1, end: 2 },
        visitor_tz: "UTC".to_owned(),
        constraint: None,
        session_ref: "fixture".to_owned(),
    })
}

// Axum can refuse an unmatched path or method before the public response
// mapper. Such a refusal is safe only when it has no content to serve.
pub(super) async fn assert_public_denial(response: Response) {
    assert!(matches!(
        response.status(),
        StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
    ));
    assert!(!response.status().is_redirection());
    assert!(!response.headers().contains_key(LOCATION));
    if response.headers().contains_key(CONTENT_DISPOSITION) {
        assert_inline(&response);
    } else {
        assert!(!response.headers().contains_key(CONTENT_TYPE));
        if let Some(value) = response.headers().get(X_CONTENT_TYPE_OPTIONS) {
            assert_eq!(value, "nosniff");
        }
        if let Some(value) = response.headers().get(CACHE_CONTROL) {
            assert_eq!(value, "no-store");
        }
        assert!(
            bytes(response).await.is_empty(),
            "framework refusal must be empty"
        );
    }
}

pub(super) fn assert_inline(response: &Response) {
    assert!(!response.status().is_redirection());
    assert!(!response.headers().contains_key(LOCATION));
    assert_eq!(response.headers()[CONTENT_DISPOSITION], "inline");
    assert_eq!(response.headers()[X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
}

pub(super) async fn bytes(response: Response) -> Vec<u8> {
    to_bytes(response.into_body(), 1_048_576)
        .await
        .expect("body")
        .to_vec()
}
