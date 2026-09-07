use super::fixture::*;
use super::*;

fn install_slot_cache(fixture: &Fixture) {
    let scope = BookingRuleScope { page_ref: fixture.page, event_type: None };
    let rule = BookingAntiAbuseRule::SlotListRate {
        per_minute_per_ip: NonZeroU32::new(1).expect("rate"),
        cache_ttl_secs: std::num::NonZeroU64::new(60).expect("TTL"),
    };
    apply_rule_amendment(&fixture.server.vault, 0, BookingAntiAbuseRuleRow {
        row_id: booking_rule_row_id(&scope, &rule), scope, rule, version: 1,
        amended_at: 0, amended_by: fixture.page, owner_stamp_ref: None,
    }, None).expect("cache rule");
}

fn listing(now: u64) -> BookingAvailabilityInput {
    BookingAvailabilityInput {
        event_type: EventTypeKey("intro".to_owned()),
        window: TimeRange { start: now + 86_400, end: now + 4 * 86_400 - 1 },
        visitor_tz: "UTC".to_owned(), constraint: None, session_ref: "availability".to_owned(),
    }
}

#[tokio::test]
async fn public_availability_serves_each_card_and_changed_timezone_window_constraint() {
    let fixture = Fixture::new();
    let vault = &fixture.server.vault;
    let mut body = vault.get_claim(&id(0x72)).expect("read").expect("config");
    let mut value = oneiron::booking::decode_event_type_claim_value(&body.value).expect("decode");
    value.config.key = EventTypeKey("second".to_owned());
    value.config.duration_min = 60;
    body.value = encode_event_type_claim_value(&value).expect("encode");
    vault.put_claim(&id(0x75), &body, TimeRange { start: 1, end: 1 }, 1).expect("second config");
    let now = now_secs().expect("clock");
    let mut publication = publication_input(fixture.page, true, 1, now + 86_400);
    publication.value["event_types"].as_array_mut().expect("cards").push(json!({
        "key": "second", "title": "Second event", "duration_min": 60, "description": "Fixture",
    }));
    publication.value["event_config_hashes"]["second"] = json!(oneiron::booking::booking_config_hash(&value.config).expect("hash"));
    vault.memory(id(0x77), EdgeActorClass::Human).claim_upsert(&publication).expect("owner authorizes both");
    for key in ["intro", "second"] {
        let mut input = listing(now);
        input.event_type = EventTypeKey(key.to_owned());
        input.visitor_tz = "America/New_York".to_owned();
        input.constraint = Some(BookingConstraintInput::Object(ConstraintObject {
            schema_version: oneiron::booking::constraint::CONSTRAINT_SCHEMA_VERSION,
            weekdays: Vec::new(), local_time_windows: Vec::new(), utc_window: None, allow_flex_pool: false,
        }));
        let response = fixture.route("POST", &format!("/public/booking/{}/availability", fixture.token), serde_json::to_value(input).expect("request")).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_inline(&response);
        let result: BookingOperationResponse = serde_json::from_slice(&bytes(response).await).expect("response");
        let BookingOperationResponse::Availability { slots, .. } = result else { panic!("availability"); };
        assert!(!slots.is_empty() && slots.len() <= 128);
        assert!(slots.iter().all(|slot| slot.end_utc - slot.start_utc == if key == "intro" { 1_800 } else { 3_600 }));
    }
    let mut input = listing(now);
    input.event_type = EventTypeKey("private".to_owned());
    assert_eq!(fixture.route("POST", &format!("/public/booking/{}/availability", fixture.token), serde_json::to_value(input).expect("request")).await.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn public_slot_cache_reuses_matching_query_but_not_changed_window_or_revocation() {
    for _ in 0..3 {
        let fixture = Fixture::new();
        install_slot_cache(&fixture);
        let now = now_secs().expect("clock");
        let input = listing(now);
        let path = format!("/public/booking/{}/availability", fixture.token);
        let first = fixture.route("POST", &path, serde_json::to_value(&input).expect("request")).await;
        assert_eq!(first.status(), StatusCode::OK);
        let first = bytes(first).await;
        let second = fixture.route("POST", &path, serde_json::to_value(&input).expect("request")).await;
        assert_eq!(second.status(), StatusCode::OK, "a matching cache hit must not spend a second token");
        assert_eq!(first, bytes(second).await);
        if now / 60 != now_secs().expect("clock") / 60 { continue; }
        let mut changed = input;
        changed.window.end -= 86_400;
        let miss = fixture.route("POST", &path, serde_json::to_value(changed).expect("request")).await;
        assert_ne!(miss.status(), StatusCode::OK, "a different query cannot reuse the scope's cached body or bypass quota");
        fixture.publish_page(fixture.page, false, 1, now + 86_400);
        let revoked = fixture.route("POST", &path, serde_json::to_value(listing(now)).expect("request")).await;
        assert_eq!(revoked.status(), StatusCode::NOT_FOUND, "cached slots are not publication authority");
        return;
    }
    panic!("could not observe one rate window");
}

#[tokio::test]
async fn queued_public_hold_loses_authority_before_the_lifecycle_writer() {
    struct EmptyOracle;
    impl SlotOracle for EmptyOracle {
        fn solve(&self, _: &SolveRequest) -> Result<SolveResult, BookingError> {
            Ok(SolveResult { slots: Vec::new(), flex_used: false })
        }
    }
    let fixture = Fixture::new();
    let now = now_secs().expect("clock");
    let authority = oneiron::booking::publication::PublicBookingAuthority {
        page_ref: fixture.page,
        publication: load_public_booking_page(&fixture.server.vault, fixture.page, now).expect("read").expect("public"),
    };
    oneiron::booking::lifecycle::enqueue_booking_verb_with_publication(&fixture.server.vault,
        BookingVerbRequest::Hold(HoldSpec {
            page_ref: fixture.page, event_type: EventTypeKey("intro".to_owned()),
            slot: TimeRange { start: now + 86_400, end: now + 88_200 },
            session_key: session_key(fixture.page, "queued"), visitor_tz: "UTC".to_owned(), constraint: None,
            lease: HoldLeaseSpec::Ordinary, idempotency_key: Some("queued-public".to_owned()),
        }), now, Some(authority)).expect("enqueue");
    fixture.publish_page(fixture.page, false, 1, now + 86_400);
    let outcome = oneiron::booking::run_booking_lifecycle_once(&fixture.server.vault, |_| Ok(EmptyOracle),
        &oneiron::booking::BookingLifecycleConsumerInput { local_node_id: 9, lease_owner: "public-regression".to_owned(), now_utc: now });
    assert!(outcome.is_err(), "delayed public attempts must recheck authority inside the writer");
}
