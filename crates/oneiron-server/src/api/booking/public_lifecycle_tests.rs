use super::fixture::*;
use super::*;

#[tokio::test]
async fn public_booking_route_accepts_only_canonical_pack_verbs() {
    let fixture = Fixture::new();
    let token = "ab".repeat(32);
    let slot = SelectedSlot {
        start_utc: 10,
        end_utc: 20,
    };
    let requests = [
        cancel(token.clone(), "cancel"),
        confirm(token.clone(), "confirm"),
        hold(slot, "hold", None),
        reschedule(token, slot, "reschedule"),
    ];
    for (expected, request) in BOOKING_VERBS.into_iter().zip(requests) {
        assert!(is_booking_pack_verb(expected));
        assert!(match_public_booking_verb(expected, &request).is_ok());
        for other in BOOKING_VERBS {
            assert_eq!(
                match_public_booking_verb(other, &request).is_ok(),
                other == expected
            );
        }
        assert!(match_public_booking_verb(expected, &availability()).is_err());
        let wire = serde_json::to_value(&request).expect("request");
        let response = fixture
            .route(
                "POST",
                &format!("/public/booking/{}/verbs/{expected}", fixture.token),
                wire,
            )
            .await;
        assert_ne!(
            response.status(),
            StatusCode::NOT_FOUND,
            "canonical verb reached ordinary validation"
        );
    }
    assert!(!is_booking_pack_verb("booking.availability"));
    assert!(match_public_booking_verb("booking.availability", &availability()).is_err());
    let held = hold(slot, "typed-mismatch", None);
    assert_eq!(
        fixture
            .dispatch("booking.confirm", held)
            .await
            .expect_err("typed mismatch"),
        StatusCode::NOT_FOUND
    );
    let mut with_actor = serde_json::to_value(hold(slot, "actor", None)).expect("wire");
    with_actor["input"]["input"]["authenticated_actor_ref"] = json!(fixture.page.to_hex());
    assert!(serde_json::from_value::<BookingOperationRequest>(with_actor).is_err());
}

#[tokio::test]
async fn public_booking_route_runs_shared_anti_abuse_once() {
    for _ in 0..3 {
        // Amend after publication: both booking claim schemas are present.
        let fixture = Fixture::new();
        let scope = BookingRuleScope {
            page_ref: fixture.page,
            event_type: None,
        };
        let limit = NonZeroU32::new(2).expect("positive");
        let rule = BookingAntiAbuseRule::HoldRate {
            max_active_per_session: 1,
            per_minute_per_ip: limit,
        };
        apply_rule_amendment(
            &fixture.server.vault,
            0,
            BookingAntiAbuseRuleRow {
                row_id: booking_rule_row_id(&scope, &rule),
                scope,
                rule,
                version: 1,
                amended_at: 0,
                amended_by: fixture.page,
                owner_stamp_ref: None,
            },
            None,
        )
        .expect("rate rule");
        // An unoffered one-second slot reaches admission but cannot mint a hold.
        let now = now_secs().expect("clock");
        let response = fixture
            .dispatch(
                "booking.hold",
                hold(
                    SelectedSlot {
                        start_utc: now + 86_400,
                        end_utc: now + 86_401,
                    },
                    "quota",
                    None,
                ),
            )
            .await
            .expect("unoffered slot response");
        assert!(matches!(
            response,
            BookingOperationResponse::Book(BookingBookResult::SlotTaken { .. })
        ));
        if now / 60 != now_secs().expect("clock") / 60 {
            continue;
        }
        let ip = booking_ip_hash("127.0.0.1");
        // Query the admission minute explicitly, even if the next wall-clock
        // tick crosses it. One executor call must leave exactly one token.
        assert_eq!(
            observe_hold_request(&fixture.server.vault, &ip, limit, now).expect("remaining token"),
            BookingRateDecision::Allowed
        );
        assert!(matches!(
            observe_hold_request(&fixture.server.vault, &ip, limit, now).expect("spent"),
            BookingRateDecision::Exceeded { .. }
        ));
        return;
    }
    panic!("could not observe one admission within a single rate window");
}

#[tokio::test]
async fn public_booking_hold_confirm_and_action_tokens_are_opaque() {
    let fixture = Fixture::new();
    let slots = fixture.slots().await;
    assert!(slots.len() > 4);
    let slot = selected(&slots[0]);
    let before = now_secs().expect("clock");
    let held = fixture
        .dispatch("booking.hold", hold(slot, "ordinary", None))
        .await
        .expect("hold");
    let BookingOperationResponse::Book(BookingBookResult::Held {
        hold_token,
        expires_at,
        ..
    }) = held
    else {
        panic!("held")
    };
    assert_eq!(hold_token.len(), 64);
    assert!(expires_at >= before + DEFAULT_HOLD_TTL_SECS);
    assert!(expires_at <= now_secs().expect("clock") + DEFAULT_HOLD_TTL_SECS);
    assert!(
        fixture
            .dispatch(
                "booking.confirm",
                confirm(hold_token.clone(), "wrong-session")
            )
            .await
            .is_err()
    );
    let confirmed = fixture
        .dispatch("booking.confirm", confirm(hold_token.clone(), "ordinary"))
        .await
        .expect("confirm");
    let BookingOperationResponse::Book(BookingBookResult::Confirmed {
        reschedule_token,
        cancel_token,
    }) = &confirmed
    else {
        panic!("confirmed")
    };
    assert_ne!(reschedule_token, cancel_token);
    for token in [&hold_token, reschedule_token, cancel_token] {
        assert_eq!(token.len(), 64);
        assert!(token.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(EntityId::from_hex(token).is_err());
        assert!(!token.contains(&fixture.page.to_hex()));
    }
    let other_page = id(0x75);
    fixture.configure_page(other_page, id(0x76));
    fixture.publish_page(other_page, true, 1, now_secs().expect("clock") + 86_400);
    for (verb, request) in [
        (
            "booking.reschedule",
            reschedule(reschedule_token.clone(), selected(&slots[3]), "cross-page"),
        ),
        (
            "booking.cancel",
            cancel(cancel_token.clone(), "cross-page-cancel"),
        ),
    ] {
        let cross = fixture
            .dispatch_at(&booking_page_token(other_page), verb, request)
            .await
            .expect_err("cross page");
        assert_eq!(cross, unknown_action_token().status());
    }
    assert!(
        fixture
            .dispatch(
                "booking.reschedule",
                reschedule(
                    cancel_token.clone(),
                    selected(&slots[3]),
                    "wrong-action-reschedule"
                )
            )
            .await
            .is_err()
    );
    let moved = fixture
        .dispatch(
            "booking.reschedule",
            reschedule(reschedule_token.clone(), selected(&slots[3]), "move"),
        )
        .await
        .expect("reschedule");
    assert!(matches!(moved, BookingOperationResponse::Reschedule { .. }));
    assert!(
        fixture
            .dispatch(
                "booking.cancel",
                cancel(reschedule_token.clone(), "wrong-action-cancel")
            )
            .await
            .is_err()
    );
    let cancelled = fixture
        .dispatch("booking.cancel", cancel(cancel_token.clone(), "cancel"))
        .await
        .expect("cancel");
    let wire = serde_json::to_string(&confirmed).expect("wire");
    let event_ids = fixture
        .server
        .vault
        .entities_by_type(oneiron::registry::ENTITY_TYPE_EVENT)
        .expect("events");
    assert!(
        !event_ids.is_empty(),
        "a genuine confirm must persist an event"
    );
    for event_id in event_ids {
        assert!(!wire.contains(&event_id.to_hex()));
    }
    assert_inline(&public_booking_response(Json(cancelled).into_response()).await);
    let lease_now = now_secs().expect("clock");
    let (lease, lease_expiry) = issue_checkout_lease(
        &fixture.server.vault,
        &session_key(fixture.page, "checkout"),
        u64::MAX,
        lease_now,
    )
    .expect("server-issued lease");
    assert_eq!(lease_expiry, lease_now + MAX_CHECKOUT_HOLD_TTL_SECS);
    let extended = fixture
        .dispatch(
            "booking.hold",
            hold(slot, "checkout", Some(lease.0.clone())),
        )
        .await
        .expect("lease hold");
    let BookingOperationResponse::Book(BookingBookResult::Held { expires_at, .. }) = extended
    else {
        panic!("extended hold")
    };
    assert!(expires_at <= lease_expiry);
    assert!(expires_at > lease_now + DEFAULT_HOLD_TTL_SECS);
    assert!(
        fixture
            .dispatch(
                "booking.hold",
                hold(selected(&slots[2]), "forged", Some("ff".repeat(32)))
            )
            .await
            .is_err()
    );
    assert!(
        fixture
            .dispatch(
                "booking.hold",
                hold(selected(&slots[2]), "wrong-session", Some(lease.0))
            )
            .await
            .is_err()
    );
    let expired_at = now_secs().expect("clock") - MAX_CHECKOUT_HOLD_TTL_SECS - 1;
    let (expired_lease, expiry) = issue_checkout_lease(
        &fixture.server.vault,
        &session_key(fixture.page, "expired-lease"),
        u64::MAX,
        expired_at,
    )
    .expect("expired genuine lease");
    assert!(expiry < now_secs().expect("clock"));
    assert!(
        fixture
            .dispatch(
                "booking.hold",
                hold(selected(&slots[2]), "expired-lease", Some(expired_lease.0))
            )
            .await
            .is_err()
    );
    let mut ttl = serde_json::to_value(hold(slot, "ttl", None)).expect("wire");
    ttl["input"]["input"]["ttl_secs"] = json!(u64::MAX);
    assert!(serde_json::from_value::<BookingOperationRequest>(ttl).is_err());
}

#[tokio::test]
async fn public_booking_unlisted_event_and_typed_mismatches_never_dispatch() {
    let fixture = Fixture::new();
    let now = now_secs().expect("clock");
    let slot = SelectedSlot {
        start_utc: now + 86_400,
        end_utc: now + 88_200,
    };
    for verb in BOOKING_VERBS {
        let response = fixture.dispatch(verb, availability()).await;
        assert_eq!(
            response.expect_err("availability is render input only"),
            StatusCode::NOT_FOUND
        );
    }
    let mut hidden = hold(slot, "unlisted", None);
    let BookingOperationRequest::Book(BookingBookInput::Hold(input)) = &mut hidden else {
        panic!("hold")
    };
    input.event_type = EventTypeKey("unlisted".to_owned());
    assert_eq!(
        fixture
            .dispatch("booking.hold", hidden)
            .await
            .expect_err("unlisted"),
        StatusCode::NOT_FOUND
    );
    for (field, value) in [
        ("ttl_secs", json!(u64::MAX)),
        ("authenticated_actor_ref", json!(fixture.page.to_hex())),
    ] {
        let mut input = serde_json::to_value(hold(slot, "injected", None)).expect("request");
        input["input"]["input"][field] = value;
        let response = fixture
            .route(
                "POST",
                &format!("/public/booking/{}/verbs/booking.hold", fixture.token),
                input,
            )
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_inline(&response);
    }
    assert!(
        fixture
            .server
            .vault
            .entities_by_type(oneiron::registry::ENTITY_TYPE_EVENT)
            .expect("events")
            .is_empty()
    );
}

#[tokio::test]
async fn public_booking_cross_page_action_credentials_are_non_oracular() {
    let fixture = Fixture::new();
    let slots = fixture.slots().await;
    let held = fixture
        .dispatch("booking.hold", hold(selected(&slots[0]), "binding", None))
        .await
        .expect("hold");
    let BookingOperationResponse::Book(BookingBookResult::Held { hold_token, .. }) = held else {
        panic!("held")
    };
    let other_page = id(0x75);
    fixture.configure_page(other_page, id(0x76));
    fixture.publish_page(other_page, true, 1, now_secs().expect("clock") + 86_400);
    let other_token = booking_page_token(other_page);
    assert!(
        fixture
            .dispatch_at(
                &other_token,
                "booking.confirm",
                confirm(hold_token.clone(), "binding")
            )
            .await
            .is_err()
    );
    let confirmed = fixture
        .dispatch("booking.confirm", confirm(hold_token, "binding"))
        .await
        .expect("confirm on issuing page");
    let BookingOperationResponse::Book(BookingBookResult::Confirmed {
        reschedule_token,
        cancel_token,
    }) = confirmed
    else {
        panic!("confirmed")
    };
    for (verb, known, unknown) in [
        (
            "booking.reschedule",
            reschedule(reschedule_token, selected(&slots[2]), "cross"),
            reschedule("ff".repeat(32), selected(&slots[2]), "unknown"),
        ),
        (
            "booking.cancel",
            cancel(cancel_token, "cross"),
            cancel("ff".repeat(32), "unknown"),
        ),
    ] {
        let path = format!("/public/booking/{other_token}/verbs/{verb}");
        let known = fixture
            .route("POST", &path, serde_json::to_value(known).expect("request"))
            .await;
        let unknown = fixture
            .route(
                "POST",
                &path,
                serde_json::to_value(unknown).expect("request"),
            )
            .await;
        assert_eq!(known.status(), unknown.status());
        assert!(known.status().is_client_error());
        assert_inline(&known);
        assert_eq!(bytes(known).await, bytes(unknown).await);
    }
}
