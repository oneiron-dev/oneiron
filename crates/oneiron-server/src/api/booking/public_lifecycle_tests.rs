use super::fixture::*;
use super::*;
use std::num::NonZeroU16;

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
async fn a_page_wide_required_intake_refuses_a_confirm_but_never_an_amendment() {
    let fixture = Fixture::new();
    let slots = fixture.slots().await;
    assert!(slots.len() > 4);

    // One ordinary booking, made before the owner arms the intake control,
    // so the visitor holds genuine reschedule and cancel tokens.
    let held = fixture
        .dispatch("booking.hold", hold(selected(&slots[0]), "amendable", None))
        .await
        .expect("hold");
    let BookingOperationResponse::Book(BookingBookResult::Held { hold_token, .. }) = held else {
        panic!("held")
    };
    let confirmed = fixture
        .dispatch("booking.confirm", confirm(hold_token, "amendable"))
        .await
        .expect("confirm");
    let BookingOperationResponse::Book(BookingBookResult::Confirmed {
        reschedule_token,
        cancel_token,
    }) = confirmed
    else {
        panic!("confirmed")
    };

    // The owner now requires open-text intake page-wide, which is how a
    // page-scoped row reaches every event type.
    let scope = BookingRuleScope {
        page_ref: fixture.page,
        event_type: None,
    };
    let rule = BookingAntiAbuseRule::RequiredIntake {
        min_chars: NonZeroU16::new(10).expect("positive"),
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
    .expect("required intake row");

    // Booking time is where the control belongs: an empty intake is refused.
    let second = fixture
        .dispatch(
            "booking.hold",
            hold(selected(&slots[1]), "empty-intake", None),
        )
        .await
        .expect("second hold");
    let BookingOperationResponse::Book(BookingBookResult::Held { hold_token, .. }) = second else {
        panic!("held")
    };
    assert_eq!(
        fixture
            .dispatch("booking.confirm", confirm(hold_token, "empty-intake"))
            .await
            .expect_err("an empty intake is refused at booking time"),
        StatusCode::BAD_REQUEST
    );

    // Amendment time is not: the visitor already answered the question, and
    // a token carries no form to answer it again with. Both directions.
    let moved = fixture
        .dispatch(
            "booking.reschedule",
            reschedule(reschedule_token, selected(&slots[3]), "amend-move"),
        )
        .await
        .expect("a required-intake row must not refuse a reschedule");
    assert!(matches!(moved, BookingOperationResponse::Reschedule { .. }));
    let cancelled = fixture
        .dispatch("booking.cancel", cancel(cancel_token, "amend-cancel"))
        .await
        .expect("a required-intake row must not refuse a cancel");
    assert!(matches!(cancelled, BookingOperationResponse::Cancel { .. }));
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

/// engine-crates-01: a confirm answers with its own attempt's receipt. A
/// first visitor's confirm is queued and its request has not run its turn
/// yet. A second visitor's confirm must not run that attempt and answer with
/// the first visitor's cancel and reschedule tokens, whether it carries
/// another idempotency key or the very same one.
#[tokio::test]
async fn a_confirm_answers_with_its_own_attempt_never_another_visitors() {
    use oneiron::attempt_queue::{AttemptQueue, AttemptState};
    use oneiron::booking::lifecycle::enqueue_booking_verb_with_publication;
    use oneiron::booking::publication::PublicBookingAuthority;

    let fixture = Fixture::new();
    let slots = fixture.slots().await;
    assert!(slots.len() > 4);
    for (round, shared_key) in [(0_usize, false), (1, true)] {
        let first = format!("first-{round}");
        let second = format!("second-{round}");
        let first_hold = held_token(&fixture, &slots[2 * round], &first).await;
        let second_hold = held_token(&fixture, &slots[2 * round + 1], &second).await;

        let now = now_secs().expect("clock");
        let (page_ref, publication) =
            resolve_public_booking_page(&fixture.server, &fixture.token).expect("live page");
        let authority = PublicBookingAuthority {
            page_ref,
            publication,
        };
        let first_key = format!("confirm-{first}");
        let queued = enqueue_booking_verb_with_publication(
            &fixture.server.vault,
            BookingVerbRequest::Confirm(ConfirmSpec {
                hold_token: OpaqueLifecycleToken(first_hold),
                session_key: session_key(fixture.page, &first),
                booker_contact: resolve_booker_contact(
                    &fixture.server,
                    "first@example.test",
                    now,
                    Some(&authority),
                )
                .expect("first booker"),
                intake: Vec::new(),
                idempotency_key: Some(first_key.clone()),
            }),
            now,
            Some(authority),
        )
        .expect("first visitor's confirm is queued");

        let key = if shared_key {
            first_key
        } else {
            format!("confirm-{second}")
        };
        let answered = confirmed_tokens(
            fixture
                .dispatch(
                    "booking.confirm",
                    confirm_with_key(second_hold.clone(), &second, &key),
                )
                .await
                .expect("second visitor confirms"),
        );
        // A retry under a fresh key reaches the receipt recorded for this
        // hold token, which carries the second visitor's own tokens.
        let own = confirmed_tokens(
            fixture
                .dispatch(
                    "booking.confirm",
                    confirm_with_key(second_hold, &second, &format!("retry-{second}")),
                )
                .await
                .expect("second visitor retries"),
        );
        assert_eq!(
            answered, own,
            "round {round}: the confirm answered with another visitor's tokens"
        );
        let first_row = AttemptQueue::new(&fixture.server.vault)
            .get(queued)
            .expect("queue read")
            .expect("first visitor's attempt");
        assert_eq!(
            first_row.state,
            AttemptState::Queued,
            "round {round}: another request ran the first visitor's attempt"
        );
    }
}

async fn held_token(fixture: &Fixture, slot: &RankedSlot, session: &str) -> String {
    let held = fixture
        .dispatch("booking.hold", hold(selected(slot), session, None))
        .await
        .expect("hold");
    let BookingOperationResponse::Book(BookingBookResult::Held { hold_token, .. }) = held else {
        panic!("held")
    };
    hold_token
}

fn confirm_with_key(token: String, session: &str, key: &str) -> BookingOperationRequest {
    let mut request = confirm(token, session);
    if let BookingOperationRequest::Book(BookingBookInput::Confirm(input)) = &mut request {
        key.clone_into(&mut input.idempotency_key);
    }
    request
}

fn confirmed_tokens(response: BookingOperationResponse) -> (String, String) {
    let BookingOperationResponse::Book(BookingBookResult::Confirmed {
        reschedule_token,
        cancel_token,
    }) = response
    else {
        panic!("confirmed, got {response:?}")
    };
    (reschedule_token, cancel_token)
}

/// engine-crates-24: a control the owner scoped to one event type binds a
/// confirm for that type. A confirm names its event type only through its
/// hold, or once the hold is spent through the booking it made, so a retry
/// of a confirm is bound too. A confirm naming no hold of its session is
/// refused before anything is recorded for it.
#[tokio::test]
async fn an_event_scoped_required_intake_refuses_a_confirm_for_that_event() {
    let fixture = Fixture::new();
    let slots = fixture.slots().await;
    assert!(slots.len() > 2);
    let booked = held_token(&fixture, &slots[0], "booked").await;
    let mut first = confirm(booked, "booked");
    if let BookingOperationRequest::Book(BookingBookInput::Confirm(input)) = &mut first {
        input.intake = vec![oneiron::booking::agent_api::BookingIntakeAnswer {
            field_key: "topic".to_owned(),
            value: "short".to_owned(),
        }];
    }
    confirmed_tokens(
        fixture
            .dispatch("booking.confirm", first.clone())
            .await
            .expect("confirm before the rule"),
    );

    let scope = BookingRuleScope {
        page_ref: fixture.page,
        event_type: Some(EventTypeKey("intro".to_owned())),
    };
    let rule = BookingAntiAbuseRule::RequiredIntake {
        min_chars: NonZeroU16::new(10).expect("positive"),
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
    .expect("event-scoped intake rule");

    let held = held_token(&fixture, &slots[1], "empty-intake").await;
    assert_eq!(
        fixture
            .dispatch("booking.confirm", confirm(held, "empty-intake"))
            .await
            .expect_err("an empty intake is refused for the scoped event type"),
        StatusCode::BAD_REQUEST
    );
    // The retry is refused for its intake, not for its spent hold.
    let retry = fixture
        .route(
            "POST",
            &format!("/public/booking/{}/verbs/booking.confirm", fixture.token),
            serde_json::to_value(first).expect("wire"),
        )
        .await;
    assert_eq!(retry.status(), StatusCode::BAD_REQUEST);
    let body = String::from_utf8(bytes(retry).await).expect("utf-8");
    assert!(body.contains("intake"), "{body}");

    let mut stranger = confirm("ab".repeat(32), "no-hold");
    if let BookingOperationRequest::Book(BookingBookInput::Confirm(input)) = &mut stranger {
        "stranger@example.test".clone_into(&mut input.booker_email);
    }
    assert_eq!(
        fixture
            .dispatch("booking.confirm", stranger)
            .await
            .expect_err("a confirm naming no hold is refused"),
        StatusCode::BAD_REQUEST
    );
    let contact = super::super::subject::booker_contact_ref("stranger@example.test")
        .expect("contact ref");
    assert!(
        fixture
            .server
            .vault
            .get(&contact)
            .expect("contact read")
            .is_none(),
        "a refused confirm recorded a booker contact"
    );
}

/// engine-core-03 on the public route: with a daily cap of one, a second
/// visitor's confirm on a day already booked is refused, and the first
/// booking still moves within its own day, which it does not fill twice.
#[tokio::test]
async fn a_daily_cap_closes_a_booked_day_but_lets_its_booking_move_within_it() {
    let mut config = fixture_config();
    config.daily_cap = Some(1);
    let fixture = Fixture::with_config(config);
    let slots = fixture.slots().await;
    let day = |slot: &RankedSlot| slot.start_utc / 86_400;
    let busiest = slots
        .iter()
        .map(day)
        .max_by_key(|candidate| slots.iter().filter(|slot| day(slot) == *candidate).count())
        .expect("slots");
    let same_day: Vec<&RankedSlot> = slots.iter().filter(|slot| day(slot) == busiest).collect();
    assert!(same_day.len() > 4);

    let first = held_token(&fixture, same_day[0], "first").await;
    let second = held_token(&fixture, same_day[2], "second").await;
    let (reschedule_token, _) = confirmed_tokens(
        fixture
            .dispatch("booking.confirm", confirm(first, "first"))
            .await
            .expect("first confirm"),
    );
    assert!(matches!(
        fixture
            .dispatch("booking.confirm", confirm(second, "second"))
            .await
            .expect("second confirm answers"),
        BookingOperationResponse::Book(BookingBookResult::SlotTaken { .. })
    ));

    let moved = fixture
        .dispatch(
            "booking.reschedule",
            reschedule(reschedule_token, selected(same_day[4]), "same-day-move"),
        )
        .await
        .expect("a booking moves within its own capped day");
    assert!(matches!(moved, BookingOperationResponse::Reschedule { .. }));
}
