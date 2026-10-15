//! Rule 5: an authenticated caller is never refused for rate or count. The
//! owner's booking rates and caps shed the anonymous public route per address;
//! an authenticated actor's requests are counted instead, and a burst past the
//! advisory threshold raises one typed question (OF-520) per kind and window.

use axum::http::header::AUTHORIZATION;
use oneiron::booking::anti_abuse::{
    BOOKING_ADVISORY_THRESHOLD, BookingBudgetCheck, BookingBudgetKind, BookingBudgetReceipt,
    booking_budget_checks, observe_authenticated_booking,
};

use super::fixture::*;
use super::*;

/// Every owner cap at one: one listing, one hold and one write a minute per
/// address, one active hold per session and one upcoming booking per email.
fn install_caps(fixture: &Fixture) {
    let one = NonZeroU32::new(1).expect("one");
    for rule in [
        BookingAntiAbuseRule::SlotListRate {
            per_minute_per_ip: one,
            cache_ttl_secs: std::num::NonZeroU64::new(30).expect("TTL"),
        },
        BookingAntiAbuseRule::HoldRate {
            max_active_per_session: 1,
            per_minute_per_ip: one,
        },
        BookingAntiAbuseRule::BookRate {
            per_minute_per_ip: one,
            max_active_future_per_email: 1,
        },
    ] {
        let scope = BookingRuleScope {
            page_ref: fixture.page,
            event_type: None,
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
        .expect("cap");
    }
}

/// One request to the authenticated route `/api/booking/{token}/{verb}` as
/// the actor `id(0x77)`, or to the anonymous one without a credential, from
/// one connection.
async fn send(
    fixture: &Fixture,
    authenticated: bool,
    verb: &str,
    body: Value,
) -> Result<BookingOperationResponse, StatusCode> {
    let mut request = Request::builder();
    let path = if authenticated {
        request = request.header(
            AUTHORIZATION,
            format!(
                "{}jti=booking-actor;principal_ref={}",
                crate::test_credentials::RECIPE_PREFIX,
                id(0x77).to_hex()
            ),
        );
        format!("/api/booking/{}/{verb}", fixture.token)
    } else {
        format!("/public/booking/{}/{verb}", fixture.token)
    };
    let request = request
        .method("POST")
        .uri(path)
        .header(CONTENT_TYPE, "application/json")
        .extension(ConnectInfo(
            "203.0.113.9:43123".parse::<SocketAddr>().expect("peer"),
        ))
        .body(Body::from(serde_json::to_vec(&body).expect("body")))
        .expect("request");
    let request = crate::test_credentials::bind_request(&fixture.server, request);
    let response = crate::build_app(fixture.server.clone())
        .oneshot(request)
        .await
        .expect("response");
    if response.status() != StatusCode::OK {
        return Err(response.status());
    }
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    Ok(serde_json::from_slice(&body).expect("typed operation response"))
}

fn listing(nth: u64) -> Value {
    let now = now_secs().expect("clock");
    serde_json::to_value(BookingAvailabilityInput {
        event_type: EventTypeKey("intro".to_owned()),
        window: TimeRange {
            start: now + 86_400 + nth * 3_600,
            end: now + 3 * 86_400 + nth * 3_600,
        },
        visitor_tz: "UTC".to_owned(),
        constraint: None,
        session_ref: format!("burst-{nth}"),
    })
    .expect("listing")
}

/// With every owner cap at one, an authenticated actor sends three of each
/// kind in one window: all complete. Each kind's count, carried on to past
/// the advisory threshold, records its typed question once per window, in one
/// row per kind. The anonymous route from the same connection is still shed
/// at the cap.
#[tokio::test]
async fn an_authenticated_burst_past_every_booking_cap_completes() {
    let mut fixture = Fixture::new();
    let now = now_secs().expect("clock");
    std::sync::Arc::get_mut(&mut fixture.server)
        .expect("the fixture holds the only server handle")
        .booking_test_now_secs = Some(now);
    install_caps(&fixture);

    // A session keeps one live hold, so the hold burst leaves the last one
    // live; each later confirmation books a fresh hold of its own.
    let hold = |slot: &RankedSlot, session: &str, key: String| {
        json!(BookingBookInput::Hold(BookingHoldInput {
            event_type: EventTypeKey("intro".to_owned()),
            selected_slot: selected(slot),
            visitor_tz: "UTC".to_owned(),
            constraint: None,
            session_ref: session.to_owned(),
            checkout_lease_token: None,
            idempotency_key: key,
        }))
    };
    let mut offered = Vec::new();
    let mut live = String::new();
    let mut bookings = Vec::new();
    for budget in BookingBudgetKind::ALL {
        for nth in 0..3 {
            let sent = match budget {
                BookingBudgetKind::SlotList => {
                    send(&fixture, true, "availability", listing(nth as u64)).await
                }
                BookingBudgetKind::Hold => {
                    let body = hold(&offered[nth], "burst", format!("burst-hold-{nth}"));
                    send(&fixture, true, "book", body).await
                }
                BookingBudgetKind::Book => {
                    let (hold_token, session) = if nth == 0 {
                        (std::mem::take(&mut live), "burst".to_owned())
                    } else {
                        let session = format!("book-{nth}");
                        let body = hold(&offered[2 + nth], &session, format!("book-hold-{nth}"));
                        let Ok(BookingOperationResponse::Book(BookingBookResult::Held {
                            hold_token,
                            ..
                        })) = send(&fixture, true, "book", body).await
                        else {
                            panic!("a hold for confirmation {nth}");
                        };
                        (hold_token, session)
                    };
                    let body = json!(BookingBookInput::Confirm(BookingConfirmInput {
                        hold_token,
                        booker_email: "visitor@example.test".to_owned(),
                        intake: Vec::new(),
                        session_ref: session,
                        idempotency_key: format!("burst-confirm-{nth}"),
                    }));
                    send(&fixture, true, "book", body).await
                }
                BookingBudgetKind::Amend => {
                    let (reschedule_token, cancel_token): &(String, String) = &bookings[nth];
                    if nth == 0 {
                        let body = json!(BookingRescheduleInput {
                            reschedule_token: reschedule_token.clone(),
                            selected_slot: selected(&offered[5]),
                            visitor_tz: "UTC".to_owned(),
                            idempotency_key: "burst-reschedule".to_owned(),
                        });
                        send(&fixture, true, "reschedule", body).await
                    } else {
                        let body = json!(BookingCancelInput {
                            cancel_token: cancel_token.clone(),
                            idempotency_key: format!("burst-cancel-{nth}"),
                        });
                        send(&fixture, true, "cancel", body).await
                    }
                }
            };
            let response = sent.unwrap_or_else(|status| panic!("{budget:?} {nth}: {status}"));
            match (budget, response) {
                (
                    BookingBudgetKind::SlotList,
                    BookingOperationResponse::Availability { slots, .. },
                ) => {
                    if offered.is_empty() {
                        offered = slots;
                        assert!(offered.len() > 5, "{} slots offered", offered.len());
                    }
                }
                (
                    BookingBudgetKind::Hold,
                    BookingOperationResponse::Book(BookingBookResult::Held { hold_token, .. }),
                ) => live = hold_token,
                (
                    BookingBudgetKind::Book,
                    BookingOperationResponse::Book(BookingBookResult::Confirmed {
                        reschedule_token,
                        cancel_token,
                    }),
                ) => bookings.push((reschedule_token, cancel_token)),
                (
                    BookingBudgetKind::Amend,
                    BookingOperationResponse::Reschedule { .. }
                    | BookingOperationResponse::Cancel { .. },
                ) => {}
                (budget, response) => panic!("{budget:?} {nth}: {response:?}"),
            }
        }
    }

    // The anonymous route from the same connection still sheds at the cap.
    let first = send(&fixture, false, "availability", listing(10)).await;
    let second = send(&fixture, false, "availability", listing(11)).await;
    assert!(first.is_ok() && second.is_err());

    let window = now / 60 * 60;
    for budget in BookingBudgetKind::ALL {
        for _ in 3..BOOKING_ADVISORY_THRESHOLD + 3 {
            observe_authenticated_booking(&fixture.server.vault, id(0x77), budget, now)
                .expect("count");
        }
    }
    let checks = booking_budget_checks(&fixture.server.vault, id(0x77)).expect("checks");
    let expected: Vec<_> = BookingBudgetKind::ALL
        .into_iter()
        .map(|budget| BookingBudgetCheck {
            receipt: BookingBudgetReceipt {
                actor: id(0x77).to_hex(),
                budget,
                window_started_at_secs: window,
                count: BOOKING_ADVISORY_THRESHOLD + 1,
            },
            threshold: BOOKING_ADVISORY_THRESHOLD,
            windows_crossed: 1,
        })
        .collect();
    assert_eq!(checks, expected);

    // A burst that lasts updates its kind's one check, window by window.
    let later = now + 60;
    for _ in 0..=BOOKING_ADVISORY_THRESHOLD {
        observe_authenticated_booking(
            &fixture.server.vault,
            id(0x77),
            BookingBudgetKind::Hold,
            later,
        )
        .expect("count");
    }
    let checks = booking_budget_checks(&fixture.server.vault, id(0x77)).expect("checks");
    assert_eq!(checks.len(), BookingBudgetKind::ALL.len());
    let hold = &checks[1];
    assert_eq!(
        (
            hold.receipt.budget,
            hold.receipt.window_started_at_secs,
            hold.windows_crossed
        ),
        (BookingBudgetKind::Hold, later / 60 * 60, 2)
    );
}
