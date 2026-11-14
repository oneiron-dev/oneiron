//! BK-VARIABLE-DURATION through the real public router: one link carries the
//! event type's allowed lengths, the visitor picks one, and a different
//! length after a hold is a new hold. Every configuration, card and body
//! here goes in as JSON, so the file builds wherever the router does.

use super::fixture::*;
use super::*;

/// The fixture's `intro` event type, offering `lengths` (minutes) beside
/// its 30-minute default.
fn config_with_lengths(lengths: &[u16]) -> EventTypeConfig {
    let mut value = serde_json::to_value(fixture_config()).expect("config JSON");
    value["allowed_durations_min"] = json!(lengths);
    serde_json::from_value(value).expect("a configuration with allowed lengths")
}

async fn page_json(fixture: &Fixture) -> Value {
    let response = fixture
        .route(
            "GET",
            &format!("/public/booking/{}", fixture.token),
            Value::Null,
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_slice(&bytes(response).await).expect("page JSON")
}

/// Public availability over `window`, at `minutes` when given.
async fn availability_at(
    fixture: &Fixture,
    window: TimeRange,
    minutes: Option<u16>,
    session: &str,
) -> Result<Vec<RankedSlot>, StatusCode> {
    let mut body = json!({
        "event_type": "intro",
        "window": {"start": window.start, "end": window.end},
        "visitor_tz": "UTC",
        "constraint": null,
        "session_ref": session,
    });
    if let Some(minutes) = minutes {
        body["duration_min"] = json!(minutes);
    }
    let response = fixture
        .route(
            "POST",
            &format!("/public/booking/{}/availability", fixture.token),
            body,
        )
        .await;
    if response.status() != StatusCode::OK {
        return Err(response.status());
    }
    let BookingOperationResponse::Availability { slots, .. } =
        serde_json::from_slice(&bytes(response).await).expect("availability")
    else {
        panic!("availability")
    };
    Ok(slots)
}

fn interval(start: u64, minutes: u64) -> SelectedSlot {
    SelectedSlot {
        start_utc: start,
        end_utc: start + minutes * 60,
    }
}

async fn hold_at(fixture: &Fixture, slot: SelectedSlot, session: &str) -> BookingBookResult {
    let BookingOperationResponse::Book(result) = fixture
        .dispatch("booking.hold", hold(slot, session, None))
        .await
        .expect("hold answers")
    else {
        panic!("a book result")
    };
    result
}

fn held_token(result: BookingBookResult) -> String {
    let BookingBookResult::Held { hold_token, .. } = result else {
        panic!("held, got {result:?}")
    };
    hold_token
}

fn confirm_keyed(token: String, session: &str, key: &str) -> BookingOperationRequest {
    let mut request = confirm(token, session);
    if let BookingOperationRequest::Book(BookingBookInput::Confirm(input)) = &mut request {
        key.clone_into(&mut input.idempotency_key);
    }
    request
}

#[tokio::test]
async fn public_booking_variable_duration_link_offers_and_holds_each_allowed_length() {
    let fixture = Fixture::with_config(config_with_lengths(&[30, 60]));

    // One link, every length: the card lists them.
    let page = page_json(&fixture).await;
    assert_eq!(
        page["model"]["event_types"][0]["allowed_durations_min"],
        json!([30, 60])
    );
    let default = fixture.slots().await;
    assert!(
        default
            .iter()
            .all(|slot| slot.end_utc - slot.start_utc == 1_800)
    );
    let start = default[0].start_utc;
    let window = TimeRange {
        start,
        end: start + 6 * 3_600 - 1,
    };

    // The visitor picks an hour.
    let hours = availability_at(&fixture, window, Some(60), "pick")
        .await
        .expect("an allowed length is offered");
    assert!(!hours.is_empty());
    assert!(
        hours
            .iter()
            .all(|slot| slot.end_utc - slot.start_utc == 3_600)
    );
    assert_eq!(hours[0].start_utc, start);

    // An hour holds, and its confirm re-solves at the held length.
    let hour = held_token(hold_at(&fixture, interval(start, 60), "hour").await);
    let confirmed = fixture
        .dispatch("booking.confirm", confirm(hour, "hour"))
        .await
        .expect("the held hour confirms");
    assert!(matches!(
        confirmed,
        BookingOperationResponse::Book(BookingBookResult::Confirmed { .. })
    ));

    // The default half hour holds beside it, in another session.
    let half = hold_at(&fixture, interval(start + 3_600, 30), "half").await;
    assert!(matches!(half, BookingBookResult::Held { .. }), "{half:?}");

    // A length the event type does not offer is never held or listed.
    let odd = hold_at(&fixture, interval(start + 2 * 3_600, 45), "odd").await;
    assert!(
        matches!(odd, BookingBookResult::SlotTaken { .. }),
        "{odd:?}"
    );
    assert_eq!(
        availability_at(&fixture, window, Some(45), "odd")
            .await
            .expect_err("a length off the card is not offered"),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn a_held_length_changes_only_by_a_new_hold() {
    let fixture = Fixture::with_config(config_with_lengths(&[30, 60]));
    let start = fixture.slots().await[0].start_utc;

    // The session holds an hour, then changes its mind to half an hour:
    // that is a new hold, which replaces the first.
    let hour = held_token(hold_at(&fixture, interval(start, 60), "visitor").await);
    let half = held_token(hold_at(&fixture, interval(start, 30), "visitor").await);
    assert_ne!(hour, half);
    assert!(
        fixture
            .dispatch(
                "booking.confirm",
                confirm_keyed(hour, "visitor", "confirm-hour")
            )
            .await
            .is_err(),
        "the replaced hour's token confirms nothing"
    );
    let confirmed = fixture
        .dispatch(
            "booking.confirm",
            confirm_keyed(half, "visitor", "confirm-half"),
        )
        .await
        .expect("the half hour confirms");
    assert!(matches!(
        confirmed,
        BookingOperationResponse::Book(BookingBookResult::Confirmed { .. })
    ));

    // Half an hour was booked: the next half hour is still offered.
    let after = availability_at(
        &fixture,
        TimeRange {
            start,
            end: start + 3_600 - 1,
        },
        None,
        "after",
    )
    .await
    .expect("availability");
    let starts: Vec<u64> = after.iter().map(|slot| slot.start_utc).collect();
    assert!(!starts.contains(&start), "{starts:?}");
    assert!(starts.contains(&(start + 1_800)), "{starts:?}");
}
