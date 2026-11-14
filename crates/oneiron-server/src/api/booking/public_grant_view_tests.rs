//! ARCH-0062 #grant-view (owner ruling BOOKING-GRANT-VIEW = A, 2026-10-20;
//! Engine ruling L3-10, 2026-11-13): an availability answer shows a caller
//! whose live calendar grants name every calendar a host binds that host's
//! busy blocks, held to its working hours, beside the same slots everyone
//! gets. Every other caller gets the public default, and the slot cache never
//! carries a caller's view.

use super::fixture::*;
use super::*;

const DAY: u64 = 86_400;
const HOUR: u64 = 3_600;
const OPEN_HOUR: u64 = 9;
const CLOSE_HOUR: u64 = 17;

/// The fixture's one event type, its one host binding two calendars and
/// working 09:00-17:00 UTC every day.
fn grant_view_config() -> EventTypeConfig {
    let mut config = fixture_config();
    let host = &mut config.hosts[0];
    host.calendar_refs = vec![id(0x74), id(0x7a)];
    host.working_hours = (0..7)
        .map(|weekday| WeeklyWallWindow {
            weekday,
            start_minute: 9 * 60,
            end_minute: 17 * 60,
        })
        .collect();
    config
}

/// Midnight UTC two days on: a whole bookable day.
fn asked_day() -> u64 {
    (now_secs().expect("clock") / DAY + 2) * DAY
}

fn listing(day: u64) -> BookingAvailabilityInput {
    BookingAvailabilityInput {
        event_type: EventTypeKey("intro".to_owned()),
        window: TimeRange {
            start: day,
            end: day + DAY - 1,
        },
        visitor_tz: "UTC".to_owned(),
        constraint: None,
        session_ref: "grant-view".to_owned(),
    }
}

/// Three busy EVENTs on `day`: 11:00-12:00 inside working hours, 16:00-18:00
/// across the close, 20:00-21:00 after it.
fn seed_busy(fixture: &Fixture, day: u64) {
    let owner = oneiron::WriteActor::new(id(0x77), EdgeActorClass::Human);
    for (name, from, to) in [("standup", 11, 12), ("review", 16, 18), ("dinner", 20, 21)] {
        fixture
            .server
            .vault
            .create_native_calendar_event(
                &oneiron::calendar::origin::CalendarEventInput {
                    name: name.to_owned(),
                    ..Default::default()
                },
                TimeRange {
                    start: day + from * HOUR,
                    end: day + to * HOUR - 1,
                },
                owner,
            )
            .expect("busy EVENT");
    }
}

/// The busy blocks a grantee should see on `day`: the busy union inside
/// working hours, so the 16:00-18:00 EVENT shows to 17:00 and the evening one
/// not at all.
fn expected_busy(day: u64) -> Value {
    json!([{
        "calendar_refs": [id(0x74).to_hex(), id(0x7a).to_hex()],
        "busy": [
            {"start_utc": day + 11 * HOUR, "end_utc": day + 12 * HOUR},
            {"start_utc": day + 16 * HOUR, "end_utc": day + CLOSE_HOUR * HOUR},
        ],
    }])
}

fn calendar_grant(
    fixture: &Fixture,
    grant_byte: u8,
    principal: EntityId,
    calendar: EntityId,
    rung: oneiron::booking::DisclosureRung,
) -> EntityId {
    let grant_ref = id(grant_byte);
    fixture
        .server
        .vault
        .put_access_grant(
            &grant_ref,
            &oneiron::AccessGrant::calendar_disclosure(
                principal,
                calendar,
                rung,
                now_secs().expect("clock") - 60,
            ),
        )
        .expect("calendar grant");
    grant_ref
}

/// One availability request on the fixture's page as `principal`, through
/// the credential transport the `vault.booking.availability` door uses.
async fn availability_as(fixture: &Fixture, principal: EntityId, day: u64) -> Value {
    let recipe = format!(
        "jti=grant-view-{principal};principal_ref={principal};actor_class=human;scope=core:read",
        principal = principal.to_hex()
    );
    let auth = crate::test_credentials::authenticate(&fixture.server, &recipe);
    let transport = crate::api::booking::credential_transport_context(&fixture.server, &auth)
        .expect("credential transport");
    let response = crate::api::booking::execute_booking_operation(
        &fixture.server,
        &fixture.token,
        BookingOperationRequest::Availability(listing(day)),
        transport,
    )
    .await
    .expect("availability answer");
    serde_json::to_value(response).expect("answer JSON")
}

/// The working time on `day` no offered slot covers, as busy-block JSON.
fn uncovered(slots: &Value, day: u64) -> Vec<Value> {
    let mut taken: Vec<(u64, u64)> = slots
        .as_array()
        .expect("slots")
        .iter()
        .map(|slot| {
            (
                slot["start_utc"].as_u64().expect("slot start"),
                slot["end_utc"].as_u64().expect("slot end"),
            )
        })
        .collect();
    taken.sort_unstable();
    let close = day + CLOSE_HOUR * HOUR;
    let mut cursor = day + OPEN_HOUR * HOUR;
    let mut gaps = Vec::new();
    for (start, end) in taken {
        if start > cursor {
            gaps.push(json!({"start_utc": cursor, "end_utc": start}));
        }
        cursor = cursor.max(end);
    }
    if cursor < close {
        gaps.push(json!({"start_utc": cursor, "end_utc": close}));
    }
    gaps
}

fn install_slot_cache(fixture: &Fixture) {
    let scope = BookingRuleScope {
        page_ref: fixture.page,
        event_type: None,
    };
    let rule = BookingAntiAbuseRule::SlotListRate {
        per_minute_per_ip: NonZeroU32::new(100).expect("rate"),
        cache_ttl_secs: std::num::NonZeroU64::new(60).expect("TTL"),
    };
    apply_rule_amendment(
        &fixture.server.vault,
        &crate::test_credentials::embedded_owner(&fixture.server.vault),
        0,
        BookingAntiAbuseRuleRow {
            row_id: booking_rule_row_id(&scope, &rule),
            scope,
            rule,
            version: 1,
            amended_at: 0,
            amended_by: fixture.owner_actor(),
            owner_stamp_ref: None,
        },
        None,
    )
    .expect("cache rule");
}

/// A grantee at `Busy` on both host calendars sees the busy union inside
/// working hours: exactly the working time the offered slots leave
/// uncovered. An anonymous visitor and a caller with no grant get the same
/// slots and no `busy` at all.
#[tokio::test]
async fn a_busy_grantee_sees_the_working_time_the_slots_leave_uncovered() {
    use oneiron::booking::DisclosureRung;
    let fixture = Fixture::with_config(grant_view_config());
    let day = asked_day();
    seed_busy(&fixture, day);
    let grantee = id(0x81);
    calendar_grant(&fixture, 0x91, grantee, id(0x74), DisclosureRung::Busy);
    calendar_grant(&fixture, 0x92, grantee, id(0x7a), DisclosureRung::Busy);

    let anonymous = fixture
        .route(
            "POST",
            &format!("/public/booking/{}/availability", fixture.token),
            serde_json::to_value(listing(day)).expect("request"),
        )
        .await;
    assert_eq!(anonymous.status(), StatusCode::OK);
    let anonymous: Value = serde_json::from_slice(&bytes(anonymous).await).expect("JSON");
    let outsider = availability_as(&fixture, id(0x82), day).await;
    let granted = availability_as(&fixture, grantee, day).await;

    assert!(
        !anonymous["result"]["slots"]
            .as_array()
            .expect("slots")
            .is_empty()
    );
    for public in [&anonymous, &outsider] {
        assert!(
            public["result"].get("busy").is_none(),
            "no grant, no busy: {public}"
        );
        assert_eq!(public["result"]["slots"], granted["result"]["slots"]);
    }
    assert_eq!(
        granted["result"]["busy"],
        expected_busy(day),
        "a Busy grantee sees the busy union inside working hours"
    );
    assert_eq!(
        Value::Array(uncovered(&granted["result"]["slots"], day)),
        granted["result"]["busy"][0]["busy"],
        "the busy blocks are exactly the working time no slot covers"
    );
}

/// The view is judged per caller on every answer: a cached answer carries
/// none, a `Full` grant still shows opaque blocks only, a grant on one of the
/// host's two calendars or at the `Slots` rung shows nothing, and a revoked
/// grant stops showing at the next answer.
#[tokio::test]
async fn the_grant_view_follows_live_grants_and_never_rides_the_slot_cache() {
    use oneiron::booking::DisclosureRung;
    let fixture = Fixture::with_config(grant_view_config());
    install_slot_cache(&fixture);
    let day = asked_day();
    seed_busy(&fixture, day);
    let full = id(0x84);
    calendar_grant(&fixture, 0x93, full, id(0x74), DisclosureRung::Full);
    let revocable = calendar_grant(&fixture, 0x94, full, id(0x7a), DisclosureRung::Full);
    let one_calendar = id(0x83);
    calendar_grant(&fixture, 0x95, one_calendar, id(0x74), DisclosureRung::Busy);
    let slots_rung = id(0x85);
    calendar_grant(&fixture, 0x96, slots_rung, id(0x74), DisclosureRung::Slots);
    calendar_grant(&fixture, 0x97, slots_rung, id(0x7a), DisclosureRung::Slots);

    // The first answer solves and fills the caller-free cache; the rest are
    // served from it.
    let first = availability_as(&fixture, id(0x82), day).await;
    assert!(first["result"].get("busy").is_none());
    let granted = availability_as(&fixture, full, day).await;
    let again = availability_as(&fixture, id(0x82), day).await;
    let partial = availability_as(&fixture, one_calendar, day).await;
    let below_busy = availability_as(&fixture, slots_rung, day).await;
    for public in [&again, &partial, &below_busy] {
        assert!(
            public["result"].get("busy").is_none(),
            "no view for this caller: {public}"
        );
        assert_eq!(public["result"]["slots"], first["result"]["slots"]);
    }
    assert_eq!(granted["result"]["slots"], first["result"]["slots"]);
    assert_eq!(
        granted["result"]["busy"],
        expected_busy(day),
        "a Full grant shows the Busy view on a cached answer"
    );
    assert!(
        granted["result"]["busy"][0]["busy"]
            .as_array()
            .expect("blocks")
            .iter()
            .all(|block| block.as_object().expect("block").len() == 2),
        "opaque blocks only: no title, body or source"
    );

    fixture
        .server
        .vault
        .revoke_calendar_access_grant(&revocable, now_secs().expect("clock"))
        .expect("revoke one grant");
    let revoked = availability_as(&fixture, full, day).await;
    assert!(
        revoked["result"].get("busy").is_none(),
        "a revoked grant shows nothing at the next answer: {revoked}"
    );
    assert_eq!(revoked["result"]["slots"], first["result"]["slots"]);
}
