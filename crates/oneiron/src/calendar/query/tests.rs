//! A claim awaiting its owner's critical confirm in the calendar's operational
//! reads: free/busy, and the rows an action (emergency reschedule) takes.

use rmpv::Value;

use super::facts::{CalendarRead, visit_calendar_events, visit_calendar_events_for_effect};
use crate::calendar::claims::{
    PREDICATE_CALENDAR_ORIGIN, PREDICATE_CALENDAR_STATUS, PREDICATE_CALENDAR_TIME_KIND,
};
use crate::calendar::test_support::{event_name_body, open_calendar_vault};
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::entity_id::EntityId;
use crate::registry::ENTITY_TYPE_EVENT;
use crate::temporal::TimeRange;
use crate::vault::Vault;

fn origin() -> (&'static str, Value) {
    (PREDICATE_CALENDAR_ORIGIN, Value::from("imported"))
}

fn time_kind(kind: &str, transparency: &str) -> (&'static str, Value) {
    let value = Value::Map(vec![
        (Value::from("kind"), Value::from(kind)),
        (Value::from("busy_transparency"), Value::from(transparency)),
    ]);
    (PREDICATE_CALENDAR_TIME_KIND, value)
}

fn cancelled() -> (&'static str, Value) {
    let value = Value::Map(vec![
        (Value::from("status"), Value::from("cancelled")),
        (Value::from("basis"), Value::from("imported_cancel")),
        (Value::from("recorded_at"), Value::from(1_754_400_000_u64)),
    ]);
    (PREDICATE_CALENDAR_STATUS, value)
}

/// Writes a calendar EVENT over `[start, start + 99]` carrying `claims`, and
/// holds the claims at the indexes in `held` (the helper asserts each hold).
fn event(
    vault: &Vault,
    seed: u8,
    start: u64,
    claims: &[(&'static str, Value)],
    held: &[u8],
) -> EntityId {
    let id = crate::test_util::entity(seed);
    let occurred = TimeRange {
        start,
        end: start + 99,
    };
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_EVENT,
            occurred,
            1,
            &event_name_body("held"),
        )
        .expect("put event");
    for (index, (predicate, value)) in (0_u8..).zip(claims) {
        let mut bytes = [0xC1_u8; 16];
        bytes[1] = seed;
        bytes[2] = index;
        let claim = EntityId::from_bytes(bytes).expect("claim id");
        let body = ClaimBody::new(
            *predicate,
            ClaimSubject::Entity(id),
            value.clone(),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
        .expect("claim body");
        vault
            .put_claim(&claim, &body, TimeRange { start: 1, end: 1 }, 1)
            .expect("put calendar claim");
        if held.contains(&index) {
            // Seeds 0x31..=0x38 times four plus an index below four: unique.
            crate::test_util::hold_claim_for_critical_confirm(vault, claim, seed * 4 + index);
        }
    }
    id
}

/// A held claim may make a slot busy and never frees one. An EVENT that is a
/// calendar EVENT only through held claims still blocks, and a held
/// cancellation or free floating time frees nothing, even when every claim on
/// the EVENT is held. A settled cancellation still frees its slot.
#[test]
fn a_held_claim_keeps_a_slot_busy_and_never_frees_one() {
    let (_dir, vault) = open_calendar_vault();
    let busy = time_kind("absolute", "busy");
    let held_event = event(&vault, 0x31, 100, &[origin(), busy.clone()], &[0, 1]);
    let held_cancel = event(
        &vault,
        0x32,
        300,
        &[origin(), busy.clone(), cancelled()],
        &[2],
    );
    let all_held = event(
        &vault,
        0x33,
        500,
        &[origin(), busy.clone(), cancelled()],
        &[0, 1, 2],
    );
    let held_free = event(
        &vault,
        0x34,
        700,
        &[origin(), time_kind("floating", "free")],
        &[1],
    );
    event(&vault, 0x35, 900, &[origin(), busy, cancelled()], &[]);

    let window = TimeRange {
        start: 0,
        end: 1_000,
    };
    let intervals: Vec<_> = crate::calendar::freebusy::freebusy(&vault, &[], window)
        .expect("freebusy")
        .into_iter()
        .map(|interval| (interval.start_utc, interval.end_utc, interval.source))
        .collect();
    assert_eq!(
        intervals,
        vec![
            (100, 200, held_event),
            (300, 400, held_cancel),
            (500, 600, all_held),
            (700, 800, held_free),
        ]
    );
}

/// Emergency reschedule's reader: an action takes no row from a held claim,
/// and a held restriction still applies. An EVENT that is a calendar
/// EVENT only through held claims is not taken; a held floating time leaves
/// its EVENT un-anchored, and a held absolute time never anchors one whose
/// settled time kind is floating, so no booking there is moved.
#[test]
fn an_action_takes_no_row_from_a_held_claim_and_keeps_its_held_restriction() {
    let (_dir, vault) = open_calendar_vault();
    let busy = time_kind("absolute", "busy");
    let held_event = event(&vault, 0x36, 100, &[origin(), busy.clone()], &[0, 1]);
    let floating = event(
        &vault,
        0x37,
        300,
        &[origin(), time_kind("floating", "busy")],
        &[1],
    );
    let settled = event(&vault, 0x38, 500, &[origin(), busy.clone()], &[]);
    // Two live time-kind heads: the held absolute one has the lower id, so
    // main's lowest-id read takes it and anchors the EVENT.
    let held_absolute = event(
        &vault,
        0x39,
        700,
        &[origin(), busy, time_kind("floating", "busy")],
        &[1],
    );
    let read = CalendarRead::Vault(&vault);
    let range = |start| TimeRange {
        start,
        end: start + 99,
    };

    let mut written = Vec::new();
    visit_calendar_events(&read, |row| {
        written.push((row.id, row.occurred));
        Ok(())
    })
    .expect("main's read");
    written.sort_unstable_by_key(|(id, _)| *id);
    assert_eq!(
        written,
        vec![
            (held_event, Some(range(100))),
            (floating, None),
            (settled, Some(range(500))),
            (held_absolute, Some(range(700))),
        ]
    );

    let mut taken = Vec::new();
    visit_calendar_events_for_effect(&read, |row| {
        taken.push((row.id, row.occurred));
        Ok(())
    })
    .expect("action read");
    taken.sort_unstable_by_key(|(id, _)| *id);
    assert_eq!(
        taken,
        vec![
            (floating, None),
            (settled, Some(range(500))),
            (held_absolute, None),
        ]
    );
}
