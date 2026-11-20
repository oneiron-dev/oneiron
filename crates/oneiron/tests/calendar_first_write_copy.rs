//! CAL-FIRST-WRITE-COPY-PULLED-UNSETTLED-IMPORTS-DUPLICATE-EVENT: the first
//! write of a native EVENT to a seat stages under the UID it mints
//! (`<event>@calendar.invalid`), and nothing resolves that UID to the EVENT
//! until the write's receipt settles. A pull of the provider's copy before
//! then, or after a replay the provider refused on its precondition, must
//! land on that one EVENT and never import the copy as a second EVENT.
//!
//! Each test checks the UID after the pull: it resolves to the native EVENT
//! or, while the write is in flight, to none. A second EVENT carrying the
//! copy's passport is the defect.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test calendar_first_write_copy`.

mod booking_host_seat_support;
#[path = "booking_deposit_support/fixture.rs"]
mod fixture;

use booking_host_seat_support::Seat;
use fixture::{Fixture, MONDAY, NOW, test_id};
use oneiron::calendar::claims::CalendarPassportDirection;
use oneiron::calendar::connectors::calendar_write_outbox_rows;
use oneiron::calendar::passport::{live_passports_for_event, resolve_event_by_uid};
use oneiron::registry::ENTITY_TYPE_EVENT;
use oneiron::{EntityId, TimeRange, Vault};

/// The seat every test writes the native EVENT to.
const SEAT_SYSTEM: &str = "first-write-seat";

/// The seed of the native EVENT: clear of the fixture's own seeds.
const NATIVE_EVENT_SEED: u8 = 0x71;

/// A native EVENT the owner made in the vault, on the fixture Monday at
/// 11:00 for 30 minutes: no source carries it, so no passport names it.
fn mint_native_event(vault: &Vault) -> EntityId {
    let id = test_id(NATIVE_EVENT_SEED);
    let mut data = Vec::new();
    rmpv::encode::write_value(
        &mut data,
        &rmpv::Value::Map(vec![(
            rmpv::Value::from("name"),
            rmpv::Value::from("planning-session"),
        )]),
    )
    .expect("encode the EVENT body");
    let start = MONDAY + 11 * 3_600;
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_EVENT,
            TimeRange {
                start,
                end: start + 30 * 60,
            },
            NOW,
            &data,
        )
        .expect("put the native EVENT");
    id
}

/// The UID the seat's staged write of `event` carries.
fn staged_uid(vault: &Vault, event: EntityId) -> String {
    let uid = calendar_write_outbox_rows(vault)
        .expect("the outbox rows")
        .into_iter()
        .find(|row| row.system == SEAT_SYSTEM && row.event_ref == event)
        .expect("the seat's write of the EVENT is staged")
        .uid;
    assert!(
        uid.ends_with("@calendar.invalid"),
        "a first write mints its UID: {uid}"
    );
    uid
}

/// Asserts that `uid` resolves to no EVENT other than `native`: the pull
/// imported no second EVENT for the copy.
fn assert_no_second_event(vault: &Vault, uid: &str, native: EntityId, label: &str) {
    let resolved = resolve_event_by_uid(vault, uid).expect("resolve the UID");
    assert!(
        resolved.is_none_or(|event| event == native),
        "{label}: the copy imported a second EVENT {resolved:?} beside the native {native:?}"
    );
}

/// The seat's live passport on `event` for `uid`, as `(direction,
/// SEQUENCE)`.
fn seat_passport(
    vault: &Vault,
    event: EntityId,
    uid: &str,
) -> Option<(CalendarPassportDirection, u32)> {
    live_passports_for_event(vault, &event)
        .expect("the EVENT's passports")
        .into_iter()
        .find(|(_, value)| value.system == SEAT_SYSTEM && value.uid == uid)
        .map(|(_, value)| (value.direction, value.last_sequence))
}

#[test]
fn a_first_write_s_copy_pulled_before_its_answer_imports_no_second_event() {
    // The provider stores the first write, but its answer is lost: the
    // write stays in flight. A pull reads the stored copy before the
    // replay settles it. The copy waits, owed, and the pull after the
    // settlement reads it as the write's echo, on the native EVENT.
    let fixture = Fixture::open(None);
    let seat = Seat::install(&fixture.vault, SEAT_SYSTEM);
    let native = mint_native_event(&fixture.vault);

    let stored = seat.write_with_lost_answer(&fixture.vault, native, NOW + 10);
    let uid = staged_uid(&fixture.vault, native);
    let locator = seat.resource_locator(&uid);
    seat.pull_own_write(&fixture.vault, &locator, NOW + 20)
        .expect("seat pull");
    assert_no_second_event(
        &fixture.vault,
        &uid,
        native,
        "a pull while the first write is in flight",
    );

    let wrote = seat.write(&fixture.vault, native, NOW + 30);
    assert_eq!(
        wrote.sequence, stored,
        "the replay settles the staged write"
    );
    seat.pull_own_write(&fixture.vault, &wrote, NOW + 40)
        .expect("seat pull");
    assert_eq!(
        resolve_event_by_uid(&fixture.vault, &uid).expect("resolve the UID"),
        Some(native),
        "the copy read after the settlement is the native EVENT's"
    );
    assert_eq!(
        seat_passport(&fixture.vault, native, &uid),
        Some((CalendarPassportDirection::Outbound, stored)),
        "the seat holds the native EVENT as written"
    );
}

#[test]
fn a_first_write_replay_refused_over_its_own_copy_lands_on_its_event() {
    // The provider stores the first write and rewrites it, but the answer
    // is lost; the replay is refused on the rewritten copy, which proves
    // the write's own. The refusal publishes the write as its receipt would
    // have, so the seat's report of the rewrite lands on the native EVENT.
    let fixture = Fixture::open(None);
    let seat = Seat::install(&fixture.vault, SEAT_SYSTEM);
    let native = mint_native_event(&fixture.vault);

    let stored = seat.write_with_lost_answer(&fixture.vault, native, NOW + 10);
    let uid = staged_uid(&fixture.vault, native);
    let locator = seat.resource_locator(&uid);
    seat.replay_refused_over_rewritten_own_write(
        &fixture.vault,
        native,
        &locator,
        stored,
        NOW + 20,
    );
    assert_eq!(
        seat_passport(&fixture.vault, native, &uid),
        Some((CalendarPassportDirection::Outbound, stored)),
        "the refused replay publishes the write's own stored copy"
    );

    seat.pull_rewritten_own_write(&fixture.vault, &locator, stored, NOW + 30)
        .expect("seat pull");
    assert_no_second_event(
        &fixture.vault,
        &uid,
        native,
        "the seat's report of the rewritten copy",
    );
}

#[test]
fn a_host_s_change_read_by_a_refused_first_write_replay_lands_on_its_event() {
    // The provider stores the first write, but the answer is lost, and the
    // host cancels the event in a client that writes another marker; the
    // replay is refused on that copy, which is not the write's own. Only
    // the write stores a resource under the UID it minted, so the copy is
    // that write's as the host changed it: the write lands as written, and
    // the host's cancel is a change of the native EVENT.
    let fixture = Fixture::open(None);
    let seat = Seat::install(&fixture.vault, SEAT_SYSTEM);
    let native = mint_native_event(&fixture.vault);

    let stored = seat.write_with_lost_answer(&fixture.vault, native, NOW + 10);
    let uid = staged_uid(&fixture.vault, native);
    let locator = seat.resource_locator(&uid);
    seat.replay_refused_over(
        &fixture.vault,
        native,
        &seat.host_cancel_of_own_write(&locator, stored + 1),
        NOW + 20,
    );
    assert_eq!(
        seat_passport(&fixture.vault, native, &uid),
        Some((CalendarPassportDirection::Outbound, stored)),
        "the refused first write lands as written"
    );

    seat.pull(
        &fixture.vault,
        &[seat.host_cancel_of_own_write(&locator, stored + 1)],
        NOW + 30,
    )
    .expect("seat pull");
    assert_no_second_event(&fixture.vault, &uid, native, "the host's cancel");
    assert_eq!(
        seat_passport(&fixture.vault, native, &uid),
        Some((CalendarPassportDirection::Outbound, stored + 1)),
        "the host's cancel is a change of the native EVENT"
    );
}

#[test]
fn a_first_write_replay_whose_read_failed_is_proved_by_the_next_pull() {
    // The provider stores the first write, but the answer is lost; the
    // replay is refused, and its reconciliation read fails. The seat's next
    // pull of the stored copy proves it the write's own before admitting
    // it: the copy is the write's echo on the native EVENT.
    let fixture = Fixture::open(None);
    let seat = Seat::install(&fixture.vault, SEAT_SYSTEM);
    let native = mint_native_event(&fixture.vault);

    let stored = seat.write_with_lost_answer(&fixture.vault, native, NOW + 10);
    let uid = staged_uid(&fixture.vault, native);
    let locator = seat.resource_locator(&uid);
    seat.replay_refused_unread(&fixture.vault, native, NOW + 20);
    seat.pull_own_write(&fixture.vault, &locator, NOW + 30)
        .expect("seat pull");
    assert_no_second_event(
        &fixture.vault,
        &uid,
        native,
        "the pull of the unproven copy",
    );
    assert_eq!(
        seat_passport(&fixture.vault, native, &uid),
        Some((CalendarPassportDirection::Outbound, stored)),
        "the pull proves the write's own stored copy"
    );
}

#[test]
fn a_host_s_change_proving_an_unread_first_write_replay_lands_on_its_event() {
    // The provider stores the first write, but the answer is lost; the
    // replay is refused, and its reconciliation read fails. The host then
    // cancels the event, and the seat's next pull reads that copy, which is
    // not the write's own: the write lands as written, and the host's
    // cancel is a change of the native EVENT.
    let fixture = Fixture::open(None);
    let seat = Seat::install(&fixture.vault, SEAT_SYSTEM);
    let native = mint_native_event(&fixture.vault);

    let stored = seat.write_with_lost_answer(&fixture.vault, native, NOW + 10);
    let uid = staged_uid(&fixture.vault, native);
    let locator = seat.resource_locator(&uid);
    seat.replay_refused_unread(&fixture.vault, native, NOW + 20);
    seat.pull(
        &fixture.vault,
        &[seat.host_cancel_of_own_write(&locator, stored + 1)],
        NOW + 30,
    )
    .expect("seat pull");
    assert_no_second_event(&fixture.vault, &uid, native, "the host's cancel");
    assert_eq!(
        seat_passport(&fixture.vault, native, &uid),
        Some((CalendarPassportDirection::Outbound, stored + 1)),
        "the host's cancel is a change of the native EVENT"
    );
}
