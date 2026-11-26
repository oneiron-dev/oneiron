//! CAL-FIRST-WRITE-COPY-PULLED-UNSETTLED-IMPORTS-DUPLICATE-EVENT: the first
//! write of a native EVENT to a seat stages under the UID it mints
//! (`<event>@calendar.invalid`), and nothing resolves that UID to the EVENT
//! until the write's receipt settles. A pull of the provider's copy before
//! then, or after a replay the provider refused on its precondition, or
//! after a call refused over the copy an overlapping replay of the same
//! write stored, must land on that one EVENT and never import the copy as a
//! second EVENT.
//!
//! Each test checks the UID after the pull: it resolves to the native EVENT
//! or, while the write is in flight, to none. A second EVENT carrying the
//! copy's passport is the defect. The same holds for a second seat that
//! reads the collection under another system name: its pull of the copy
//! must wait until the first write binds the UID.
//!
//! The last tests read a passport whose system name or UID the claim door
//! stored as a custody handle: the seat's own next pull must find that
//! passport, a series member's included, and never file a second passport
//! of the same seat beside it
//! (CAL-PASSPORT-SYSTEM-UID-LOOKUP-MISSES-MASKED-PASSPORT). A write to the
//! seat must read such a passport as the seat's own too, and send the UID
//! the provider holds, never the handle
//! (CAL-MASKED-SYSTEM-LITERAL-COMPARES-OUTSIDE-KEYED-LOOKUP).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test calendar_first_write_copy`.

mod booking_host_seat_support;
#[path = "booking_deposit_support/fixture.rs"]
mod fixture;

use booking_host_seat_support::{Seat, SeatChange, seat_owner};
use fixture::{Fixture, MONDAY, NOW, test_id};
use oneiron::calendar::claims::{CalendarPassportDirection, PREDICATE_CALENDAR_PASSPORT};
use oneiron::calendar::connectors::{
    CalendarSyncOutcome, RemoteCalendarObject, calendar_write_outbox_rows,
};
use oneiron::calendar::parse_ics_feed;
use oneiron::calendar::passport::{live_passports_for_event, resolve_event_by_uid};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use oneiron::memory::{ClaimProposalReviewRequest, ClaimSettleDecision, ClaimSettleRequest};
use oneiron::registry::ENTITY_TYPE_EVENT;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault};

/// The seat every test writes the native EVENT to.
const SEAT_SYSTEM: &str = "first-write-seat";

/// A second seat on the collection the native EVENT is written to,
/// installed under another system name: no write of its own stages the UID.
const SIBLING_SEAT_SYSTEM: &str = "first-write-sibling-seat";

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
    system_passport(vault, event, SEAT_SYSTEM, uid)
}

/// The live passport of the seat installed under `system` on `event` for
/// `uid`, as `(direction, SEQUENCE)`.
fn system_passport(
    vault: &Vault,
    event: EntityId,
    system: &str,
    uid: &str,
) -> Option<(CalendarPassportDirection, u32)> {
    live_passports_for_event(vault, &event)
        .expect("the EVENT's passports")
        .into_iter()
        .find(|(_, value)| value.system == system && value.uid == uid)
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

#[test]
fn a_first_write_refused_over_an_overlapping_replay_s_copy_lands_on_its_event() {
    // Review round 1 of #9903: two calls of the first write overlap. The
    // second finds the write prepared and replays it while the first call's
    // request is out; the provider stores the replay, but its answer is
    // lost. The first call's own request is then refused on its
    // precondition, and its reconciliation reads the replay's stored copy.
    // Only the write stores a resource under the UID it minted, so the
    // refusal publishes the write as its receipt would have, and the seat's
    // report of the copy lands on the native EVENT.
    let fixture = Fixture::open(None);
    let seat = Seat::install(&fixture.vault, SEAT_SYSTEM);
    let native = mint_native_event(&fixture.vault);

    let stored = seat.write_refused_over_overlapping_replay(
        &fixture.vault,
        native,
        false,
        NOW + 15,
        NOW + 10,
    );
    let uid = staged_uid(&fixture.vault, native);
    let locator = seat.resource_locator(&uid);
    seat.pull_own_write(&fixture.vault, &locator, NOW + 30)
        .expect("seat pull");
    assert_no_second_event(
        &fixture.vault,
        &uid,
        native,
        "the seat's report of the overlapping replay's copy",
    );
    assert_eq!(
        seat_passport(&fixture.vault, native, &uid),
        Some((CalendarPassportDirection::Outbound, stored)),
        "the refused call publishes the replay's stored copy"
    );
}

#[test]
fn a_first_write_refused_over_an_overlapping_replay_unread_is_proved_by_the_next_pull() {
    // Review round 1 of #9903: as above, but the first call's
    // reconciliation read fails, so the refusal reads no copy. The proof
    // stays owed: the seat's next pull of the replay's stored copy proves it
    // the write's before admitting it, on the native EVENT.
    let fixture = Fixture::open(None);
    let seat = Seat::install(&fixture.vault, SEAT_SYSTEM);
    let native = mint_native_event(&fixture.vault);

    let stored = seat.write_refused_over_overlapping_replay(
        &fixture.vault,
        native,
        true,
        NOW + 15,
        NOW + 10,
    );
    let uid = staged_uid(&fixture.vault, native);
    let locator = seat.resource_locator(&uid);
    seat.pull_own_write(&fixture.vault, &locator, NOW + 30)
        .expect("seat pull");
    assert_no_second_event(
        &fixture.vault,
        &uid,
        native,
        "the pull of the overlapping replay's unproven copy",
    );
    assert_eq!(
        seat_passport(&fixture.vault, native, &uid),
        Some((CalendarPassportDirection::Outbound, stored)),
        "the pull proves the replay's stored copy"
    );
}

#[test]
fn a_sibling_seat_s_pull_of_a_first_write_in_flight_imports_no_second_event() {
    // Review round 2 of #9903: two seats read one collection under
    // different system names. The first seat's first write is stored, but
    // its answer is lost: the write stays in flight. The sibling seat pulls
    // the stored copy; no write of its own stages the UID, and nothing
    // resolves the UID yet. The copy waits, owed, and the sibling's pull
    // after the settlement reads it on the native EVENT.
    let fixture = Fixture::open(None);
    let seat = Seat::install(&fixture.vault, SEAT_SYSTEM);
    let sibling = Seat::install(&fixture.vault, SIBLING_SEAT_SYSTEM);
    let native = mint_native_event(&fixture.vault);

    let stored = seat.write_with_lost_answer(&fixture.vault, native, NOW + 10);
    let uid = staged_uid(&fixture.vault, native);
    sibling
        .pull(&fixture.vault, &[seat.stored_own_write(&uid)], NOW + 20)
        .expect("sibling seat pull");
    assert_no_second_event(
        &fixture.vault,
        &uid,
        native,
        "the sibling seat's pull while the first write is in flight",
    );

    let wrote = seat.write(&fixture.vault, native, NOW + 30);
    assert_eq!(
        wrote.sequence, stored,
        "the replay settles the staged write"
    );
    sibling
        .pull(&fixture.vault, &[seat.stored_own_write(&uid)], NOW + 40)
        .expect("sibling seat pull");
    assert_no_second_event(
        &fixture.vault,
        &uid,
        native,
        "the sibling seat's pull after the settlement",
    );
    assert_eq!(
        system_passport(&fixture.vault, native, SIBLING_SEAT_SYSTEM, &uid)
            .map(|(_, sequence)| sequence),
        Some(stored),
        "the sibling seat reads the copy on the native EVENT"
    );
}

#[test]
fn a_sibling_seat_s_pull_of_an_unproven_first_write_imports_no_second_event() {
    // Review round 2 of #9903: as above, but the first seat's replay is
    // refused and its reconciliation read fails, so the write's proof stays
    // owed to the first seat's next pull. The sibling seat's pull of the
    // stored copy waits, owed, until that pull proves the copy the write's
    // own; the sibling's next pull reads it on the native EVENT.
    let fixture = Fixture::open(None);
    let seat = Seat::install(&fixture.vault, SEAT_SYSTEM);
    let sibling = Seat::install(&fixture.vault, SIBLING_SEAT_SYSTEM);
    let native = mint_native_event(&fixture.vault);

    let stored = seat.write_with_lost_answer(&fixture.vault, native, NOW + 10);
    let uid = staged_uid(&fixture.vault, native);
    let locator = seat.resource_locator(&uid);
    seat.replay_refused_unread(&fixture.vault, native, NOW + 20);
    sibling
        .pull(&fixture.vault, &[seat.stored_own_write(&uid)], NOW + 30)
        .expect("sibling seat pull");
    assert_no_second_event(
        &fixture.vault,
        &uid,
        native,
        "the sibling seat's pull while the first write's proof is owed",
    );

    seat.pull_own_write(&fixture.vault, &locator, NOW + 40)
        .expect("seat pull");
    assert_eq!(
        seat_passport(&fixture.vault, native, &uid),
        Some((CalendarPassportDirection::Outbound, stored)),
        "the seat's pull proves the write's own stored copy"
    );
    sibling
        .pull(&fixture.vault, &[seat.stored_own_write(&uid)], NOW + 50)
        .expect("sibling seat pull");
    assert_no_second_event(
        &fixture.vault,
        &uid,
        native,
        "the sibling seat's pull after the proof",
    );
    assert_eq!(
        system_passport(&fixture.vault, native, SIBLING_SEAT_SYSTEM, &uid)
            .map(|(_, sequence)| sequence),
        Some(stored),
        "the sibling seat reads the copy on the native EVENT"
    );
}

/// Registers `value` as a custody value under `name`, so a row or claim the
/// vault stores from now on keeps it as a custody handle (`[secret sc..]`).
fn register_custody_value(vault: &Vault, name: &str, value: &str) {
    vault
        .register_test_secret(name, value.as_bytes(), Vec::new(), NOW)
        .expect("the value is a custody value");
}

/// The UID a first write of `event` mints: `<event>@calendar.invalid`.
fn minted_uid(event: EntityId) -> String {
    format!("{}@calendar.invalid", event.to_hex())
}

/// Asserts that the seat's staged write of `event` keeps its minted `uid` as
/// a custody handle. The row is found by its EVENT: its strings no longer
/// name the UID.
fn assert_staged_uid_masked(vault: &Vault, event: EntityId, uid: &str) {
    let row = calendar_write_outbox_rows(vault)
        .expect("the outbox rows")
        .into_iter()
        .find(|row| row.event_ref == event)
        .expect("the seat's write of the EVENT is staged");
    assert!(
        row.uid != uid && row.uid.contains("[secret sc"),
        "FIXTURE: the stored outbox row keeps the minted UID as a custody handle: {}",
        row.uid
    );
}

/// The number of EVENTs the vault holds: a pull that imports the copy as a
/// second EVENT raises it, whatever its passport's UID reads as.
fn event_count(vault: &Vault) -> u64 {
    vault
        .count_entities_by_type(ENTITY_TYPE_EVENT)
        .expect("count the EVENTs")
}

/// The SEQUENCE of the live passport of the seat installed under `system`
/// on `event`, found by the system alone: its UID may be a custody handle.
fn system_sequence(vault: &Vault, event: EntityId, system: &str) -> Option<u32> {
    live_passports_for_event(vault, &event)
        .expect("the EVENT's passports")
        .into_iter()
        .find(|(_, value)| value.system == system)
        .map(|(_, value)| value.last_sequence)
}

#[test]
fn a_sibling_seat_s_pull_of_a_masked_first_write_in_flight_imports_no_second_event() {
    // Blind review round 1 of #10090 (P1-1),
    // CAL-OUTBOX-SCAN-MASKED-SYSTEM-MISSES-ROW: as the sibling test above,
    // but the first seat's system name and the UID its first write mints
    // are custody values when the write stages, so the stored outbox row
    // keeps both as custody handles. The sibling reads the collection under
    // another system name, so neither the row's readable strings nor a key
    // either seat derives name the UID; only the row's UID read as custody
    // reads it does. The copy waits, owed, and the sibling's pull after the
    // settlement reads it on the native EVENT.
    let fixture = Fixture::open(None);
    let seat = Seat::install(&fixture.vault, SEAT_SYSTEM);
    let sibling = Seat::install(&fixture.vault, SIBLING_SEAT_SYSTEM);
    let native = mint_native_event(&fixture.vault);
    let uid = minted_uid(native);
    register_custody_value(&fixture.vault, "first-write-seat-system", SEAT_SYSTEM);
    register_custody_value(&fixture.vault, "first-write-minted-uid", &uid);
    let events = event_count(&fixture.vault);

    let stored = seat.write_with_lost_answer(&fixture.vault, native, NOW + 10);
    assert_staged_uid_masked(&fixture.vault, native, &uid);
    sibling
        .pull(&fixture.vault, &[seat.stored_own_write(&uid)], NOW + 20)
        .expect("sibling seat pull");
    assert_eq!(
        event_count(&fixture.vault),
        events,
        "the sibling seat's pull of the masked first write in flight imports no second EVENT"
    );

    let wrote = seat.write(&fixture.vault, native, NOW + 30);
    assert_eq!(
        wrote.sequence, stored,
        "the replay settles the staged write"
    );
    sibling
        .pull(&fixture.vault, &[seat.stored_own_write(&uid)], NOW + 40)
        .expect("sibling seat pull");
    assert_eq!(
        event_count(&fixture.vault),
        events,
        "the sibling seat's pull after the settlement imports no second EVENT"
    );
    assert_eq!(
        resolve_event_by_uid(&fixture.vault, &uid).expect("resolve the UID"),
        Some(native),
        "the masked minted UID resolves to the native EVENT"
    );
    assert_eq!(
        system_sequence(&fixture.vault, native, SIBLING_SEAT_SYSTEM),
        Some(stored),
        "the sibling seat reads the copy on the native EVENT"
    );
}

#[test]
fn a_sibling_seat_s_pull_after_a_masked_first_write_settles_lands_on_its_event() {
    // Blind review round 1 of #10090 (P1-2): only the UID the first write
    // mints is a custody value, so the stored outbox row keeps it as a
    // custody handle and matches by its key: the sibling's pull of the copy
    // waits, owed. The settlement indexes the UID, and the passport it files
    // keeps the UID as a custody handle too. That passport must still vouch
    // for the index entry, or the sibling's pull after the settlement
    // imports the copy as a second EVENT.
    let fixture = Fixture::open(None);
    let seat = Seat::install(&fixture.vault, SEAT_SYSTEM);
    let sibling = Seat::install(&fixture.vault, SIBLING_SEAT_SYSTEM);
    let native = mint_native_event(&fixture.vault);
    let uid = minted_uid(native);
    register_custody_value(&fixture.vault, "first-write-minted-uid", &uid);
    let events = event_count(&fixture.vault);

    let stored = seat.write_with_lost_answer(&fixture.vault, native, NOW + 10);
    assert_staged_uid_masked(&fixture.vault, native, &uid);
    sibling
        .pull(&fixture.vault, &[seat.stored_own_write(&uid)], NOW + 20)
        .expect("sibling seat pull");
    assert_eq!(
        event_count(&fixture.vault),
        events,
        "the sibling seat's pull while the masked first write is in flight imports no second EVENT"
    );

    let wrote = seat.write(&fixture.vault, native, NOW + 30);
    assert_eq!(
        wrote.sequence, stored,
        "the replay settles the staged write"
    );
    assert!(
        live_passports_for_event(&fixture.vault, &native)
            .expect("the EVENT's passports")
            .iter()
            .any(|(_, value)| value.system == SEAT_SYSTEM
                && value.uid != uid
                && value.uid.contains("[secret sc")),
        "FIXTURE: the settled write's passport keeps the minted UID as a custody handle"
    );
    sibling
        .pull(&fixture.vault, &[seat.stored_own_write(&uid)], NOW + 40)
        .expect("sibling seat pull");
    assert_eq!(
        event_count(&fixture.vault),
        events,
        "the sibling seat's pull after the masked first write settles imports no second EVENT"
    );
    assert_eq!(
        resolve_event_by_uid(&fixture.vault, &uid).expect("resolve the UID"),
        Some(native),
        "the masked minted UID resolves to the native EVENT"
    );
    assert_eq!(
        system_sequence(&fixture.vault, native, SIBLING_SEAT_SYSTEM),
        Some(stored),
        "the sibling seat reads the copy on the native EVENT"
    );
}

/// The custody record that holds an imported VEVENT's UID.
const IMPORTED_UID_SECRET: &str = "imported-vevent-uid";

/// The semantic applications (create, attach, update) one pull made.
fn applied(outcome: &CalendarSyncOutcome) -> u32 {
    match outcome {
        CalendarSyncOutcome::Reenqueued { applied, .. } => *applied,
        CalendarSyncOutcome::Killed => panic!("the calendar kill switch is off"),
    }
}

/// Asserts that a live passport of the seat installed under `system` on
/// `event` keeps `uid` as a custody handle.
fn assert_passport_uid_masked(vault: &Vault, event: EntityId, system: &str, uid: &str) {
    assert!(
        live_passports_for_event(vault, &event)
            .expect("the EVENT's passports")
            .iter()
            .any(|(_, value)| value.system == system
                && value.uid != uid
                && value.uid.contains("[secret sc")),
        "FIXTURE: the imported passport keeps the UID as a custody handle"
    );
}

#[test]
fn a_vevent_under_the_uid_a_rotation_gave_a_custody_record_imports_its_own_event() {
    // Blind review round 2 of #10090 (P1-1): a custody record holds the
    // UID of an imported VEVENT, so its passport keeps the UID as the
    // record's handle. A rotation then gives the record another UID, which
    // a second VEVENT carries. The handle meets every value its record ever
    // held, so read alone it would land the second VEVENT on the first
    // VEVENT's EVENT; only a UID pinned to that EVENT is read through it.
    let fixture = Fixture::open(None);
    let seat = Seat::install(&fixture.vault, SEAT_SYSTEM);
    let first_uid = "custody-rotation-first@host.example.test";
    let second_uid = "custody-rotation-second@host.example.test";
    register_custody_value(&fixture.vault, IMPORTED_UID_SECRET, first_uid);
    let events = event_count(&fixture.vault);
    let start = MONDAY + 9 * 3_600;

    seat.pull(
        &fixture.vault,
        &[SeatChange::foreign(
            &seat,
            first_uid,
            start,
            start + 30 * 60,
            0,
            false,
        )],
        NOW + 10,
    )
    .expect("seat pull");
    assert_eq!(
        event_count(&fixture.vault),
        events + 1,
        "FIXTURE: the first VEVENT imports one EVENT"
    );
    let first = resolve_event_by_uid(&fixture.vault, first_uid)
        .expect("resolve the first UID")
        .expect("FIXTURE: the first UID resolves to its EVENT");
    assert_passport_uid_masked(&fixture.vault, first, SEAT_SYSTEM, first_uid);

    let (_, owner) = seat_owner(&fixture.vault);
    fixture
        .vault
        .rotate_secret_as_owner(&owner, IMPORTED_UID_SECRET, second_uid.as_bytes(), NOW + 20)
        .expect("rotate the custody record to the second UID");
    let later = start + 2 * 3_600;
    seat.pull(
        &fixture.vault,
        &[SeatChange::foreign(
            &seat,
            second_uid,
            later,
            later + 30 * 60,
            0,
            false,
        )],
        NOW + 30,
    )
    .expect("seat pull");
    assert_eq!(
        event_count(&fixture.vault),
        events + 2,
        "the second VEVENT imports an EVENT of its own"
    );
    let second = resolve_event_by_uid(&fixture.vault, second_uid).expect("resolve the second UID");
    assert!(
        second.is_some_and(|second| second != first),
        "the second UID resolves to its own EVENT: {second:?}"
    );
    assert_eq!(
        resolve_event_by_uid(&fixture.vault, first_uid).expect("resolve the first UID"),
        Some(first),
        "the first UID still resolves to its EVENT"
    );
}

#[test]
fn an_older_cancel_of_a_masked_uid_is_skipped_and_a_newer_version_revises_its_passport() {
    // Blind review round 2 of #10090 (P1-2),
    // CAL-PASSPORT-SYSTEM-UID-LOOKUP-MISSES-MASKED-PASSPORT: the UID of an
    // imported VEVENT is a custody value, so its passport keeps the UID as
    // a custody handle. The seat's pull of an older version, cancelled, must
    // read that passport's SEQUENCE and skip, not attach a fresh passport
    // and an imported cancellation; a newer version revises that passport.
    let fixture = Fixture::open(None);
    let seat = Seat::install(&fixture.vault, SEAT_SYSTEM);
    let uid = "custody-masked-cancel@host.example.test";
    register_custody_value(&fixture.vault, IMPORTED_UID_SECRET, uid);
    let events = event_count(&fixture.vault);
    let start = MONDAY + 9 * 3_600;
    let end = start + 30 * 60;

    seat.pull(
        &fixture.vault,
        &[SeatChange::foreign(&seat, uid, start, end, 3, false)],
        NOW + 10,
    )
    .expect("seat pull");
    let event = resolve_event_by_uid(&fixture.vault, uid)
        .expect("resolve the UID")
        .expect("FIXTURE: the UID resolves to its EVENT");
    assert_passport_uid_masked(&fixture.vault, event, SEAT_SYSTEM, uid);
    assert_eq!(
        system_sequence(&fixture.vault, event, SEAT_SYSTEM),
        Some(3),
        "FIXTURE: the passport records the imported SEQUENCE"
    );

    let older = seat
        .pull(
            &fixture.vault,
            &[SeatChange::foreign(&seat, uid, start, end, 2, true)],
            NOW + 20,
        )
        .expect("seat pull");
    assert_eq!(
        applied(&older),
        0,
        "the older cancelled version applies nothing"
    );
    assert_eq!(
        event_count(&fixture.vault),
        events + 1,
        "the older cancelled version imports no second EVENT"
    );
    assert_eq!(
        system_sequence(&fixture.vault, event, SEAT_SYSTEM),
        Some(3),
        "the passport keeps the newer SEQUENCE"
    );
    assert!(
        live_passports_for_event(&fixture.vault, &event)
            .expect("the EVENT's passports")
            .iter()
            .all(|(_, value)| value.cancelled_since.is_none()),
        "no passport records the older version's cancellation"
    );

    let newer = seat
        .pull(
            &fixture.vault,
            &[SeatChange::foreign(
                &seat,
                uid,
                start,
                end + 30 * 60,
                4,
                false,
            )],
            NOW + 30,
        )
        .expect("the newer version revises the masked passport");
    assert_eq!(applied(&newer), 1, "the newer version applies");
    assert_eq!(
        system_sequence(&fixture.vault, event, SEAT_SYSTEM),
        Some(4),
        "the newer version revises the seat's passport"
    );
    assert_eq!(
        event_count(&fixture.vault),
        events + 1,
        "the newer version imports no second EVENT"
    );
}

/// The custody record that holds the seat's system name.
const SEAT_SYSTEM_SECRET: &str = "masked-seat-system";

/// One lifecycle-active `calendar.passport` claim, as its value stores it.
#[derive(Debug)]
struct ActivePassport {
    id: EntityId,
    system: String,
    uid: String,
    sequence: u64,
    approval: ClaimApprovalStatus,
}

/// The lifecycle-active `calendar.passport` claims on `event`, one per
/// claim. The folded view (`live_passports_for_event`) keeps one claim per
/// stored key, so two passports of one seat stored under one custody handle
/// read there as one.
fn active_passports(vault: &Vault, event: EntityId) -> Vec<ActivePassport> {
    let field = |value: &rmpv::Value, key: &str| -> rmpv::Value {
        value
            .as_map()
            .expect("FIXTURE: a passport value is a map")
            .iter()
            .find(|(name, _)| name.as_str() == Some(key))
            .map(|(_, field)| field.clone())
            .unwrap_or_else(|| panic!("FIXTURE: a passport value carries {key}"))
    };
    let text = |value: &rmpv::Value, key: &str| -> String {
        field(value, key)
            .as_str()
            .expect("FIXTURE: the passport field is text")
            .to_owned()
    };
    let mut passports = Vec::new();
    for id in vault
        .claims_for_subject(&event)
        .expect("the EVENT's claims")
    {
        let Some(body) = vault.get_claim(&id).expect("read the claim") else {
            continue;
        };
        if body.predicate != PREDICATE_CALENDAR_PASSPORT
            || body.lifecycle != ClaimLifecycleStatus::Active
        {
            continue;
        }
        passports.push(ActivePassport {
            id,
            system: text(&body.value, "system"),
            uid: text(&body.value, "uid"),
            sequence: field(&body.value, "last_sequence")
                .as_u64()
                .expect("FIXTURE: the passport SEQUENCE is a number"),
            approval: body.approval,
        });
    }
    passports
}

/// Whether `stored`, a string a passport keeps, holds a custody handle in
/// place of `value`.
fn masked(stored: &str, value: &str) -> bool {
    stored != value && stored.contains("[secret sc")
}

#[test]
fn a_seat_s_own_echo_under_a_masked_system_files_no_second_passport() {
    // CAL-PASSPORT-SYSTEM-UID-LOOKUP-MISSES-MASKED-PASSPORT: the seat's
    // system name is a custody value, so the passport its settled write
    // files keeps the system as a custody handle. The seat's pull of its own
    // write must read that passport as the seat's, not attach a second
    // passport of the same seat beside it.
    let fixture = Fixture::open(None);
    let seat = Seat::install(&fixture.vault, SEAT_SYSTEM);
    let native = mint_native_event(&fixture.vault);
    register_custody_value(&fixture.vault, SEAT_SYSTEM_SECRET, SEAT_SYSTEM);

    let wrote = seat.write(&fixture.vault, native, NOW + 10);
    let filed = active_passports(&fixture.vault, native);
    assert!(
        filed.len() == 1 && masked(&filed[0].system, SEAT_SYSTEM) && filed[0].uid == wrote.uid,
        "FIXTURE: the settled write files one passport whose system is a custody handle: {filed:?}"
    );

    seat.pull_own_write(&fixture.vault, &wrote, NOW + 20)
        .expect("the seat's pull of its own write");
    let after = active_passports(&fixture.vault, native);
    assert_eq!(
        after.len(),
        1,
        "the seat's own echo files no second passport of the seat: {after:?}"
    );
    assert_eq!(
        resolve_event_by_uid(&fixture.vault, &wrote.uid).expect("resolve the UID"),
        Some(native),
        "the written UID resolves to the native EVENT"
    );
}

#[test]
fn an_older_cancel_under_a_masked_system_is_skipped_and_a_newer_version_revises_its_passport() {
    // CAL-PASSPORT-SYSTEM-UID-LOOKUP-MISSES-MASKED-PASSPORT: the seat's
    // system name is a custody value, so the passport of an imported VEVENT
    // keeps the system as a custody handle. The seat's pull of an older
    // version, cancelled, must read that passport's SEQUENCE and skip, not
    // attach a fresh passport and an imported cancellation; a newer version
    // revises that passport.
    let fixture = Fixture::open(None);
    let seat = Seat::install(&fixture.vault, SEAT_SYSTEM);
    register_custody_value(&fixture.vault, SEAT_SYSTEM_SECRET, SEAT_SYSTEM);
    let uid = "masked-system-cancel@host.example.test";
    let events = event_count(&fixture.vault);
    let start = MONDAY + 9 * 3_600;
    let end = start + 30 * 60;

    seat.pull(
        &fixture.vault,
        &[SeatChange::foreign(&seat, uid, start, end, 3, false)],
        NOW + 10,
    )
    .expect("seat pull");
    let event = resolve_event_by_uid(&fixture.vault, uid)
        .expect("resolve the UID")
        .expect("FIXTURE: the UID resolves to its EVENT");
    let filed = active_passports(&fixture.vault, event);
    assert!(
        filed.len() == 1 && masked(&filed[0].system, SEAT_SYSTEM) && filed[0].sequence == 3,
        "FIXTURE: the import files one passport whose system is a custody handle: {filed:?}"
    );

    let older = seat
        .pull(
            &fixture.vault,
            &[SeatChange::foreign(&seat, uid, start, end, 2, true)],
            NOW + 20,
        )
        .expect("seat pull");
    assert_eq!(
        applied(&older),
        0,
        "the older cancelled version applies nothing"
    );
    let after = active_passports(&fixture.vault, event);
    assert_eq!(
        after.len(),
        1,
        "the older cancelled version files no second passport: {after:?}"
    );
    assert!(
        live_passports_for_event(&fixture.vault, &event)
            .expect("the EVENT's passports")
            .iter()
            .all(|(_, value)| value.cancelled_since.is_none()),
        "no passport records the older version's cancellation"
    );

    let newer = seat
        .pull(
            &fixture.vault,
            &[SeatChange::foreign(
                &seat,
                uid,
                start,
                end + 30 * 60,
                4,
                false,
            )],
            NOW + 30,
        )
        .expect("the newer version revises the masked passport");
    assert_eq!(applied(&newer), 1, "the newer version applies");
    assert!(
        active_passports(&fixture.vault, event)
            .iter()
            .any(|passport| passport.sequence == 4),
        "the newer version files the seat's next passport"
    );
    assert_eq!(
        event_count(&fixture.vault),
        events + 1,
        "the newer version imports no second EVENT"
    );
}

/// The UID of the series the seat's calendar holds.
const SERIES_UID: &str = "masked-series@host.example.test";

/// The custody record that holds the series UID.
const SERIES_UID_SECRET: &str = "masked-series-uid";

/// The seat's resource of one daily series of three, its master at
/// SEQUENCE 1 and its first occurrence detached and moved two hours later,
/// at `member_sequence` and titled `member_summary`, exactly as the
/// calendar stores it. The resource's SEQUENCE is the member's, so a pull
/// reads a change of the member alone.
fn series_resource(seat: &Seat, member_sequence: u32, member_summary: &str) -> SeatChange {
    let ics = format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:{SERIES_UID}\r\nSEQUENCE:1\r\n\
         DTSTART:20260806T140000Z\r\nDTEND:20260806T150000Z\r\nRRULE:FREQ=DAILY;COUNT=3\r\n\
         SUMMARY:series master\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:{SERIES_UID}\r\n\
         SEQUENCE:{member_sequence}\r\nRECURRENCE-ID:20260806T140000Z\r\n\
         DTSTART:20260806T160000Z\r\nDTEND:20260806T170000Z\r\nSUMMARY:{member_summary}\r\n\
         END:VEVENT\r\nEND:VCALENDAR\r\n"
    );
    let feed = parse_ics_feed(ics.as_bytes()).expect("FIXTURE: the series parses");
    let master = feed
        .events
        .first()
        .expect("FIXTURE: the series carries its master");
    SeatChange::Stored(RemoteCalendarObject {
        href: seat.resource_locator(SERIES_UID).href,
        etag: Some(format!("\"masked-series-{member_sequence}\"")),
        uid: master.uid.clone(),
        sequence: member_sequence,
        content_hash: master.content_hash,
        ics: ics.into_bytes(),
    })
}

#[test]
fn a_series_member_s_masked_uid_is_revised_by_its_next_pull() {
    // CAL-PASSPORT-SYSTEM-UID-LOOKUP-MISSES-MASKED-PASSPORT: a series UID is
    // a custody value, so the passport of the series' detached member keeps
    // the UID as a custody handle. The UID index points the UID at the
    // master alone, so the member's UID is pinned only through its master.
    // The member's next version must revise the member's passport, not
    // attach a second one beside it.
    let fixture = Fixture::open(None);
    let seat = Seat::install(&fixture.vault, SEAT_SYSTEM);
    register_custody_value(&fixture.vault, SERIES_UID_SECRET, SERIES_UID);
    let before = fixture
        .vault
        .entities_by_type(ENTITY_TYPE_EVENT)
        .expect("the EVENTs");

    seat.pull(
        &fixture.vault,
        &[series_resource(&seat, 1, "member first")],
        NOW + 10,
    )
    .expect("seat pull");
    let master = resolve_event_by_uid(&fixture.vault, SERIES_UID)
        .expect("resolve the series UID")
        .expect("FIXTURE: the series UID resolves to its master");
    let added: Vec<EntityId> = fixture
        .vault
        .entities_by_type(ENTITY_TYPE_EVENT)
        .expect("the EVENTs")
        .into_iter()
        .filter(|event| !before.contains(event))
        .collect();
    assert!(
        added.len() == 2 && added.contains(&master),
        "FIXTURE: the series imports its master and one member EVENT: {added:?}"
    );
    let member = added
        .into_iter()
        .find(|event| *event != master)
        .expect("FIXTURE: the member EVENT");
    let filed = active_passports(&fixture.vault, member);
    assert!(
        filed.len() == 1
            && filed[0].system == SEAT_SYSTEM
            && masked(&filed[0].uid, SERIES_UID)
            && filed[0].approval == ClaimApprovalStatus::Proposed,
        "FIXTURE: the member's import files one pending passport whose UID is a custody handle: \
         {filed:?}"
    );
    let events = event_count(&fixture.vault);

    seat.pull(
        &fixture.vault,
        &[series_resource(&seat, 2, "member moved")],
        NOW + 20,
    )
    .expect("the member's next version revises its passport");
    let after = active_passports(&fixture.vault, member);
    assert!(
        after.len() == 1 && after[0].sequence == 2,
        "the member's next version revises its one passport: {after:?}"
    );
    assert_eq!(
        fixture
            .vault
            .get_claim(&filed[0].id)
            .expect("read the member's first passport")
            .map(|body| body.lifecycle),
        Some(ClaimLifecycleStatus::Superseded),
        "the member's next passport supersedes its first"
    );
    assert_eq!(
        event_count(&fixture.vault),
        events,
        "the member's next version imports no EVENT"
    );
    assert_eq!(
        resolve_event_by_uid(&fixture.vault, SERIES_UID).expect("resolve the series UID"),
        Some(master),
        "the series UID still resolves to its master"
    );
}

/// The custody record that holds the UID the seat's first write of the
/// native EVENT mints.
const MINTED_UID_SECRET: &str = "masked-minted-uid";

/// The custody record that holds the UID of a VEVENT the seat imports.
const PENDING_UID_SECRET: &str = "masked-pending-uid";

/// The UID of the VEVENT the seat imports and the owner has not reviewed.
const PENDING_UID: &str = "pending-import@host.example.test";

/// Asserts that the one lifecycle-active passport on `event` keeps `uid` as
/// a custody handle, and keeps `system` as a handle too when `system_masked`.
fn assert_one_passport_masked(
    vault: &Vault,
    event: EntityId,
    system_masked: bool,
    uid: &str,
    label: &str,
) {
    let filed = active_passports(vault, event);
    assert!(
        filed.len() == 1
            && masked(&filed[0].uid, uid)
            && if system_masked {
                masked(&filed[0].system, SEAT_SYSTEM)
            } else {
                filed[0].system == SEAT_SYSTEM
            },
        "FIXTURE: {label}: {filed:?}"
    );
}

/// The seat's pull of a VEVENT under `uid` that no write of the vault made:
/// it imports one EVENT whose passport waits for the owner's review.
fn pull_pending_import(vault: &Vault, seat: &Seat, uid: &str) -> EntityId {
    let start = MONDAY + 14 * 3_600;
    let events = event_count(vault);
    seat.pull(
        vault,
        &[SeatChange::foreign(
            seat,
            uid,
            start,
            start + 30 * 60,
            1,
            false,
        )],
        NOW + 10,
    )
    .expect("seat pull");
    assert_eq!(
        event_count(vault),
        events + 1,
        "FIXTURE: the pulled VEVENT imports one EVENT"
    );
    let event = resolve_event_by_uid(vault, uid)
        .expect("resolve the pulled UID")
        .expect("FIXTURE: the pulled UID resolves to its EVENT");
    let filed = active_passports(vault, event);
    assert!(
        filed.len() == 1 && filed[0].approval == ClaimApprovalStatus::Proposed,
        "FIXTURE: the import files one passport that waits for the owner's review: {filed:?}"
    );
    event
}

#[test]
fn a_second_write_of_a_passport_with_a_masked_uid_sends_the_uid_the_provider_holds() {
    // CAL-MASKED-SYSTEM-LITERAL-COMPARES-OUTSIDE-KEYED-LOOKUP: the UID the
    // seat's first write mints is a custody value, so the passport the
    // settled write files keeps it as a custody handle. The seat's next
    // write takes that passport as its own and must send the minted UID,
    // which the provider holds, never the handle.
    let fixture = Fixture::open(None);
    let seat = Seat::install(&fixture.vault, SEAT_SYSTEM);
    let native = mint_native_event(&fixture.vault);
    let uid = minted_uid(native);
    register_custody_value(&fixture.vault, MINTED_UID_SECRET, &uid);

    let first = seat.write(&fixture.vault, native, NOW + 10);
    assert_eq!(
        first.uid, uid,
        "FIXTURE: the first write sends the minted UID"
    );
    assert_one_passport_masked(
        &fixture.vault,
        native,
        false,
        &uid,
        "the settled write files one passport whose UID is a custody handle",
    );

    let second = seat.write(&fixture.vault, native, NOW + 20);
    assert_eq!(
        second.uid, uid,
        "the next write sends the UID the provider holds, never the stored handle"
    );
    assert!(
        second.sequence > first.sequence,
        "the next write revises the seat's copy: {} after {}",
        second.sequence,
        first.sequence
    );
}

#[test]
fn a_second_write_of_a_passport_with_a_masked_system_and_uid_sends_the_uid_the_provider_holds() {
    // CAL-MASKED-SYSTEM-LITERAL-COMPARES-OUTSIDE-KEYED-LOOKUP: the seat's
    // system name and the UID its first write mints are custody values, so
    // the settled write's passport keeps both as custody handles. The next
    // write must read that passport as the seat's own (its system as the
    // calendar registry pins it) and send the minted UID; no other source's
    // UID stands in for it.
    let fixture = Fixture::open(None);
    let seat = Seat::install(&fixture.vault, SEAT_SYSTEM);
    let native = mint_native_event(&fixture.vault);
    let uid = minted_uid(native);
    register_custody_value(&fixture.vault, SEAT_SYSTEM_SECRET, SEAT_SYSTEM);
    register_custody_value(&fixture.vault, MINTED_UID_SECRET, &uid);

    let first = seat.write(&fixture.vault, native, NOW + 10);
    assert_eq!(
        first.uid, uid,
        "FIXTURE: the first write sends the minted UID"
    );
    assert_one_passport_masked(
        &fixture.vault,
        native,
        true,
        &uid,
        "the settled write files one passport whose system and UID are custody handles",
    );

    let second = seat.write(&fixture.vault, native, NOW + 20);
    assert_eq!(
        second.uid, uid,
        "the next write sends the UID the provider holds, never the stored handle"
    );
    assert!(
        second.sequence > first.sequence,
        "the next write revises the seat's copy: {} after {}",
        second.sequence,
        first.sequence
    );
}

#[test]
fn a_write_back_of_a_pending_import_under_a_masked_system_replaces_the_pulled_object() {
    // CAL-MASKED-SYSTEM-LITERAL-COMPARES-OUTSIDE-KEYED-LOOKUP with FIX
    // CALDAV-PENDING-IMPORT-WRITEBACK-DUPLICATE: the seat's system name is a
    // custody value, so the passport of a VEVENT it imports keeps the system
    // as a custody handle and waits for the owner's review. A write of the
    // EVENT back to the seat must find that pending passport as the seat's
    // and write under the pulled UID, never mint a second object.
    let fixture = Fixture::open(None);
    let seat = Seat::install(&fixture.vault, SEAT_SYSTEM);
    register_custody_value(&fixture.vault, SEAT_SYSTEM_SECRET, SEAT_SYSTEM);
    let event = pull_pending_import(&fixture.vault, &seat, PENDING_UID);
    let filed = active_passports(&fixture.vault, event);
    assert!(
        masked(&filed[0].system, SEAT_SYSTEM) && filed[0].uid == PENDING_UID,
        "FIXTURE: the pending passport keeps the system as a custody handle: {filed:?}"
    );

    let wrote = seat.write(&fixture.vault, event, NOW + 20);
    assert_eq!(
        wrote.uid, PENDING_UID,
        "the write-back keeps the pulled UID, never a minted one"
    );
    assert!(
        wrote.sequence > 1,
        "the write-back revises the pulled object: SEQUENCE {}",
        wrote.sequence
    );
}

#[test]
fn a_write_back_of_a_pending_import_under_a_masked_uid_replaces_the_pulled_object() {
    // CAL-MASKED-SYSTEM-LITERAL-COMPARES-OUTSIDE-KEYED-LOOKUP with FIX
    // CALDAV-PENDING-IMPORT-WRITEBACK-DUPLICATE: the UID of a VEVENT the seat
    // imports is a custody value, so its pending passport keeps the UID as a
    // custody handle. The write-back reads the handle through the seat's
    // own copy of the pulled object and writes under the pulled UID: the
    // handle is no key of that copy and never a UID to send.
    let fixture = Fixture::open(None);
    let seat = Seat::install(&fixture.vault, SEAT_SYSTEM);
    register_custody_value(&fixture.vault, PENDING_UID_SECRET, PENDING_UID);
    let event = pull_pending_import(&fixture.vault, &seat, PENDING_UID);
    let filed = active_passports(&fixture.vault, event);
    assert!(
        filed[0].system == SEAT_SYSTEM && masked(&filed[0].uid, PENDING_UID),
        "FIXTURE: the pending passport keeps the UID as a custody handle: {filed:?}"
    );

    let wrote = seat.write(&fixture.vault, event, NOW + 20);
    assert_eq!(
        wrote.uid, PENDING_UID,
        "the write-back keeps the pulled UID, never a minted one or the handle"
    );
    assert!(
        wrote.sequence > 1,
        "the write-back revises the pulled object: SEQUENCE {}",
        wrote.sequence
    );
}

#[test]
fn a_write_to_a_second_calendar_never_sends_another_seat_s_masked_uid() {
    // CAL-MASKED-SYSTEM-LITERAL-COMPARES-OUTSIDE-KEYED-LOOKUP: a write to a
    // seat with no passport of its own shares the UID another source's
    // passport carries. That passport keeps its UID as a custody handle,
    // which only the seat that holds the source's copy reads, so the write
    // to the second calendar must not send the handle as its UID.
    let fixture = Fixture::open(None);
    let seat = Seat::install(&fixture.vault, SEAT_SYSTEM);
    let sibling = Seat::install(&fixture.vault, SIBLING_SEAT_SYSTEM);
    let native = mint_native_event(&fixture.vault);
    let uid = minted_uid(native);
    register_custody_value(&fixture.vault, MINTED_UID_SECRET, &uid);
    let first = seat.write(&fixture.vault, native, NOW + 10);
    assert_eq!(
        first.uid, uid,
        "FIXTURE: the first write sends the minted UID"
    );
    assert_one_passport_masked(
        &fixture.vault,
        native,
        false,
        &uid,
        "the settled write files one passport whose UID is a custody handle",
    );

    let wrote = sibling.write(&fixture.vault, native, NOW + 20);
    assert!(
        !wrote.uid.contains("[secret "),
        "the write to the second calendar sends no custody handle as its UID: {}",
        wrote.uid
    );
    assert_eq!(
        wrote.uid, uid,
        "the write to the second calendar sends the EVENT's own minted UID"
    );
}

/// The UID of a VEVENT the seat imports that holds the text a custody handle
/// opens with, and no handle: a provider may choose any UID text.
const HANDLE_TEXT_UID: &str = "item-[secret note]@host.example.test";

/// The owner approves every passport the import filed on `event`, as the
/// connector smoke does: the import gate files them pending review, and only
/// an admitted passport lends its UID to a write to another calendar.
fn approve_import_passports(vault: &Vault, event: EntityId) {
    let (id, owner) = seat_owner(vault);
    let memory = vault.memory(id, EdgeActorClass::Human);
    for (passport, _) in live_passports_for_event(vault, &event).expect("passports") {
        let claim_ref = passport.to_hex();
        let review = memory
            .claim_review_as_owner(
                &owner,
                &ClaimProposalReviewRequest {
                    claim_ref: claim_ref.clone(),
                    grant_ref: None,
                },
            )
            .expect("review the import's passport");
        memory
            .claim_settle_as_owner(
                &owner,
                &ClaimSettleRequest {
                    claim_ref,
                    review_id: review.review_id,
                    decision: ClaimSettleDecision::Approve,
                    grant_ref: None,
                },
            )
            .expect("approve the import's passport");
    }
}

#[test]
fn a_write_to_a_second_calendar_shares_a_uid_that_holds_handle_text_but_no_handle() {
    // CAL-MASKED-SYSTEM-LITERAL-COMPARES-OUTSIDE-KEYED-LOOKUP: a provider's
    // UID may hold `[secret ` as literal text. No mask placed a handle there,
    // so it is the UID the first calendar's provider holds, and a write to a
    // second calendar shares it as it shares any other source's UID.
    let fixture = Fixture::open(None);
    let seat = Seat::install(&fixture.vault, SEAT_SYSTEM);
    let sibling = Seat::install(&fixture.vault, SIBLING_SEAT_SYSTEM);
    let event = pull_pending_import(&fixture.vault, &seat, HANDLE_TEXT_UID);
    approve_import_passports(&fixture.vault, event);
    let filed = active_passports(&fixture.vault, event);
    assert!(
        filed.len() == 1
            && filed[0].uid == HANDLE_TEXT_UID
            && filed[0].approval == ClaimApprovalStatus::Approved,
        "FIXTURE: the owner approves the import's one passport, which keeps the UID as written: \
         {filed:?}"
    );

    let wrote = sibling.write(&fixture.vault, event, NOW + 20);
    assert_eq!(
        wrote.uid, HANDLE_TEXT_UID,
        "the write to the second calendar shares the UID the first calendar's provider holds"
    );
}
