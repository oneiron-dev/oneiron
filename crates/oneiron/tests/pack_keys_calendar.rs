//! The calendar's two pack Setting keys move the prep lead and the check-in re-ask hour.
//!
//! Proves the head's contract for `calendar.prep.lead_secs` (default 2700, T-45) and
//! `calendar.check_in.re_ask_local_hour` (default 9): with no setting row each pass behaves as
//! the base does today (the guard half), and once the owner sets a row the next pass follows
//! the owner's value (the red half on the base, where the set fails as an unknown key). Every
//! assertion reads the `CalendarCardPass` the pass returns, with a fresh EVENT id per timing
//! case (cards dedupe per EVENT start).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test pack_keys_calendar`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use oneiron::calendar::prep::{CHECK_IN_RE_ASK_LOCAL_HOUR, DEFAULT_PREP_LEAD_SECS, PrepLensCopy};
use oneiron::calendar::{
    CalendarCardCopy, CheckInCopy, outcome_grace_secs, run_calendar_card_pass,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeKind;
use oneiron::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, TimeRange, Vault,
    VaultConfig,
};
use rmpv::Value;
use serde_json::json;

/// Seconds in a UTC day: the re-ask clock's day.
const DAY_SECS: u64 = 86_400;
/// Seconds in an hour.
const HOUR_SECS: u64 = 3_600;
/// Every fixture meeting lasts one hour.
const MEETING_SECS: u64 = 3_600;

/// First check-in meeting's start, 2025-08-05 13:20:00 UTC: its first ask lands mid-afternoon,
/// so the next-day 09:00 re-ask is the next UTC morning.
const CHECK_START_1: u64 = 1_754_400_000;
/// First prep meeting's start. The prep test runs in its own vault, so the base repeats.
const PREP_START_3: u64 = 1_754_400_000;
/// Gap between prep meetings' starts: past every earlier meeting's windows.
const PREP_GAP_SECS: u64 = 300_000;

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
}

/// A seeded vault on a clock pinned at `pinned_at`: `Vault::open` stages the embedded owner,
/// and the pin keeps the engine clock at or below every meeting end.
fn open_fixture(pinned_at: u64) -> Fixture {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = common::on_pinned_clock(VaultConfig::device(), pinned_at);
    let vault = Vault::open(dir.path(), config).expect("open vault");
    assert!(
        vault
            .commitment_reminder_route()
            .expect("reminder route")
            .is_none(),
        "a fresh vault sets no reminder route, so the re-ask clock is UTC"
    );
    Fixture { _dir: dir, vault }
}

/// The vault's owner, authenticated: the proof the setting door revalidates in its write.
fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(owner, "principal:owner", true, GateDecisionId::now())
        .expect("owner proof")
}

/// The owner sets one vault-scope key; the door must apply it.
fn set_owner_setting(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    key: &str,
    value: serde_json::Value,
) {
    let outcome = vault
        .set_setting(
            SettingCaller::Owner(owner),
            SetSetting::vault_value(key, value),
        )
        .expect("owner sets the key");
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "the owner's set of {key} applies"
    );
}

/// Every word the pass puts on a card: distinctive, non-empty, caller-owned.
fn card_copy() -> CalendarCardCopy {
    CalendarCardCopy {
        prep: PrepLensCopy {
            title: "PK2 prep title".to_owned(),
            commitment_heading: "PK2 commitment heading".to_owned(),
            thread_heading: "PK2 thread heading".to_owned(),
            dossier_heading: "PK2 dossier heading".to_owned(),
        },
        check_in: CheckInCopy {
            title: "PK2 check-in title".to_owned(),
            body: "PK2 check-in body".to_owned(),
            held_label: "PK2 held".to_owned(),
            no_show_label: "PK2 no-show".to_owned(),
            rescheduled_label: "PK2 rescheduled".to_owned(),
            recording_label: "PK2 recording".to_owned(),
        },
    }
}

/// `hour`:00 UTC on the UTC day after `after`: the re-ask instant the engine names for an
/// offset-0 owner clock, recomputed here in plain integers.
fn next_day_at_hour(after: u64, hour: u64) -> u64 {
    (after / DAY_SECS + 1) * DAY_SECS + hour * HOUR_SECS
}

fn at(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

/// A one-key MessagePack body, the shape the prep layer reads an entity's text from.
fn text_body(key: &str, text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(
        &mut out,
        &Value::Map(vec![(Value::from(key), Value::from(text))]),
    )
    .expect("encode body");
    out
}

/// Claim ids keyed `(0xB5, seed, index)` so no fixture claim aliases a generic id.
fn claim_id(seed: u8, index: u8) -> EntityId {
    let mut bytes = [0xB5_u8; 16];
    bytes[1] = seed;
    bytes[2] = index;
    EntityId::from_bytes(bytes).expect("fixture claim id")
}

/// One EVENT entity. Trimmed from the prep oracle: no `calendar.origin` claim, which the card
/// pass never reads.
fn put_event(vault: &Vault, seed: u8, start: u64, end: u64, learned_at: u64) -> EntityId {
    let id = common::entity(seed);
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_EVENT,
            TimeRange { start, end },
            learned_at,
            &text_body("name", "planning sync"),
        )
        .expect("put event");
    id
}

fn put_text_entity(
    vault: &Vault,
    seed: u8,
    entity_type: u8,
    key: &str,
    text: &str,
    learned_at: u64,
) -> EntityId {
    let id = common::entity(seed);
    vault
        .put_entity(
            &id,
            entity_type,
            at(learned_at),
            learned_at,
            &text_body(key, text),
        )
        .expect("put text entity");
    id
}

/// One surfaceable claim through the ordinary public claim door.
fn put_claim(
    vault: &Vault,
    id: EntityId,
    predicate: &str,
    subject: EntityId,
    value: Value,
    learned_at: u64,
) {
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        value,
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    body.scope_facet = vault.default_facet().expect("vault default facet");
    vault
        .put_claim(&id, &body, at(learned_at), learned_at)
        .expect("put claim");
}

/// The engine-owned `calendar.attendee` row. `event_seed` keys the claim id, so each EVENT's
/// attendee line is its own row.
fn put_attendee(
    vault: &Vault,
    event_seed: u8,
    index: u8,
    event_ref: EntityId,
    who: &str,
    learned_at: u64,
) {
    put_claim(
        vault,
        claim_id(event_seed, index),
        "calendar.attendee",
        event_ref,
        Value::Map(vec![
            (Value::from("who"), Value::from(who)),
            (Value::from("role"), Value::from("REQ-PARTICIPANT")),
            (Value::from("partstat"), Value::from("ACCEPTED")),
        ]),
        learned_at,
    );
}

/// One preppable meeting: EVENT, PERSON, an external attendee line, a commitment claim and one
/// evidence TURN with `txt` about the person, and the EVENT-`ParticipatesIn`-PERSON and
/// PERSON-`About` edges the assembly walks (the prep oracle's shape, less its dossier and late
/// rows). Every row is learned a day before the start, inside every fire bound.
fn put_prep_meeting(
    vault: &Vault,
    event_seed: u8,
    person_seed: u8,
    turn_seed: u8,
    start: u64,
    person: &str,
    thread: &str,
) -> EntityId {
    let learned_at = start - DAY_SECS;
    let event_ref = put_event(vault, event_seed, start, start + MEETING_SECS, learned_at);
    let person_ref = put_text_entity(
        vault,
        person_seed,
        ENTITY_TYPE_PERSON,
        "name",
        person,
        learned_at,
    );
    put_attendee(
        vault,
        event_seed,
        0,
        event_ref,
        &format!("mailto:{person}@example.com"),
        learned_at,
    );
    let commitment_ref = claim_id(person_seed, 1);
    put_claim(
        vault,
        commitment_ref,
        "prep.commitment",
        person_ref,
        Value::from(format!("owes {person} a revised quote")),
        learned_at,
    );
    let turn_ref = put_text_entity(
        vault,
        turn_seed,
        ENTITY_TYPE_TURN,
        "txt",
        thread,
        learned_at,
    );
    vault
        .batch()
        .edge(&event_ref, EdgeKind::ParticipatesIn, &person_ref, 1.0)
        .edge(&person_ref, EdgeKind::About, &commitment_ref, 1.0)
        .edge(&person_ref, EdgeKind::About, &turn_ref, 1.0)
        .commit()
        .expect("fixture edges");
    event_ref
}

#[test]
fn the_check_in_is_asked_again_at_9_by_default_and_at_the_owners_hour() {
    assert_eq!(
        CHECK_IN_RE_ASK_LOCAL_HOUR, 9,
        "the shipped re-ask hour is 09:00"
    );
    let fixture = open_fixture(CHECK_START_1);
    let vault = &fixture.vault;
    let grace = outcome_grace_secs(vault).expect("grace");
    assert_eq!(grace, 1_800, "the shipped outcome grace");
    let copy = card_copy();

    // No setting row: the check-in is asked once past end + grace.
    let start_1 = CHECK_START_1;
    let end_1 = start_1 + MEETING_SECS;
    let event_1 = put_event(vault, 0x51, start_1, end_1, start_1 - DAY_SECS);
    put_attendee(
        vault,
        0x51,
        0,
        event_1,
        "mailto:owen@example.com",
        start_1 - DAY_SECS,
    );
    let asked_1_at = end_1 + grace + 60;
    let pass = run_calendar_card_pass(vault, asked_1_at, &copy).expect("pass 1");
    assert_eq!(pass.asked, 1, "the check-in is asked once past end + grace");
    assert_eq!(pass.prepped, 0, "past the start, no prep fires");
    assert_eq!(pass.failed, 0, "no card fails");

    // Its re-ask is planned for 09:00 UTC the next morning.
    let reask_1_at = next_day_at_hour(asked_1_at, 9);
    let pass = run_calendar_card_pass(vault, reask_1_at - 1, &copy).expect("pass 2a");
    assert_eq!(
        pass.re_asked, 0,
        "one second before 09:00 the re-ask is still planned"
    );
    assert_eq!(pass.failed, 0, "no card fails");
    let pass = run_calendar_card_pass(vault, reask_1_at, &copy).expect("pass 2b");
    assert_eq!(pass.re_asked, 1, "at 09:00 the check-in is asked again");
    assert_eq!(pass.failed, 0, "no card fails");

    // The owner moves the hour to 15:00; a new meeting's check-in re-asks then.
    let owner = owner_proof(vault);
    set_owner_setting(
        vault,
        &owner,
        "calendar.check_in.re_ask_local_hour",
        json!(15),
    );
    let start_2 = reask_1_at + 2 * HOUR_SECS;
    let end_2 = start_2 + MEETING_SECS;
    let event_2 = put_event(vault, 0x52, start_2, end_2, start_2 - DAY_SECS);
    put_attendee(
        vault,
        0x52,
        0,
        event_2,
        "mailto:yuki@example.com",
        start_2 - DAY_SECS,
    );
    let asked_2_at = end_2 + grace + 60;
    let pass = run_calendar_card_pass(vault, asked_2_at, &copy).expect("pass 3");
    assert_eq!(pass.asked, 1, "the second meeting's check-in is asked");
    assert_eq!(pass.failed, 0, "no card fails");
    let nine_2 = next_day_at_hour(asked_2_at, 9);
    let pass = run_calendar_card_pass(vault, nine_2, &copy).expect("pass 4a");
    assert_eq!(
        pass.re_asked, 0,
        "at 09:00 the owner's 15:00 re-ask is still planned"
    );
    assert_eq!(pass.failed, 0, "no card fails");
    let fifteen_2 = next_day_at_hour(asked_2_at, 15);
    let pass = run_calendar_card_pass(vault, fifteen_2, &copy).expect("pass 4b");
    assert_eq!(pass.re_asked, 1, "at 15:00 the check-in is asked again");
    assert_eq!(pass.failed, 0, "no card fails");
}

#[test]
fn prep_is_delivered_45_minutes_before_by_default_and_at_the_owners_lead() {
    assert_eq!(
        DEFAULT_PREP_LEAD_SECS, 2_700,
        "the shipped prep lead is T-45"
    );
    let fixture = open_fixture(PREP_START_3);
    let vault = &fixture.vault;
    let copy = card_copy();

    // No setting row: inside [T-45, start) the prep pack is delivered.
    let start_3 = PREP_START_3;
    put_prep_meeting(
        vault,
        0x51,
        0x61,
        0x71,
        start_3,
        "owen",
        "owen asked for the revised quote",
    );
    let pass = run_calendar_card_pass(vault, start_3 - DEFAULT_PREP_LEAD_SECS + 60, &copy)
        .expect("prep pass 1");
    assert_eq!(
        pass.prepped, 1,
        "inside [T-45, start) the prep pack is delivered"
    );
    assert_eq!(pass.failed, 0, "no card fails");

    // The boundary: one second before T-45 nothing is due; at T-45 it fires.
    let start_4 = start_3 + PREP_GAP_SECS;
    put_prep_meeting(
        vault,
        0x52,
        0x62,
        0x72,
        start_4,
        "yuki",
        "yuki asked about the launch date",
    );
    let pass = run_calendar_card_pass(vault, start_4 - DEFAULT_PREP_LEAD_SECS - 1, &copy)
        .expect("prep pass 2a");
    assert_eq!(pass.prepped, 0, "one second before T-45 nothing is due");
    assert_eq!(pass.failed, 0, "no card fails");
    let pass = run_calendar_card_pass(vault, start_4 - DEFAULT_PREP_LEAD_SECS, &copy)
        .expect("prep pass 2b");
    assert_eq!(pass.prepped, 1, "at T-45 the prep pack is delivered");
    assert_eq!(pass.failed, 0, "no card fails");

    // The owner moves the lead to T-60: T-50 delivers, which T-45 would not.
    let owner = owner_proof(vault);
    set_owner_setting(vault, &owner, "calendar.prep.lead_secs", json!(3_600));
    let start_5 = start_4 + PREP_GAP_SECS;
    put_prep_meeting(
        vault,
        0x53,
        0x63,
        0x73,
        start_5,
        "owen",
        "owen confirmed the agenda",
    );
    let pass = run_calendar_card_pass(vault, start_5 - 3_000, &copy).expect("prep pass 3");
    assert_eq!(
        pass.prepped, 1,
        "at T-50 the owner's T-60 lead delivers, which T-45 would not"
    );
    assert_eq!(pass.failed, 0, "no card fails");
}
