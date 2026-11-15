//! The calendar's prep ceiling, external-only rule and check-in windows follow their pack
//! Setting keys.
//!
//! Proves the head's contract for `calendar.prep.max_words` (default 250),
//! `calendar.prep.external_only` (default true), `calendar.check_in.catch_up_secs` (default 86,400)
//! and `calendar.check_in.rested_keep_secs` (default 86,400): with no setting row each pass and
//! each meeting read behaves as the base does today (the guard half), and once the owner sets a
//! row the next pass or read follows the owner's value (the red half on the base, where the set
//! fails as an unknown key). A fifth test pins that a ceiling of 0 and a window of 0 fail their
//! checks. Every card-pass assertion reads the `CalendarCardPass` the pass returns and every
//! prep-read assertion reads the `PrepPack` the read returns, with a fresh EVENT id per timing
//! case (cards dedupe per EVENT start).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test pack_keys_calendar_prep`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use oneiron::calendar::meeting::CalendarMeetingRequest;
use oneiron::calendar::prep::{
    CHECK_IN_RE_ASK_LOCAL_HOUR, DEFAULT_PREP_LEAD_SECS, DEFAULT_PREP_MAX_WORDS, PrepLensCopy,
};
use oneiron::calendar::{
    CHECK_IN_CATCH_UP_SECS, CalendarCardCopy, CheckInCopy, outcome_grace_secs,
    run_calendar_card_pass,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeKind;
use oneiron::memory::Memory;
use oneiron::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig,
};
use rmpv::Value;
use serde_json::json;

/// Seconds in a UTC day: the re-ask clock's day and the shipped check-in windows.
const DAY_SECS: u64 = 86_400;
/// Every fixture meeting lasts one hour.
const MEETING_SECS: u64 = 3_600;
/// The owner's widened check-in window in the owner half of the window tests: 3 days.
const THREE_DAY_SECS: u64 = 259_200;

/// First check-in meeting's start, 2025-08-05 13:20:00 UTC, as in PK-2's test: its first ask
/// lands mid-afternoon, so the next-day 09:00 re-ask is the next UTC morning.
const CHECK_START_1: u64 = 1_754_400_000;
/// First prep meeting's start. Each test runs in its own vault, so the base repeats.
const PREP_START_1: u64 = 1_754_400_000;
/// The prep-read meeting's start; the vault clock is pinned here.
const MEETING_START: u64 = 1_754_400_000;
/// Gap between prep meetings' starts: past every earlier meeting's windows.
const PREP_GAP_SECS: u64 = 300_000;
/// Gap between check-in meetings' starts: past the owner's 3-day window plus the 2-day lag, so
/// the first EVENT is never asked again in the second half's passes.
const CHECK_GAP_SECS: u64 = 400_000;

/// The prep-read meeting's thread: 12 words.
const MEETING_THREAD: &str = "owen asked about the revised quote and the launch date twice daily";
/// The prep-read meeting's commitment, as `put_prep_meeting` writes it for person `owen`.
const COMMITMENT_TEXT: &str = "owes owen a revised quote";

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

/// The owner's own `Memory`: the embedded owner as a human, whose read lane reads the EVENT.
fn owner_memory(vault: &Vault) -> Memory<'_> {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault.memory(owner, EdgeActorClass::Human)
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
            title: "PK5 prep title".to_owned(),
            commitment_heading: "PK5 commitment heading".to_owned(),
            thread_heading: "PK5 thread heading".to_owned(),
            dossier_heading: "PK5 dossier heading".to_owned(),
        },
        check_in: CheckInCopy {
            title: "PK5 check-in title".to_owned(),
            body: "PK5 check-in body".to_owned(),
            held_label: "PK5 held".to_owned(),
            no_show_label: "PK5 no-show".to_owned(),
            rescheduled_label: "PK5 rescheduled".to_owned(),
            recording_label: "PK5 recording".to_owned(),
        },
    }
}

/// `hour`:00 UTC on the UTC day after `after`: the re-ask instant the engine names for an
/// offset-0 owner clock, recomputed here in plain integers.
fn next_day_at_hour(after: u64, hour: u64) -> u64 {
    (after / DAY_SECS + 1) * DAY_SECS + hour * 3_600
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
/// pass never reads (the prep-read meeting adds one separately).
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

/// CAL-00's `calendar.origin` row: the agent's meeting read only sees EVENTs with a live origin,
/// so the prep-read meeting carries one.
fn put_origin(vault: &Vault, event_seed: u8, index: u8, event_ref: EntityId, learned_at: u64) {
    put_claim(
        vault,
        claim_id(event_seed, index),
        "calendar.origin",
        event_ref,
        Value::from("native"),
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

/// One internal preppable meeting: `put_prep_meeting` without the attendee line. With no
/// external attendee, no campaign or commitment linkage and no per-event opt-in, the only thing
/// that decides its eligibility is the vault's `external_only`.
fn put_internal_prep_meeting(
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

/// Words in one evidence string, by the whitespace split the ceiling is spent in.
fn word_count(text: &str) -> usize {
    text.split_whitespace().count()
}

#[test]
fn a_check_in_two_days_late_is_left_by_default_and_asked_in_the_owners_catch_up_window() {
    assert_eq!(
        CHECK_IN_CATCH_UP_SECS, 86_400,
        "the shipped catch-up window is a day"
    );
    let fixture = open_fixture(CHECK_START_1);
    let vault = &fixture.vault;
    let grace = outcome_grace_secs(vault).expect("grace");
    assert_eq!(grace, 1_800, "the shipped outcome grace");
    let copy = card_copy();

    // No setting row: two days past end + grace the check-in is left unasked.
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
    let late_1_at = end_1 + grace + 2 * DAY_SECS;
    let pass = run_calendar_card_pass(vault, late_1_at, &copy).expect("pass 1");
    assert_eq!(
        pass.asked, 0,
        "two days past end + grace, the default day-long window leaves the check-in"
    );
    assert_eq!(pass.prepped, 0, "past the start, no prep fires");
    assert_eq!(pass.failed, 0, "no card fails");

    // The owner widens the catch-up window to three days: a new meeting two days late is asked.
    let owner = owner_proof(vault);
    set_owner_setting(
        vault,
        &owner,
        "calendar.check_in.catch_up_secs",
        json!(THREE_DAY_SECS),
    );
    let start_2 = start_1 + CHECK_GAP_SECS;
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
    let late_2_at = end_2 + grace + 2 * DAY_SECS;
    let pass = run_calendar_card_pass(vault, late_2_at, &copy).expect("pass 2");
    assert_eq!(
        pass.asked, 1,
        "two days late is inside the owner's three-day window"
    );
    assert_eq!(pass.prepped, 0, "past the start, no prep fires");
    assert_eq!(pass.failed, 0, "no card fails");
}

#[test]
fn a_rested_check_in_leaves_a_day_after_its_re_ask_by_default_and_stays_for_the_owners_keep() {
    assert_eq!(
        CHECK_IN_CATCH_UP_SECS, 86_400,
        "the shipped rested-keep window is a day"
    );
    assert_eq!(
        CHECK_IN_RE_ASK_LOCAL_HOUR, 9,
        "the shipped re-ask hour is 09:00"
    );
    let fixture = open_fixture(CHECK_START_1);
    let vault = &fixture.vault;
    let grace = outcome_grace_secs(vault).expect("grace");
    assert_eq!(grace, 1_800, "the shipped outcome grace");
    let copy = card_copy();

    // No setting row: asked once past end + grace, asked again at 09:00, then gone a day later.
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
    let pass = run_calendar_card_pass(vault, asked_1_at, &copy).expect("ask 1");
    assert_eq!(pass.asked, 1, "the check-in is asked once past end + grace");
    assert_eq!(pass.failed, 0, "no card fails");
    let reask_1_at = next_day_at_hour(asked_1_at, 9);
    let pass = run_calendar_card_pass(vault, reask_1_at, &copy).expect("re-ask 1");
    assert_eq!(pass.re_asked, 1, "at 09:00 the check-in is asked again");
    assert_eq!(pass.failed, 0, "no card fails");
    let pass = run_calendar_card_pass(vault, reask_1_at + DAY_SECS + 1, &copy).expect("rested 1");
    assert_eq!(
        pass.withdrawn, 1,
        "a day after its re-ask settled, the rested check-in leaves by default"
    );
    assert_eq!(
        pass.asked, 0,
        "the default catch-up window has passed, so the scan does not ask it again"
    );
    assert_eq!(pass.failed, 0, "no card fails");

    // The owner keeps rested check-ins for three days: a new meeting's card stays a day after
    // its re-ask and leaves once the three days have passed.
    let owner = owner_proof(vault);
    set_owner_setting(
        vault,
        &owner,
        "calendar.check_in.rested_keep_secs",
        json!(THREE_DAY_SECS),
    );
    let start_2 = start_1 + CHECK_GAP_SECS;
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
    let pass = run_calendar_card_pass(vault, asked_2_at, &copy).expect("ask 2");
    assert_eq!(pass.asked, 1, "the second meeting's check-in is asked");
    assert_eq!(pass.failed, 0, "no card fails");
    let reask_2_at = next_day_at_hour(asked_2_at, 9);
    let pass = run_calendar_card_pass(vault, reask_2_at, &copy).expect("re-ask 2");
    assert_eq!(pass.re_asked, 1, "at 09:00 the check-in is asked again");
    assert_eq!(pass.failed, 0, "no card fails");
    let pass = run_calendar_card_pass(vault, reask_2_at + DAY_SECS + 1, &copy).expect("kept 2");
    assert_eq!(
        pass.withdrawn, 0,
        "a day after the re-ask the owner's three-day keep still holds the card"
    );
    assert_eq!(
        pass.asked, 0,
        "the default catch-up window has passed, so the scan does not ask it again"
    );
    assert_eq!(pass.failed, 0, "no card fails");
    let pass =
        run_calendar_card_pass(vault, reask_2_at + THREE_DAY_SECS + 1, &copy).expect("rested 2");
    assert_eq!(
        pass.withdrawn, 1,
        "past the owner's three-day keep the rested check-in leaves"
    );
    assert_eq!(
        pass.asked, 0,
        "asked once and never re-delivered: the scan stays out of the catch-up window"
    );
    assert_eq!(pass.failed, 0, "no card fails");
}

#[test]
fn an_internal_meeting_gets_no_prep_by_default_and_gets_it_once_the_owner_turns_external_only_off()
{
    assert_eq!(
        DEFAULT_PREP_LEAD_SECS, 2_700,
        "the shipped prep lead is T-45"
    );
    let fixture = open_fixture(PREP_START_1);
    let vault = &fixture.vault;
    let copy = card_copy();

    // No setting row: an internal meeting with evidence but no opt-in gets no prep at T-45.
    let start_1 = PREP_START_1;
    put_internal_prep_meeting(
        vault,
        0x51,
        0x61,
        0x71,
        start_1,
        "owen",
        "owen asked for the revised quote",
    );
    let pass = run_calendar_card_pass(vault, start_1 - DEFAULT_PREP_LEAD_SECS, &copy)
        .expect("prep pass 1");
    assert_eq!(
        pass.prepped, 0,
        "internal with no opt-in: external_only keeps it out by default"
    );
    assert_eq!(pass.failed, 0, "no card fails");

    // The owner clears external_only: a new internal meeting's evidence is delivered at T-45.
    let owner = owner_proof(vault);
    set_owner_setting(vault, &owner, "calendar.prep.external_only", json!(false));
    let start_2 = start_1 + PREP_GAP_SECS;
    put_internal_prep_meeting(
        vault,
        0x52,
        0x62,
        0x72,
        start_2,
        "yuki",
        "yuki asked about the launch date",
    );
    let pass = run_calendar_card_pass(vault, start_2 - DEFAULT_PREP_LEAD_SECS, &copy)
        .expect("prep pass 2");
    assert_eq!(
        pass.prepped, 1,
        "with external_only off, the internal meeting's evidence is delivered"
    );
    assert_eq!(pass.failed, 0, "no card fails");
}

#[test]
fn the_meeting_prep_read_keeps_250_words_by_default_and_the_owners_ceiling() {
    assert_eq!(
        DEFAULT_PREP_MAX_WORDS, 250,
        "the shipped prep word ceiling is 250 words"
    );
    let fixture = open_fixture(MEETING_START);
    let vault = &fixture.vault;
    let start = MEETING_START;
    let event_ref = put_prep_meeting(vault, 0x51, 0x61, 0x71, start, "owen", MEETING_THREAD);
    put_origin(vault, 0x51, 1, event_ref, start - DAY_SECS);
    let memory = owner_memory(vault);
    let request = CalendarMeetingRequest {
        event_ref: event_ref.to_hex(),
    };

    // No setting row: the pack keeps every evidence word. Other rows on the EVENT may add a
    // few words of their own, so the count is bounded, not pinned.
    let expected = word_count(MEETING_THREAD) + word_count(COMMITMENT_TEXT);
    assert!(
        expected > 12 && expected < 250,
        "the fixture holds {expected} evidence words: more than 12, under the 250-word ceiling"
    );
    let pack = memory
        .calendar_prep(&request)
        .expect("prep read")
        .value
        .expect("the external meeting has evidence");
    assert!(
        pack.word_count >= expected && pack.word_count < 250,
        "with no row the pack keeps all {expected} evidence words: {}",
        pack.word_count
    );
    let texts: Vec<&str> = pack
        .sections
        .iter()
        .flat_map(|section| &section.items)
        .map(|item| item.text.as_str())
        .collect();
    assert!(
        texts.iter().any(|text| text.contains(MEETING_THREAD)),
        "the thread is kept whole"
    );
    assert!(
        texts.iter().any(|text| text.contains(COMMITMENT_TEXT)),
        "the commitment is kept whole"
    );

    // The owner sets the ceiling to 5 words: the same read keeps 5.
    let owner = owner_proof(vault);
    set_owner_setting(vault, &owner, "calendar.prep.max_words", json!(5));
    let pack = memory
        .calendar_prep(&request)
        .expect("prep read")
        .value
        .expect("the external meeting still has evidence");
    assert_eq!(
        pack.word_count, 5,
        "the owner's 5-word ceiling cuts the pack to 5 words"
    );
}

#[test]
fn the_owner_cannot_set_an_empty_prep_ceiling_or_a_zero_check_in_window() {
    let fixture = open_fixture(CHECK_START_1);
    let vault = &fixture.vault;
    let owner = owner_proof(vault);
    let ceiling = vault.set_setting(
        SettingCaller::Owner(&owner),
        SetSetting::vault_value("calendar.prep.max_words", json!(0)),
    );
    assert!(
        matches!(ceiling, Err(oneiron::Error::InvalidConfig(_))),
        "a 0-word ceiling fails its check: {ceiling:?}"
    );
    let window = vault.set_setting(
        SettingCaller::Owner(&owner),
        SetSetting::vault_value("calendar.check_in.catch_up_secs", json!(0)),
    );
    assert!(
        matches!(window, Err(oneiron::Error::InvalidConfig(_))),
        "a 0-second window fails its check: {window:?}"
    );
}
