//! CAL-07: the machine evidence that disputes an owner's answer, and the
//! answer door that lets the owner correct it (CAL-07-OUTCOME-CONFLICT = A,
//! Engine 15 Nov 12:04 and 12:07).
//!
//! The owner's answer stands, and a disagreeing machine outcome is kept as
//! evidence linked to it: `read_disputing_machine_outcomes` names each one,
//! whether it arrived after the answer or was the machine head the answer
//! corrected. Agreeing evidence disputes nothing, and a new answer settles the
//! dispute. A recorded outcome no longer closes the check-in's answer door
//! (#3073 refused an owner answer over machine evidence), while the card itself
//! still stops once any outcome is recorded.
//!
//! Both functions are new, so this file does not compile on main.
//!
//! Runs on public paths: `cargo test -p oneiron --all-features --test
//! calendar_outcome_disputing`.
#![cfg(feature = "test-support")]

use oneiron::calendar::outcome::{
    DueOutcomeCheckIn, EventOutcome, EventOutcomeBasis, EventOutcomeClaimValue,
    MeetingClassSignals, PREDICATE_CALENDAR_EVENT_OUTCOME, check_in_accepts_answer,
    check_in_is_still_due, read_disputing_machine_outcomes, record_event_outcome,
};
use oneiron::registry::ENTITY_TYPE_EVENT;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    TimeRange, Vault, VaultConfig,
};
use rmpv::Value;

const EVENT_START: u64 = 1_754_400_000;
const EVENT_END: u64 = EVENT_START + 3_600;
const ANSWERED_AT: u64 = EVENT_END + 1_800;
const TRANSCRIPT_AT: u64 = ANSWERED_AT + 600;

/// Fixture ids under their own prefix, clear of the seeded agent rows.
fn entity(seed: u8) -> EntityId {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x7d;
    bytes[15] = seed;
    EntityId::from_bytes(bytes).expect("fixture id")
}

/// Raw claim ids keyed `(0xB7, 0x7d, index)`, so none aliases an `entity` id.
fn claim_id(index: u8) -> EntityId {
    let mut bytes = [0xB7_u8; 16];
    bytes[1] = 0x7d;
    bytes[2] = index;
    EntityId::from_bytes(bytes).expect("fixture claim id")
}

/// An unseeded vault, as in `tests/it/calendar_outcome.rs`.
fn temp_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_unseeded_for_test(dir.path(), config).expect("open vault");
    (dir, vault)
}

fn event(vault: &Vault, seed: u8) -> EntityId {
    let id = entity(seed);
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![(Value::from("name"), Value::from("intro call"))]),
    )
    .expect("encode event body");
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_EVENT,
            TimeRange {
                start: EVENT_START,
                end: EVENT_END,
            },
            EVENT_START,
            &body,
        )
        .expect("put event");
    id
}

fn owner(outcome: EventOutcome, recorded_at: u64) -> EventOutcomeClaimValue {
    EventOutcomeClaimValue {
        outcome,
        basis: EventOutcomeBasis::OwnerAttested,
        recorded_at,
    }
}

fn machine(outcome: EventOutcome, recorded_at: u64) -> EventOutcomeClaimValue {
    EventOutcomeClaimValue {
        outcome,
        basis: EventOutcomeBasis::Machine,
        recorded_at,
    }
}

fn record_owner(vault: &Vault, event_ref: EntityId, value: &EventOutcomeClaimValue) {
    record_event_outcome(vault, event_ref, value, ClaimSource::UserStated).expect("owner answer");
}

fn record_machine(vault: &Vault, event_ref: EntityId, value: &EventOutcomeClaimValue) {
    record_event_outcome(vault, event_ref, value, ClaimSource::Observed).expect("machine outcome");
}

fn disputing(vault: &Vault, event_ref: EntityId) -> Vec<EventOutcomeClaimValue> {
    read_disputing_machine_outcomes(vault, event_ref).expect("disputing read")
}

/// One live outcome claim written straight through the public claim door, so
/// two heads can stand side by side as they do after a sync fork.
fn put_raw_outcome(
    vault: &Vault,
    id: EntityId,
    event_ref: EntityId,
    value: &EventOutcomeClaimValue,
) {
    let wire = Value::Map(vec![
        (Value::from("outcome"), Value::from(value.outcome.as_str())),
        (Value::from("basis"), Value::from(value.basis.as_str())),
        (Value::from("recorded_at"), Value::from(value.recorded_at)),
    ]);
    let mut body = ClaimBody::new(
        PREDICATE_CALENDAR_EVENT_OUTCOME,
        ClaimSubject::Entity(event_ref),
        wire,
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .expect("outcome claim body");
    body.scope_facet = vault.default_facet().expect("default facet");
    vault
        .put_claim(
            &id,
            &body,
            TimeRange {
                start: value.recorded_at,
                end: value.recorded_at,
            },
            value.recorded_at,
        )
        .expect("raw outcome claim");
}

fn check_in(event_ref: EntityId, external_attendee_count: u32) -> DueOutcomeCheckIn {
    DueOutcomeCheckIn {
        wake_id: format!("calendar.event_outcome.check_in:{}", event_ref.to_hex()),
        event_ref,
        scheduled_start_utc: EVENT_START,
        signals: MeetingClassSignals {
            external_attendee_count,
            has_campaign_linkage: false,
            has_commitment_linkage: false,
            internal_meeting_opt_in: false,
        },
    }
}

#[test]
fn a_later_disagreeing_machine_outcome_disputes_the_answer() {
    let (_dir, vault) = temp_vault();
    let event_ref = event(&vault, 1);
    record_owner(&vault, event_ref, &owner(EventOutcome::NoShow, ANSWERED_AT));
    let transcript = machine(EventOutcome::Held, TRANSCRIPT_AT);
    record_machine(&vault, event_ref, &transcript);

    assert_eq!(disputing(&vault, event_ref), vec![transcript]);
}

#[test]
fn the_machine_head_an_answer_corrected_disputes_it() {
    let (_dir, vault) = temp_vault();
    let event_ref = event(&vault, 2);
    let join = machine(EventOutcome::Held, EVENT_END);
    record_machine(&vault, event_ref, &join);
    assert!(
        disputing(&vault, event_ref).is_empty(),
        "no owner answer, so nothing is disputed"
    );

    record_owner(&vault, event_ref, &owner(EventOutcome::NoShow, ANSWERED_AT));

    assert_eq!(disputing(&vault, event_ref), vec![join]);
}

#[test]
fn agreeing_machine_evidence_disputes_nothing() {
    let (_dir, vault) = temp_vault();
    let event_ref = event(&vault, 3);
    record_owner(&vault, event_ref, &owner(EventOutcome::Held, ANSWERED_AT));
    record_machine(
        &vault,
        event_ref,
        &machine(EventOutcome::Held, TRANSCRIPT_AT),
    );

    assert!(disputing(&vault, event_ref).is_empty());
}

#[test]
fn a_new_answer_settles_the_dispute() {
    let (_dir, vault) = temp_vault();
    let event_ref = event(&vault, 4);
    record_owner(&vault, event_ref, &owner(EventOutcome::NoShow, ANSWERED_AT));
    record_machine(
        &vault,
        event_ref,
        &machine(EventOutcome::Held, TRANSCRIPT_AT),
    );
    assert_eq!(disputing(&vault, event_ref).len(), 1);

    // The owner saw the dispute and answers again, keeping the no-show.
    record_owner(
        &vault,
        event_ref,
        &owner(EventOutcome::NoShow, TRANSCRIPT_AT + 60),
    );

    assert!(disputing(&vault, event_ref).is_empty());
}

#[test]
fn a_forked_machine_head_disputes_the_answer() {
    let (_dir, vault) = temp_vault();
    let event_ref = event(&vault, 5);
    put_raw_outcome(
        &vault,
        claim_id(0),
        event_ref,
        &owner(EventOutcome::NoShow, ANSWERED_AT),
    );
    let transcript = machine(EventOutcome::Held, TRANSCRIPT_AT);
    put_raw_outcome(&vault, claim_id(1), event_ref, &transcript);

    assert_eq!(disputing(&vault, event_ref), vec![transcript]);
}

#[test]
fn a_recorded_outcome_leaves_the_answer_door_open() {
    let (_dir, vault) = temp_vault();
    let event_ref = event(&vault, 6);
    record_machine(&vault, event_ref, &machine(EventOutcome::Held, EVENT_END));

    let meeting = check_in(event_ref, 1);
    assert!(
        !check_in_is_still_due(&vault, &meeting).expect("due"),
        "the card stops once an outcome is recorded"
    );
    assert!(
        check_in_accepts_answer(&vault, &meeting).expect("accepts"),
        "the owner may still correct the machine outcome"
    );

    assert!(
        !check_in_accepts_answer(&vault, &check_in(event_ref, 0)).expect("accepts"),
        "an EVENT that is not meeting-class takes no answer"
    );
}
