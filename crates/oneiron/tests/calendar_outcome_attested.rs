//! CAL-07: the owner's answer stands (CAL-07-OUTCOME-CONFLICT = A, Engine
//! 15 Nov 12:04; canon ARCH-0060 D8, whose ladder runs machine evidence ->
//! outcome card -> owner attestation).
//!
//! Machine evidence never replaces an owner's check-in answer. A machine
//! outcome that arrives after the answer is written, and the answer supersedes
//! it at once, so the read stays the owner's answer and the evidence stays in
//! the EVENT's claim history. The same holds across a sync fork, where an
//! answer and a machine outcome are both live. A reschedule's owner-attested
//! `unknown` answers no outcome, so machine evidence still settles it, and an
//! owner answer still replaces a machine head.
//!
//! On main a later machine outcome replaced the answer, and the latest head won
//! a fork, so the first three tests fail there. The last two pass on main and
//! on the head: they pin what the change keeps.
//!
//! Runs on public paths: `cargo test -p oneiron --all-features --test
//! calendar_outcome_attested`.
#![cfg(feature = "test-support")]

use oneiron::calendar::outcome::{
    EventOutcome, EventOutcomeBasis, EventOutcomeClaimValue, PREDICATE_CALENDAR_EVENT_OUTCOME,
    read_event_outcome, record_event_outcome,
};
use oneiron::registry::ENTITY_TYPE_EVENT;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    TimeRange, Vault, VaultConfig,
};
use rmpv::Value;

const EVENT_START: u64 = 1_754_400_000;
const EVENT_END: u64 = EVENT_START + 3_600;
/// The owner answers the check-in after the default 30 min grace.
const ANSWERED_AT: u64 = EVENT_END + 1_800;
/// A transcript lands ten minutes after the answer.
const TRANSCRIPT_AT: u64 = ANSWERED_AT + 600;

/// Fixture ids under their own prefix, clear of the seeded agent rows.
fn entity(seed: u8) -> EntityId {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x7e;
    bytes[15] = seed;
    EntityId::from_bytes(bytes).expect("fixture id")
}

/// Raw claim ids keyed `(0xB7, 0x7e, index)`, so none aliases an `entity` id.
fn claim_id(index: u8) -> EntityId {
    let mut bytes = [0xB7_u8; 16];
    bytes[1] = 0x7e;
    bytes[2] = index;
    EntityId::from_bytes(bytes).expect("fixture claim id")
}

/// An unseeded vault, as in `tests/it/calendar_outcome.rs`: the subject is the
/// outcome layer's own law, not the policy manifest.
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

fn record_owner(vault: &Vault, event_ref: EntityId, value: &EventOutcomeClaimValue) -> EntityId {
    record_event_outcome(vault, event_ref, value, ClaimSource::UserStated).expect("owner answer")
}

fn record_machine(vault: &Vault, event_ref: EntityId, value: &EventOutcomeClaimValue) -> EntityId {
    record_event_outcome(vault, event_ref, value, ClaimSource::Observed).expect("machine outcome")
}

fn claim(vault: &Vault, id: EntityId) -> ClaimBody {
    vault
        .get_claim(&id)
        .expect("read claim")
        .expect("claim present")
}

/// The ids of the EVENT's lifecycle-active outcome claims.
fn live_outcomes(vault: &Vault, event_ref: EntityId) -> Vec<EntityId> {
    vault
        .claims_for_subject(&event_ref)
        .expect("claims")
        .into_iter()
        .filter(|id| {
            let body = claim(vault, *id);
            body.predicate == PREDICATE_CALENDAR_EVENT_OUTCOME
                && body.lifecycle == ClaimLifecycleStatus::Active
        })
        .collect()
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

#[test]
fn owner_answer_stands_over_a_later_disagreeing_machine_outcome() {
    let (_dir, vault) = temp_vault();
    let event_ref = event(&vault, 1);
    let answer = owner(EventOutcome::NoShow, ANSWERED_AT);
    let answer_id = record_owner(&vault, event_ref, &answer);

    let transcript = machine(EventOutcome::Held, TRANSCRIPT_AT);
    let transcript_id = record_machine(&vault, event_ref, &transcript);

    assert_eq!(
        read_event_outcome(&vault, event_ref).expect("read"),
        Some(answer),
        "the owner's no-show stands over the later transcript"
    );
    assert_eq!(live_outcomes(&vault, event_ref), vec![answer_id]);
    // The machine outcome is kept as history the answer supersedes. Its
    // validity window closes where it opens: it was never the current outcome.
    let kept = claim(&vault, transcript_id);
    assert_eq!(kept.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(kept.valid_from, Some(TRANSCRIPT_AT));
    assert_eq!(kept.valid_to, Some(TRANSCRIPT_AT));
    assert_eq!(claim(&vault, answer_id).valid_to, None);
}

#[test]
fn owner_answer_stays_current_when_machine_evidence_agrees() {
    let (_dir, vault) = temp_vault();
    let event_ref = event(&vault, 2);
    let answer = owner(EventOutcome::Held, ANSWERED_AT);
    let answer_id = record_owner(&vault, event_ref, &answer);

    let transcript_id = record_machine(
        &vault,
        event_ref,
        &machine(EventOutcome::Held, TRANSCRIPT_AT),
    );

    let read = read_event_outcome(&vault, event_ref)
        .expect("read")
        .expect("an outcome");
    assert_eq!(read.basis, EventOutcomeBasis::OwnerAttested);
    assert_eq!(read, answer);
    assert_eq!(live_outcomes(&vault, event_ref), vec![answer_id]);
    assert_eq!(
        claim(&vault, transcript_id).lifecycle,
        ClaimLifecycleStatus::Superseded
    );
}

#[test]
fn owner_answer_stands_across_a_sync_fork() {
    let (_dir, vault) = temp_vault();
    let event_ref = event(&vault, 3);
    // Two replicas each recorded an outcome, and neither supersession crossed
    // the wire: the owner's no-show on one, a later transcript's held on the
    // other.
    let answer = owner(EventOutcome::NoShow, ANSWERED_AT);
    put_raw_outcome(&vault, claim_id(0), event_ref, &answer);
    put_raw_outcome(
        &vault,
        claim_id(1),
        event_ref,
        &machine(EventOutcome::Held, TRANSCRIPT_AT),
    );
    assert_eq!(live_outcomes(&vault, event_ref).len(), 2);

    assert_eq!(
        read_event_outcome(&vault, event_ref).expect("read"),
        Some(answer),
        "the owner's answer wins the fork over later machine evidence"
    );
}

#[test]
fn machine_evidence_settles_a_reschedule_unknown() {
    let (_dir, vault) = temp_vault();
    let event_ref = event(&vault, 4);
    // A reschedule records an owner-attested `unknown`: the owner answered, but
    // stated no outcome, so evidence still establishes one.
    let rescheduled = record_owner(
        &vault,
        event_ref,
        &owner(EventOutcome::Unknown, ANSWERED_AT),
    );

    let transcript = machine(EventOutcome::Held, TRANSCRIPT_AT);
    let transcript_id = record_machine(&vault, event_ref, &transcript);

    assert_eq!(
        read_event_outcome(&vault, event_ref).expect("read"),
        Some(transcript)
    );
    assert_eq!(live_outcomes(&vault, event_ref), vec![transcript_id]);
    assert_eq!(
        claim(&vault, rescheduled).lifecycle,
        ClaimLifecycleStatus::Superseded
    );
}

#[test]
fn owner_answer_replaces_a_machine_outcome() {
    let (_dir, vault) = temp_vault();
    let event_ref = event(&vault, 5);
    let join = record_machine(&vault, event_ref, &machine(EventOutcome::Held, EVENT_END));

    let answer = owner(EventOutcome::NoShow, ANSWERED_AT);
    let answer_id = record_owner(&vault, event_ref, &answer);

    assert_eq!(
        read_event_outcome(&vault, event_ref).expect("read"),
        Some(answer)
    );
    assert_eq!(live_outcomes(&vault, event_ref), vec![answer_id]);
    let corrected = claim(&vault, join);
    assert_eq!(corrected.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(corrected.valid_to, Some(ANSWERED_AT));
}
