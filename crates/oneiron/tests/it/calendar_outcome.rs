//! CAL-07 outcome oracle (ONE-1789).
//!
//! Pins the four laws the outcome layer exists to hold, at the public boundary:
//!
//! 1. **Silence is never `held`.** No live claim projects `Unknown`; elapsed
//!    calendar time mints nothing; only explicit evidence or an owner answer
//!    writes an outcome.
//! 2. **Cancellation has two homes.** Imported cancellation and feed absence
//!    stay on CAL-00's `calendar.status`; only a pre-start lifecycle
//!    cancellation records `cancelled_pre_start` here — and it kills the card.
//! 3. **The check-in is a question, re-asked against current state.** It arms
//!    only for meeting-class EVENTs, fires exactly end + 30 min, and is
//!    rechecked against live evidence before the inbox surfaces anything.
//! 4. **Two independent doors.** An answer records an owner-attested outcome
//!    (`rescheduled` records `unknown`, never a fifth value); a recording drop
//!    stores a blob and infers nothing.
//!
//! ## Known hole this file inherits (NOT owned by CAL-07)
//!
//! `gate::default_policy_manifest()` has no `calendar.` rule, so under the
//! shipped default every calendar claim write is gate-pending — the hole
//! `calendar_claims_are_gate_pending_under_the_default_policy_manifest`
//! (tests/calendar_surface_oracle.rs, CAL-09) already pins, whose fix lives in
//! `crates/oneiron/src/gate.rs`, a lane-wide CAL non-claim. These oracles
//! therefore run on an unseeded vault, exactly like the CA-01 gate oracle: the
//! subject here is the outcome layer's own laws, not the policy manifest's.

use crate::common::entity as test_id;
use oneiron::calendar::claims::CALENDAR_CLAIM_PREDICATES;
use oneiron::calendar::outcome::{
    CheckInAnswer, CheckInCardModel, CheckInCopy, CheckInResolution, DEFAULT_OUTCOME_GRACE_SECS,
    DueOutcomeCheckIn, EventOutcome, EventOutcomeBasis, EventOutcomeClaimValue,
    MachineOutcomeEvidence, MeetingClassSignals, OUTCOME_CHECK_IN_REASON_TAG,
    PREDICATE_CALENDAR_EVENT_OUTCOME, accept_check_in_recording, build_check_in_lens,
    check_in_recording_artifact_id, is_meeting_class, outcome_from_machine_evidence,
    plan_outcome_check_in, project_event_outcome, read_event_outcome, record_event_outcome,
    resolve_owner_check_in,
};
use oneiron::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_PERSON};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, Error, TimeRange, Vault, VaultConfig, WriteActor,
    blob_artifact::BlobArtifactBody, blob_artifact::BlobVersionProvenance,
    inbox::InboxExceptionClass,
};
use rmpv::Value;

/// EVENT seeds. All outside `PINNED_ID_BYTES`.
const EVENT_SEED: u8 = 0x61;
const SECOND_EVENT_SEED: u8 = 0x62;
const THIRD_EVENT_SEED: u8 = 0x65;
const PERSON_SEED: u8 = 0x63;
const EVIDENCE_SEED: u8 = 0x64;
const ACTOR_SEED: u8 = 0x71;

const EVENT_START: u64 = 1_754_400_000;
const EVENT_END: u64 = EVENT_START + 3_600;

/// An unseeded vault: keeps the claim write door open without a policy fixture,
/// so these oracles measure CAL-07's laws rather than the missing `calendar.`
/// rule in the default policy manifest (see the module note).
fn temp_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_unseeded_for_test(dir.path(), config).expect("open vault");
    (dir, vault)
}

fn at(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

fn event_body(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(
        &mut out,
        &Value::Map(vec![(Value::from("name"), Value::from(name))]),
    )
    .expect("encode event body");
    out
}

/// One EVENT entity, the only structure this ticket's subjects need.
fn event(vault: &Vault, seed: u8) -> EntityId {
    let id = test_id(seed);
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_EVENT,
            TimeRange {
                start: EVENT_START,
                end: EVENT_END,
            },
            EVENT_START,
            &event_body("standup"),
        )
        .expect("put event");
    id
}

/// The exact wire object, built with no CAL-07 type in sight.
fn wire_value(outcome: &str, basis: &str, recorded_at: u64) -> Value {
    Value::Map(vec![
        (Value::from("outcome"), Value::from(outcome)),
        (Value::from("basis"), Value::from(basis)),
        (Value::from("recorded_at"), Value::from(recorded_at)),
    ])
}

/// Writes a raw claim through the ordinary public claim door.
fn put_raw_claim(
    vault: &Vault,
    claim_id: EntityId,
    predicate: &str,
    subject: ClaimSubject,
    value: Value,
    approval: ClaimApprovalStatus,
) -> Result<(), Error> {
    let body = ClaimBody::new(
        predicate,
        subject,
        value,
        1.0,
        approval,
        ClaimLifecycleStatus::Active,
    );
    vault.put_claim(&claim_id, &body, at(EVENT_START), EVENT_START)
}

/// Writes CAL-00's `calendar.status` head — the other home of cancellation,
/// which CAL-07 reads but never writes.
fn put_status(vault: &Vault, claim_id: EntityId, event_ref: EntityId, status: &str) {
    put_raw_claim(
        vault,
        claim_id,
        "calendar.status",
        ClaimSubject::Entity(event_ref),
        Value::Map(vec![
            (Value::from("status"), Value::from(status)),
            // Cancellation arrives by feed absence; a standing EVENT is
            // owner-confirmed.
            (
                Value::from("basis"),
                Value::from(if status == "cancelled" {
                    "imported_absence"
                } else {
                    "owner"
                }),
            ),
            (Value::from("recorded_at"), Value::from(EVENT_START)),
        ]),
        ClaimApprovalStatus::Approved,
    )
    .expect("status claim");
}

/// How many `calendar.event_outcome` claims on `event_ref` are still live,
/// whatever their approval state. Never two, by this layer's contract.
fn active_outcome_claims(vault: &Vault, event_ref: EntityId) -> usize {
    vault
        .claims_for_subject(&event_ref)
        .expect("claims")
        .into_iter()
        .filter_map(|id| vault.get_claim(&id).expect("claim"))
        .filter(|body| {
            body.predicate == PREDICATE_CALENDAR_EVENT_OUTCOME
                && body.lifecycle == ClaimLifecycleStatus::Active
        })
        .count()
}

/// Claim ids are keyed `(0xB7, seed, index)` so no fixture claim aliases a
/// generic `entity(seed)` id.
fn claim_id(seed: u8, index: u8) -> EntityId {
    let mut bytes = [0xB7_u8; 16];
    bytes[1] = seed;
    bytes[2] = index;
    EntityId::from_bytes(bytes).expect("fixture claim id")
}

fn meeting() -> MeetingClassSignals {
    MeetingClassSignals {
        external_attendee_count: 1,
        has_campaign_linkage: false,
        has_commitment_linkage: false,
        internal_meeting_opt_in: false,
    }
}

fn ambient() -> MeetingClassSignals {
    MeetingClassSignals {
        external_attendee_count: 0,
        has_campaign_linkage: false,
        has_commitment_linkage: false,
        internal_meeting_opt_in: false,
    }
}

fn due(event_ref: EntityId, wake_id: &str, signals: MeetingClassSignals) -> DueOutcomeCheckIn {
    DueOutcomeCheckIn {
        wake_id: wake_id.to_owned(),
        event_ref,
        scheduled_start_utc: EVENT_START,
        signals,
    }
}

fn copy() -> CheckInCopy {
    CheckInCopy {
        title: "Did the standup happen?".to_owned(),
        body: "Your 10:00 with Acme ended half an hour ago.".to_owned(),
        held_label: "It happened".to_owned(),
        no_show_label: "Nobody came".to_owned(),
        rescheduled_label: "We moved it".to_owned(),
        recording_label: "Drop a recording".to_owned(),
    }
}

#[test]
fn event_outcome_wire_contract_uses_exact_four_outcomes_and_two_bases() {
    let outcomes = [
        (EventOutcome::Held, "held"),
        (EventOutcome::NoShow, "no_show"),
        (EventOutcome::CancelledPreStart, "cancelled_pre_start"),
        (EventOutcome::Unknown, "unknown"),
    ];
    for (outcome, token) in outcomes {
        assert_eq!(outcome.as_str(), token);
        assert_eq!(EventOutcome::parse(token), Some(outcome));
    }
    for (basis, token) in [
        (EventOutcomeBasis::Machine, "machine"),
        (EventOutcomeBasis::OwnerAttested, "owner_attested"),
    ] {
        assert_eq!(basis.as_str(), token);
        assert_eq!(EventOutcomeBasis::parse(token), Some(basis));
    }
    // Closed sets: neighbouring vocabularies never leak in.
    for token in ["rescheduled", "cancelled", "attended", "", "Held"] {
        assert_eq!(EventOutcome::parse(token), None, "{token}");
    }
    for token in ["owner", "inferred", "imported_cancel"] {
        assert_eq!(EventOutcomeBasis::parse(token), None, "{token}");
    }

    // The serialization fixture: the exact wire object, JSON-round-tripped.
    let value = EventOutcomeClaimValue {
        outcome: EventOutcome::Held,
        basis: EventOutcomeBasis::Machine,
        recorded_at: EVENT_END,
    };
    let json = serde_json::to_value(value).expect("serialize");
    assert_eq!(
        json,
        serde_json::json!({
            "outcome": "held",
            "basis": "machine",
            "recorded_at": EVENT_END,
        })
    );
    assert_eq!(
        serde_json::from_value::<EventOutcomeClaimValue>(json).expect("deserialize"),
        value
    );

    // The predicate is one exact member of the CAL-00 family table.
    assert_eq!(PREDICATE_CALENDAR_EVENT_OUTCOME, "calendar.event_outcome");
    assert_eq!(
        CALENDAR_CLAIM_PREDICATES
            .iter()
            .filter(|predicate| **predicate == PREDICATE_CALENDAR_EVENT_OUTCOME)
            .count(),
        1
    );
}

#[test]
fn event_outcome_validator_rejects_unknown_fields_and_non_event_subjects() {
    let (_dir, vault) = temp_vault();
    let event_ref = event(&vault, EVENT_SEED);
    let person = test_id(PERSON_SEED);
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            at(EVENT_START),
            EVENT_START,
            b"person",
        )
        .expect("put person");

    // The canonical wire object is accepted, and readable without CAL-07 types.
    put_raw_claim(
        &vault,
        claim_id(EVENT_SEED, 0),
        PREDICATE_CALENDAR_EVENT_OUTCOME,
        ClaimSubject::Entity(event_ref),
        wire_value("held", "machine", EVENT_END),
        ClaimApprovalStatus::Approved,
    )
    .expect("canonical outcome claim");
    assert_eq!(
        read_event_outcome(&vault, event_ref).expect("read"),
        Some(EventOutcomeClaimValue {
            outcome: EventOutcome::Held,
            basis: EventOutcomeBasis::Machine,
            recorded_at: EVENT_END,
        })
    );

    // Unknown field.
    let mut extra = wire_value("held", "machine", EVENT_END);
    if let Value::Map(entries) = &mut extra {
        entries.push((Value::from("evidence_ref"), Value::from("deadbeef")));
    }
    assert!(matches!(
        put_raw_claim(
            &vault,
            claim_id(EVENT_SEED, 1),
            PREDICATE_CALENDAR_EVENT_OUTCOME,
            ClaimSubject::Entity(event_ref),
            extra,
            ClaimApprovalStatus::Approved,
        ),
        Err(Error::InvalidClaimBody(_))
    ));

    // Tokens outside the closed sets, and a non-`u64` `recorded_at`.
    for value in [
        wire_value("rescheduled", "machine", EVENT_END),
        wire_value("held", "owner", EVENT_END),
        Value::Map(vec![
            (Value::from("outcome"), Value::from("held")),
            (Value::from("basis"), Value::from("machine")),
            (Value::from("recorded_at"), Value::from("just now")),
        ]),
        Value::Map(vec![
            (Value::from("outcome"), Value::from("held")),
            (Value::from("basis"), Value::from("machine")),
        ]),
    ] {
        assert!(
            matches!(
                put_raw_claim(
                    &vault,
                    claim_id(EVENT_SEED, 2),
                    PREDICATE_CALENDAR_EVENT_OUTCOME,
                    ClaimSubject::Entity(event_ref),
                    value.clone(),
                    ClaimApprovalStatus::Approved,
                ),
                Err(Error::InvalidClaimBody(_))
            ),
            "{value} must be rejected"
        );
    }

    // Non-EVENT subject: the store-aware half of the family rule.
    let owner_answer = EventOutcomeClaimValue {
        outcome: EventOutcome::Held,
        basis: EventOutcomeBasis::OwnerAttested,
        recorded_at: EVENT_END,
    };
    assert!(matches!(
        record_event_outcome(&vault, person, &owner_answer, ClaimSource::UserStated),
        Err(Error::EntityNotFound)
    ));
    assert!(matches!(
        record_event_outcome(
            &vault,
            test_id(SECOND_EVENT_SEED),
            &owner_answer,
            ClaimSource::UserStated,
        ),
        Err(Error::EntityNotFound)
    ));
}

#[test]
fn event_outcome_supersedes_prior_live_claim_without_deleting_history() {
    let (_dir, vault) = temp_vault();
    let event_ref = event(&vault, EVENT_SEED);

    let first = record_event_outcome(
        &vault,
        event_ref,
        &EventOutcomeClaimValue {
            outcome: EventOutcome::NoShow,
            basis: EventOutcomeBasis::OwnerAttested,
            recorded_at: EVENT_END,
        },
        ClaimSource::UserStated,
    )
    .expect("first outcome");
    let second = record_event_outcome(
        &vault,
        event_ref,
        &EventOutcomeClaimValue {
            outcome: EventOutcome::Held,
            basis: EventOutcomeBasis::Machine,
            recorded_at: EVENT_END + 60,
        },
        ClaimSource::Observed,
    )
    .expect("second outcome");
    assert_ne!(first, second);

    // One current outcome per EVENT.
    assert_eq!(
        read_event_outcome(&vault, event_ref).expect("read"),
        Some(EventOutcomeClaimValue {
            outcome: EventOutcome::Held,
            basis: EventOutcomeBasis::Machine,
            recorded_at: EVENT_END + 60,
        })
    );

    // History is retained, not deleted: the prior head stays fully readable.
    let prior = vault
        .get_claim(&first)
        .expect("read prior")
        .expect("present");
    assert_eq!(prior.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(prior.valid_to, Some(EVENT_END + 60));
    assert_eq!(prior.predicate, PREDICATE_CALENDAR_EVENT_OUTCOME);

    assert_eq!(active_outcome_claims(&vault, event_ref), 1);

    // Evidence observed DURING the meeting can be ingested after the answer:
    // the late head still wins, and closing the one it replaces never writes an
    // inverted validity window.
    let late = record_event_outcome(
        &vault,
        event_ref,
        &EventOutcomeClaimValue {
            outcome: EventOutcome::NoShow,
            basis: EventOutcomeBasis::Machine,
            recorded_at: EVENT_START + 1,
        },
        ClaimSource::Observed,
    )
    .expect("out-of-order outcome");
    let closed = vault
        .get_claim(&second)
        .expect("read head")
        .expect("present");
    assert_eq!(closed.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(closed.valid_to, Some(EVENT_END + 60));
    assert!(closed.valid_to >= closed.valid_from);
    assert_eq!(
        read_event_outcome(&vault, event_ref)
            .expect("read")
            .map(|value| value.outcome),
        Some(EventOutcome::NoShow)
    );
    assert_ne!(late, second);
}

#[test]
fn silence_returns_none_and_projects_unknown_never_held() {
    let (_dir, vault) = temp_vault();
    let event_ref = event(&vault, EVENT_SEED);

    let read = read_event_outcome(&vault, event_ref).expect("read");
    assert_eq!(read, None);
    assert_eq!(project_event_outcome(read), EventOutcome::Unknown);
    assert_ne!(project_event_outcome(None), EventOutcome::Held);
    assert_ne!(project_event_outcome(None), EventOutcome::NoShow);
}

#[test]
fn elapsed_calendar_time_alone_mints_no_outcome() {
    let (_dir, vault) = temp_vault();
    let event_ref = event(&vault, EVENT_SEED);
    let wake = plan_outcome_check_in("wake-1".to_owned(), event_ref, EVENT_END, meeting())
        .expect("meeting-class event arms");

    // The wake fires; nothing else happens. Long past the grace, the EVENT
    // still carries no outcome and still projects unknown.
    assert!(wake.at_utc < EVENT_END + 86_400);
    assert_eq!(read_event_outcome(&vault, event_ref).expect("read"), None);
    assert_eq!(
        project_event_outcome(read_event_outcome(&vault, event_ref).expect("read")),
        EventOutcome::Unknown
    );

    // The question survives the grace; only the answer is missing.
    let rows = vault
        .inbox_meeting_outcome_check_ins(&[due(event_ref, &wake.id, meeting())])
        .expect("project");
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].exception_class,
        InboxExceptionClass::MeetingOutcomeCheckIn
    );
}

#[test]
fn pre_start_cancel_records_cancelled_pre_start_and_skips_grace_card() {
    let (_dir, vault) = temp_vault();
    let event_ref = event(&vault, EVENT_SEED);
    let evidence_ref = test_id(EVIDENCE_SEED);

    let pre_start = outcome_from_machine_evidence(
        EVENT_START,
        &MachineOutcomeEvidence::CancelReceived {
            evidence_ref,
            observed_at: EVENT_START - 600,
        },
    )
    .expect("pre-start cancel earns an outcome");
    assert_eq!(pre_start.outcome, EventOutcome::CancelledPreStart);
    assert_eq!(pre_start.basis, EventOutcomeBasis::Machine);
    assert_eq!(pre_start.recorded_at, EVENT_START - 600);

    // A cancellation that arrives once the EVENT has begun earns nothing.
    for observed_at in [EVENT_START, EVENT_START + 1, EVENT_END + 10] {
        assert_eq!(
            outcome_from_machine_evidence(
                EVENT_START,
                &MachineOutcomeEvidence::CancelReceived {
                    evidence_ref,
                    observed_at,
                },
            ),
            None,
            "{observed_at}"
        );
    }

    // The outcome head lands `Auto`, so the engine's source-trust rule still
    // rules on the source: a source that needs an explicit Auto permit is
    // refused loudly rather than parking an outcome the read path cannot see.
    // CAL-02's importer inherits this seam.
    assert!(matches!(
        record_event_outcome(&vault, event_ref, &pre_start, ClaimSource::Imported),
        Err(Error::SourceNotTrustedForAuto { .. })
    ));
    record_event_outcome(&vault, event_ref, &pre_start, ClaimSource::Observed).expect("record");
    // The grace card is skipped: the recheck finds the outcome already there.
    assert!(
        vault
            .inbox_meeting_outcome_check_ins(&[due(event_ref, "wake-1", meeting())])
            .expect("project")
            .is_empty()
    );
}

#[test]
fn feed_absence_uses_calendar_status_never_event_outcome() {
    let (_dir, vault) = temp_vault();
    let event_ref = event(&vault, EVENT_SEED);

    // The multi-source absence verdict is a `calendar.status` claim.
    put_status(&vault, claim_id(EVENT_SEED, 0), event_ref, "cancelled");

    // It never becomes an outcome, and the outcome predicate is a distinct
    // member of the family table.
    assert_eq!(read_event_outcome(&vault, event_ref).expect("read"), None);
    assert_eq!(
        project_event_outcome(read_event_outcome(&vault, event_ref).expect("read")),
        EventOutcome::Unknown
    );
    assert!(CALENDAR_CLAIM_PREDICATES.contains(&"calendar.status"));
    assert!(CALENDAR_CLAIM_PREDICATES.contains(&PREDICATE_CALENDAR_EVENT_OUTCOME));
    assert_ne!(PREDICATE_CALENDAR_EVENT_OUTCOME, "calendar.status");
}

#[test]
fn cancelled_status_suppresses_the_post_end_check_in() {
    let (_dir, vault) = temp_vault();
    let cancelled = event(&vault, EVENT_SEED);
    let confirmed = event(&vault, SECOND_EVENT_SEED);

    // Cancellation's other home. The outcome predicate stays silent by law, so
    // a recheck that consulted only `calendar.event_outcome` would ask the owner
    // how a meeting went that the feed already said was called off.
    put_status(&vault, claim_id(EVENT_SEED, 0), cancelled, "cancelled");
    put_status(
        &vault,
        claim_id(SECOND_EVENT_SEED, 0),
        confirmed,
        "confirmed",
    );
    assert_eq!(read_event_outcome(&vault, cancelled).expect("read"), None);

    let rows = vault
        .inbox_meeting_outcome_check_ins(&[
            due(cancelled, "wake-cancelled", meeting()),
            due(confirmed, "wake-confirmed", meeting()),
        ])
        .expect("project");
    // Only the EVENT that still stands is asked about.
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event_ref, confirmed.to_hex());

    // Suppressing the card mints no outcome: cancelled-by-feed stays `unknown`
    // here, exactly as the two-homes law requires.
    assert_eq!(
        project_event_outcome(read_event_outcome(&vault, cancelled).expect("read")),
        EventOutcome::Unknown
    );
}

#[test]
fn gate_pending_outcome_head_is_superseded_not_left_beside_its_replacement() {
    let (_dir, vault) = temp_vault();
    let event_ref = event(&vault, EVENT_SEED);

    // A `Proposed` outcome: invisible to readers, still a live head. On a
    // default-seeded vault this is the ORDINARY state of a calendar claim write
    // (no `calendar.` rule in the policy manifest — see the module note), not an
    // exotic one.
    put_raw_claim(
        &vault,
        claim_id(EVENT_SEED, 0),
        PREDICATE_CALENDAR_EVENT_OUTCOME,
        ClaimSubject::Entity(event_ref),
        wire_value("no_show", "owner_attested", EVENT_END),
        ClaimApprovalStatus::Proposed,
    )
    .expect("proposed outcome claim");
    assert_eq!(read_event_outcome(&vault, event_ref).expect("read"), None);
    assert_eq!(active_outcome_claims(&vault, event_ref), 1);

    record_event_outcome(
        &vault,
        event_ref,
        &EventOutcomeClaimValue {
            outcome: EventOutcome::Held,
            basis: EventOutcomeBasis::Machine,
            recorded_at: EVENT_END + 120,
        },
        ClaimSource::Observed,
    )
    .expect("record");

    // Never two live outcomes. Were the proposal left open, a later consent
    // approval would resurrect it beside the claim that replaced it.
    assert_eq!(active_outcome_claims(&vault, event_ref), 1);
    let proposal = vault
        .get_claim(&claim_id(EVENT_SEED, 0))
        .expect("read proposal")
        .expect("present");
    assert_eq!(proposal.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(proposal.valid_to, Some(EVENT_END + 120));
    assert_eq!(
        project_event_outcome(read_event_outcome(&vault, event_ref).expect("read")),
        EventOutcome::Held
    );
}

#[test]
fn forked_outcome_heads_resolve_to_the_later_evidence() {
    let (_dir, vault) = temp_vault();
    let ascending = event(&vault, EVENT_SEED);
    let descending = event(&vault, SECOND_EVENT_SEED);

    // A post-sync fork: two replicas each recorded an outcome and neither
    // supersession crossed the wire. Claim ids are time-ordered UUIDv7 PER
    // WRITER, so across the fork id order is not evidence order — both id
    // arrangements must resolve to the same later evidence.
    let fork = |event_ref: EntityId, seed: u8, low: (&str, u64), high: (&str, u64)| {
        put_raw_claim(
            &vault,
            claim_id(seed, 0),
            PREDICATE_CALENDAR_EVENT_OUTCOME,
            ClaimSubject::Entity(event_ref),
            wire_value(low.0, "machine", low.1),
            ClaimApprovalStatus::Approved,
        )
        .expect("low-id head");
        put_raw_claim(
            &vault,
            claim_id(seed, 1),
            PREDICATE_CALENDAR_EVENT_OUTCOME,
            ClaimSubject::Entity(event_ref),
            wire_value(high.0, "machine", high.1),
            ClaimApprovalStatus::Approved,
        )
        .expect("high-id head");
        assert_eq!(active_outcome_claims(&vault, event_ref), 2);
    };

    // Lower id carries the older evidence.
    fork(
        ascending,
        EVENT_SEED,
        ("no_show", EVENT_END),
        ("held", EVENT_END + 600),
    );
    // ...and the reverse, which is what pins `recorded_at` rather than id as
    // the ordering key.
    fork(
        descending,
        SECOND_EVENT_SEED,
        ("held", EVENT_END + 600),
        ("no_show", EVENT_END),
    );

    assert_eq!(
        read_event_outcome(&vault, ascending)
            .expect("read")
            .map(|value| value.recorded_at),
        Some(EVENT_END + 600)
    );
    assert_eq!(
        project_event_outcome(read_event_outcome(&vault, ascending).expect("read")),
        EventOutcome::Held
    );
    assert_eq!(
        project_event_outcome(read_event_outcome(&vault, descending).expect("read")),
        EventOutcome::Held
    );

    // Same instant on both sides: the id breaks the tie, so the contest stays
    // total and two replicas reading the same fork agree.
    let tied = event(&vault, THIRD_EVENT_SEED);
    fork(
        tied,
        THIRD_EVENT_SEED,
        ("no_show", EVENT_END),
        ("held", EVENT_END),
    );
    assert_eq!(
        project_event_outcome(read_event_outcome(&vault, tied).expect("read")),
        EventOutcome::Held
    );
}

#[test]
fn transcript_or_join_evidence_can_record_machine_held() {
    let (_dir, vault) = temp_vault();
    let event_ref = event(&vault, EVENT_SEED);
    let evidence_ref = test_id(EVIDENCE_SEED);

    for evidence in [
        MachineOutcomeEvidence::Transcript {
            evidence_ref,
            observed_at: EVENT_END + 30,
        },
        MachineOutcomeEvidence::JoinTelemetry {
            evidence_ref,
            observed_at: EVENT_END + 30,
        },
    ] {
        let value =
            outcome_from_machine_evidence(EVENT_START, &evidence).expect("evidence earns held");
        assert_eq!(value.outcome, EventOutcome::Held);
        assert_eq!(value.basis, EventOutcomeBasis::Machine);
        record_event_outcome(&vault, event_ref, &value, ClaimSource::Observed).expect("record");
        assert_eq!(
            project_event_outcome(read_event_outcome(&vault, event_ref).expect("read")),
            EventOutcome::Held
        );
    }
}

#[test]
fn no_show_requires_explicit_machine_evidence_or_owner_attestation() {
    let (_dir, vault) = temp_vault();
    let silent = event(&vault, EVENT_SEED);
    let evidenced = event(&vault, SECOND_EVENT_SEED);
    let evidence_ref = test_id(EVIDENCE_SEED);

    // Silence is never no-show.
    assert_ne!(
        project_event_outcome(read_event_outcome(&vault, silent).expect("read")),
        EventOutcome::NoShow
    );

    // Held-shaped evidence never yields no-show.
    for evidence in [
        MachineOutcomeEvidence::Transcript {
            evidence_ref,
            observed_at: EVENT_END,
        },
        MachineOutcomeEvidence::JoinTelemetry {
            evidence_ref,
            observed_at: EVENT_END,
        },
    ] {
        assert_ne!(
            outcome_from_machine_evidence(EVENT_START, &evidence)
                .expect("held")
                .outcome,
            EventOutcome::NoShow
        );
    }

    // Explicit machine evidence.
    let machine = outcome_from_machine_evidence(
        EVENT_START,
        &MachineOutcomeEvidence::ExplicitNoShow {
            evidence_ref,
            observed_at: EVENT_END + 5,
        },
    )
    .expect("explicit no-show");
    assert_eq!(machine.outcome, EventOutcome::NoShow);
    assert_eq!(machine.basis, EventOutcomeBasis::Machine);
    record_event_outcome(&vault, evidenced, &machine, ClaimSource::Observed).expect("record");
    assert_eq!(
        project_event_outcome(read_event_outcome(&vault, evidenced).expect("read")),
        EventOutcome::NoShow
    );

    // Or an owner attestation.
    let CheckInResolution::Outcome(owner) =
        resolve_owner_check_in(silent, CheckInAnswer::NoShow, EVENT_END + 900)
    else {
        panic!("a no-show answer resolves to an outcome");
    };
    assert_eq!(owner.outcome, EventOutcome::NoShow);
    assert_eq!(owner.basis, EventOutcomeBasis::OwnerAttested);
    record_event_outcome(&vault, silent, &owner, ClaimSource::UserStated).expect("record");
    assert_eq!(
        project_event_outcome(read_event_outcome(&vault, silent).expect("read")),
        EventOutcome::NoShow
    );
}

#[test]
fn owner_answer_records_owner_attested_basis() {
    let (_dir, vault) = temp_vault();
    let event_ref = event(&vault, EVENT_SEED);

    let CheckInResolution::Outcome(value) =
        resolve_owner_check_in(event_ref, CheckInAnswer::Held, EVENT_END + 1_800)
    else {
        panic!("a held answer resolves to an outcome");
    };
    assert_eq!(
        value,
        EventOutcomeClaimValue {
            outcome: EventOutcome::Held,
            basis: EventOutcomeBasis::OwnerAttested,
            recorded_at: EVENT_END + 1_800,
        }
    );
    record_event_outcome(&vault, event_ref, &value, ClaimSource::UserStated).expect("record");

    let stored = read_event_outcome(&vault, event_ref)
        .expect("read")
        .expect("present");
    assert_eq!(stored.basis, EventOutcomeBasis::OwnerAttested);
    assert_eq!(stored.outcome, EventOutcome::Held);
    // The answer resolves the check-in.
    assert!(
        vault
            .inbox_meeting_outcome_check_ins(&[due(event_ref, "wake-1", meeting())])
            .expect("project")
            .is_empty()
    );
}

#[test]
fn rescheduled_answer_does_not_invent_a_fifth_outcome_value() {
    let (_dir, vault) = temp_vault();
    let event_ref = event(&vault, EVENT_SEED);

    let resolution = resolve_owner_check_in(event_ref, CheckInAnswer::Rescheduled, EVENT_END + 60);
    assert_eq!(
        resolution,
        CheckInResolution::RescheduleRequested {
            event_ref,
            recorded_at: EVENT_END + 60,
        }
    );

    // No fifth wire value exists, at the enum or on the wire.
    assert_eq!(EventOutcome::parse("rescheduled"), None);
    let recorded = resolution.recorded_value();
    assert_eq!(recorded.outcome, EventOutcome::Unknown);
    assert_eq!(recorded.basis, EventOutcomeBasis::OwnerAttested);

    record_event_outcome(&vault, event_ref, &recorded, ClaimSource::UserStated).expect("record");
    assert_eq!(
        project_event_outcome(read_event_outcome(&vault, event_ref).expect("read")),
        EventOutcome::Unknown
    );
    // The owner answered, so the card resolves — while the outcome stays unknown.
    assert!(
        vault
            .inbox_meeting_outcome_check_ins(&[due(event_ref, "wake-1", meeting())])
            .expect("project")
            .is_empty()
    );
}

#[test]
fn ambient_internal_and_solo_events_do_not_arm_check_in() {
    let solo = ambient();
    let internal_without_opt_in = MeetingClassSignals {
        external_attendee_count: 0,
        has_campaign_linkage: false,
        has_commitment_linkage: false,
        internal_meeting_opt_in: false,
    };
    for signals in [solo, internal_without_opt_in] {
        assert!(!is_meeting_class(signals));
        assert_eq!(
            plan_outcome_check_in("wake-1".to_owned(), test_id(EVENT_SEED), EVENT_END, signals,),
            None
        );
    }

    // A due wake for a non-meeting-class EVENT surfaces nothing either.
    let (_dir, vault) = temp_vault();
    let event_ref = event(&vault, EVENT_SEED);
    assert!(
        vault
            .inbox_meeting_outcome_check_ins(&[due(event_ref, "wake-1", ambient())])
            .expect("project")
            .is_empty()
    );
}

#[test]
fn external_campaign_or_commitment_linked_event_arms_check_in() {
    let external = meeting();
    let campaign = MeetingClassSignals {
        has_campaign_linkage: true,
        ..ambient()
    };
    let commitment = MeetingClassSignals {
        has_commitment_linkage: true,
        ..ambient()
    };
    let internal_opt_in = MeetingClassSignals {
        internal_meeting_opt_in: true,
        ..ambient()
    };
    for signals in [external, campaign, commitment, internal_opt_in] {
        assert!(is_meeting_class(signals));
        assert!(
            plan_outcome_check_in("wake-1".to_owned(), test_id(EVENT_SEED), EVENT_END, signals)
                .is_some()
        );
    }
}

#[test]
fn check_in_wake_is_exactly_end_plus_thirty_minutes() {
    assert_eq!(DEFAULT_OUTCOME_GRACE_SECS, 30 * 60);
    let wake = plan_outcome_check_in(
        "wake-1789".to_owned(),
        test_id(EVENT_SEED),
        EVENT_END,
        meeting(),
    )
    .expect("armed");
    assert_eq!(wake.id, "wake-1789");
    assert_eq!(wake.at_utc, EVENT_END + 1_800);
    assert_eq!(wake.reason_tag, OUTCOME_CHECK_IN_REASON_TAG);

    // Saturating, never wrapping, at the far end of the clock.
    let far = plan_outcome_check_in(
        "wake-far".to_owned(),
        test_id(EVENT_SEED),
        u64::MAX,
        meeting(),
    )
    .expect("armed");
    assert_eq!(far.at_utc, u64::MAX);
}

#[test]
fn due_check_in_rechecks_evidence_before_inbox_surface() {
    let (_dir, vault) = temp_vault();
    let answered = event(&vault, EVENT_SEED);
    let open = event(&vault, SECOND_EVENT_SEED);
    let evidence_ref = test_id(EVIDENCE_SEED);

    // Evidence that arrived DURING the grace window.
    let held = outcome_from_machine_evidence(
        EVENT_START,
        &MachineOutcomeEvidence::Transcript {
            evidence_ref,
            observed_at: EVENT_END + 120,
        },
    )
    .expect("held");
    record_event_outcome(&vault, answered, &held, ClaimSource::Observed).expect("record");

    let rows = vault
        .inbox_meeting_outcome_check_ins(&[
            due(answered, "wake-a", meeting()),
            due(open, "wake-b", meeting()),
        ])
        .expect("project");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event_ref, open.to_hex());
    assert_eq!(rows[0].wake_id, "wake-b");
    assert_eq!(rows[0].scheduled_start_utc, EVENT_START);

    // A redelivered wake for the same EVENT never double-asks.
    let repeated = vault
        .inbox_meeting_outcome_check_ins(&[
            due(open, "wake-b", meeting()),
            due(open, "wake-b-again", meeting()),
        ])
        .expect("project");
    assert_eq!(repeated.len(), 1);
}

#[test]
fn check_in_card_exposes_answer_and_recording_drop_zone() {
    let model = CheckInCardModel {
        event_ref: test_id(EVENT_SEED),
        scheduled_start_utc: EVENT_START,
        answer_action_id: "calendar.outcome.answer".to_owned(),
        recording_upload_action_id: "calendar.outcome.recording".to_owned(),
    };
    let copy = copy();
    let lens = build_check_in_lens(&model, &copy).expect("card");
    let json = serde_json::to_string(&lens).expect("serialize lens");

    // Two independent doors.
    assert!(json.contains("calendar.outcome.answer"));
    assert!(json.contains("calendar.outcome.recording"));
    // Three answers on the answer door, and the closed tokens the caller gets back.
    for token in ["held", "no_show", "rescheduled"] {
        assert!(json.contains(token), "{token}");
    }
    // Every human-facing string came from the caller's copy.
    for text in [
        copy.title.as_str(),
        copy.body.as_str(),
        copy.held_label.as_str(),
        copy.no_show_label.as_str(),
        copy.rescheduled_label.as_str(),
        copy.recording_label.as_str(),
    ] {
        assert!(json.contains(text), "{text}");
    }
    // The card asks; it states no outcome.
    assert!(!json.contains("cancelled_pre_start"));
    // The EVENT and its scheduled start ride the card for the host.
    assert!(json.contains(&model.event_ref.to_hex()));
    assert!(json.contains(&EVENT_START.to_string()));
}

#[test]
fn recording_drop_zone_appends_blob_and_does_not_infer_outcome() {
    let (_dir, vault) = temp_vault();
    let event_ref = event(&vault, EVENT_SEED);
    let uploader = test_id(ACTOR_SEED);
    vault
        .put_entity(
            &uploader,
            ENTITY_TYPE_PERSON,
            at(EVENT_START),
            EVENT_START,
            b"uploader",
        )
        .expect("put uploader");
    let actor = WriteActor::new(uploader, EdgeActorClass::Human);

    let artifact = accept_check_in_recording(
        &vault,
        event_ref,
        BlobArtifactBody::new("standup.m4a", "audio/mp4"),
        EVENT_END + 300,
    )
    .expect("open recording artifact");
    assert_eq!(
        artifact,
        check_in_recording_artifact_id(&event_ref).expect("derived id")
    );

    // The bytes ride the existing append-only chain.
    let first = vault
        .append_blob_artifact_version(
            &artifact,
            b"riff-bytes",
            &BlobVersionProvenance::UserUpload,
            actor,
            at(EVENT_END + 300),
            EVENT_END + 300,
        )
        .expect("append version");
    assert_eq!(first.version, 1);

    // The drop zone infers nothing: the outcome is still unknown.
    assert_eq!(read_event_outcome(&vault, event_ref).expect("read"), None);
    assert_eq!(
        project_event_outcome(read_event_outcome(&vault, event_ref).expect("read")),
        EventOutcome::Unknown
    );
    // ...and the check-in is still open, because a recording is not an answer.
    assert_eq!(
        vault
            .inbox_meeting_outcome_check_ins(&[due(event_ref, "wake-1", meeting())])
            .expect("project")
            .len(),
        1
    );

    // A second drop appends to the same artifact rather than forking one.
    let again = accept_check_in_recording(
        &vault,
        event_ref,
        BlobArtifactBody::new("standup-2.m4a", "audio/mp4"),
        EVENT_END + 900,
    )
    .expect("second drop");
    assert_eq!(again, artifact);
    let second = vault
        .append_blob_artifact_version(
            &artifact,
            b"riff-bytes-2",
            &BlobVersionProvenance::UserUpload,
            actor,
            at(EVENT_END + 900),
            EVENT_END + 900,
        )
        .expect("append version");
    assert_eq!(second.version, 2);

    // A recording dropped on a non-EVENT is refused.
    let person = test_id(PERSON_SEED);
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            at(EVENT_START),
            EVENT_START,
            b"person",
        )
        .expect("put person");
    assert!(matches!(
        accept_check_in_recording(
            &vault,
            person,
            BlobArtifactBody::new("standup.m4a", "audio/mp4"),
            EVENT_END,
        ),
        Err(Error::EntityNotFound)
    ));
}
