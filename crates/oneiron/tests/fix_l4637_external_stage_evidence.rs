// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
#![cfg(oneiron_test_support)]
//! FIX 4637: the external stage-evidence ingress checked only the declared
//! evidence class and that some reference was present, so a forged
//! MESSAGE/EVENT reference could advance a stage. Machine evidence for a
//! source this engine owns must re-read as that source: a meaningful reply
//! cites a MESSAGE, a booking cites an EVENT, and a held call cites a
//! `held` calendar outcome (silence is never held).
//!
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test fix_l4637_external_stage_evidence`.

use oneiron::calendar::outcome::{
    EventOutcome, EventOutcomeBasis, EventOutcomeClaimValue, record_event_outcome,
};
use oneiron::campaign::claims::{EvidenceBasis, PREDICATE_CRM_STAGE, StageEvidenceClass, StageKey};
use oneiron::campaign::stage::{
    CodedCommReply, ExternalStageEvidenceHook, NO_SHOW_BUMP_AFTER_SECS, NoShowRecoveryRule,
    PromotionMode, ReplyCode, ReplyDisposition, ReplyRouteRule, StageDefinition, StageEvidence,
    StageLadderDefinition, StageProjectResult, StageTransitionRule, apply_coded_reply,
    apply_external_stage_evidence,
};
use oneiron::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_PERSON};
use oneiron::{ClaimLifecycleStatus, ClaimSource, EntityId, Error, TimeRange, Vault, VaultConfig};
use rmpv::Value;

// Seeds, all outside `PINNED_ID_BYTES` (mirroring the stage-ladder oracle).
const PERSON_SEED: u8 = 0x51;
const CAMPAIGN_SEED: u8 = 0x52;
const MEMBER_SEED: u8 = 0x53;
const MESSAGE_SEED: u8 = 0x54;
const EVENT_SEED: u8 = 0x55;
const ICS_SEED: u8 = 0x56;

const REPLY_AT: u64 = 1_754_400_000;
const BOOKING_AT: u64 = REPLY_AT + 600;
const EVENT_START: u64 = REPLY_AT + 3_600;
const EVENT_END: u64 = EVENT_START + 1_800;
const OUTCOME_AT: u64 = EVENT_END + 60;

const REPLIED: &str = "replied";
const CALL_BOOKED: &str = "call_booked";
const CALL_HELD: &str = "call_held";

fn test_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("a fixture id")
}

fn test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 32 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    config
}

/// An unseeded vault carrying the PERSON and the EVENT, as the stage-ladder
/// oracle builds it. No stage head exists yet.
fn evidence_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open_unseeded_for_test(dir.path(), test_config()).unwrap();
    vault
        .put_entity(
            &test_id(PERSON_SEED),
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"external evidence person",
        )
        .unwrap();
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![(Value::from("name"), Value::from("discovery call"))]),
    )
    .unwrap();
    vault
        .put_entity(
            &test_id(EVENT_SEED),
            ENTITY_TYPE_EVENT,
            TimeRange {
                start: EVENT_START,
                end: EVENT_END,
            },
            EVENT_START,
            &body,
        )
        .unwrap();
    (dir, vault)
}

fn key(token: &str) -> StageKey {
    StageKey(token.to_owned())
}

fn transition(
    from: Option<&str>,
    to: &str,
    evidence_class: StageEvidenceClass,
) -> StageTransitionRule {
    StageTransitionRule {
        from: from.map(key),
        to: key(to),
        evidence_class,
        owner_attested_allowed: false,
    }
}

fn ladder() -> StageLadderDefinition {
    StageLadderDefinition {
        key: "fix-4637.v1".to_owned(),
        stages: [REPLIED, CALL_BOOKED, CALL_HELD]
            .into_iter()
            .map(|token| StageDefinition {
                key: key(token),
                label: token.to_owned(),
            })
            .collect(),
        transitions: vec![
            transition(None, REPLIED, StageEvidenceClass::MeaningfulReply),
            transition(
                Some(REPLIED),
                CALL_BOOKED,
                StageEvidenceClass::CalendarEvent,
            ),
            transition(
                Some(CALL_BOOKED),
                CALL_HELD,
                StageEvidenceClass::CalendarEventOutcome,
            ),
        ],
        reply_routes: vec![ReplyRouteRule {
            code: ReplyCode::PositiveNow,
            disposition: ReplyDisposition::Promote {
                stage: key(REPLIED),
            },
        }],
        no_show_recovery: NoShowRecoveryRule {
            same_day_reschedule: true,
            bump_after_secs: NO_SHOW_BUMP_AFTER_SECS,
            snooze_after_failed_bump: true,
        },
    }
}

fn hook(
    target: &str,
    class: StageEvidenceClass,
    evidence_refs: Vec<EntityId>,
    recorded_at: u64,
) -> ExternalStageEvidenceHook {
    ExternalStageEvidenceHook {
        party_ref: test_id(PERSON_SEED),
        campaign_ref: test_id(CAMPAIGN_SEED),
        target_stage: key(target),
        evidence: StageEvidence {
            class,
            basis: EvidenceBasis::Machine,
            evidence_refs,
            recorded_at,
        },
    }
}

fn advanced(result: StageProjectResult) -> EntityId {
    match result {
        StageProjectResult::Advanced { new_claim_ref } => new_claim_ref,
        other => panic!("expected an advanced stage, got {other:?}"),
    }
}

fn live_stage_count(vault: &Vault) -> usize {
    vault
        .claims_for_subject(&test_id(PERSON_SEED))
        .unwrap()
        .into_iter()
        .filter_map(|id| vault.get_claim(&id).unwrap())
        .filter(|body| {
            body.predicate == PREDICATE_CRM_STAGE
                && body.lifecycle == ClaimLifecycleStatus::Active
        })
        .count()
}

/// Earns `replied` through the coded-reply door: the ladder's reply-code
/// routing, not the external hook under test.
fn walk_to_replied(vault: &Vault) {
    advanced(
        apply_coded_reply(
            vault,
            &ladder(),
            &CodedCommReply {
                party_ref: test_id(PERSON_SEED),
                campaign_ref: test_id(CAMPAIGN_SEED),
                membership_claim_ref: test_id(MEMBER_SEED),
                message_ref: test_id(MESSAGE_SEED),
                thread_ref: None,
                code: ReplyCode::PositiveNow,
                occurred_at: REPLY_AT,
            },
            PromotionMode::Auto,
        )
        .unwrap(),
    );
}

fn walk_to_call_booked(vault: &Vault) {
    walk_to_replied(vault);
    advanced(
        apply_external_stage_evidence(
            vault,
            &ladder(),
            &hook(
                CALL_BOOKED,
                StageEvidenceClass::CalendarEvent,
                vec![test_id(EVENT_SEED), test_id(ICS_SEED)],
                BOOKING_AT,
            ),
            PromotionMode::Auto,
        )
        .unwrap(),
    );
}

#[test]
fn forged_meaningful_reply_ref_does_not_advance() {
    let (_dir, vault) = evidence_vault();

    // The cited reference is a real entity, but it is the PERSON, not a
    // MESSAGE: declaring the class is not the reply.
    let forged = apply_external_stage_evidence(
        &vault,
        &ladder(),
        &hook(
            REPLIED,
            StageEvidenceClass::MeaningfulReply,
            vec![test_id(PERSON_SEED)],
            REPLY_AT,
        ),
        PromotionMode::Auto,
    );
    assert!(
        matches!(forged, Err(Error::InvalidClaimBody(_))),
        "a non-MESSAGE ref must not earn the reply stage: {forged:?}"
    );
    assert_eq!(live_stage_count(&vault), 0, "no stage head was written");
}

#[test]
fn forged_calendar_event_ref_does_not_advance_but_real_event_does() {
    let (_dir, vault) = evidence_vault();
    walk_to_replied(&vault);

    // An ICS-shaped reference that names no stored EVENT earns no booking.
    let forged = apply_external_stage_evidence(
        &vault,
        &ladder(),
        &hook(
            CALL_BOOKED,
            StageEvidenceClass::CalendarEvent,
            vec![test_id(ICS_SEED)],
            BOOKING_AT,
        ),
        PromotionMode::Auto,
    );
    assert!(
        matches!(forged, Err(Error::InvalidClaimBody(_))),
        "a ref naming no EVENT must not earn the booking stage: {forged:?}"
    );
    assert_eq!(live_stage_count(&vault), 1, "only the reply head is live");

    // The same transition citing the stored EVENT still advances.
    advanced(
        apply_external_stage_evidence(
            &vault,
            &ladder(),
            &hook(
                CALL_BOOKED,
                StageEvidenceClass::CalendarEvent,
                vec![test_id(EVENT_SEED), test_id(ICS_SEED)],
                BOOKING_AT,
            ),
            PromotionMode::Auto,
        )
        .unwrap(),
    );
    assert_eq!(live_stage_count(&vault), 1, "the booking replaced the head");
}

#[test]
fn silent_calendar_outcome_ref_does_not_advance_but_held_outcome_does() {
    let (_dir, vault) = evidence_vault();
    walk_to_call_booked(&vault);

    // No outcome is recorded for the EVENT: silence is never `held`, even
    // when the caller declares the outcome class and cites the EVENT.
    let forged = apply_external_stage_evidence(
        &vault,
        &ladder(),
        &hook(
            CALL_HELD,
            StageEvidenceClass::CalendarEventOutcome,
            vec![test_id(EVENT_SEED)],
            OUTCOME_AT,
        ),
        PromotionMode::Auto,
    );
    assert!(
        matches!(forged, Err(Error::InvalidClaimBody(_))),
        "an EVENT with no held outcome must not earn the held stage: {forged:?}"
    );
    assert_eq!(live_stage_count(&vault), 1, "only the booking head is live");

    // Once a `held` outcome is recorded, citing its claim advances.
    let outcome_claim = record_event_outcome(
        &vault,
        test_id(EVENT_SEED),
        &EventOutcomeClaimValue {
            outcome: EventOutcome::Held,
            basis: EventOutcomeBasis::Machine,
            recorded_at: OUTCOME_AT,
        },
        ClaimSource::Observed,
    )
    .unwrap();
    advanced(
        apply_external_stage_evidence(
            &vault,
            &ladder(),
            &hook(
                CALL_HELD,
                StageEvidenceClass::CalendarEventOutcome,
                vec![outcome_claim],
                OUTCOME_AT,
            ),
            PromotionMode::Auto,
        )
        .unwrap(),
    );
}

#[test]
fn held_outcome_cited_by_event_advances() {
    let (_dir, vault) = evidence_vault();
    walk_to_call_booked(&vault);
    record_event_outcome(
        &vault,
        test_id(EVENT_SEED),
        &EventOutcomeClaimValue {
            outcome: EventOutcome::Held,
            basis: EventOutcomeBasis::Machine,
            recorded_at: OUTCOME_AT,
        },
        ClaimSource::Observed,
    )
    .unwrap();

    // Citing the EVENT itself also carries its recorded `held` outcome.
    advanced(
        apply_external_stage_evidence(
            &vault,
            &ladder(),
            &hook(
                CALL_HELD,
                StageEvidenceClass::CalendarEventOutcome,
                vec![test_id(EVENT_SEED)],
                OUTCOME_AT,
            ),
            PromotionMode::Auto,
        )
        .unwrap(),
    );
}
