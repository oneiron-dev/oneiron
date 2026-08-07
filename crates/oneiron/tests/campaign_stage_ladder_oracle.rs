// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! ONE-1775 (CA-04) cross-module oracle for the stage ladder.
//!
//! Everything here runs through the crate's PUBLIC API, and every `crm.stage` /
//! `campaign.member` assertion compares against CA-01's own ENCODERS rather than
//! a hand-spelled MessagePack map — so a schema change breaks the codec's tests,
//! not this file's guesses about it.
//!
//! Five laws are the subject:
//!
//! 1. `member (cold)` is not a `crm.stage`. Provenance picks a LANE; only
//!    configured transition evidence mints a pipeline head.
//! 2. AUTO is the default and Propose is a dial, not a wall.
//! 3. `crm.stage` is projector-only and superseding: one live head per
//!    `(party, campaign)`, never an append-only pile.
//! 4. Silence is never `held`. `None` and an explicit `unknown` both refuse to
//!    promote; `no_show` produces the ratified recovery order and writes no
//!    held stage.
//! 5. Downstream stages are evidence hooks. An owner attestation is admissible
//!    only past the proposal stage, and the hook mints no source truth.
//!
//! The vault is unseeded, matching the CA-01/CA-03/CA-05 and CAL-07 oracles:
//! the subject is CA-04's laws, not the default policy manifest's missing
//! `campaign.` / `calendar.` rules.

mod common;

use common::entity as test_id;
use oneiron::calendar::outcome::{
    EventOutcome, EventOutcomeBasis, EventOutcomeClaimValue, PREDICATE_CALENDAR_EVENT_OUTCOME,
    project_event_outcome, read_event_outcome, record_event_outcome,
};
use oneiron::campaign::claims::{
    CampaignMemberChannel, CampaignMemberDerivation, CampaignMemberState, CampaignMemberValue,
    CrmStageValue, EvidenceBasis, PREDICATE_CAMPAIGN_MEMBER, PREDICATE_CRM_STAGE,
    StageEvidenceClass, StageKey, claim_class_descriptors, encode_campaign_member_value,
    encode_crm_stage_value,
};
use oneiron::campaign::enrollment::{
    CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND, CampaignEnrollmentAttemptPayload,
};
use oneiron::campaign::stage::{
    CodedCommReply, ExternalStageEvidenceHook, LaneClockPolicy, MembershipProvenance,
    NO_SHOW_BUMP_AFTER_SECS, NoShowRecoveryRule, NoShowRecoveryStep, OutreachLane, PromotionMode,
    ReentryPlan, ReplyCode, ReplyDisposition, ReplyRouteRule, StageDefinition, StageEvidence,
    StageLadderDefinition, StageProjectResult, StageRoute, StageTransitionRule, WakeCondition,
    apply_coded_reply, apply_event_outcome, apply_external_stage_evidence, route_membership_lane,
    snooze_with_wake, validate_ladder,
};
use oneiron::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_PERSON};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    Error, Result, TimeRange, Vault, VaultConfig,
};
use rmpv::Value;

// Seeds, all outside `PINNED_ID_BYTES`.
const PERSON_SEED: u8 = 0x51;
const CAMPAIGN_SEED: u8 = 0x52;
const MEMBER_SEED: u8 = 0x53;
const MESSAGE_SEED: u8 = 0x54;
const EVENT_SEED: u8 = 0x55;
const ICS_SEED: u8 = 0x56;
const DOC_SEED: u8 = 0x57;
const LEDGER_SEED: u8 = 0x58;
const BASIS_SEED: u8 = 0x59;
const SENDER_SEED: u8 = 0x5A;
const QUERY_SEED: u8 = 0x5B;
const RELATIONSHIP_SEED: u8 = 0x5C;
const PLANTED_SEED: u8 = 0x5D;
const PROGRAM_SEED: u8 = 0x5E;
const STEP_SEED: u8 = 0x5F;
const MISSING_EVENT_SEED: u8 = 0x60;
const OTHER_CAMPAIGN_SEED: u8 = 0x61;
const OTHER_EVENT_SEED: u8 = 0x62;
const PLANTED_OUTCOME_SEED: u8 = 0x63;

const CHANNEL: &str = "email";
const REPLY_AT: u64 = 1_754_400_000;
const EVENT_START: u64 = REPLY_AT + 3_600;
const EVENT_END: u64 = EVENT_START + 1_800;
const OUTCOME_AT: u64 = EVENT_END + 60;
// Evidence arrives in ladder order, and the ladder order IS clock order here: a
// stage head is never superseded by evidence recorded before it, which would be
// an inverted validity window rather than a transition.
const BOOKING_AT: u64 = REPLY_AT + 600;
const PROPOSAL_AT: u64 = OUTCOME_AT + 600;
const DEPOSIT_AT: u64 = PROPOSAL_AT + 600;

// Stage tokens are TEST data. The engine spells none of them; ONE-1779's preset
// supplies the real ladder.
const REPLIED: &str = "replied";
const CALL_BOOKED: &str = "call_booked";
const CALL_HELD: &str = "call_held";
const PROPOSAL_SENT: &str = "proposal_sent";
const DEPOSIT_PAID: &str = "deposit_paid";
const DESK_ACTIVE: &str = "desk_active";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 32 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    config
}

/// An unseeded vault carrying the PERSON, the EVENT, and one enrolled cohort
/// row. Nothing here is a stage: the pipeline starts empty by construction.
fn oracle_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open_unseeded_for_test(dir.path(), test_config()).unwrap();
    put_person(&vault, test_id(PERSON_SEED));
    put_event(&vault, test_id(EVENT_SEED));
    put_member(&vault, MEMBER_SEED, &enrolled_member());
    (dir, vault)
}

fn put_person(vault: &Vault, id: EntityId) {
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"stage ladder oracle person",
        )
        .unwrap();
}

fn put_event(vault: &Vault, id: EntityId) {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![(Value::from("name"), Value::from("discovery call"))]),
    )
    .unwrap();
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
        .unwrap();
}

/// The cohort row every test starts from: enrolled, one email channel bound to a
/// sticky sender, and a machine derivation whose survival across a pause is the
/// point of half the membership assertions.
fn enrolled_member() -> CampaignMemberValue {
    CampaignMemberValue {
        campaign: test_id(CAMPAIGN_SEED),
        state: CampaignMemberState::Enrolled,
        channels: vec![CampaignMemberChannel {
            channel: CHANNEL.to_owned(),
            basis_evidence: test_id(BASIS_SEED),
            sender_ref: test_id(SENDER_SEED),
        }],
        derivation: Some(CampaignMemberDerivation {
            source_query: test_id(QUERY_SEED),
            evidence_hash: [0x7C; 32],
            epoch: 3,
        }),
    }
}

fn put_member(vault: &Vault, claim_seed: u8, value: &CampaignMemberValue) {
    vault
        .put_claim(
            &test_id(claim_seed),
            &ClaimBody::new(
                PREDICATE_CAMPAIGN_MEMBER,
                ClaimSubject::Entity(test_id(PERSON_SEED)),
                encode_campaign_member_value(value),
                1.0,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
            ),
            TimeRange { start: 1, end: 1 },
            1,
        )
        .unwrap();
}

fn key(token: &str) -> StageKey {
    StageKey(token.to_owned())
}

/// The test ladder. Six stages in order; the owner-attestation boundary is
/// `proposal_sent`, identified structurally by its
/// `DocumentArtifactAndSendReceipt` transition rather than by its name.
///
/// `replied -> call_booked` deliberately sets `owner_attested_allowed`, which
/// the position rule must still refuse: a ladder may withhold attestation from a
/// late stage but cannot grant it to an early one.
fn ladder() -> StageLadderDefinition {
    StageLadderDefinition {
        key: "oracle.v1".to_owned(),
        stages: [
            REPLIED,
            CALL_BOOKED,
            CALL_HELD,
            PROPOSAL_SENT,
            DEPOSIT_PAID,
            DESK_ACTIVE,
        ]
        .into_iter()
        .map(|token| StageDefinition {
            key: key(token),
            label: token.to_owned(),
        })
        .collect(),
        transitions: vec![
            transition(None, REPLIED, StageEvidenceClass::MeaningfulReply, false),
            transition(
                Some(REPLIED),
                CALL_BOOKED,
                StageEvidenceClass::CalendarEvent,
                true,
            ),
            transition(
                Some(CALL_BOOKED),
                CALL_HELD,
                StageEvidenceClass::CalendarEventOutcome,
                false,
            ),
            transition(
                Some(CALL_HELD),
                PROPOSAL_SENT,
                StageEvidenceClass::DocumentArtifactAndSendReceipt,
                false,
            ),
            transition(
                Some(PROPOSAL_SENT),
                DEPOSIT_PAID,
                StageEvidenceClass::CounterpartyLedger,
                true,
            ),
            transition(
                Some(DEPOSIT_PAID),
                DESK_ACTIVE,
                StageEvidenceClass::RecurringCommitment,
                true,
            ),
        ],
        reply_routes: vec![
            route(
                ReplyCode::PositiveNow,
                ReplyDisposition::Promote {
                    stage: key(REPLIED),
                },
            ),
            route(ReplyCode::PositiveLater, ReplyDisposition::Snooze),
            route(ReplyCode::Referral, ReplyDisposition::RouteReferral),
            route(ReplyCode::Objection, ReplyDisposition::RecordOnly),
            route(ReplyCode::NotInterested, ReplyDisposition::Exit),
            route(ReplyCode::Complaint, ReplyDisposition::Suppress),
        ],
        no_show_recovery: NoShowRecoveryRule {
            same_day_reschedule: true,
            bump_after_secs: NO_SHOW_BUMP_AFTER_SECS,
            snooze_after_failed_bump: true,
        },
    }
}

fn transition(
    from: Option<&str>,
    to: &str,
    evidence_class: StageEvidenceClass,
    owner_attested_allowed: bool,
) -> StageTransitionRule {
    StageTransitionRule {
        from: from.map(key),
        to: key(to),
        evidence_class,
        owner_attested_allowed,
    }
}

fn route(code: ReplyCode, disposition: ReplyDisposition) -> ReplyRouteRule {
    ReplyRouteRule { code, disposition }
}

fn reply(code: ReplyCode) -> CodedCommReply {
    CodedCommReply {
        party_ref: test_id(PERSON_SEED),
        campaign_ref: test_id(CAMPAIGN_SEED),
        membership_claim_ref: test_id(MEMBER_SEED),
        message_ref: test_id(MESSAGE_SEED),
        thread_ref: Some("thread:oracle".to_owned()),
        code,
        occurred_at: REPLY_AT,
    }
}

fn hook(
    target: &str,
    class: StageEvidenceClass,
    basis: EvidenceBasis,
    evidence_refs: Vec<EntityId>,
    recorded_at: u64,
) -> ExternalStageEvidenceHook {
    ExternalStageEvidenceHook {
        party_ref: test_id(PERSON_SEED),
        campaign_ref: test_id(CAMPAIGN_SEED),
        target_stage: key(target),
        evidence: StageEvidence {
            class,
            basis,
            evidence_refs,
            recorded_at,
        },
    }
}

fn stage_value(stage: &str, class: StageEvidenceClass, refs: Vec<EntityId>, at: u64) -> Value {
    encode_crm_stage_value(&CrmStageValue {
        campaign_ref: test_id(CAMPAIGN_SEED),
        stage: key(stage),
        evidence_class: class,
        evidence_refs: refs,
        basis: EvidenceBasis::Machine,
        recorded_at: at,
    })
}

fn live_claims(vault: &Vault, subject: EntityId, predicate: &str) -> Vec<(EntityId, ClaimBody)> {
    vault
        .claims_for_subject(&subject)
        .unwrap()
        .into_iter()
        .filter_map(|id| vault.get_claim(&id).unwrap().map(|body| (id, body)))
        .filter(|(_, body)| {
            body.predicate == predicate && body.lifecycle == ClaimLifecycleStatus::Active
        })
        .collect()
}

fn only_live_claim(vault: &Vault, subject: EntityId, predicate: &str) -> (EntityId, ClaimBody) {
    let mut claims = live_claims(vault, subject, predicate);
    assert_eq!(
        claims.len(),
        1,
        "expected exactly one live {predicate} head, found {}",
        claims.len()
    );
    claims.pop().unwrap()
}

fn all_claims(vault: &Vault, subject: EntityId) -> Vec<ClaimBody> {
    vault
        .claims_for_subject(&subject)
        .unwrap()
        .into_iter()
        .filter_map(|id| vault.get_claim(&id).unwrap())
        .collect()
}

fn advanced(result: StageProjectResult) -> EntityId {
    match result {
        StageProjectResult::Advanced { new_claim_ref } => new_claim_ref,
        other => panic!("expected an advanced stage, got {other:?}"),
    }
}

/// Walks the ladder to `call_booked`, the state every calendar-outcome test
/// starts from: a coded reply earns `replied`, an ICS evidence hook earns
/// `call_booked`. Neither step reads a calendar outcome.
fn walk_to_call_booked(vault: &Vault) {
    advanced(
        apply_coded_reply(
            vault,
            &ladder(),
            &reply(ReplyCode::PositiveNow),
            PromotionMode::Auto,
        )
        .unwrap(),
    );
    advanced(
        apply_external_stage_evidence(
            vault,
            &ladder(),
            &hook(
                CALL_BOOKED,
                StageEvidenceClass::CalendarEvent,
                EvidenceBasis::Machine,
                vec![test_id(EVENT_SEED), test_id(ICS_SEED)],
                BOOKING_AT,
            ),
            PromotionMode::Auto,
        )
        .unwrap(),
    );
}

fn record_outcome(vault: &Vault, outcome: EventOutcome) {
    record_outcome_as(vault, outcome, EventOutcomeBasis::Machine);
}

fn record_outcome_as(vault: &Vault, outcome: EventOutcome, basis: EventOutcomeBasis) {
    record_event_outcome(
        vault,
        test_id(EVENT_SEED),
        &EventOutcomeClaimValue {
            outcome,
            basis,
            recorded_at: OUTCOME_AT,
        },
        ClaimSource::Observed,
    )
    .unwrap();
}

fn apply_outcome(vault: &Vault) -> StageProjectResult {
    apply_event_outcome(
        vault,
        &ladder(),
        &test_id(PERSON_SEED),
        &test_id(CAMPAIGN_SEED),
        &test_id(EVENT_SEED),
        PromotionMode::Auto,
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// Law 1 — membership is not a stage
// ---------------------------------------------------------------------------

#[test]
fn cold_membership_never_creates_crm_stage() {
    let (_dir, vault) = oracle_vault();
    let person = test_id(PERSON_SEED);

    // A live cohort row exists...
    assert_eq!(
        only_live_claim(&vault, person, PREDICATE_CAMPAIGN_MEMBER)
            .1
            .value,
        encode_campaign_member_value(&enrolled_member()),
    );
    // ...and lane selection runs over it, writing nothing.
    let lane = route_membership_lane(
        &MembershipProvenance {
            membership_claim_ref: test_id(MEMBER_SEED),
            trigger_evidence_refs: vec![test_id(QUERY_SEED)],
            trigger_observed_at: REPLY_AT,
            prior_thread_ref: None,
            prior_relationship_evidence_ref: None,
            prior_touch_at: None,
        },
        LaneClockPolicy {
            trigger_fresh_for_secs: 30 * 24 * 60 * 60,
            prior_touch_warm_for_secs: 90 * 24 * 60 * 60,
        },
        REPLY_AT,
    );
    assert_eq!(lane, OutreachLane::Cold);
    assert!(
        live_claims(&vault, person, PREDICATE_CRM_STAGE).is_empty(),
        "a cold membership must not mint a pipeline head",
    );
}

#[test]
fn warm_reconnect_requires_real_prior_evidence() {
    let policy = LaneClockPolicy {
        trigger_fresh_for_secs: 30 * 24 * 60 * 60,
        prior_touch_warm_for_secs: 90 * 24 * 60 * 60,
    };
    let base = MembershipProvenance {
        membership_claim_ref: test_id(MEMBER_SEED),
        trigger_evidence_refs: vec![test_id(QUERY_SEED)],
        trigger_observed_at: REPLY_AT,
        prior_thread_ref: None,
        prior_relationship_evidence_ref: None,
        prior_touch_at: Some(REPLY_AT - 60 * 60),
    };

    // A real thread reference earns the warm lane and RIDES it.
    let threaded = MembershipProvenance {
        prior_thread_ref: Some("thread:prior".to_owned()),
        ..base.clone()
    };
    assert_eq!(
        route_membership_lane(&threaded, policy, REPLY_AT),
        OutreachLane::WarmReconnect {
            thread_ref: Some("thread:prior".to_owned()),
            relationship_evidence_ref: None,
        },
    );

    // So does a relationship evidence entity.
    let related = MembershipProvenance {
        prior_relationship_evidence_ref: Some(test_id(RELATIONSHIP_SEED)),
        ..base.clone()
    };
    assert_eq!(
        route_membership_lane(&related, policy, REPLY_AT),
        OutreachLane::WarmReconnect {
            thread_ref: None,
            relationship_evidence_ref: Some(test_id(RELATIONSHIP_SEED)),
        },
    );

    // A blank thread token is an ASSERTION of warmth with nothing behind it.
    let unreferenced = MembershipProvenance {
        prior_thread_ref: Some("   ".to_owned()),
        ..base
    };
    assert_eq!(
        route_membership_lane(&unreferenced, policy, REPLY_AT),
        OutreachLane::Cold,
    );

    // Policy horizons are data, and both bite: a prior touch outside the warm
    // window, and a trigger that is no longer a live reason to reach out.
    assert_eq!(
        route_membership_lane(&threaded, policy, REPLY_AT + 120 * 24 * 60 * 60),
        OutreachLane::Cold,
    );
    let stale_trigger = MembershipProvenance {
        trigger_observed_at: REPLY_AT - 60 * 24 * 60 * 60,
        ..threaded
    };
    assert_eq!(
        route_membership_lane(&stale_trigger, policy, REPLY_AT),
        OutreachLane::Cold,
    );
}

// ---------------------------------------------------------------------------
// Law 2 — AUTO is the default, Propose is a dial
// ---------------------------------------------------------------------------

#[test]
fn positive_now_reply_auto_promotes_with_message_evidence() {
    let (_dir, vault) = oracle_vault();
    let person = test_id(PERSON_SEED);

    let new_claim_ref = advanced(
        apply_coded_reply(
            &vault,
            &ladder(),
            &reply(ReplyCode::PositiveNow),
            PromotionMode::Auto,
        )
        .unwrap(),
    );

    let (id, body) = only_live_claim(&vault, person, PREDICATE_CRM_STAGE);
    assert_eq!(id, new_claim_ref);
    assert_eq!(
        body.value,
        stage_value(
            REPLIED,
            StageEvidenceClass::MeaningfulReply,
            vec![test_id(MESSAGE_SEED)],
            REPLY_AT,
        ),
        "the head must be CA-01's exact flattened value",
    );
    assert_eq!(body.approval, ClaimApprovalStatus::Approved);
    assert_eq!(
        body.evidence,
        Some(Value::Array(vec![Value::from(
            test_id(MESSAGE_SEED).to_hex()
        )])),
        "the reply message rides the claim as evidence",
    );
}

#[test]
fn propose_mode_is_a_dial_not_a_gate() {
    let (_dir, auto_vault) = oracle_vault();
    let (_propose_dir, propose_vault) = oracle_vault();
    let person = test_id(PERSON_SEED);

    // The SAME evidence, through the same door, differing only in the dial.
    let auto = apply_coded_reply(
        &auto_vault,
        &ladder(),
        &reply(ReplyCode::PositiveNow),
        PromotionMode::Auto,
    )
    .unwrap();
    let proposed = apply_coded_reply(
        &propose_vault,
        &ladder(),
        &reply(ReplyCode::PositiveNow),
        PromotionMode::Propose,
    )
    .unwrap();

    assert!(matches!(auto, StageProjectResult::Advanced { .. }));
    let StageProjectResult::Proposed { proposed_claim_ref } = proposed else {
        panic!("propose mode must return a proposed head, got {proposed:?}");
    };

    // AUTO needed no approval step to be invented for it.
    assert_eq!(
        only_live_claim(&auto_vault, person, PREDICATE_CRM_STAGE)
            .1
            .approval,
        ClaimApprovalStatus::Approved,
    );
    // Propose lands on the crate's EXISTING approval status; CA-04 mints no
    // second approval mechanism.
    let (id, body) = only_live_claim(&propose_vault, person, PREDICATE_CRM_STAGE);
    assert_eq!(id, proposed_claim_ref);
    assert_eq!(body.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(
        body.value,
        stage_value(
            REPLIED,
            StageEvidenceClass::MeaningfulReply,
            vec![test_id(MESSAGE_SEED)],
            REPLY_AT,
        ),
    );
}

// ---------------------------------------------------------------------------
// Law 3 — projector-only, superseding
// ---------------------------------------------------------------------------

#[test]
fn replacement_stage_supersedes_prior_head() {
    let (_dir, vault) = oracle_vault();
    let person = test_id(PERSON_SEED);

    let first = advanced(
        apply_coded_reply(
            &vault,
            &ladder(),
            &reply(ReplyCode::PositiveNow),
            PromotionMode::Auto,
        )
        .unwrap(),
    );
    let second = advanced(
        apply_external_stage_evidence(
            &vault,
            &ladder(),
            &hook(
                CALL_BOOKED,
                StageEvidenceClass::CalendarEvent,
                EvidenceBasis::Machine,
                vec![test_id(EVENT_SEED), test_id(ICS_SEED)],
                BOOKING_AT,
            ),
            PromotionMode::Auto,
        )
        .unwrap(),
    );

    // Not append-only: two writes, ONE live head, and the older one is closed
    // rather than deleted.
    let (live_id, _) = only_live_claim(&vault, person, PREDICATE_CRM_STAGE);
    assert_eq!(live_id, second);
    let prior = vault.get_claim(&first).unwrap().unwrap();
    assert_eq!(prior.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(
        all_claims(&vault, person)
            .iter()
            .filter(|body| body.predicate == PREDICATE_CRM_STAGE)
            .count(),
        2,
        "supersession keeps history; it is not a delete",
    );

    // A competing live head is a TORN pipeline. The next promotion fails closed
    // and writes nothing — the head check runs before any claim lands.
    vault
        .put_claim(
            &test_id(PLANTED_SEED),
            &ClaimBody::new(
                PREDICATE_CRM_STAGE,
                ClaimSubject::Entity(person),
                stage_value(
                    REPLIED,
                    StageEvidenceClass::MeaningfulReply,
                    vec![test_id(MESSAGE_SEED)],
                    REPLY_AT,
                ),
                1.0,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
            ),
            TimeRange {
                start: REPLY_AT,
                end: REPLY_AT,
            },
            REPLY_AT,
        )
        .unwrap();
    let before = all_claims(&vault, person).len();
    let torn = apply_external_stage_evidence(
        &vault,
        &ladder(),
        &hook(
            CALL_BOOKED,
            StageEvidenceClass::CalendarEvent,
            EvidenceBasis::Machine,
            vec![test_id(EVENT_SEED)],
            BOOKING_AT,
        ),
        PromotionMode::Auto,
    );
    assert!(matches!(torn, Err(Error::InvalidClaimBody(_))), "{torn:?}");
    assert_eq!(all_claims(&vault, person).len(), before);
}

#[test]
fn coded_and_external_ingress_use_projector_only_path() {
    let (_dir, vault) = oracle_vault();
    let person = test_id(PERSON_SEED);

    // Both public ingresses land the same shape through the same door.
    advanced(
        apply_coded_reply(
            &vault,
            &ladder(),
            &reply(ReplyCode::PositiveNow),
            PromotionMode::Auto,
        )
        .unwrap(),
    );
    advanced(
        apply_external_stage_evidence(
            &vault,
            &ladder(),
            &hook(
                CALL_BOOKED,
                StageEvidenceClass::CalendarEvent,
                EvidenceBasis::Machine,
                vec![test_id(EVENT_SEED), test_id(ICS_SEED)],
                BOOKING_AT,
            ),
            PromotionMode::Auto,
        )
        .unwrap(),
    );
    assert_eq!(
        only_live_claim(&vault, person, PREDICATE_CRM_STAGE).1.value,
        stage_value(
            CALL_BOOKED,
            StageEvidenceClass::CalendarEvent,
            vec![test_id(EVENT_SEED), test_id(ICS_SEED)],
            BOOKING_AT,
        ),
    );

    // Neither ingress can put or supersede a `crm.stage` claim directly: the
    // projector is crate-visible, so an external caller cannot name it, and the
    // family's own descriptor row says the same thing.
    let descriptor = claim_class_descriptors()
        .into_iter()
        .find(|row| row.predicate == PREDICATE_CRM_STAGE)
        .expect("crm.stage descriptor");
    assert!(descriptor.projector_only);

    // Evidence is never optional on this path.
    let empty = apply_external_stage_evidence(
        &vault,
        &ladder(),
        &hook(
            CALL_HELD,
            StageEvidenceClass::CalendarEventOutcome,
            EvidenceBasis::Machine,
            Vec::new(),
            OUTCOME_AT,
        ),
        PromotionMode::Auto,
    );
    assert!(
        matches!(empty, Err(Error::InvalidClaimBody(_))),
        "{empty:?}"
    );

    // A class that disagrees with the configured transition is refused too: the
    // ladder names the evidence, not the caller.
    let mismatched = apply_external_stage_evidence(
        &vault,
        &ladder(),
        &hook(
            CALL_HELD,
            StageEvidenceClass::MeaningfulReply,
            EvidenceBasis::Machine,
            vec![test_id(MESSAGE_SEED)],
            OUTCOME_AT,
        ),
        PromotionMode::Auto,
    );
    assert!(
        matches!(mismatched, Err(Error::InvalidClaimBody(_))),
        "{mismatched:?}",
    );
}

// ---------------------------------------------------------------------------
// Law 4 — silence is never `held`
// ---------------------------------------------------------------------------

#[test]
fn held_outcome_is_required_for_call_held() {
    let (_dir, vault) = oracle_vault();
    let person = test_id(PERSON_SEED);
    walk_to_call_booked(&vault);

    record_outcome(&vault, EventOutcome::Held);
    let outcome_claim = only_live_claim(
        &vault,
        test_id(EVENT_SEED),
        PREDICATE_CALENDAR_EVENT_OUTCOME,
    )
    .0;
    let advanced_ref = advanced(apply_outcome(&vault));

    let (id, body) = only_live_claim(&vault, person, PREDICATE_CRM_STAGE);
    assert_eq!(id, advanced_ref);
    assert_eq!(
        body.value,
        stage_value(
            CALL_HELD,
            StageEvidenceClass::CalendarEventOutcome,
            vec![outcome_claim],
            OUTCOME_AT,
        ),
        "the recorded outcome claim itself is the evidence",
    );
}

#[test]
fn silent_outcome_is_none_and_projects_unknown() {
    let (_dir, vault) = oracle_vault();
    let person = test_id(PERSON_SEED);
    walk_to_call_booked(&vault);

    // CAL-07's reader, on an EVENT nobody recorded anything about.
    let read = read_event_outcome(&vault, test_id(EVENT_SEED)).unwrap();
    assert_eq!(read, None);
    assert_eq!(project_event_outcome(read), EventOutcome::Unknown);

    assert_eq!(apply_outcome(&vault), StageProjectResult::NoChange);
    assert_eq!(
        only_live_claim(&vault, person, PREDICATE_CRM_STAGE).1.value,
        stage_value(
            CALL_BOOKED,
            StageEvidenceClass::CalendarEvent,
            vec![test_id(EVENT_SEED), test_id(ICS_SEED)],
            BOOKING_AT,
        ),
        "silence leaves the pipeline exactly where it was",
    );
}

#[test]
fn explicit_unknown_never_promotes() {
    let (_dir, vault) = oracle_vault();
    let person = test_id(PERSON_SEED);
    walk_to_call_booked(&vault);

    record_outcome(&vault, EventOutcome::Unknown);
    assert_eq!(apply_outcome(&vault), StageProjectResult::NoChange);

    // The same holds for a pre-start cancellation: it is a real recorded value,
    // and it is still not evidence that a call happened.
    record_outcome(&vault, EventOutcome::CancelledPreStart);
    assert_eq!(apply_outcome(&vault), StageProjectResult::NoChange);

    assert_eq!(
        only_live_claim(&vault, person, PREDICATE_CRM_STAGE).1.value,
        stage_value(
            CALL_BOOKED,
            StageEvidenceClass::CalendarEvent,
            vec![test_id(EVENT_SEED), test_id(ICS_SEED)],
            BOOKING_AT,
        ),
    );
}

#[test]
fn no_show_routes_same_day_d3_then_snooze() {
    let (_dir, vault) = oracle_vault();
    let person = test_id(PERSON_SEED);
    walk_to_call_booked(&vault);

    record_outcome(&vault, EventOutcome::NoShow);
    let outcome_claim = only_live_claim(
        &vault,
        test_id(EVENT_SEED),
        PREDICATE_CALENDAR_EVENT_OUTCOME,
    )
    .0;

    let StageProjectResult::Routed(StageRoute::Reengage(plan)) = apply_outcome(&vault) else {
        panic!("a no-show must route re-engagement");
    };
    assert_eq!(plan.event_ref, test_id(EVENT_SEED));
    assert_eq!(plan.outcome_claim_ref, outcome_claim);
    assert_eq!(
        plan.steps,
        vec![
            NoShowRecoveryStep::SameDayReschedule,
            NoShowRecoveryStep::BumpAfter {
                delay_secs: NO_SHOW_BUMP_AFTER_SECS,
            },
            NoShowRecoveryStep::Snooze,
        ],
        "the recovery ORDER is ratified, not a dial",
    );
    assert_eq!(
        only_live_claim(&vault, person, PREDICATE_CRM_STAGE).1.value,
        stage_value(
            CALL_BOOKED,
            StageEvidenceClass::CalendarEvent,
            vec![test_id(EVENT_SEED), test_id(ICS_SEED)],
            BOOKING_AT,
        ),
        "a no-show never writes call_held",
    );
}

#[test]
fn call_held_cites_the_claim_the_outcome_was_read_from() {
    let (_dir, vault) = oracle_vault();
    let person = test_id(PERSON_SEED);
    walk_to_call_booked(&vault);

    record_outcome(&vault, EventOutcome::Held);
    let held_claim = only_live_claim(
        &vault,
        test_id(EVENT_SEED),
        PREDICATE_CALENDAR_EVENT_OUTCOME,
    )
    .0;

    // A LATER no-show head on the same EVENT that the read path cannot see:
    // gate-pending, which CAL-07 documents as the ORDINARY state of a calendar
    // claim write. Its value is CAL-07's own encoding, borrowed from a claim
    // CAL-07 wrote, so nothing here hand-spells the wire shape.
    put_event(&vault, test_id(OTHER_EVENT_SEED));
    record_event_outcome(
        &vault,
        test_id(OTHER_EVENT_SEED),
        &EventOutcomeClaimValue {
            outcome: EventOutcome::NoShow,
            basis: EventOutcomeBasis::Machine,
            recorded_at: OUTCOME_AT + 60,
        },
        ClaimSource::Observed,
    )
    .unwrap();
    let no_show = only_live_claim(
        &vault,
        test_id(OTHER_EVENT_SEED),
        PREDICATE_CALENDAR_EVENT_OUTCOME,
    )
    .1;
    let mut planted = ClaimBody::new(
        PREDICATE_CALENDAR_EVENT_OUTCOME,
        ClaimSubject::Entity(test_id(EVENT_SEED)),
        no_show.value,
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    );
    planted.valid_from = Some(OUTCOME_AT + 60);
    vault
        .put_claim(
            &test_id(PLANTED_OUTCOME_SEED),
            &planted,
            TimeRange {
                start: OUTCOME_AT + 60,
                end: OUTCOME_AT + 60,
            },
            OUTCOME_AT + 60,
        )
        .unwrap();

    // CAL-07 still answers HELD, so the promotion has to cite a claim that SAYS
    // held. Citing the invisible no-show head instead would rest `call_held` on
    // a claim asserting the call never happened — the outcome value and the
    // claim id are one generation or they are nothing.
    assert_eq!(
        read_event_outcome(&vault, test_id(EVENT_SEED))
            .unwrap()
            .map(|value| value.outcome),
        Some(EventOutcome::Held),
    );
    let advanced_ref = advanced(apply_outcome(&vault));

    let (id, body) = only_live_claim(&vault, person, PREDICATE_CRM_STAGE);
    assert_eq!(id, advanced_ref);
    assert_eq!(
        body.value,
        stage_value(
            CALL_HELD,
            StageEvidenceClass::CalendarEventOutcome,
            vec![held_claim],
            OUTCOME_AT,
        ),
        "the cited claim is the one the decided outcome was read from",
    );
}

#[test]
fn an_owner_attested_outcome_is_never_relabelled_machine() {
    // The test ladder's `call_booked -> call_held` demands machine evidence, so
    // the owner's check-in answer advances nothing rather than being written as
    // an observation the engine never made.
    let (_dir, vault) = oracle_vault();
    let person = test_id(PERSON_SEED);
    walk_to_call_booked(&vault);
    record_outcome_as(&vault, EventOutcome::Held, EventOutcomeBasis::OwnerAttested);

    assert_eq!(apply_outcome(&vault), StageProjectResult::NoChange);
    assert_eq!(
        only_live_claim(&vault, person, PREDICATE_CRM_STAGE).1.value,
        stage_value(
            CALL_BOOKED,
            StageEvidenceClass::CalendarEvent,
            vec![test_id(EVENT_SEED), test_id(ICS_SEED)],
            BOOKING_AT,
        ),
    );

    // A ladder that DOES admit attestation on that rung promotes on the same
    // answer, and the head says whose answer it was.
    let (_attesting_dir, attesting_vault) = oracle_vault();
    walk_to_call_booked(&attesting_vault);
    record_outcome_as(
        &attesting_vault,
        EventOutcome::Held,
        EventOutcomeBasis::OwnerAttested,
    );
    let outcome_claim = only_live_claim(
        &attesting_vault,
        test_id(EVENT_SEED),
        PREDICATE_CALENDAR_EVENT_OUTCOME,
    )
    .0;
    let mut attesting = ladder();
    attesting.transitions = attesting
        .transitions
        .into_iter()
        .map(|rule| StageTransitionRule {
            owner_attested_allowed: rule.owner_attested_allowed || rule.to == key(CALL_HELD),
            ..rule
        })
        .collect();

    let advanced_ref = advanced(
        apply_event_outcome(
            &attesting_vault,
            &attesting,
            &person,
            &test_id(CAMPAIGN_SEED),
            &test_id(EVENT_SEED),
            PromotionMode::Auto,
        )
        .unwrap(),
    );
    let (id, body) = only_live_claim(&attesting_vault, person, PREDICATE_CRM_STAGE);
    assert_eq!(id, advanced_ref);
    assert_eq!(
        body.value,
        encode_crm_stage_value(&CrmStageValue {
            campaign_ref: test_id(CAMPAIGN_SEED),
            stage: key(CALL_HELD),
            evidence_class: StageEvidenceClass::CalendarEventOutcome,
            evidence_refs: vec![outcome_claim],
            basis: EvidenceBasis::OwnerAttested,
            recorded_at: OUTCOME_AT,
        }),
        "CAL-07's basis rides onto the stage head",
    );
    assert_eq!(
        body.source,
        Some(ClaimSource::UserStated),
        "an owner attestation is not a machine observation",
    );
}

// ---------------------------------------------------------------------------
// Snooze with wake
// ---------------------------------------------------------------------------

#[test]
fn positive_later_snoozes_and_reenters_at_touch_one() {
    let (_dir, vault) = oracle_vault();
    let person = test_id(PERSON_SEED);

    let StageProjectResult::Routed(StageRoute::Snoozed(plan)) = apply_coded_reply(
        &vault,
        &ladder(),
        &reply(ReplyCode::PositiveLater),
        PromotionMode::Auto,
    )
    .unwrap() else {
        panic!("positive_later must snooze");
    };
    assert_eq!(plan.restart_touch_index, 0, "re-entry restarts at touch 1");
    assert_eq!(plan.reason_evidence_ref, test_id(MESSAGE_SEED));
    assert_eq!(plan.wake, WakeCondition::NewTrigger);
    assert_eq!(plan.reentry_attempt, None);

    // The membership is paused with a wake condition; channels and derivation
    // ride across the transition untouched.
    let paused = CampaignMemberValue {
        state: CampaignMemberState::Paused {
            until: None,
            new_trigger: Some(true),
        },
        ..enrolled_member()
    };
    let (member_id, body) = only_live_claim(&vault, person, PREDICATE_CAMPAIGN_MEMBER);
    assert_eq!(body.value, encode_campaign_member_value(&paused));

    // `AtOrNewTrigger` persists BOTH fields.
    let both = ReentryPlan {
        party_ref: person,
        campaign_ref: test_id(CAMPAIGN_SEED),
        wake: WakeCondition::AtOrNewTrigger { at: BOOKING_AT },
        restart_touch_index: 0,
        reason_evidence_ref: test_id(MESSAGE_SEED),
        reentry_attempt: None,
    };
    let next = snooze_with_wake(&vault, &member_id, &both, BOOKING_AT).unwrap();
    assert_eq!(
        only_live_claim(&vault, person, PREDICATE_CAMPAIGN_MEMBER)
            .1
            .value,
        encode_campaign_member_value(&CampaignMemberValue {
            state: CampaignMemberState::Paused {
                until: Some(BOOKING_AT),
                new_trigger: Some(true),
            },
            ..enrolled_member()
        }),
    );

    // A deadline alone sets only `until`.
    let dated = ReentryPlan {
        wake: WakeCondition::At(BOOKING_AT + 60),
        ..both
    };
    snooze_with_wake(&vault, &next, &dated, BOOKING_AT + 60).unwrap();
    assert_eq!(
        only_live_claim(&vault, person, PREDICATE_CAMPAIGN_MEMBER)
            .1
            .value,
        encode_campaign_member_value(&CampaignMemberValue {
            state: CampaignMemberState::Paused {
                until: Some(BOOKING_AT + 60),
                new_trigger: None,
            },
            ..enrolled_member()
        }),
    );
}

#[test]
fn reentry_rides_the_existing_enrollment_attempt_kind() {
    let (_dir, vault) = oracle_vault();
    let person = test_id(PERSON_SEED);

    // CA-04 adds no attempt kind: the re-export IS CA-03's constant.
    assert_eq!(
        oneiron::campaign::stage::CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND,
        CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND,
    );
    assert_eq!(
        CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND,
        "campaign.enrollment.macro",
    );

    // A re-entry attempt is vetted through CA-03's OWN door before the pause is
    // written, so an unresolvable membership event refuses with nothing applied.
    let plan = ReentryPlan {
        party_ref: person,
        campaign_ref: test_id(CAMPAIGN_SEED),
        wake: WakeCondition::NewTrigger,
        restart_touch_index: 0,
        reason_evidence_ref: test_id(MESSAGE_SEED),
        reentry_attempt: Some(CampaignEnrollmentAttemptPayload {
            membership_event_ref: test_id(MISSING_EVENT_SEED),
            campaign_program_ref: test_id(PROGRAM_SEED),
            program_step_ref: test_id(STEP_SEED),
        }),
    };
    assert!(matches!(
        snooze_with_wake(&vault, &test_id(MEMBER_SEED), &plan, BOOKING_AT),
        Err(Error::EntityNotFound),
    ));
    assert_eq!(
        only_live_claim(&vault, person, PREDICATE_CAMPAIGN_MEMBER)
            .1
            .value,
        encode_campaign_member_value(&enrolled_member()),
        "a refused re-entry leaves the membership exactly as it was",
    );

    // Touch 1 is the only re-entry point.
    let wrong_touch = ReentryPlan {
        restart_touch_index: 1,
        reentry_attempt: None,
        ..plan
    };
    assert!(matches!(
        snooze_with_wake(&vault, &test_id(MEMBER_SEED), &wrong_touch, BOOKING_AT),
        Err(Error::InvalidClaimBody(_)),
    ));
}

#[test]
fn complaint_and_exit_reuse_campaign_member_state() {
    let (_dir, vault) = oracle_vault();
    let person = test_id(PERSON_SEED);

    let result = apply_coded_reply(
        &vault,
        &ladder(),
        &reply(ReplyCode::Complaint),
        PromotionMode::Auto,
    )
    .unwrap();
    assert_eq!(result, StageProjectResult::Routed(StageRoute::Suppressed));
    let (member_id, body) = only_live_claim(&vault, person, PREDICATE_CAMPAIGN_MEMBER);
    assert_eq!(
        body.value,
        encode_campaign_member_value(&CampaignMemberValue {
            state: CampaignMemberState::Suppressed,
            ..enrolled_member()
        }),
        "suppression reuses CA-01 membership state; no second primitive is minted",
    );

    let exited = apply_coded_reply(
        &vault,
        &ladder(),
        &CodedCommReply {
            membership_claim_ref: member_id,
            ..reply(ReplyCode::NotInterested)
        },
        PromotionMode::Auto,
    )
    .unwrap();
    assert_eq!(exited, StageProjectResult::Routed(StageRoute::Exited));
    assert_eq!(
        only_live_claim(&vault, person, PREDICATE_CAMPAIGN_MEMBER)
            .1
            .value,
        encode_campaign_member_value(&CampaignMemberValue {
            state: CampaignMemberState::Exited,
            ..enrolled_member()
        }),
    );
    assert!(
        live_claims(&vault, person, PREDICATE_CRM_STAGE).is_empty(),
        "neither route invents a pipeline head",
    );
}

// ---------------------------------------------------------------------------
// Law 5 — downstream stages are evidence hooks
// ---------------------------------------------------------------------------

/// Walks to `proposal_sent`, the boundary past which owner attestation is
/// admissible.
fn walk_to_proposal_sent(vault: &Vault) {
    walk_to_call_booked(vault);
    record_outcome(vault, EventOutcome::Held);
    advanced(apply_outcome(vault));
    advanced(
        apply_external_stage_evidence(
            vault,
            &ladder(),
            &hook(
                PROPOSAL_SENT,
                StageEvidenceClass::DocumentArtifactAndSendReceipt,
                EvidenceBasis::Machine,
                vec![test_id(DOC_SEED)],
                PROPOSAL_AT,
            ),
            PromotionMode::Auto,
        )
        .unwrap(),
    );
}

#[test]
fn owner_attested_is_allowed_only_after_proposal_sent() {
    let (_dir, vault) = oracle_vault();
    let person = test_id(PERSON_SEED);

    // BEFORE the boundary: the ladder even flags this transition
    // `owner_attested_allowed`, and the position rule still refuses.
    advanced(
        apply_coded_reply(
            &vault,
            &ladder(),
            &reply(ReplyCode::PositiveNow),
            PromotionMode::Auto,
        )
        .unwrap(),
    );
    let early = apply_external_stage_evidence(
        &vault,
        &ladder(),
        &hook(
            CALL_BOOKED,
            StageEvidenceClass::CalendarEvent,
            EvidenceBasis::OwnerAttested,
            vec![test_id(EVENT_SEED)],
            BOOKING_AT,
        ),
        PromotionMode::Auto,
    );
    assert!(
        matches!(early, Err(Error::InvalidClaimBody(_))),
        "{early:?}"
    );

    // PAST the boundary: a deposit attestation is admissible.
    let (_deposit_dir, deposit_vault) = oracle_vault();
    walk_to_proposal_sent(&deposit_vault);
    let deposit = advanced(
        apply_external_stage_evidence(
            &deposit_vault,
            &ladder(),
            &hook(
                DEPOSIT_PAID,
                StageEvidenceClass::CounterpartyLedger,
                EvidenceBasis::OwnerAttested,
                vec![test_id(LEDGER_SEED)],
                DEPOSIT_AT,
            ),
            PromotionMode::Auto,
        )
        .unwrap(),
    );
    let (id, body) = only_live_claim(&deposit_vault, person, PREDICATE_CRM_STAGE);
    assert_eq!(id, deposit);
    assert_eq!(
        body.value,
        encode_crm_stage_value(&CrmStageValue {
            campaign_ref: test_id(CAMPAIGN_SEED),
            stage: key(DEPOSIT_PAID),
            evidence_class: StageEvidenceClass::CounterpartyLedger,
            evidence_refs: vec![test_id(LEDGER_SEED)],
            basis: EvidenceBasis::OwnerAttested,
            recorded_at: DEPOSIT_AT,
        }),
    );
}

#[test]
fn deposit_and_desk_hooks_do_not_mint_source_truth() {
    let (_dir, vault) = oracle_vault();
    let person = test_id(PERSON_SEED);
    walk_to_proposal_sent(&vault);

    let before = vault.claims_for_subject(&person).unwrap().len();
    advanced(
        apply_external_stage_evidence(
            &vault,
            &ladder(),
            &hook(
                DEPOSIT_PAID,
                StageEvidenceClass::CounterpartyLedger,
                EvidenceBasis::OwnerAttested,
                vec![test_id(LEDGER_SEED)],
                DEPOSIT_AT,
            ),
            PromotionMode::Auto,
        )
        .unwrap(),
    );

    // Exactly ONE new claim, and it is a stage. No payment, commitment,
    // renewal, or TASK_LIST record is created: the counterparty ledger keeps
    // its truth, and CA-04 stores only the reference to it.
    assert_eq!(vault.claims_for_subject(&person).unwrap().len(), before + 1);
    let predicates: Vec<String> = all_claims(&vault, person)
        .into_iter()
        .map(|body| body.predicate)
        .collect();
    assert!(
        predicates
            .iter()
            .all(|predicate| predicate == PREDICATE_CRM_STAGE
                || predicate == PREDICATE_CAMPAIGN_MEMBER),
        "CA-04 wrote a foreign family: {predicates:?}",
    );
    assert_eq!(
        only_live_claim(&vault, person, PREDICATE_CRM_STAGE)
            .1
            .evidence,
        Some(Value::Array(vec![Value::from(
            test_id(LEDGER_SEED).to_hex()
        )])),
        "the hook keeps only the evidence REFERENCE",
    );
}

// ---------------------------------------------------------------------------
// Ladder validation
// ---------------------------------------------------------------------------

#[test]
fn a_self_contradicting_ladder_is_rejected() {
    assert!(validate_ladder(&ladder()).is_ok());

    let empty_key = StageLadderDefinition {
        key: "  ".to_owned(),
        ..ladder()
    };
    assert!(validate_ladder(&empty_key).is_err());

    let mut duplicate_stage = ladder();
    duplicate_stage.stages.push(StageDefinition {
        key: key(REPLIED),
        label: "again".to_owned(),
    });
    assert!(validate_ladder(&duplicate_stage).is_err());

    let mut undeclared = ladder();
    undeclared.transitions.push(transition(
        Some(DESK_ACTIVE),
        "renewed",
        StageEvidenceClass::RecurringCommitment,
        false,
    ));
    assert!(validate_ladder(&undeclared).is_err());

    // Two ways out of one stage on the SAME evidence class would make the
    // calendar-outcome path pick arbitrarily.
    let mut ambiguous = ladder();
    ambiguous.transitions.push(transition(
        Some(CALL_BOOKED),
        DESK_ACTIVE,
        StageEvidenceClass::CalendarEventOutcome,
        false,
    ));
    assert!(validate_ladder(&ambiguous).is_err());

    let mut twice_routed = ladder();
    twice_routed
        .reply_routes
        .push(route(ReplyCode::PositiveNow, ReplyDisposition::RecordOnly));
    assert!(validate_ladder(&twice_routed).is_err());

    let mut phantom_promotion = ladder();
    phantom_promotion.reply_routes = vec![route(
        ReplyCode::PositiveNow,
        ReplyDisposition::Promote {
            stage: key("nowhere"),
        },
    )];
    assert!(validate_ladder(&phantom_promotion).is_err());
}

#[test]
fn an_unrouted_code_and_an_unconfigured_transition_are_not_errors() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let person = test_id(PERSON_SEED);

    let mut sparse = ladder();
    sparse.reply_routes.clear();
    assert_eq!(
        apply_coded_reply(
            &vault,
            &sparse,
            &reply(ReplyCode::PositiveNow),
            PromotionMode::Auto,
        )?,
        StageProjectResult::NoChange,
    );

    // A hook naming a stage no transition reaches from HERE changes nothing —
    // a configuration statement, not a failure.
    assert_eq!(
        apply_external_stage_evidence(
            &vault,
            &ladder(),
            &hook(
                DESK_ACTIVE,
                StageEvidenceClass::RecurringCommitment,
                EvidenceBasis::Machine,
                vec![test_id(LEDGER_SEED)],
                DEPOSIT_AT,
            ),
            PromotionMode::Auto,
        )?,
        StageProjectResult::NoChange,
    );
    assert!(live_claims(&vault, person, PREDICATE_CRM_STAGE).is_empty());

    // A stage scoped to another campaign is not this campaign's head.
    let other = apply_event_outcome(
        &vault,
        &ladder(),
        &test_id(PERSON_SEED),
        &test_id(OTHER_CAMPAIGN_SEED),
        &test_id(EVENT_SEED),
        PromotionMode::Auto,
    )?;
    assert_eq!(other, StageProjectResult::NoChange);
    Ok(())
}
