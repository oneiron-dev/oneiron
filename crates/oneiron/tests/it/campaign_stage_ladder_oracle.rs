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

use crate::common::entity as test_id;
use oneiron::calendar::outcome::{
    EventOutcome, EventOutcomeBasis, EventOutcomeClaimValue, PREDICATE_CALENDAR_EVENT_OUTCOME,
    project_event_outcome, read_event_outcome, record_event_outcome,
};
use oneiron::campaign::claims::{
    CampaignMemberChannel, CampaignMemberDerivation, CampaignMemberState, CampaignMemberValue,
    CrmStageValue, EvidenceBasis, PREDICATE_CAMPAIGN_MEMBER, PREDICATE_CRM_STAGE,
    StageEvidenceClass, StageKey, claim_class_descriptors, decode_campaign_member_value,
    decode_crm_stage_value, encode_campaign_member_value, encode_crm_stage_value,
};
use oneiron::campaign::enrollment::{
    CAMPAIGN_ENROLLMENT_MACRO_ATTEMPT_KIND, CampaignEnrollmentAttemptPayload,
};
use oneiron::campaign::stage::{
    CodedCommReply, ExternalStageEvidenceHook, NO_SHOW_BUMP_AFTER_SECS, NoShowRecoveryRule,
    PromotionMode, ReentryPlan, ReplyCode, ReplyDisposition, ReplyRouteRule, StageDefinition,
    StageEvidence, StageLadderDefinition, StageProjectResult, StageTransitionRule, WakeCondition,
    apply_coded_reply, apply_event_outcome, apply_external_stage_evidence, snooze_with_wake,
};
use oneiron::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_PERSON};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    Error, TimeRange, Vault, VaultConfig,
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
const PLANTED_SEED: u8 = 0x5D;
const PROGRAM_SEED: u8 = 0x5E;
const STEP_SEED: u8 = 0x5F;
const MISSING_EVENT_SEED: u8 = 0x60;
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
            )
            .expect("fixture"),
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
/// `call_booked`. Neither step reads a calendar outcome. Returns the
/// `call_booked` head, so a test whose law is "the head did not move" can name
/// the exact claim that must still be live.
fn walk_to_call_booked(vault: &Vault) -> EntityId {
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
    )
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
            )
            .expect("fixture"),
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
    let stage =
        decode_crm_stage_value(&only_live_claim(&vault, person, PREDICATE_CRM_STAGE).1.value)
            .unwrap();
    assert_eq!(stage.stage, key(CALL_BOOKED));
    assert_eq!(
        stage.evidence_refs,
        vec![test_id(EVENT_SEED), test_id(ICS_SEED)],
    );
    assert_eq!(stage.evidence_class, StageEvidenceClass::CalendarEvent);
    assert_eq!(stage.basis, EvidenceBasis::Machine);
    assert_eq!(stage.recorded_at, BOOKING_AT);
    assert_eq!(stage.campaign_ref, test_id(CAMPAIGN_SEED));

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
fn silent_outcome_is_none_and_projects_unknown() {
    let (_dir, vault) = oracle_vault();
    let person = test_id(PERSON_SEED);
    let booked_ref = walk_to_call_booked(&vault);

    // CAL-07's reader, on an EVENT nobody recorded anything about.
    let read = read_event_outcome(&vault, test_id(EVENT_SEED)).unwrap();
    assert_eq!(read, None);
    assert_eq!(project_event_outcome(read), EventOutcome::Unknown);

    assert_eq!(apply_outcome(&vault), StageProjectResult::NoChange);
    let (head_id, body) = only_live_claim(&vault, person, PREDICATE_CRM_STAGE);
    assert_eq!(
        head_id, booked_ref,
        "silence leaves the pipeline exactly where it was",
    );
    assert_eq!(
        decode_crm_stage_value(&body.value).unwrap().stage,
        key(CALL_BOOKED),
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
    )
    .expect("fixture");
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
    let stage = decode_crm_stage_value(&body.value).unwrap();
    assert_eq!(
        stage.evidence_refs,
        vec![held_claim],
        "the cited claim is the one the decided outcome was read from",
    );
    assert_eq!(
        stage.evidence_class,
        StageEvidenceClass::CalendarEventOutcome
    );
    assert_eq!(stage.recorded_at, OUTCOME_AT);
    assert_eq!(stage.stage, key(CALL_HELD));
    assert_eq!(stage.basis, EvidenceBasis::Machine);
    assert_eq!(stage.campaign_ref, test_id(CAMPAIGN_SEED));
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
    let stage = decode_crm_stage_value(&body.value).unwrap();
    assert_eq!(stage.stage, key(CALL_HELD));
    assert_eq!(
        stage.basis,
        EvidenceBasis::OwnerAttested,
        "CAL-07's basis rides onto the stage head",
    );
    assert_eq!(stage.evidence_refs, vec![outcome_claim]);
    assert_eq!(
        stage.evidence_class,
        StageEvidenceClass::CalendarEventOutcome
    );
    assert_eq!(stage.campaign_ref, test_id(CAMPAIGN_SEED));
    assert_eq!(stage.recorded_at, OUTCOME_AT);
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
    let (member_id, body) = only_live_claim(&vault, person, PREDICATE_CAMPAIGN_MEMBER);
    assert_eq!(
        member_id,
        test_id(MEMBER_SEED),
        "a refused re-entry leaves the membership exactly as it was",
    );
    assert_eq!(
        decode_campaign_member_value(&body.value).unwrap().state,
        CampaignMemberState::Enrolled,
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
    let stage = decode_crm_stage_value(&body.value).unwrap();
    assert_eq!(
        (stage.stage, stage.basis, stage.campaign_ref),
        (
            key(DEPOSIT_PAID),
            EvidenceBasis::OwnerAttested,
            test_id(CAMPAIGN_SEED),
        ),
    );
    assert_eq!(stage.evidence_refs, vec![test_id(LEDGER_SEED)]);
    assert_eq!(stage.evidence_class, StageEvidenceClass::CounterpartyLedger);
    assert_eq!(stage.recorded_at, DEPOSIT_AT);
}
