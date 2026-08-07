//! CA-08 preset-content tests.
//!
//! The subject is the CONTRACT, not CA-04's machinery: every behavioural
//! assertion runs the loaded preset's own ladder through ONE-1775's public
//! functions, so a preset that disagrees with the mechanism it instantiates
//! fails here rather than in production.
//!
//! Every fixture string is deliberately synthetic placeholder text. A fixture
//! carrying real SOW, one-pager, or interview copy would be the embedded
//! consultancy content this ticket exists to keep out of the crate, merely
//! spelled in a test file.

use super::*;

use serde_json::{Value as JsonValue, json};

use crate::Vault;
use crate::calendar::outcome::{
    EventOutcome, EventOutcomeBasis, EventOutcomeClaimValue, read_event_outcome,
    record_event_outcome,
};
use crate::campaign::claims::{
    CampaignMemberChannel, CampaignMemberState, CampaignMemberValue, CrmStageValue, EvidenceBasis,
    PREDICATE_CAMPAIGN_MEMBER, PREDICATE_CRM_STAGE, decode_campaign_member_value,
    decode_crm_stage_value, encode_campaign_member_value,
};
use crate::campaign::stage::{
    CodedCommReply, ExternalStageEvidenceHook, LaneClockPolicy, MembershipProvenance,
    NoShowRecoveryStep, OutreachLane, PromotionMode, ReentryPlan, StageEvidence,
    StageProjectResult, StageRoute, WakeCondition, apply_coded_reply, apply_event_outcome,
    apply_external_stage_evidence, route_membership_lane, snooze_with_wake,
};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::config::VaultConfig;
use crate::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_PERSON};
use crate::temporal::TimeRange;
use crate::test_util::{entity, open_test_vault_with};

// Seeds, all outside `PINNED_ID_BYTES`.
const PERSON_SEED: u8 = 0x81;
const CAMPAIGN_SEED: u8 = 0x82;
const MEMBER_SEED: u8 = 0x83;
const MESSAGE_SEED: u8 = 0x84;
const EVENT_SEED: u8 = 0x85;
const ICS_SEED: u8 = 0x86;
const BASIS_SEED: u8 = 0x87;
const SENDER_SEED: u8 = 0x88;

// The fixture clock runs in LADDER order, because a stage head superseded by
// evidence recorded before it is an inverted validity window rather than a
// transition. Reply, then booking, then the meeting, then its outcome.
const REPLY_AT: u64 = 1_754_400_000;
const BOOKING_AT: u64 = REPLY_AT + 600;
const EVENT_START: u64 = REPLY_AT + 3_600;
const EVENT_END: u64 = EVENT_START + 1_800;
const OUTCOME_AT: u64 = EVENT_END + 60;

/// One synthetic host-supplied pack config for `crm.consultancy.v1`.
///
/// Hand-authored rather than serialized from the Rust types on purpose: the
/// wire field NAMES are half the contract with the host, and a fixture built
/// through the structs could never catch a rename.
const HOST_PRESET_FIXTURE: &str = r#"{
  "id": "crm.consultancy.v1",
  "version": 1,
  "display_name": "fixture: consultancy pipeline",
  "stage_ladder": {
    "key": "crm.consultancy.v1",
    "stages": [
      { "key": "replied",        "label": "fixture stage: replied" },
      { "key": "call_booked",    "label": "fixture stage: call booked" },
      { "key": "call_held",      "label": "fixture stage: call held" },
      { "key": "proposal_sent",  "label": "fixture stage: proposal sent" },
      { "key": "deposit_paid",   "label": "fixture stage: deposit paid" },
      { "key": "audit_active",   "label": "fixture stage: audit active" },
      { "key": "audit_complete", "label": "fixture stage: audit complete" },
      { "key": "desk_client",    "label": "fixture stage: desk client" }
    ],
    "transitions": [
      { "from": null,             "to": "replied",        "evidence_class": "meaningful_reply",                   "owner_attested_allowed": false },
      { "from": "replied",        "to": "call_booked",    "evidence_class": "calendar_event",                     "owner_attested_allowed": false },
      { "from": "call_booked",    "to": "call_held",      "evidence_class": "calendar_event_outcome",             "owner_attested_allowed": false },
      { "from": "call_held",      "to": "proposal_sent",  "evidence_class": "document_artifact_and_send_receipt", "owner_attested_allowed": false },
      { "from": "proposal_sent",  "to": "deposit_paid",   "evidence_class": "counterparty_ledger",                "owner_attested_allowed": true },
      { "from": "deposit_paid",   "to": "audit_active",   "evidence_class": "task_list_progress",                 "owner_attested_allowed": true },
      { "from": "audit_active",   "to": "audit_complete", "evidence_class": "task_list_progress",                 "owner_attested_allowed": true },
      { "from": "audit_complete", "to": "desk_client",    "evidence_class": "recurring_commitment",               "owner_attested_allowed": true }
    ],
    "reply_routes": [
      { "code": "positive_now",   "disposition": { "kind": "promote", "stage": "replied" } },
      { "code": "positive_later", "disposition": { "kind": "snooze" } },
      { "code": "referral",       "disposition": { "kind": "route_referral" } },
      { "code": "objection",      "disposition": { "kind": "record_only" } },
      { "code": "not_interested", "disposition": { "kind": "exit" } },
      { "code": "complaint",      "disposition": { "kind": "suppress" } }
    ],
    "no_show_recovery": {
      "same_day_reschedule": true,
      "bump_after_secs": 259200,
      "snooze_after_failed_bump": true
    }
  },
  "lane_policy": {
    "trigger_fresh_for_secs": 2592000,
    "prior_touch_warm_for_secs": 15552000,
    "warm_requires_evidence": true
  },
  "snooze_policy": {
    "min_secs": 5184000,
    "default_secs": 6480000,
    "max_secs": 7776000,
    "wake_on_new_trigger": true,
    "restart_touch_index": 0
  },
  "templates": {
    "sow": {
      "key": "fixture.sow",
      "kind": "sow",
      "title_template": "fixture title {{engagement}}",
      "sections": [
        { "key": "context_and_evidence", "heading": "fixture heading A", "required_evidence_slots": ["call_held_notes", "observed_signal"], "body_template": "fixture body {{observed_signal}}" },
        { "key": "outcomes",             "heading": "fixture heading B", "required_evidence_slots": [], "body_template": "fixture body B" },
        { "key": "scope",                "heading": "fixture heading C", "required_evidence_slots": [], "body_template": "fixture body C" },
        { "key": "out_of_scope",         "heading": "fixture heading D", "required_evidence_slots": [], "body_template": "fixture body D" },
        { "key": "timeline",             "heading": "fixture heading E", "required_evidence_slots": [], "body_template": "fixture body E" },
        { "key": "fees_and_deposit",     "heading": "fixture heading F", "required_evidence_slots": [], "body_template": "fixture body F" },
        { "key": "acceptance",           "heading": "fixture heading G", "required_evidence_slots": [], "body_template": "fixture body G" },
        { "key": "next_step",            "heading": "fixture heading H", "required_evidence_slots": [], "body_template": "fixture body H" }
      ]
    },
    "one_pager": {
      "key": "fixture.one_pager",
      "kind": "one_pager",
      "title_template": "fixture title {{situation}}",
      "sections": [
        { "key": "situation",           "heading": "fixture heading J", "required_evidence_slots": [], "body_template": "fixture body J" },
        { "key": "observed_evidence",   "heading": "fixture heading K", "required_evidence_slots": ["observed_signal"], "body_template": "fixture body {{observed_signal}}" },
        { "key": "proposed_engagement", "heading": "fixture heading L", "required_evidence_slots": [], "body_template": "fixture body L" },
        { "key": "timeline",            "heading": "fixture heading M", "required_evidence_slots": [], "body_template": "fixture body M" },
        { "key": "commercial_shape",    "heading": "fixture heading N", "required_evidence_slots": [], "body_template": "fixture body N" },
        { "key": "next_step",           "heading": "fixture heading P", "required_evidence_slots": [], "body_template": "fixture body P" }
      ]
    }
  },
  "desk_month": {
    "period": "P1M",
    "checkpoints": [
      { "key": "period_open",     "anchor": "period_start",      "offset_days": 0,  "evidence_slots": ["desk_month_open"] },
      { "key": "weekly_evidence", "anchor": "weekly",            "offset_days": 7,  "evidence_slots": ["weekly_task_progress"] },
      { "key": "renewal_review",  "anchor": "before_period_end", "offset_days": -7, "evidence_slots": ["renewal_signal"] },
      { "key": "period_close",    "anchor": "period_end",        "offset_days": 0,  "evidence_slots": ["period_close_summary"] }
    ],
    "renewal_evidence": ["recurring_commitment", "counterparty_ledger"]
  },
  "campaign_templates": [
    {
      "key": "mom_test",
      "purpose": "fixture purpose: research interview",
      "participant_role": "interviewee",
      "cross_campaign_exclusions": ["prospect"],
      "opening_template": "fixture opening {{interviewee}}",
      "question_blocks": [
        { "key": "past_behavior",          "intent": "fixture intent 1", "questions": ["fixture question 1"] },
        { "key": "most_recent_occurrence", "intent": "fixture intent 2", "questions": ["fixture question 2"] },
        { "key": "current_workflow",       "intent": "fixture intent 3", "questions": ["fixture question 3"] },
        { "key": "cost_and_time",          "intent": "fixture intent 4", "questions": ["fixture question 4"] },
        { "key": "prior_attempts",         "intent": "fixture intent 5", "questions": ["fixture question 5"] },
        { "key": "decision_process",       "intent": "fixture intent 6", "questions": ["fixture question 6"] }
      ],
      "exit_rules": ["fixture rule: no pitch in the interview body"]
    }
  ],
  "audit_window_days": 14
}"#;

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

fn preset() -> CampaignPresetData {
    load_campaign_preset(HOST_PRESET_FIXTURE).expect("the host fixture loads")
}

fn ladder() -> StageLadderDefinition {
    preset().stage_ladder
}

/// Rejects a config that differs from the accepted one ONLY by `edit`, so every
/// rejection arm names exactly one defect.
fn rejects(edit: impl FnOnce(&mut JsonValue)) {
    let mut value: JsonValue =
        serde_json::from_str(HOST_PRESET_FIXTURE).expect("the fixture is JSON");
    edit(&mut value);
    let result = load_campaign_preset(&value.to_string());
    assert!(
        matches!(result, Err(Error::InvalidConfig(_))),
        "the edited config must be refused, got {result:?}"
    );
}

fn field_names(value: &JsonValue) -> Vec<&str> {
    let mut names: Vec<&str> = value
        .as_object()
        .expect("a JSON object")
        .keys()
        .map(String::as_str)
        .collect();
    names.sort_unstable();
    names
}

fn section_keys(template: &BriefTemplateData) -> Vec<&str> {
    template
        .sections
        .iter()
        .map(|section| section.key.as_str())
        .collect()
}

fn section<'a>(template: &'a BriefTemplateData, key: &str) -> &'a BriefSectionData {
    template
        .sections
        .iter()
        .find(|section| section.key == key)
        .expect("the fixture declares the section")
}

/// A vault carrying the PERSON, the EVENT, and one enrolled cohort row. Nothing
/// here is a stage: the pipeline starts empty.
fn preset_vault() -> (tempfile::TempDir, Vault) {
    let mut config = VaultConfig::device();
    config.map_size = 32 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let (dir, vault) = open_test_vault_with(config);
    vault
        .put_entity(
            &entity(PERSON_SEED),
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"consultancy preset party",
        )
        .expect("put person");
    vault
        .put_entity(
            &entity(EVENT_SEED),
            ENTITY_TYPE_EVENT,
            TimeRange {
                start: EVENT_START,
                end: EVENT_END,
            },
            EVENT_START,
            b"consultancy discovery call",
        )
        .expect("put event");
    vault
        .put_claim(
            &entity(MEMBER_SEED),
            &ClaimBody::new(
                PREDICATE_CAMPAIGN_MEMBER,
                ClaimSubject::Entity(entity(PERSON_SEED)),
                encode_campaign_member_value(&enrolled_member()),
                1.0,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
            ),
            TimeRange { start: 1, end: 1 },
            1,
        )
        .expect("put membership");
    (dir, vault)
}

fn enrolled_member() -> CampaignMemberValue {
    CampaignMemberValue {
        campaign: entity(CAMPAIGN_SEED),
        state: CampaignMemberState::Enrolled,
        channels: vec![CampaignMemberChannel {
            channel: "email".to_owned(),
            basis_evidence: entity(BASIS_SEED),
            sender_ref: entity(SENDER_SEED),
        }],
        derivation: None,
    }
}

/// Walks the preset's OWN ladder to `call_booked`: a coded reply earns
/// `replied`, an EVENT-plus-ICS hook earns `call_booked`. Neither step reads a
/// calendar outcome.
fn walk_to_call_booked(vault: &Vault, ladder: &StageLadderDefinition) {
    let replied = apply_coded_reply(
        vault,
        ladder,
        &CodedCommReply {
            party_ref: entity(PERSON_SEED),
            campaign_ref: entity(CAMPAIGN_SEED),
            membership_claim_ref: entity(MEMBER_SEED),
            message_ref: entity(MESSAGE_SEED),
            thread_ref: None,
            code: ReplyCode::PositiveNow,
            occurred_at: REPLY_AT,
        },
        PromotionMode::Auto,
    )
    .expect("the coded reply applies");
    assert!(
        matches!(replied, StageProjectResult::Advanced { .. }),
        "{replied:?}"
    );

    let booked = apply_external_stage_evidence(
        vault,
        ladder,
        &ExternalStageEvidenceHook {
            party_ref: entity(PERSON_SEED),
            campaign_ref: entity(CAMPAIGN_SEED),
            target_stage: StageKey("call_booked".to_owned()),
            evidence: StageEvidence {
                class: StageEvidenceClass::CalendarEvent,
                basis: EvidenceBasis::Machine,
                evidence_refs: vec![entity(EVENT_SEED), entity(ICS_SEED)],
                recorded_at: BOOKING_AT,
            },
        },
        PromotionMode::Auto,
    )
    .expect("the booking hook applies");
    assert!(
        matches!(booked, StageProjectResult::Advanced { .. }),
        "{booked:?}"
    );
}

fn record_outcome(vault: &Vault, outcome: EventOutcome) {
    record_event_outcome(
        vault,
        entity(EVENT_SEED),
        &EventOutcomeClaimValue {
            outcome,
            basis: EventOutcomeBasis::Machine,
            recorded_at: OUTCOME_AT,
        },
        ClaimSource::Observed,
    )
    .expect("record the calendar outcome");
}

fn apply_outcome(vault: &Vault, ladder: &StageLadderDefinition) -> StageProjectResult {
    apply_event_outcome(
        vault,
        ladder,
        &entity(PERSON_SEED),
        &entity(CAMPAIGN_SEED),
        &entity(EVENT_SEED),
        PromotionMode::Auto,
    )
    .expect("the outcome applies")
}

fn live_stage(vault: &Vault) -> CrmStageValue {
    let mut head = None;
    for id in vault
        .claims_for_subject(&entity(PERSON_SEED))
        .expect("claims for subject")
    {
        let Some(body) = vault.get_claim(&id).expect("claim body") else {
            continue;
        };
        if body.predicate != PREDICATE_CRM_STAGE || body.lifecycle != ClaimLifecycleStatus::Active {
            continue;
        }
        assert!(head.is_none(), "more than one live crm.stage head");
        head = Some(decode_crm_stage_value(&body.value).expect("decode stage value"));
    }
    head.expect("a live crm.stage head")
}

fn live_member(vault: &Vault) -> CampaignMemberValue {
    let mut head = None;
    for id in vault
        .claims_for_subject(&entity(PERSON_SEED))
        .expect("claims for subject")
    {
        let Some(body) = vault.get_claim(&id).expect("claim body") else {
            continue;
        };
        if body.predicate != PREDICATE_CAMPAIGN_MEMBER
            || body.lifecycle != ClaimLifecycleStatus::Active
        {
            continue;
        }
        assert!(head.is_none(), "more than one live campaign.member head");
        head = Some(decode_campaign_member_value(&body.value).expect("decode member value"));
    }
    head.expect("a live campaign.member head")
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

#[test]
fn consultancy_v1_deserializes_against_ca04_schema() {
    let preset = preset();
    assert_eq!(preset.id, CONSULTANCY_PRESET_ID);
    assert_eq!(preset.version, CONSULTANCY_PRESET_VERSION);

    // What the loader returns is what a host can write back.
    let encoded = serde_json::to_string(&preset).expect("the preset serializes");
    assert_eq!(
        load_campaign_preset(&encoded).expect("the round trip loads"),
        preset
    );

    // A required field is not optional...
    rejects(|value| {
        value
            .as_object_mut()
            .expect("object")
            .remove("snooze_policy");
    });
    // ...and an unknown one is a defect rather than a silently dropped key: a
    // host smuggling content past the shape gets told, not ignored.
    rejects(|value| value["consultancy_body_text"] = json!("a paragraph the engine must not ship"));
    // The imported ladder subtree keeps the same promise. CA-04's structs do not
    // deny unknown fields, so without the wire-level check a misspelled dial
    // would deserialize to the ratified value the host never actually wrote.
    rejects(|value| value["stage_ladder"]["mystery"] = json!(1));
    rejects(|value| value["stage_ladder"]["stages"][0]["mystery"] = json!(1));
    rejects(|value| value["stage_ladder"]["transitions"][0]["mystery"] = json!(1));
    rejects(|value| value["stage_ladder"]["reply_routes"][0]["mystery"] = json!(1));
    rejects(|value| {
        value["stage_ladder"]["reply_routes"][1]["disposition"]["stage"] = json!("replied");
    });
    rejects(|value| value["stage_ladder"]["no_show_recovery"]["mystery"] = json!(1));
    // Both halves of the identity pair are exact.
    rejects(|value| value["id"] = json!("crm.consultancy.v2"));
    rejects(|value| value["version"] = json!(2));
    rejects(|value| value["display_name"] = json!("   "));
}

// ---------------------------------------------------------------------------
// The pipeline
// ---------------------------------------------------------------------------

#[test]
fn consultancy_stage_order_is_call_deposit_audit_desk() {
    let preset = preset();
    let stages: Vec<&str> = preset
        .stage_ladder
        .stages
        .iter()
        .map(|stage| stage.key.0.as_str())
        .collect();
    assert_eq!(
        stages,
        [
            "replied",
            "call_booked",
            "call_held",
            "proposal_sent",
            "deposit_paid",
            "audit_active",
            "audit_complete",
            "desk_client",
        ],
    );

    // Membership is not pipeline: a query match earns an outreach LANE, and only
    // configured transition evidence earns a head.
    assert!(!stages.contains(&"member"), "{stages:?}");
    assert!(!stages.contains(&"cold"), "{stages:?}");

    // The audit is a declared duration, not a timer this crate runs.
    assert_eq!(preset.audit_window_days, 14);

    rejects(|value| {
        value["stage_ladder"]["stages"]
            .as_array_mut()
            .expect("stages")
            .retain(|stage| stage["key"] != "call_held");
    });
    rejects(|value| {
        value["stage_ladder"]["stages"]
            .as_array_mut()
            .expect("stages")
            .insert(0, json!({ "key": "member", "label": "cold cohort" }));
    });
    rejects(|value| value["audit_window_days"] = json!(30));
}

#[test]
fn consultancy_stage_evidence_map_is_complete() {
    let preset = preset();
    let earned: Vec<(Option<&str>, &str, StageEvidenceClass)> = preset
        .stage_ladder
        .transitions
        .iter()
        .map(|rule| {
            (
                rule.from.as_ref().map(|from| from.0.as_str()),
                rule.to.0.as_str(),
                rule.evidence_class,
            )
        })
        .collect();
    // Each stage is earned FROM its immediate predecessor, so the ordered list
    // is the ladder rather than a decoration over a graph that skips it.
    assert_eq!(
        earned,
        [
            (None, "replied", StageEvidenceClass::MeaningfulReply),
            (
                Some("replied"),
                "call_booked",
                StageEvidenceClass::CalendarEvent,
            ),
            (
                Some("call_booked"),
                "call_held",
                StageEvidenceClass::CalendarEventOutcome,
            ),
            (
                Some("call_held"),
                "proposal_sent",
                StageEvidenceClass::DocumentArtifactAndSendReceipt,
            ),
            (
                Some("proposal_sent"),
                "deposit_paid",
                StageEvidenceClass::CounterpartyLedger,
            ),
            (
                Some("deposit_paid"),
                "audit_active",
                StageEvidenceClass::TaskListProgress,
            ),
            (
                Some("audit_active"),
                "audit_complete",
                StageEvidenceClass::TaskListProgress,
            ),
            (
                Some("audit_complete"),
                "desk_client",
                StageEvidenceClass::RecurringCommitment,
            ),
        ],
    );

    // Everything past the proposal rests on evidence somebody ELSE records: the
    // counterparty ledger, the task list, the commitment. This layer stores the
    // stage and the reference, and asserts no payment or delivery truth.
    for &(_, stage, class) in earned.iter().skip(4) {
        assert!(is_external_hook(class), "{stage} is not an external hook");
    }

    // A funnel with a shortcut is not this funnel: re-parenting `call_held` on
    // `replied` still lists eight stages while letting a party reach the
    // proposal with no meeting having happened...
    rejects(|value| value["stage_ladder"]["transitions"][2]["from"] = json!("replied"));
    // ...and neither is one that keeps the ratified chain and adds the shortcut
    // beside it.
    rejects(|value| {
        value["stage_ladder"]["transitions"]
            .as_array_mut()
            .expect("transitions")
            .push(json!({
                "from": "replied",
                "to": "call_held",
                "evidence_class": "calendar_event_outcome",
                "owner_attested_allowed": false
            }));
    });
    rejects(|value| {
        value["stage_ladder"]["transitions"][2]["evidence_class"] = json!("calendar_event");
    });
    rejects(|value| {
        value["stage_ladder"]["transitions"][4]["evidence_class"] = json!("meaningful_reply");
    });
    rejects(|value| {
        value["stage_ladder"]["transitions"]
            .as_array_mut()
            .expect("transitions")
            .retain(|rule| rule["to"] != "desk_client");
    });
}

#[test]
fn consultancy_reply_routes_cover_all_six_codes() {
    let routes = preset().stage_ladder.reply_routes;
    let routed: Vec<(ReplyCode, ReplyDisposition)> = routes
        .iter()
        .map(|route| (route.code, route.disposition.clone()))
        .collect();
    assert_eq!(
        routed,
        vec![
            (
                ReplyCode::PositiveNow,
                ReplyDisposition::Promote {
                    stage: StageKey("replied".to_owned()),
                },
            ),
            (ReplyCode::PositiveLater, ReplyDisposition::Snooze),
            (ReplyCode::Referral, ReplyDisposition::RouteReferral),
            (ReplyCode::Objection, ReplyDisposition::RecordOnly),
            (ReplyCode::NotInterested, ReplyDisposition::Exit),
            (ReplyCode::Complaint, ReplyDisposition::Suppress),
        ],
        "each of the six codes lands on its ratified disposition, exactly once",
    );

    rejects(|value| {
        value["stage_ladder"]["reply_routes"][3]["disposition"] = json!({ "kind": "exit" });
    });
    rejects(|value| {
        value["stage_ladder"]["reply_routes"]
            .as_array_mut()
            .expect("reply routes")
            .retain(|route| route["code"] != "complaint");
    });
}

// ---------------------------------------------------------------------------
// Calendar outcomes — silence is never `held`
// ---------------------------------------------------------------------------

#[test]
fn held_is_required_for_call_held() {
    let ladder = ladder();

    // Silence. CAL-07's reader answers `None`, and `None` is Unknown at
    // projection — never `held`, whatever the elapsed clock might suggest.
    let (_silent_dir, silent) = preset_vault();
    walk_to_call_booked(&silent, &ladder);
    assert_eq!(
        read_event_outcome(&silent, entity(EVENT_SEED)).expect("read the outcome"),
        None,
    );
    assert_eq!(
        apply_outcome(&silent, &ladder),
        StageProjectResult::NoChange
    );
    assert_eq!(live_stage(&silent).stage.0, "call_booked");

    // An explicitly recorded `unknown` is a real value and still not evidence
    // that a call happened.
    record_outcome(&silent, EventOutcome::Unknown);
    assert_eq!(
        apply_outcome(&silent, &ladder),
        StageProjectResult::NoChange
    );
    assert_eq!(live_stage(&silent).stage.0, "call_booked");

    // Only `held` advances, and only citing the outcome claim itself.
    let (_dir, vault) = preset_vault();
    walk_to_call_booked(&vault, &ladder);
    record_outcome(&vault, EventOutcome::Held);
    let advanced = apply_outcome(&vault, &ladder);
    assert!(
        matches!(advanced, StageProjectResult::Advanced { .. }),
        "{advanced:?}"
    );
    let head = live_stage(&vault);
    assert_eq!(head.stage.0, "call_held");
    assert_eq!(
        head.evidence_class,
        StageEvidenceClass::CalendarEventOutcome,
        "the preset earns call_held from the OUTCOME, never from the booking",
    );
    assert_eq!(head.basis, EvidenceBasis::Machine);
    assert_eq!(head.recorded_at, OUTCOME_AT);
    assert_eq!(head.evidence_refs.len(), 1);
}

#[test]
fn no_show_uses_reengagement_route() {
    let preset = preset();
    let recovery = &preset.stage_ladder.no_show_recovery;
    assert!(recovery.same_day_reschedule);
    assert_eq!(recovery.bump_after_secs, 259_200);
    assert_eq!(
        recovery.bump_after_secs, NO_SHOW_BUMP_AFTER_SECS,
        "the preset adopts CA-04's ratified D+3, it does not invent a second one",
    );
    assert!(recovery.snooze_after_failed_bump);

    let (_dir, vault) = preset_vault();
    walk_to_call_booked(&vault, &preset.stage_ladder);
    record_outcome(&vault, EventOutcome::NoShow);

    let StageProjectResult::Routed(StageRoute::Reengage(plan)) =
        apply_outcome(&vault, &preset.stage_ladder)
    else {
        panic!("a no-show must route re-engagement");
    };
    assert_eq!(
        plan.steps,
        vec![
            NoShowRecoveryStep::SameDayReschedule,
            NoShowRecoveryStep::BumpAfter {
                delay_secs: 259_200,
            },
            NoShowRecoveryStep::Snooze,
        ],
    );
    assert_eq!(plan.event_ref, entity(EVENT_SEED));
    assert_eq!(
        live_stage(&vault).stage.0,
        "call_booked",
        "a no-show never writes call_held",
    );

    rejects(|value| {
        value["stage_ladder"]["no_show_recovery"]["bump_after_secs"] = json!(86_400);
    });
    rejects(|value| {
        value["stage_ladder"]["no_show_recovery"]["same_day_reschedule"] = json!(false);
    });
    rejects(|value| {
        value["stage_ladder"]["no_show_recovery"]["snooze_after_failed_bump"] = json!(false);
    });
}

// ---------------------------------------------------------------------------
// Dials
// ---------------------------------------------------------------------------

#[test]
fn positive_later_snooze_is_a_dial() {
    let preset = preset();
    let snooze = &preset.snooze_policy;
    assert_eq!(snooze.min_secs, 60 * 24 * 60 * 60);
    assert_eq!(snooze.max_secs, 90 * 24 * 60 * 60);
    assert!(
        (snooze.min_secs..=snooze.max_secs).contains(&snooze.default_secs),
        "{}",
        snooze.default_secs,
    );
    assert!(snooze.wake_on_new_trigger);
    assert_eq!(
        snooze.restart_touch_index, 0,
        "re-entry restarts at touch 1"
    );

    // A timed wake PLUS a fresh trigger is one paused membership, not two: the
    // dials drive CA-01's combined form with both fields set.
    let (_dir, vault) = preset_vault();
    snooze_with_wake(
        &vault,
        &entity(MEMBER_SEED),
        &ReentryPlan {
            party_ref: entity(PERSON_SEED),
            campaign_ref: entity(CAMPAIGN_SEED),
            wake: WakeCondition::AtOrNewTrigger {
                at: REPLY_AT + snooze.default_secs,
            },
            restart_touch_index: snooze.restart_touch_index,
            reason_evidence_ref: entity(MESSAGE_SEED),
            reentry_attempt: None,
        },
        REPLY_AT,
    )
    .expect("the snooze applies");
    assert_eq!(
        live_member(&vault).state,
        CampaignMemberState::Paused {
            until: Some(REPLY_AT + snooze.default_secs),
            new_trigger: Some(true),
        },
    );

    rejects(|value| value["snooze_policy"]["min_secs"] = json!(59 * 24 * 60 * 60));
    rejects(|value| value["snooze_policy"]["max_secs"] = json!(100 * 24 * 60 * 60));
    rejects(|value| value["snooze_policy"]["default_secs"] = json!(24 * 60 * 60));
    rejects(|value| value["snooze_policy"]["wake_on_new_trigger"] = json!(false));
    rejects(|value| value["snooze_policy"]["restart_touch_index"] = json!(1));
}

#[test]
fn warm_reconnect_requires_evidence_slot() {
    let preset = preset();
    assert!(preset.lane_policy.warm_requires_evidence);
    let policy = LaneClockPolicy {
        trigger_fresh_for_secs: preset.lane_policy.trigger_fresh_for_secs,
        prior_touch_warm_for_secs: preset.lane_policy.prior_touch_warm_for_secs,
    };
    let base = MembershipProvenance {
        membership_claim_ref: entity(MEMBER_SEED),
        trigger_evidence_refs: vec![entity(MESSAGE_SEED)],
        trigger_observed_at: REPLY_AT,
        prior_thread_ref: None,
        prior_relationship_evidence_ref: None,
        prior_touch_at: Some(REPLY_AT - 3_600),
    };

    // Nothing to be warm ABOUT. The preset's clocks cannot manufacture a
    // relationship, so the lane is cold and the copy cannot claim otherwise.
    assert_eq!(
        route_membership_lane(&base, policy, REPLY_AT),
        OutreachLane::Cold,
    );
    // A blank thread token is an ASSERTION of familiarity with nothing behind it.
    assert_eq!(
        route_membership_lane(
            &MembershipProvenance {
                prior_thread_ref: Some("   ".to_owned()),
                ..base.clone()
            },
            policy,
            REPLY_AT,
        ),
        OutreachLane::Cold,
    );
    // A real prior thread earns the warm lane, and the reference RIDES it, so
    // rendering consumes the same evidence the decision was made on.
    assert_eq!(
        route_membership_lane(
            &MembershipProvenance {
                prior_thread_ref: Some("thread:prior".to_owned()),
                ..base
            },
            policy,
            REPLY_AT,
        ),
        OutreachLane::WarmReconnect {
            thread_ref: Some("thread:prior".to_owned()),
            relationship_evidence_ref: None,
        },
    );

    rejects(|value| value["lane_policy"]["warm_requires_evidence"] = json!(false));
    rejects(|value| value["lane_policy"]["prior_touch_warm_for_secs"] = json!(0));
}

// ---------------------------------------------------------------------------
// Documents, desk month, research
// ---------------------------------------------------------------------------

#[test]
fn sow_and_one_pager_are_arch0032b_shaped() {
    let preset = preset();
    let sow = &preset.templates.sow;
    let one_pager = &preset.templates.one_pager;
    assert_eq!(sow.kind, BriefTemplateKind::Sow);
    assert_eq!(one_pager.kind, BriefTemplateKind::OnePager);
    assert_eq!(
        section_keys(sow),
        [
            "context_and_evidence",
            "outcomes",
            "scope",
            "out_of_scope",
            "timeline",
            "fees_and_deposit",
            "acceptance",
            "next_step",
        ],
    );
    assert_eq!(
        section_keys(one_pager),
        [
            "situation",
            "observed_evidence",
            "proposed_engagement",
            "timeline",
            "commercial_shape",
            "next_step",
        ],
    );

    // Presentation is the host's, and it is really there: the engine ships the
    // slot, the host ships the sentence.
    for section in sow.sections.iter().chain(&one_pager.sections) {
        assert!(!section.heading.trim().is_empty(), "{}", section.key);
        assert!(!section.body_template.trim().is_empty(), "{}", section.key);
    }
    assert!(
        !section(sow, "context_and_evidence")
            .required_evidence_slots
            .is_empty(),
    );
    assert!(
        !section(one_pager, "observed_evidence")
            .required_evidence_slots
            .is_empty(),
    );

    // The SHAPE carries no delivery. There is no send, e-sign, payment, or
    // action field for a host to fill, so composing a brief cannot ship one.
    let encoded = serde_json::to_value(sow).expect("the brief serializes");
    assert_eq!(
        field_names(&encoded),
        ["key", "kind", "sections", "title_template"],
    );
    assert_eq!(
        field_names(&encoded["sections"][0]),
        ["body_template", "heading", "key", "required_evidence_slots"],
    );

    rejects(|value| {
        value["templates"]["sow"]["sections"]
            .as_array_mut()
            .expect("sections")
            .retain(|section| section["key"] != "acceptance");
    });
    rejects(|value| {
        value["templates"]["sow"]["sections"][0]["required_evidence_slots"] = json!([]);
    });
    // A blank slot name is an empty list wearing a string: the section still
    // claims to be evidence-backed while naming nothing a renderer can resolve.
    rejects(|value| {
        value["templates"]["sow"]["sections"][0]["required_evidence_slots"] = json!(["   "]);
    });
    rejects(|value| value["templates"]["one_pager"]["sections"][0]["body_template"] = json!(" "));
    rejects(|value| value["templates"]["one_pager"]["kind"] = json!("sow"));
}

#[test]
fn desk_month_is_declarative_only() {
    let desk = preset().desk_month;
    assert_eq!(desk.period, "P1M");
    let anchored: Vec<(&str, RhythmAnchor)> = desk
        .checkpoints
        .iter()
        .map(|checkpoint| (checkpoint.key.as_str(), checkpoint.anchor))
        .collect();
    assert_eq!(
        anchored,
        [
            ("period_open", RhythmAnchor::PeriodStart),
            ("weekly_evidence", RhythmAnchor::Weekly),
            ("renewal_review", RhythmAnchor::BeforePeriodEnd),
            ("period_close", RhythmAnchor::PeriodEnd),
        ],
    );
    for checkpoint in &desk.checkpoints {
        assert!(!checkpoint.evidence_slots.is_empty(), "{}", checkpoint.key);
    }
    assert_eq!(
        desk.renewal_evidence,
        vec![
            StageEvidenceClass::RecurringCommitment,
            StageEvidenceClass::CounterpartyLedger,
        ],
        "renewal truth stays with the commitment and the counterparty ledger",
    );

    // The period is a token the host reads, not a new `Schedule` variant, and
    // the rhythm has no commitment, invoice, or renewal-ledger field: three
    // keys, all data.
    let encoded = serde_json::to_value(&desk).expect("the rhythm serializes");
    assert!(encoded["period"].is_string());
    assert_eq!(
        field_names(&encoded),
        ["checkpoints", "period", "renewal_evidence"],
    );

    rejects(|value| value["desk_month"]["period"] = json!("P1W"));
    rejects(|value| {
        value["desk_month"]["checkpoints"]
            .as_array_mut()
            .expect("checkpoints")
            .retain(|checkpoint| checkpoint["anchor"] != "before_period_end");
    });
    // A renewal review anchored BEFORE the period end cannot sit after it.
    rejects(|value| value["desk_month"]["checkpoints"][2]["offset_days"] = json!(7));
    rejects(|value| value["desk_month"]["checkpoints"][1]["evidence_slots"] = json!([]));
    rejects(|value| value["desk_month"]["checkpoints"][1]["evidence_slots"] = json!(["   "]));
    rejects(|value| value["desk_month"]["renewal_evidence"] = json!(["meaningful_reply"]));
}

#[test]
fn mom_test_template_is_research_not_prospecting() {
    let preset = preset();
    let mom_test = preset
        .campaign_templates
        .iter()
        .find(|template| template.key == "mom_test")
        .expect("the fixture declares the mom test template");
    assert_eq!(mom_test.participant_role, "interviewee");
    assert!(
        mom_test
            .cross_campaign_exclusions
            .iter()
            .any(|role| role == "prospect"),
        "one person cannot be interviewed about a problem and sold to about it",
    );

    let blocks: Vec<&str> = mom_test
        .question_blocks
        .iter()
        .map(|block| block.key.as_str())
        .collect();
    assert_eq!(
        blocks,
        [
            "past_behavior",
            "most_recent_occurrence",
            "current_workflow",
            "cost_and_time",
            "prior_attempts",
            "decision_process",
        ],
    );
    for block in &mom_test.question_blocks {
        assert!(!block.questions.is_empty(), "{}", block.key);
    }

    // No pitch is EXPRESSIBLE. The shape has no offer, call-to-action, or free
    // body field a sales sequence could occupy — the template asks and stops.
    let encoded = serde_json::to_value(mom_test).expect("the template serializes");
    assert_eq!(
        field_names(&encoded),
        [
            "cross_campaign_exclusions",
            "exit_rules",
            "key",
            "opening_template",
            "participant_role",
            "purpose",
            "question_blocks",
        ],
    );
    assert_eq!(
        field_names(&encoded["question_blocks"][0]),
        ["intent", "key", "questions"],
    );

    rejects(|value| value["campaign_templates"][0]["participant_role"] = json!("prospect"));
    rejects(|value| value["campaign_templates"][0]["cross_campaign_exclusions"] = json!([]));
    rejects(|value| {
        value["campaign_templates"][0]["question_blocks"]
            .as_array_mut()
            .expect("question blocks")
            .retain(|block| block["key"] != "decision_process");
    });
    rejects(|value| value["campaign_templates"] = json!([]));
}
