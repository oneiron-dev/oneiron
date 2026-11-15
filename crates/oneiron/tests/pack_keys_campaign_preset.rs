//! The consultancy preset's pack Setting keys (W3 C02 + C03): the loaded preset carries
//! the owner's no-show bump delay and three reply dispositions, while the pack itself
//! stays held to the ratified D+3 bump and six ratified reply routes.
//!
//! Run: `cargo test --locked -p oneiron --all-features --test pack_keys_campaign_preset`
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::campaign::claims::StageKey;
use oneiron::campaign::presets::{CampaignPresetData, load_campaign_preset};
use oneiron::campaign::stage::{ReplyCode, ReplyDisposition};
use oneiron::consent::AuthenticatedOwner;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::{Vault, VaultConfig};
use serde_json::json;
use tempfile::TempDir;

/// A valid consultancy preset pack: id `crm.consultancy.v1` at version 1, the eight
/// ratified stages in order with their one earning transition each, the six reply codes
/// on their ratified routes, the D+3 bump with same-day reschedule and snooze after a
/// failed bump, and host-neutral brief, rhythm, and Mom-Test shapes.
const PRESET_JSON: &str = r#"{
  "id": "crm.consultancy.v1",
  "version": 1,
  "display_name": "Consultancy",
  "stage_ladder": {
    "key": "consultancy",
    "stages": [
      {"key": "replied", "label": "Replied"},
      {"key": "call_booked", "label": "Call booked"},
      {"key": "call_held", "label": "Call held"},
      {"key": "proposal_sent", "label": "Proposal sent"},
      {"key": "deposit_paid", "label": "Deposit paid"},
      {"key": "audit_active", "label": "Audit active"},
      {"key": "audit_complete", "label": "Audit complete"},
      {"key": "desk_client", "label": "Desk client"}
    ],
    "transitions": [
      {"from": null, "to": "replied", "evidence_class": "meaningful_reply", "owner_attested_allowed": false},
      {"from": "replied", "to": "call_booked", "evidence_class": "calendar_event", "owner_attested_allowed": false},
      {"from": "call_booked", "to": "call_held", "evidence_class": "calendar_event_outcome", "owner_attested_allowed": false},
      {"from": "call_held", "to": "proposal_sent", "evidence_class": "document_artifact_and_send_receipt", "owner_attested_allowed": false},
      {"from": "proposal_sent", "to": "deposit_paid", "evidence_class": "counterparty_ledger", "owner_attested_allowed": false},
      {"from": "deposit_paid", "to": "audit_active", "evidence_class": "task_list_progress", "owner_attested_allowed": false},
      {"from": "audit_active", "to": "audit_complete", "evidence_class": "task_list_progress", "owner_attested_allowed": false},
      {"from": "audit_complete", "to": "desk_client", "evidence_class": "recurring_commitment", "owner_attested_allowed": false}
    ],
    "reply_routes": [
      {"code": "positive_now", "disposition": {"kind": "promote", "stage": "replied"}},
      {"code": "positive_later", "disposition": {"kind": "snooze"}},
      {"code": "referral", "disposition": {"kind": "route_referral"}},
      {"code": "objection", "disposition": {"kind": "record_only"}},
      {"code": "not_interested", "disposition": {"kind": "exit"}},
      {"code": "complaint", "disposition": {"kind": "suppress"}}
    ],
    "no_show_recovery": {
      "same_day_reschedule": true,
      "bump_after_secs": 259200,
      "snooze_after_failed_bump": true
    }
  },
  "lane_policy": {
    "trigger_fresh_for_secs": 1209600,
    "prior_touch_warm_for_secs": 7776000,
    "warm_requires_evidence": true
  },
  "snooze_policy": {
    "min_secs": 5184000,
    "default_secs": 5184000,
    "max_secs": 7776000,
    "wake_on_new_trigger": true,
    "restart_touch_index": 0
  },
  "templates": {
    "sow": {
      "key": "sow",
      "kind": "sow",
      "title_template": "SOW",
      "sections": [
        {"key": "context_and_evidence", "heading": "Context", "required_evidence_slots": ["call_notes"], "body_template": "Host body."},
        {"key": "outcomes", "heading": "Outcomes", "required_evidence_slots": [], "body_template": "Host body."},
        {"key": "scope", "heading": "Scope", "required_evidence_slots": [], "body_template": "Host body."},
        {"key": "out_of_scope", "heading": "Out of scope", "required_evidence_slots": [], "body_template": "Host body."},
        {"key": "timeline", "heading": "Timeline", "required_evidence_slots": [], "body_template": "Host body."},
        {"key": "fees_and_deposit", "heading": "Fees", "required_evidence_slots": [], "body_template": "Host body."},
        {"key": "acceptance", "heading": "Acceptance", "required_evidence_slots": [], "body_template": "Host body."},
        {"key": "next_step", "heading": "Next step", "required_evidence_slots": [], "body_template": "Host body."}
      ]
    },
    "one_pager": {
      "key": "one_pager",
      "kind": "one_pager",
      "title_template": "One-pager",
      "sections": [
        {"key": "situation", "heading": "Situation", "required_evidence_slots": [], "body_template": "Host body."},
        {"key": "observed_evidence", "heading": "Evidence", "required_evidence_slots": ["call_notes"], "body_template": "Host body."},
        {"key": "proposed_engagement", "heading": "Proposal", "required_evidence_slots": [], "body_template": "Host body."},
        {"key": "timeline", "heading": "Timeline", "required_evidence_slots": [], "body_template": "Host body."},
        {"key": "commercial_shape", "heading": "Commercial", "required_evidence_slots": [], "body_template": "Host body."},
        {"key": "next_step", "heading": "Next step", "required_evidence_slots": [], "body_template": "Host body."}
      ]
    }
  },
  "desk_month": {
    "period": "P1M",
    "checkpoints": [
      {"key": "start", "anchor": "period_start", "offset_days": 0, "evidence_slots": ["kickoff"]},
      {"key": "weekly", "anchor": "weekly", "offset_days": 7, "evidence_slots": ["standup"]},
      {"key": "review", "anchor": "before_period_end", "offset_days": -3, "evidence_slots": ["review_notes"]},
      {"key": "close", "anchor": "period_end", "offset_days": 0, "evidence_slots": ["closeout"]}
    ],
    "renewal_evidence": ["counterparty_ledger"]
  },
  "campaign_templates": [
    {
      "key": "mom_test",
      "purpose": "Research",
      "participant_role": "interviewee",
      "cross_campaign_exclusions": ["prospect"],
      "opening_template": "Thanks for talking.",
      "question_blocks": [
        {"key": "past_behavior", "intent": "Learn.", "questions": ["What happened?"]},
        {"key": "most_recent_occurrence", "intent": "Learn.", "questions": ["When last?"]},
        {"key": "current_workflow", "intent": "Learn.", "questions": ["How today?"]},
        {"key": "cost_and_time", "intent": "Learn.", "questions": ["What cost?"]},
        {"key": "prior_attempts", "intent": "Learn.", "questions": ["What tried?"]},
        {"key": "decision_process", "intent": "Learn.", "questions": ["Who decides?"]}
      ],
      "exit_rules": []
    }
  ],
  "audit_window_days": 14
}"#;

const BUMP_KEY: &str = "campaign.no_show.bump_after_secs";
const REFERRAL_KEY: &str = "campaign.reply.referral_disposition";
const OBJECTION_KEY: &str = "campaign.reply.objection_disposition";
const NOT_INTERESTED_KEY: &str = "campaign.reply.not_interested_disposition";

fn open_vault() -> (TempDir, Vault) {
    let dir = tempfile::tempdir().expect("a temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("the vault opens");
    (dir, vault)
}

fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner actor");
    vault
        .authenticate_owner(owner, "principal:owner", true, GateDecisionId::now())
        .expect("the owner authenticates")
}

fn set_owner(
    vault: &Vault,
    proof: &AuthenticatedOwner,
    key: &str,
    value: serde_json::Value,
) -> oneiron::Result<SetSettingOutcome> {
    vault.set_setting(
        SettingCaller::Owner(proof),
        SetSetting::vault_value(key, value),
    )
}

fn set_owner_applied(
    vault: &Vault,
    proof: &AuthenticatedOwner,
    key: &str,
    value: serde_json::Value,
) {
    let outcome = set_owner(vault, proof, key, value).expect("the owner sets its key");
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "the change applies, got {outcome:?}"
    );
}

fn disposition_of(preset: &CampaignPresetData, code: ReplyCode) -> &ReplyDisposition {
    preset
        .stage_ladder
        .reply_routes
        .iter()
        .find(|route| route.code == code)
        .map(|route| &route.disposition)
        .expect("the code is routed")
}

fn preset_json_with_bump(bump_after_secs: u64) -> String {
    let count = PRESET_JSON.matches("259200").count();
    assert_eq!(count, 1, "the ratified bump appears once in the fixture");
    PRESET_JSON.replace("259200", &bump_after_secs.to_string())
}

#[test]
fn the_preset_loads_with_the_ratified_bump_and_routes_by_default_and_with_the_owners_values_once_set()
 {
    let (_dir, vault) = open_vault();
    let preset = load_campaign_preset(&vault, PRESET_JSON).expect("the fixture is a valid preset");
    assert_eq!(preset.stage_ladder.no_show_recovery.bump_after_secs, 259200);
    assert_eq!(
        disposition_of(&preset, ReplyCode::Referral),
        &ReplyDisposition::RouteReferral
    );
    assert_eq!(
        disposition_of(&preset, ReplyCode::Objection),
        &ReplyDisposition::RecordOnly
    );
    assert_eq!(
        disposition_of(&preset, ReplyCode::NotInterested),
        &ReplyDisposition::Exit
    );

    let proof = owner_proof(&vault);
    set_owner_applied(&vault, &proof, BUMP_KEY, json!(432000));
    set_owner_applied(&vault, &proof, REFERRAL_KEY, json!({"kind": "record_only"}));
    set_owner_applied(&vault, &proof, OBJECTION_KEY, json!({"kind": "exit"}));
    set_owner_applied(
        &vault,
        &proof,
        NOT_INTERESTED_KEY,
        json!({"kind": "suppress"}),
    );

    let preset = load_campaign_preset(&vault, PRESET_JSON).expect("the fixture still loads");
    assert_eq!(preset.stage_ladder.no_show_recovery.bump_after_secs, 432000);
    assert_eq!(
        disposition_of(&preset, ReplyCode::Referral),
        &ReplyDisposition::RecordOnly
    );
    assert_eq!(
        disposition_of(&preset, ReplyCode::Objection),
        &ReplyDisposition::Exit
    );
    assert_eq!(
        disposition_of(&preset, ReplyCode::NotInterested),
        &ReplyDisposition::Suppress
    );
    assert_eq!(
        disposition_of(&preset, ReplyCode::PositiveNow),
        &ReplyDisposition::Promote {
            stage: StageKey("replied".to_owned())
        }
    );
    assert_eq!(
        disposition_of(&preset, ReplyCode::PositiveLater),
        &ReplyDisposition::Snooze
    );
    assert_eq!(
        disposition_of(&preset, ReplyCode::Complaint),
        &ReplyDisposition::Suppress
    );
}

#[test]
fn the_pack_itself_is_still_held_to_the_ratified_preset() {
    let (_dir, vault) = open_vault();
    let proof = owner_proof(&vault);
    set_owner_applied(&vault, &proof, BUMP_KEY, json!(432000));
    let json = preset_json_with_bump(432000);
    assert!(
        load_campaign_preset(&vault, &json).is_err(),
        "a pack carrying its own 432000 bump is refused"
    );
}

#[test]
fn an_owner_promote_must_name_a_declared_stage() {
    let (_dir, vault) = open_vault();
    let proof = owner_proof(&vault);
    set_owner_applied(
        &vault,
        &proof,
        REFERRAL_KEY,
        json!({"kind": "promote", "stage": "replied"}),
    );
    let preset =
        load_campaign_preset(&vault, PRESET_JSON).expect("a promote into a declared stage loads");
    assert_eq!(
        disposition_of(&preset, ReplyCode::Referral),
        &ReplyDisposition::Promote {
            stage: StageKey("replied".to_owned())
        }
    );
    set_owner_applied(
        &vault,
        &proof,
        REFERRAL_KEY,
        json!({"kind": "promote", "stage": "no_such_stage"}),
    );
    assert!(
        load_campaign_preset(&vault, PRESET_JSON).is_err(),
        "a promote into an undeclared stage is refused"
    );
}

#[test]
fn the_owner_cannot_set_a_zero_bump() {
    let (_dir, vault) = open_vault();
    let proof = owner_proof(&vault);
    let outcome = set_owner(&vault, &proof, BUMP_KEY, json!(0));
    assert!(outcome.is_err(), "a zero bump is refused");
}
