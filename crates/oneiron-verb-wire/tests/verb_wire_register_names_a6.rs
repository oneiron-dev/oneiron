//! Register names (oneiron-verb-wire, wave A6): the names each hand table below wrote before its type
//! became a Register (Fable pass 25, register conversion wave part A). Generated from
//! `scripts/ratchet/hand_name_tables.py --names --only <file>` on the base, one table per
//! type. Green on the base (the hand tables) and on the adoption (`#[derive(Register)]`), so
//! no stored, sent or parsed name changed (M-1 keep). The serde test pins each name to the
//! one serde writes and reads.

use std::fmt::Debug;

use oneiron_verb_wire::policy_model::request::PolicyClassifySubject;
use oneiron_verb_wire::runtime_hooks::lineage::HookCheckReason;
use oneiron_verb_wire::skill_hub::install_transition::InstallLifecycle;
use oneiron_verb_wire::skill_hub::pack_catalog::setup::PackSetupAuth;
use oneiron_verb_wire::skill_hub::pack_catalog::setup::PackSetupRisk;
use oneiron_verb_wire::store::agent_refusal::RefusalLevel;
use oneiron_verb_wire::sync::quarantine::keys_classifier::QuarantineContainer;
use oneiron_verb_wire::team::pattern::TeamPattern;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

/// Serde writes every row as its name and reads the name back as the row.
fn serde_writes_and_reads<T: Copy + PartialEq + Debug + Serialize + DeserializeOwned>(
    rows: &[(T, &str)],
) {
    for &(row, name) in rows {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: T =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

/// `PolicyClassifySubject`: every row as its hand `as_str` table spelled it.
const POLICY_CLASSIFY_SUBJECT: [(PolicyClassifySubject, &str); 2] = [
    (PolicyClassifySubject::OutboundContent, "outbound_content"),
    (PolicyClassifySubject::Action, "action"),
];

#[test]
fn policy_classify_subject_keeps_its_names() {
    for (row, name) in POLICY_CLASSIFY_SUBJECT {
        assert_eq!(row.as_str(), name, "{row:?}");
    }
}

#[test]
fn policy_classify_subject_names_are_serde_names() {
    serde_writes_and_reads(&POLICY_CLASSIFY_SUBJECT);
}

/// `HookCheckReason`: every row as its hand `as_str` table spelled it.
const HOOK_CHECK_REASON: [(HookCheckReason, &str); 2] = [
    (HookCheckReason::Cycle, "cycle"),
    (HookCheckReason::Depth, "depth"),
];

#[test]
fn hook_check_reason_keeps_its_names() {
    for (row, name) in HOOK_CHECK_REASON {
        assert_eq!(row.as_str(), name, "{row:?}");
    }
}

#[test]
fn hook_check_reason_names_are_serde_names() {
    serde_writes_and_reads(&HOOK_CHECK_REASON);
}

/// `InstallLifecycle`: every row as its hand `as_str` table spelled it.
const INSTALL_LIFECYCLE: [(InstallLifecycle, &str); 5] = [
    (InstallLifecycle::Candidate, "candidate"),
    (InstallLifecycle::Active, "active"),
    (InstallLifecycle::Stale, "stale"),
    (InstallLifecycle::Quarantined, "quarantined"),
    (InstallLifecycle::Superseded, "superseded"),
];

#[test]
fn install_lifecycle_keeps_its_names() {
    for (row, name) in INSTALL_LIFECYCLE {
        assert_eq!(row.as_str(), name, "{row:?}");
    }
}

#[test]
fn install_lifecycle_names_are_serde_names() {
    serde_writes_and_reads(&INSTALL_LIFECYCLE);
}

/// `PackSetupAuth`: every row as its hand `as_str` table spelled it.
const PACK_SETUP_AUTH: [(PackSetupAuth, &str); 7] = [
    (PackSetupAuth::Oauth, "oauth"),
    (PackSetupAuth::ApiKey, "api_key"),
    (PackSetupAuth::BotToken, "bot_token"),
    (PackSetupAuth::AppPassword, "app_password"),
    (PackSetupAuth::Session, "session"),
    (PackSetupAuth::Webhook, "webhook"),
    (PackSetupAuth::Local, "local"),
];

#[test]
fn pack_setup_auth_keeps_its_names() {
    for (row, name) in PACK_SETUP_AUTH {
        assert_eq!(row.as_str(), name, "{row:?}");
    }
}

#[test]
fn pack_setup_auth_names_are_serde_names() {
    serde_writes_and_reads(&PACK_SETUP_AUTH);
}

/// `PackSetupRisk`: every row as its hand `as_str` table spelled it.
const PACK_SETUP_RISK: [(PackSetupRisk, &str); 3] = [
    (PackSetupRisk::Low, "low"),
    (PackSetupRisk::Medium, "medium"),
    (PackSetupRisk::High, "high"),
];

#[test]
fn pack_setup_risk_keeps_its_names() {
    for (row, name) in PACK_SETUP_RISK {
        assert_eq!(row.as_str(), name, "{row:?}");
    }
}

#[test]
fn pack_setup_risk_names_are_serde_names() {
    serde_writes_and_reads(&PACK_SETUP_RISK);
}

/// `RefusalLevel`: every row as its hand `as_str` table spelled it.
const REFUSAL_LEVEL: [(RefusalLevel, &str); 4] = [
    (RefusalLevel::None, "none"),
    (RefusalLevel::Voice, "voice"),
    (RefusalLevel::Veto, "veto"),
    (RefusalLevel::Full, "full"),
];

#[test]
fn refusal_level_keeps_its_names() {
    for (row, name) in REFUSAL_LEVEL {
        assert_eq!(row.as_str(), name, "{row:?}");
        assert_eq!(RefusalLevel::parse(name), Some(row), "{name}");
    }
    assert_eq!(RefusalLevel::parse("not_a_name"), None);
}

#[test]
fn refusal_level_names_are_serde_names() {
    serde_writes_and_reads(&REFUSAL_LEVEL);
}

/// `QuarantineContainer`: every row as its hand `as_str` table spelled it.
const QUARANTINE_CONTAINER: [(QuarantineContainer, &str); 6] = [
    (QuarantineContainer::Entities, "entities"),
    (QuarantineContainer::Edges, "edges"),
    (QuarantineContainer::Tombstones, "tombstones"),
    (QuarantineContainer::Leases, "leases"),
    (QuarantineContainer::OfficeProposals, "office_proposals"),
    (QuarantineContainer::TypedBodyRows, "typed_body_rows"),
];

#[test]
fn quarantine_container_keeps_its_names() {
    for (row, name) in QUARANTINE_CONTAINER {
        assert_eq!(row.as_str(), name, "{row:?}");
    }
}

#[test]
fn quarantine_container_names_are_serde_names() {
    serde_writes_and_reads(&QUARANTINE_CONTAINER);
}

/// `TeamPattern`: every row as its hand `as_str` table spelled it.
const TEAM_PATTERN: [(TeamPattern, &str); 6] = [
    (TeamPattern::CeoDecides, "ceo_decides"),
    (TeamPattern::Committee, "committee"),
    (TeamPattern::Vote, "vote"),
    (TeamPattern::Market, "market"),
    (TeamPattern::Rotation, "rotation"),
    (TeamPattern::Solo, "solo"),
];

#[test]
fn team_pattern_keeps_its_names() {
    for (row, name) in TEAM_PATTERN {
        assert_eq!(row.as_str(), name, "{row:?}");
    }
}

#[test]
fn team_pattern_names_are_serde_names() {
    serde_writes_and_reads(&TEAM_PATTERN);
}
