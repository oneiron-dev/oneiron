//! The names of 7 name lists in `oneiron-authority`, one line per row, generated from
//! `scripts/ratchet/hand_name_tables.py --names --only <file>` before each list became a Register
//! (Fable pass 25, the Register wave): the names each hand table wrote. Green on the hand tables and
//! on the derive, so no stored or sent name changed (M-1 keep). Each name is also pinned to the one
//! serde reads and writes, and each kept reverse fn to its rows.
//!
//! - `crates/oneiron-authority/src/channel_identity_manifest.rs`
//! - `crates/oneiron-authority/src/channel_identity_shape.rs`
//! - `crates/oneiron-authority/src/channel_selection_vocabulary.rs`
//! - `crates/oneiron-authority/src/federation/scope.rs`
//! - `crates/oneiron-authority/src/share_travel.rs`

use oneiron_authority::channel_identity_manifest::ChannelIdentityPolicyRisk;
use oneiron_authority::channel_identity_shape::ChannelIdentityShape;
use oneiron_authority::channel_selection_vocabulary::ChannelIdentityFace;
use oneiron_authority::channel_selection_vocabulary::RelationshipContext;
use oneiron_authority::channel_selection_vocabulary::SelectionRuleWriterKind;
use oneiron_authority::federation::Sensitivity;
use oneiron_authority::share_travel::BornWithField;
use serde_json::Value;

/// Every row of `ChannelIdentityPolicyRisk`, as its hand table spelled it.
const CHANNEL_IDENTITY_POLICY_RISK_ROWS: [(ChannelIdentityPolicyRisk, &str); 2] = [
    (ChannelIdentityPolicyRisk::Normal, "normal"),
    (
        ChannelIdentityPolicyRisk::HoldToProposal,
        "hold_to_proposal",
    ),
];

#[test]
fn every_channel_identity_policy_risk_keeps_its_name() {
    assert_eq!(
        ChannelIdentityPolicyRisk::Normal.as_gate_scope_value(),
        "normal"
    );
    assert_eq!(
        ChannelIdentityPolicyRisk::HoldToProposal.as_gate_scope_value(),
        "hold_to_proposal"
    );
}

#[test]
fn every_channel_identity_policy_risk_name_is_its_serde_name() {
    for (row, name) in CHANNEL_IDENTITY_POLICY_RISK_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: ChannelIdentityPolicyRisk =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

/// Every row of `ChannelIdentityShape`, as its hand table spelled it.
const CHANNEL_IDENTITY_SHAPE_ROWS: [(ChannelIdentityShape, &str); 4] = [
    (ChannelIdentityShape::DedicatedAddress, "dedicated_address"),
    (ChannelIdentityShape::DedicatedHandle, "dedicated_handle"),
    (ChannelIdentityShape::SharedPresence, "shared_presence"),
    (ChannelIdentityShape::DelegatedGrant, "delegated_grant"),
];

#[test]
fn every_channel_identity_shape_keeps_its_name() {
    assert_eq!(
        ChannelIdentityShape::DedicatedAddress.as_str(),
        "dedicated_address"
    );
    assert_eq!(
        ChannelIdentityShape::DedicatedHandle.as_str(),
        "dedicated_handle"
    );
    assert_eq!(
        ChannelIdentityShape::SharedPresence.as_str(),
        "shared_presence"
    );
    assert_eq!(
        ChannelIdentityShape::DelegatedGrant.as_str(),
        "delegated_grant"
    );
}

#[test]
fn every_channel_identity_shape_name_is_its_serde_name() {
    for (row, name) in CHANNEL_IDENTITY_SHAPE_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: ChannelIdentityShape =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn channel_identity_shape_parse_reads_each_name_back() {
    for (row, name) in CHANNEL_IDENTITY_SHAPE_ROWS {
        assert_eq!(ChannelIdentityShape::parse(name), Some(row), "{name}");
    }
    assert_eq!(ChannelIdentityShape::parse("not.a.row"), None);
}

/// Every row of `RelationshipContext`, as its hand table spelled it.
const RELATIONSHIP_CONTEXT_ROWS: [(RelationshipContext, &str); 6] = [
    (RelationshipContext::WorkDeal, "work_deal"),
    (
        RelationshipContext::SchedulingLogistics,
        "scheduling_logistics",
    ),
    (RelationshipContext::CampaignOutreach, "campaign_outreach"),
    (
        RelationshipContext::TransactionalSystem,
        "transactional_system",
    ),
    (RelationshipContext::PersonalFriends, "personal_friends"),
    (RelationshipContext::GroupSpace, "group_space"),
];

#[test]
fn every_relationship_context_keeps_its_name() {
    assert_eq!(RelationshipContext::WorkDeal.as_str(), "work_deal");
    assert_eq!(
        RelationshipContext::SchedulingLogistics.as_str(),
        "scheduling_logistics"
    );
    assert_eq!(
        RelationshipContext::CampaignOutreach.as_str(),
        "campaign_outreach"
    );
    assert_eq!(
        RelationshipContext::TransactionalSystem.as_str(),
        "transactional_system"
    );
    assert_eq!(
        RelationshipContext::PersonalFriends.as_str(),
        "personal_friends"
    );
    assert_eq!(RelationshipContext::GroupSpace.as_str(), "group_space");
}

#[test]
fn every_relationship_context_name_is_its_serde_name() {
    for (row, name) in RELATIONSHIP_CONTEXT_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: RelationshipContext =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn relationship_context_parse_reads_each_name_back() {
    for (row, name) in RELATIONSHIP_CONTEXT_ROWS {
        assert_eq!(RelationshipContext::parse(name), Some(row), "{name}");
    }
    assert_eq!(RelationshipContext::parse("not.a.row"), None);
}

/// Every row of `ChannelIdentityFace`, as its hand table spelled it.
const CHANNEL_IDENTITY_FACE_ROWS: [(ChannelIdentityFace, &str); 6] = [
    (
        ChannelIdentityFace::DelegatedOwnerAccount,
        "delegated_owner_account",
    ),
    (
        ChannelIdentityFace::AgentNamedAddress,
        "agent_named_address",
    ),
    (
        ChannelIdentityFace::SideDomainAddress,
        "side_domain_address",
    ),
    (ChannelIdentityFace::HouseIdentity, "house_identity"),
    (ChannelIdentityFace::CompanionIdentity, "companion_identity"),
    (
        ChannelIdentityFace::NamedGroupParticipant,
        "named_group_participant",
    ),
];

#[test]
fn every_channel_identity_face_keeps_its_name() {
    assert_eq!(
        ChannelIdentityFace::DelegatedOwnerAccount.as_str(),
        "delegated_owner_account"
    );
    assert_eq!(
        ChannelIdentityFace::AgentNamedAddress.as_str(),
        "agent_named_address"
    );
    assert_eq!(
        ChannelIdentityFace::SideDomainAddress.as_str(),
        "side_domain_address"
    );
    assert_eq!(
        ChannelIdentityFace::HouseIdentity.as_str(),
        "house_identity"
    );
    assert_eq!(
        ChannelIdentityFace::CompanionIdentity.as_str(),
        "companion_identity"
    );
    assert_eq!(
        ChannelIdentityFace::NamedGroupParticipant.as_str(),
        "named_group_participant"
    );
}

#[test]
fn every_channel_identity_face_name_is_its_serde_name() {
    for (row, name) in CHANNEL_IDENTITY_FACE_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: ChannelIdentityFace =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn channel_identity_face_parse_reads_each_name_back() {
    for (row, name) in CHANNEL_IDENTITY_FACE_ROWS {
        assert_eq!(ChannelIdentityFace::parse(name), Some(row), "{name}");
    }
    assert_eq!(ChannelIdentityFace::parse("not.a.row"), None);
}

/// Every row of `SelectionRuleWriterKind`, as its hand table spelled it.
const SELECTION_RULE_WRITER_KIND_ROWS: [(SelectionRuleWriterKind, &str); 3] = [
    (SelectionRuleWriterKind::SystemDefault, "system_default"),
    (SelectionRuleWriterKind::Owner, "owner"),
    (SelectionRuleWriterKind::Agent, "agent"),
];

#[test]
fn every_selection_rule_writer_kind_keeps_its_name() {
    assert_eq!(
        SelectionRuleWriterKind::SystemDefault.as_str(),
        "system_default"
    );
    assert_eq!(SelectionRuleWriterKind::Owner.as_str(), "owner");
    assert_eq!(SelectionRuleWriterKind::Agent.as_str(), "agent");
}

#[test]
fn every_selection_rule_writer_kind_name_is_its_serde_name() {
    for (row, name) in SELECTION_RULE_WRITER_KIND_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: SelectionRuleWriterKind =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn selection_rule_writer_kind_parse_reads_each_name_back() {
    for (row, name) in SELECTION_RULE_WRITER_KIND_ROWS {
        assert_eq!(SelectionRuleWriterKind::parse(name), Some(row), "{name}");
    }
    assert_eq!(SelectionRuleWriterKind::parse("not.a.row"), None);
}

/// Every row of `Sensitivity`, as its hand table spelled it.
const SENSITIVITY_ROWS: [(Sensitivity, &str); 4] = [
    (Sensitivity::Public, "public"),
    (Sensitivity::Private, "private"),
    (Sensitivity::Sensitive, "sensitive"),
    (Sensitivity::Restricted, "restricted"),
];

#[test]
fn every_sensitivity_keeps_its_name() {
    assert_eq!(Sensitivity::Public.as_str(), "public");
    assert_eq!(Sensitivity::Private.as_str(), "private");
    assert_eq!(Sensitivity::Sensitive.as_str(), "sensitive");
    assert_eq!(Sensitivity::Restricted.as_str(), "restricted");
}

#[test]
fn every_sensitivity_name_is_its_serde_name() {
    for (row, name) in SENSITIVITY_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: Sensitivity =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn sensitivity_parse_reads_each_name_back() {
    for (row, name) in SENSITIVITY_ROWS {
        assert_eq!(Sensitivity::parse(name), Some(row), "{name}");
    }
    assert_eq!(Sensitivity::parse("not.a.row"), None);
}

/// Every row of `BornWithField`, as its hand table spelled it.
const BORN_WITH_FIELD_ROWS: [(BornWithField, &str); 4] = [
    (BornWithField::Prompt, "prompt"),
    (BornWithField::Why, "why"),
    (BornWithField::Keep, "keep"),
    (BornWithField::IntentPrompt, "intent_prompt"),
];

#[test]
fn every_born_with_field_keeps_its_name() {
    assert_eq!(BornWithField::Prompt.as_str(), "prompt");
    assert_eq!(BornWithField::Why.as_str(), "why");
    assert_eq!(BornWithField::Keep.as_str(), "keep");
    assert_eq!(BornWithField::IntentPrompt.as_str(), "intent_prompt");
}

#[test]
fn every_born_with_field_name_is_its_serde_name() {
    for (row, name) in BORN_WITH_FIELD_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: BornWithField =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn born_with_field_from_name_reads_each_name_back() {
    for (row, name) in BORN_WITH_FIELD_ROWS {
        assert_eq!(BornWithField::from_name(name), Some(row), "{name}");
    }
    assert_eq!(BornWithField::from_name("not.a.row"), None);
}
