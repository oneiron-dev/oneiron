//! Four reason and kind names, one line per row, generated from
//! `scripts/ratchet/hand_name_tables.py --names --only <file>` on the R0 head before these
//! enums became Registers (Fable pass 25, the register conversion wave), for:
//! - `crates/oneiron/src/blob_artifact/esign/delivery_settlement.rs`
//! - `crates/oneiron/src/counterparty_contact/types.rs`
//! - `crates/oneiron/src/deletion/safe_delete_reason.rs`
//! - `crates/oneiron/src/store/attempt_manifest.rs`
//!
//! Green on the hand tables and on the adoption (the derive), so no stored or sent name
//! changed (M-1 keep). The second test of each enum pins each name to serde's; where the
//! adoption rewrites a parser's body, a third reads every name back through it.

use oneiron::blob_artifact::esign::EsignDeliveryEndReason;
use oneiron::counterparty_contact::CounterpartyFirstTouch;
use oneiron::deletion::SafeDeleteReason;
use oneiron::store::attempt_manifest::ManifestKind;
use serde_json::Value;

/// Every `CounterpartyFirstTouch` row, as the hand `as_str` table spelled it.
const COUNTERPARTY_FIRST_TOUCH_ROWS: [(CounterpartyFirstTouch, &str); 3] = [
    (
        CounterpartyFirstTouch::UserIntroduction,
        "user_introduction",
    ),
    (CounterpartyFirstTouch::InboundFirst, "inbound_first"),
    (CounterpartyFirstTouch::Public, "public"),
];

#[test]
fn every_counterparty_first_touch_keeps_its_name() {
    assert_eq!(
        CounterpartyFirstTouch::UserIntroduction.as_str(),
        "user_introduction"
    );
    assert_eq!(
        CounterpartyFirstTouch::InboundFirst.as_str(),
        "inbound_first"
    );
    assert_eq!(CounterpartyFirstTouch::Public.as_str(), "public");
}

#[test]
fn every_counterparty_first_touch_name_is_its_serde_name() {
    for (row, name) in COUNTERPARTY_FIRST_TOUCH_ROWS {
        let written = serde_json::to_value(row).expect("a counterparty first touch serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
    }
}

#[test]
fn every_counterparty_first_touch_name_reads_back() {
    for (row, name) in COUNTERPARTY_FIRST_TOUCH_ROWS {
        assert_eq!(CounterpartyFirstTouch::parse(name), Some(row), "{name}");
    }
    assert_eq!(CounterpartyFirstTouch::parse("not-a-name"), None);
    assert_eq!(CounterpartyFirstTouch::parse(""), None);
}

/// Every `SafeDeleteReason` row, as the hand `as_str` table spelled it.
const SAFE_DELETE_REASON_ROWS: [(SafeDeleteReason, &str); 4] = [
    (SafeDeleteReason::UserDelete, "user_delete"),
    (SafeDeleteReason::UserHardDelete, "user_hard_delete"),
    (SafeDeleteReason::GdprDelete, "gdpr_delete"),
    (SafeDeleteReason::PolicyDelete, "policy_delete"),
];

#[test]
fn every_safe_delete_reason_keeps_its_name() {
    assert_eq!(SafeDeleteReason::UserDelete.as_str(), "user_delete");
    assert_eq!(
        SafeDeleteReason::UserHardDelete.as_str(),
        "user_hard_delete"
    );
    assert_eq!(SafeDeleteReason::GdprDelete.as_str(), "gdpr_delete");
    assert_eq!(SafeDeleteReason::PolicyDelete.as_str(), "policy_delete");
}

#[test]
fn every_safe_delete_reason_name_is_its_serde_name() {
    for (row, name) in SAFE_DELETE_REASON_ROWS {
        let written = serde_json::to_value(row).expect("a safe delete reason serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: SafeDeleteReason =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn every_safe_delete_reason_name_reads_back() {
    for (row, name) in SAFE_DELETE_REASON_ROWS {
        assert_eq!(SafeDeleteReason::parse(name), Some(row), "{name}");
    }
    assert_eq!(SafeDeleteReason::parse("not-a-name"), None);
    assert_eq!(SafeDeleteReason::parse(""), None);
}

/// Every `ManifestKind` row, as the hand `as_str` table spelled it.
const MANIFEST_KIND_ROWS: [(ManifestKind, &str); 4] = [
    (ManifestKind::SkillIndex, "skill_index"),
    (ManifestKind::Skill, "skill"),
    (ManifestKind::ActorClaim, "actor_claim"),
    (ManifestKind::WorkflowContextRow, "workflow_context_row"),
];

#[test]
fn every_manifest_kind_keeps_its_name() {
    assert_eq!(ManifestKind::SkillIndex.as_str(), "skill_index");
    assert_eq!(ManifestKind::Skill.as_str(), "skill");
    assert_eq!(ManifestKind::ActorClaim.as_str(), "actor_claim");
    assert_eq!(
        ManifestKind::WorkflowContextRow.as_str(),
        "workflow_context_row"
    );
}

#[test]
fn every_manifest_kind_name_is_its_serde_name() {
    for (row, name) in MANIFEST_KIND_ROWS {
        let written = serde_json::to_value(row).expect("a manifest kind serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: ManifestKind =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

/// Every `EsignDeliveryEndReason` row, as the hand `code` table spelled it.
const ESIGN_DELIVERY_END_REASON_ROWS: [(EsignDeliveryEndReason, &str); 2] = [
    (EsignDeliveryEndReason::DocumentEnded, "document_ended"),
    (EsignDeliveryEndReason::RecipientEnded, "recipient_ended"),
];

#[test]
fn every_esign_delivery_end_reason_keeps_its_name() {
    assert_eq!(
        EsignDeliveryEndReason::DocumentEnded.code(),
        "document_ended"
    );
    assert_eq!(
        EsignDeliveryEndReason::RecipientEnded.code(),
        "recipient_ended"
    );
}

#[test]
fn every_esign_delivery_end_reason_name_is_its_serde_name() {
    for (row, name) in ESIGN_DELIVERY_END_REASON_ROWS {
        let written = serde_json::to_value(row).expect("a esign delivery end reason serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: EsignDeliveryEndReason =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}
