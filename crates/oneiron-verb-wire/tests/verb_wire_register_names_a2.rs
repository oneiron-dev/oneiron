//! Register names (oneiron-verb-wire, wave A2): the names each hand table below wrote before its type
//! became a Register (Fable pass 25, register conversion wave part A). Generated from
//! `scripts/ratchet/hand_name_tables.py --names --only <file>` on the base, one table per
//! type. Green on the base (the hand tables) and on the adoption (`#[derive(Register)]`), so
//! no stored, sent or parsed name changed (M-1 keep). The serde test pins each name to the
//! one serde writes and reads.

use std::fmt::Debug;

use oneiron_verb_wire::agent_dispatch::planner::PlannerRung;
use oneiron_verb_wire::authority::agent_tier::AgentTier;
use oneiron_verb_wire::authority::support_grant::SupportHolderClass;
use oneiron_verb_wire::batch::secret_scan::lift_history::LiftCause;
use oneiron_verb_wire::batch::secret_scan::lift_history::LiftCloseReason;
use oneiron_verb_wire::blob_artifact::esign::delivery_capability::EsignDeliveryWait;
use oneiron_verb_wire::blob_artifact::family::ArtifactKind;
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

/// `PlannerRung`: every row as its hand `as_str` table spelled it.
const PLANNER_RUNG: [(PlannerRung, &str); 3] = [
    (PlannerRung::CheapClassifier, "cheap_classifier"),
    (PlannerRung::SmallThinking, "small_thinking"),
    (PlannerRung::Strong, "strong"),
];

#[test]
fn planner_rung_keeps_its_names() {
    for (row, name) in PLANNER_RUNG {
        assert_eq!(row.as_str(), name, "{row:?}");
    }
}

#[test]
fn planner_rung_names_are_serde_names() {
    serde_writes_and_reads(&PLANNER_RUNG);
}

/// `AgentTier`: every row as its hand `wire_name` table spelled it.
const AGENT_TIER: [(AgentTier, &str); 3] = [
    (AgentTier::ReadOnly, "read"),
    (AgentTier::ProposeOnly, "propose"),
    (AgentTier::FullAccess, "full"),
];

#[test]
fn agent_tier_keeps_its_names() {
    for (row, name) in AGENT_TIER {
        assert_eq!(row.wire_name(), name, "{row:?}");
    }
}

#[test]
fn agent_tier_names_are_serde_names() {
    serde_writes_and_reads(&AGENT_TIER);
}

/// `SupportHolderClass`: every row as its hand `as_str` table spelled it.
const SUPPORT_HOLDER_CLASS: [(SupportHolderClass, &str); 2] = [
    (SupportHolderClass::Human, "human"),
    (SupportHolderClass::Agent, "agent"),
];

#[test]
fn support_holder_class_keeps_its_names() {
    for (row, name) in SUPPORT_HOLDER_CLASS {
        assert_eq!(row.as_str(), name, "{row:?}");
    }
}

#[test]
fn support_holder_class_names_are_serde_names() {
    serde_writes_and_reads(&SUPPORT_HOLDER_CLASS);
}

/// `LiftCause`: every row as its hand `code` table spelled it.
const LIFT_CAUSE: [(LiftCause, &str); 6] = [
    (LiftCause::Unplaceable, "unplaceable"),
    (LiftCause::Immutable, "immutable"),
    (LiftCause::Held, "held"),
    (LiftCause::File, "file"),
    (LiftCause::NoDoor, "no_door"),
    (LiftCause::History, "history"),
];

#[test]
fn lift_cause_keeps_its_names() {
    for (row, name) in LIFT_CAUSE {
        assert_eq!(row.code(), name, "{row:?}");
    }
}

#[test]
fn lift_cause_names_are_serde_names() {
    serde_writes_and_reads(&LIFT_CAUSE);
}

/// `LiftCloseReason`: every row as its hand `code` table spelled it.
const LIFT_CLOSE_REASON: [(LiftCloseReason, &str); 6] = [
    (LiftCloseReason::NotASecret, "not_a_secret"),
    (LiftCloseReason::Rotated, "rotated"),
    (LiftCloseReason::Accepted, "accepted"),
    (LiftCloseReason::ReadClean, "read_clean"),
    (LiftCloseReason::Answered, "answered"),
    (LiftCloseReason::Deleted, "deleted"),
];

#[test]
fn lift_close_reason_keeps_its_names() {
    for (row, name) in LIFT_CLOSE_REASON {
        assert_eq!(row.code(), name, "{row:?}");
    }
}

#[test]
fn lift_close_reason_names_are_serde_names() {
    serde_writes_and_reads(&LIFT_CLOSE_REASON);
}

/// `EsignDeliveryWait`: every row as its hand `code` table spelled it.
const ESIGN_DELIVERY_WAIT: [(EsignDeliveryWait, &str); 5] = [
    (
        EsignDeliveryWait::DocumentAwaitsOwner,
        "document_awaits_owner",
    ),
    (EsignDeliveryWait::DocumentUnreadable, "document_unreadable"),
    (EsignDeliveryWait::NoticeUnreadable, "notice_unreadable"),
    (EsignDeliveryWait::SendUnreadable, "send_unreadable"),
    (EsignDeliveryWait::LinksUnreadable, "links_unreadable"),
];

#[test]
fn esign_delivery_wait_keeps_its_names() {
    for (row, name) in ESIGN_DELIVERY_WAIT {
        assert_eq!(row.code(), name, "{row:?}");
    }
}

#[test]
fn esign_delivery_wait_names_are_serde_names() {
    serde_writes_and_reads(&ESIGN_DELIVERY_WAIT);
}

/// `ArtifactKind`: every row as its hand `as_str` table spelled it.
const ARTIFACT_KIND: [(ArtifactKind, &str); 7] = [
    (ArtifactKind::Document, "document"),
    (ArtifactKind::Sheet, "sheet"),
    (ArtifactKind::Deck, "deck"),
    (ArtifactKind::Code, "code"),
    (ArtifactKind::Canvas, "canvas"),
    (ArtifactKind::Image, "image"),
    (ArtifactKind::File, "file"),
];

#[test]
fn artifact_kind_keeps_its_names() {
    for (row, name) in ARTIFACT_KIND {
        assert_eq!(row.as_str(), name, "{row:?}");
    }
}

#[test]
fn artifact_kind_names_are_serde_names() {
    serde_writes_and_reads(&ARTIFACT_KIND);
}
