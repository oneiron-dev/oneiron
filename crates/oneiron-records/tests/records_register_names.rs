//! Register names (oneiron-records, wave A1): the names each hand table below wrote before its type
//! became a Register (Fable pass 25, register conversion wave part A). Generated from
//! `scripts/ratchet/hand_name_tables.py --names --only <file>` on the base, one table per
//! type. Green on the base (the hand tables) and on the adoption (`#[derive(Register)]`), so
//! no stored, sent or parsed name changed (M-1 keep). The serde test pins each name to the
//! one serde writes and reads.

use std::fmt::Debug;

use oneiron_records::calendar::invite::payload::CalendarInviteMethod;
use oneiron_records::context_board::memories::MemorySlot;
use oneiron_records::context_board::self_brief::class_verdicts::BriefDefaultRule;
use oneiron_records::conversation::voice_roster::VoicePrintCalibration;
use oneiron_records::genui::consent_cards::BundleApprovalScope;
use oneiron_records::genui::consent_cards::ConsentScopeEscalator;
use oneiron_records::genui::consent_eval::ConsentSurface;
use oneiron_records::genui::protocol::Of336ComponentKind;
use oneiron_records::genui::receipt_view::ViewTimeResolution;
use oneiron_records::secret_custody::pending_restore::PendingCredentialResult;
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

/// Serde writes every row as its name (the type has no Deserialize).
fn serde_writes<T: Copy + Debug + Serialize>(rows: &[(T, &str)]) {
    for &(row, name) in rows {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
    }
}

/// `CalendarInviteMethod`: every row as its hand `as_str` table spelled it.
const CALENDAR_INVITE_METHOD: [(CalendarInviteMethod, &str); 2] = [
    (CalendarInviteMethod::Request, "REQUEST"),
    (CalendarInviteMethod::Cancel, "CANCEL"),
];

#[test]
fn calendar_invite_method_keeps_its_names() {
    for (row, name) in CALENDAR_INVITE_METHOD {
        assert_eq!(row.as_str(), name, "{row:?}");
        assert_eq!(CalendarInviteMethod::parse(name), Some(row), "{name}");
    }
    assert_eq!(CalendarInviteMethod::parse("not_a_name"), None);
}

#[test]
fn calendar_invite_method_names_are_serde_names() {
    serde_writes_and_reads(&CALENDAR_INVITE_METHOD);
}

/// `MemorySlot`: every row as its hand `as_str` table spelled it.
const MEMORY_SLOT: [(MemorySlot, &str); 5] = [
    (MemorySlot::Claims, "claims"),
    (MemorySlot::Turns, "turns"),
    (MemorySlot::Summaries, "summaries"),
    (MemorySlot::Facets, "facets"),
    (MemorySlot::Other, "other"),
];

#[test]
fn memory_slot_keeps_its_names() {
    for (row, name) in MEMORY_SLOT {
        assert_eq!(row.as_str(), name, "{row:?}");
    }
}

#[test]
fn memory_slot_names_are_serde_names() {
    serde_writes_and_reads(&MEMORY_SLOT);
}

/// `BriefDefaultRule`: every row as its hand `as_str` table spelled it.
const BRIEF_DEFAULT_RULE: [(BriefDefaultRule, &str); 3] = [
    (
        BriefDefaultRule::ReversibleVaultEffect,
        "reversible_vault_effect",
    ),
    (
        BriefDefaultRule::DestructiveOutboundOrCritical,
        "destructive_outbound_or_critical",
    ),
    (BriefDefaultRule::CatastropheFloor, "catastrophe_floor"),
];

#[test]
fn brief_default_rule_keeps_its_names() {
    for (row, name) in BRIEF_DEFAULT_RULE {
        assert_eq!(row.as_str(), name, "{row:?}");
    }
}

#[test]
fn brief_default_rule_names_are_serde_names() {
    serde_writes(&BRIEF_DEFAULT_RULE);
}

/// `VoicePrintCalibration`: every row as its hand `as_str` table spelled it.
const VOICE_PRINT_CALIBRATION: [(VoicePrintCalibration, &str); 2] = [
    (VoicePrintCalibration::Collecting, "collecting"),
    (VoicePrintCalibration::Calibrated, "calibrated"),
];

#[test]
fn voice_print_calibration_keeps_its_names() {
    for (row, name) in VOICE_PRINT_CALIBRATION {
        assert_eq!(row.as_str(), name, "{row:?}");
        assert_eq!(VoicePrintCalibration::parse(name), Some(row), "{name}");
    }
    assert_eq!(VoicePrintCalibration::parse("not_a_name"), None);
}

#[test]
fn voice_print_calibration_names_are_serde_names() {
    serde_writes_and_reads(&VOICE_PRINT_CALIBRATION);
}

/// `ConsentScopeEscalator`: every row as its hand `as_str` table spelled it.
const CONSENT_SCOPE_ESCALATOR: [(ConsentScopeEscalator, &str); 4] = [
    (ConsentScopeEscalator::JustOnce, "just_once"),
    (
        ConsentScopeEscalator::AlwaysThisContact,
        "always_this_contact",
    ),
    (
        ConsentScopeEscalator::AlwaysThisVerbClass,
        "always_this_verb_class",
    ),
    (
        ConsentScopeEscalator::AlwaysThisChannel,
        "always_this_channel",
    ),
];

#[test]
fn consent_scope_escalator_keeps_its_names() {
    for (row, name) in CONSENT_SCOPE_ESCALATOR {
        assert_eq!(row.as_str(), name, "{row:?}");
    }
}

#[test]
fn consent_scope_escalator_names_are_serde_names() {
    serde_writes_and_reads(&CONSENT_SCOPE_ESCALATOR);
}

/// `BundleApprovalScope`: every row as its hand `as_str` table spelled it.
const BUNDLE_APPROVAL_SCOPE: [(BundleApprovalScope, &str); 2] = [
    (
        BundleApprovalScope::ExactEnumeratedSends,
        "exact_enumerated_sends",
    ),
    (BundleApprovalScope::BriefVerbClass, "brief_verb_class"),
];

#[test]
fn bundle_approval_scope_keeps_its_names() {
    for (row, name) in BUNDLE_APPROVAL_SCOPE {
        assert_eq!(row.as_str(), name, "{row:?}");
    }
}

#[test]
fn bundle_approval_scope_names_are_serde_names() {
    serde_writes_and_reads(&BUNDLE_APPROVAL_SCOPE);
}

/// `ConsentSurface`: every row as its hand `as_str` table spelled it.
const CONSENT_SURFACE: [(ConsentSurface, &str); 5] = [
    (
        ConsentSurface::CompanionConversation,
        "companion_conversation",
    ),
    (ConsentSurface::Dashboard, "dashboard"),
    (ConsentSurface::SharedSlack, "shared_slack"),
    (ConsentSurface::McpUi, "mcp_ui"),
    (ConsentSurface::Voice, "voice"),
];

#[test]
fn consent_surface_keeps_its_names() {
    for (row, name) in CONSENT_SURFACE {
        assert_eq!(row.as_str(), name, "{row:?}");
    }
}

#[test]
fn consent_surface_names_are_serde_names() {
    serde_writes_and_reads(&CONSENT_SURFACE);
}

/// `Of336ComponentKind`: every row as its hand `as_str` table spelled it.
const OF336_COMPONENT_KIND: [(Of336ComponentKind, &str); 4] = [
    (Of336ComponentKind::ReceiptView, "receipt_view"),
    (Of336ComponentKind::ConsentAsk, "consent_ask"),
    (Of336ComponentKind::BundleApprove, "bundle_approve"),
    (Of336ComponentKind::ProjectProposal, "project_proposal"),
];

#[test]
fn of336_component_kind_keeps_its_names() {
    for (row, name) in OF336_COMPONENT_KIND {
        assert_eq!(row.as_str(), name, "{row:?}");
    }
}

#[test]
fn of336_component_kind_names_are_serde_names() {
    serde_writes_and_reads(&OF336_COMPONENT_KIND);
}

/// `ViewTimeResolution`: every row as its hand `as_str` table spelled it.
const VIEW_TIME_RESOLUTION: [(ViewTimeResolution, &str); 3] = [
    (ViewTimeResolution::Active, "active"),
    (ViewTimeResolution::Revoked, "revoked"),
    (ViewTimeResolution::Unavailable, "unavailable"),
];

#[test]
fn view_time_resolution_keeps_its_names() {
    for (row, name) in VIEW_TIME_RESOLUTION {
        assert_eq!(row.as_str(), name, "{row:?}");
    }
}

#[test]
fn view_time_resolution_names_are_serde_names() {
    serde_writes_and_reads(&VIEW_TIME_RESOLUTION);
}

/// `PendingCredentialResult`: every row as its hand `as_str` table spelled it.
const PENDING_CREDENTIAL_RESULT: [(PendingCredentialResult, &str); 5] = [
    (PendingCredentialResult::Readable, "readable"),
    (
        PendingCredentialResult::StillUnavailable,
        "still_unavailable",
    ),
    (PendingCredentialResult::Erased, "erased"),
    (PendingCredentialResult::Superseded, "superseded"),
    (PendingCredentialResult::Pending, "pending"),
];

#[test]
fn pending_credential_result_keeps_its_names() {
    for (row, name) in PENDING_CREDENTIAL_RESULT {
        assert_eq!(row.as_str(), name, "{row:?}");
    }
}

#[test]
fn pending_credential_result_names_are_serde_names() {
    serde_writes_and_reads(&PENDING_CREDENTIAL_RESULT);
}
