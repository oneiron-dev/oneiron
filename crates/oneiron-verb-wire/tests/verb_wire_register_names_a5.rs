//! Register names (oneiron-verb-wire, wave A5): the names each hand table below wrote before its type
//! became a Register (Fable pass 25, register conversion wave part A). Generated from
//! `scripts/ratchet/hand_name_tables.py --names --only <file>` on the base, one table per
//! type. Green on the base (the hand tables) and on the adoption (`#[derive(Register)]`), so
//! no stored, sent or parsed name changed (M-1 keep). The serde test pins each name to the
//! one serde writes and reads.

use std::fmt::Debug;

use oneiron_verb_wire::memory::outbound::invite::CalendarInviteSurfaceMethod;
use oneiron_verb_wire::memory::query_records::definition::EvalMode;
use oneiron_verb_wire::memory::query_records::filter::ClaimComparison;
use oneiron_verb_wire::memory::result_facet::ResultFacet;
use oneiron_verb_wire::memory::witness::wake_outcome::UnpersistedWakeReason;
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

/// `CalendarInviteSurfaceMethod`: every row as its hand `as_str` table spelled it.
const CALENDAR_INVITE_SURFACE_METHOD: [(CalendarInviteSurfaceMethod, &str); 2] = [
    (CalendarInviteSurfaceMethod::Request, "REQUEST"),
    (CalendarInviteSurfaceMethod::Cancel, "CANCEL"),
];

#[test]
fn calendar_invite_surface_method_keeps_its_names() {
    for (row, name) in CALENDAR_INVITE_SURFACE_METHOD {
        assert_eq!(row.as_str(), name, "{row:?}");
        assert_eq!(
            CalendarInviteSurfaceMethod::parse(name),
            Some(row),
            "{name}"
        );
    }
    assert_eq!(CalendarInviteSurfaceMethod::parse("not_a_name"), None);
}

#[test]
fn calendar_invite_surface_method_names_are_serde_names() {
    serde_writes_and_reads(&CALENDAR_INVITE_SURFACE_METHOD);
}

/// `EvalMode`: every row as its hand `as_str` table spelled it.
const EVAL_MODE: [(EvalMode, &str); 3] = [
    (EvalMode::Reactive, "reactive"),
    (EvalMode::Wake, "wake"),
    (EvalMode::Manual, "manual"),
];

#[test]
fn eval_mode_keeps_its_names() {
    for (row, name) in EVAL_MODE {
        assert_eq!(row.as_str(), name, "{row:?}");
        assert_eq!(EvalMode::parse(name), Some(row), "{name}");
    }
    assert_eq!(EvalMode::parse("not_a_name"), None);
}

#[test]
fn eval_mode_names_are_serde_names() {
    serde_writes_and_reads(&EVAL_MODE);
}

/// `ClaimComparison`: every row as its hand `as_str` table spelled it.
const CLAIM_COMPARISON: [(ClaimComparison, &str); 8] = [
    (ClaimComparison::Exists, "exists"),
    (ClaimComparison::Eq, "eq"),
    (ClaimComparison::NotEq, "not_eq"),
    (ClaimComparison::Lt, "lt"),
    (ClaimComparison::Lte, "lte"),
    (ClaimComparison::Gt, "gt"),
    (ClaimComparison::Gte, "gte"),
    (ClaimComparison::Contains, "contains"),
];

#[test]
fn claim_comparison_keeps_its_names() {
    for (row, name) in CLAIM_COMPARISON {
        assert_eq!(row.as_str(), name, "{row:?}");
    }
}

#[test]
fn claim_comparison_names_are_serde_names() {
    serde_writes_and_reads(&CLAIM_COMPARISON);
}

/// `ResultFacet`: every row as its hand `as_str` table spelled it.
const RESULT_FACET: [(ResultFacet, &str); 4] = [
    (ResultFacet::Slice, "slice"),
    (ResultFacet::Search, "search"),
    (ResultFacet::Query, "query"),
    (ResultFacet::Chunks, "chunks"),
];

#[test]
fn result_facet_keeps_its_names() {
    for (row, name) in RESULT_FACET {
        assert_eq!(row.as_str(), name, "{row:?}");
    }
}

#[test]
fn result_facet_names_are_serde_names() {
    serde_writes_and_reads(&RESULT_FACET);
}

/// `UnpersistedWakeReason`: every row as its hand `as_str` table spelled it.
const UNPERSISTED_WAKE_REASON: [(UnpersistedWakeReason, &str); 2] = [
    (UnpersistedWakeReason::NoAuthority, "no_authority"),
    (UnpersistedWakeReason::StorageFailure, "storage_failure"),
];

#[test]
fn unpersisted_wake_reason_keeps_its_names() {
    for (row, name) in UNPERSISTED_WAKE_REASON {
        assert_eq!(row.as_str(), name, "{row:?}");
    }
}

#[test]
fn unpersisted_wake_reason_names_are_serde_names() {
    serde_writes_and_reads(&UNPERSISTED_WAKE_REASON);
}
