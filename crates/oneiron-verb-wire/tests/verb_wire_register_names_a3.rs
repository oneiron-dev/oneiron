//! Register names (oneiron-verb-wire, wave A3): the names each hand table below wrote before its type
//! became a Register (Fable pass 25, register conversion wave part A). Generated from
//! `scripts/ratchet/hand_name_tables.py --names --only <file>` on the base, one table per
//! type. Green on the base (the hand tables) and on the adoption (`#[derive(Register)]`), so
//! no stored, sent or parsed name changed (M-1 keep). The serde test pins each name to the
//! one serde writes and reads.

use std::fmt::Debug;

use oneiron_verb_wire::calendar::claims::values::CalendarPassportDirection;
use oneiron_verb_wire::calendar::claims::values::CalendarPassportPresence;
use oneiron_verb_wire::claim::scoped_read::weave_report::WeaveSectionKind;
use oneiron_verb_wire::code_run::blocked::BlockedCategory;
use oneiron_verb_wire::compaction::fold_kinds::FoldKind;
use oneiron_verb_wire::context_board::agent_run_status::AgentRunStatus;
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

/// `CalendarPassportDirection`: every row as its hand `as_str` table spelled it.
const CALENDAR_PASSPORT_DIRECTION: [(CalendarPassportDirection, &str); 3] = [
    (CalendarPassportDirection::Inbound, "inbound"),
    (CalendarPassportDirection::Outbound, "outbound"),
    (CalendarPassportDirection::TwoWay, "two_way"),
];

#[test]
fn calendar_passport_direction_keeps_its_names() {
    for (row, name) in CALENDAR_PASSPORT_DIRECTION {
        assert_eq!(row.as_str(), name, "{row:?}");
        assert_eq!(CalendarPassportDirection::parse(name), Some(row), "{name}");
    }
    assert_eq!(CalendarPassportDirection::parse("not_a_name"), None);
}

#[test]
fn calendar_passport_direction_names_are_serde_names() {
    serde_writes_and_reads(&CALENDAR_PASSPORT_DIRECTION);
}

/// `CalendarPassportPresence`: every row as its hand `as_str` table spelled it.
const CALENDAR_PASSPORT_PRESENCE: [(CalendarPassportPresence, &str); 2] = [
    (CalendarPassportPresence::Live, "live"),
    (CalendarPassportPresence::Absent, "absent"),
];

#[test]
fn calendar_passport_presence_keeps_its_names() {
    for (row, name) in CALENDAR_PASSPORT_PRESENCE {
        assert_eq!(row.as_str(), name, "{row:?}");
        assert_eq!(CalendarPassportPresence::parse(name), Some(row), "{name}");
    }
    assert_eq!(CalendarPassportPresence::parse("not_a_name"), None);
}

#[test]
fn calendar_passport_presence_names_are_serde_names() {
    serde_writes_and_reads(&CALENDAR_PASSPORT_PRESENCE);
}

/// `WeaveSectionKind`: every row as its hand `policy_name` table spelled it.
const WEAVE_SECTION_KIND: [(WeaveSectionKind, &str); 10] = [
    (WeaveSectionKind::Changes, "changes"),
    (WeaveSectionKind::Projects, "projects"),
    (WeaveSectionKind::OpenAsks, "open_asks"),
    (WeaveSectionKind::Links, "links"),
    (WeaveSectionKind::Conflicts, "conflicts"),
    (WeaveSectionKind::Exceptions, "exceptions"),
    (WeaveSectionKind::Admissions, "admissions"),
    (WeaveSectionKind::Budgets, "budgets"),
    (WeaveSectionKind::SieveScore, "sieve_score"),
    (WeaveSectionKind::Digest, "digest"),
];

#[test]
fn weave_section_kind_keeps_its_names() {
    for (row, name) in WEAVE_SECTION_KIND {
        assert_eq!(row.policy_name(), name, "{row:?}");
    }
}

#[test]
fn weave_section_kind_names_are_serde_names() {
    serde_writes_and_reads(&WEAVE_SECTION_KIND);
}

/// `BlockedCategory`: every row as its hand `as_str` table spelled it.
const BLOCKED_CATEGORY: [(BlockedCategory, &str); 4] = [
    (BlockedCategory::Tool, "tool"),
    (BlockedCategory::Permission, "permission"),
    (BlockedCategory::Context, "context"),
    (BlockedCategory::Environment, "environment"),
];

#[test]
fn blocked_category_keeps_its_names() {
    for (row, name) in BLOCKED_CATEGORY {
        assert_eq!(row.as_str(), name, "{row:?}");
    }
}

#[test]
fn blocked_category_names_are_serde_names() {
    serde_writes_and_reads(&BLOCKED_CATEGORY);
}

/// `FoldKind`: every row as its hand `as_str` table spelled it.
const FOLD_KIND: [(FoldKind, &str); 2] = [
    (FoldKind::ReplOutput, "repl_output"),
    (FoldKind::Program, "program"),
];

#[test]
fn fold_kind_keeps_its_names() {
    for (row, name) in FOLD_KIND {
        assert_eq!(row.as_str(), name, "{row:?}");
    }
}

#[test]
fn fold_kind_names_are_serde_names() {
    serde_writes_and_reads(&FOLD_KIND);
}

/// `AgentRunStatus`: every row as its hand `as_str` table spelled it.
const AGENT_RUN_STATUS: [(AgentRunStatus, &str); 8] = [
    (AgentRunStatus::Spawned, "spawned"),
    (AgentRunStatus::Working, "working"),
    (AgentRunStatus::NeedsInput, "needs_input"),
    (AgentRunStatus::Delivered, "delivered"),
    (AgentRunStatus::Archived, "archived"),
    (AgentRunStatus::Failed, "failed"),
    (AgentRunStatus::Abandoned, "abandoned"),
    (AgentRunStatus::Cancelled, "cancelled"),
];

#[test]
fn agent_run_status_keeps_its_names() {
    for (row, name) in AGENT_RUN_STATUS {
        assert_eq!(row.as_str(), name, "{row:?}");
    }
}

#[test]
fn agent_run_status_names_are_serde_names() {
    serde_writes_and_reads(&AGENT_RUN_STATUS);
}
