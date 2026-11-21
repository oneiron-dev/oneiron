//! The team and board names, one line per row, generated from
//! `scripts/ratchet/hand_name_tables.py --names --only <file>` on the R0 head before these
//! enums became Registers (Fable pass 25, the register conversion wave), for:
//! - `crates/oneiron/src/context_board/task_kind.rs`
//! - `crates/oneiron/src/team/spawn_need.rs`
//! - `crates/oneiron/src/team/team_shape.rs`
//!
//! Green on the hand tables and on the adoption (the derive), so no stored or sent name
//! changed (M-1 keep). The second test of each enum pins each name to serde's; where the
//! adoption rewrites a parser's body, a third reads every name back through it.

use oneiron::context_board::task_kind::TaskKind;
use oneiron::team::spawn_need::CareLevel;
use oneiron::team::team_shape::CoordinationPattern;
use serde_json::Value;

/// Every `CareLevel` row, as the hand `as_str` table spelled it.
const CARE_LEVEL_ROWS: [(CareLevel, &str); 5] = [
    (CareLevel::Light, "light"),
    (CareLevel::Medium, "medium"),
    (CareLevel::High, "high"),
    (CareLevel::XHigh, "xhigh"),
    (CareLevel::Max, "max"),
];

#[test]
fn every_care_level_keeps_its_name() {
    assert_eq!(CareLevel::Light.as_str(), "light");
    assert_eq!(CareLevel::Medium.as_str(), "medium");
    assert_eq!(CareLevel::High.as_str(), "high");
    assert_eq!(CareLevel::XHigh.as_str(), "xhigh");
    assert_eq!(CareLevel::Max.as_str(), "max");
}

#[test]
fn every_care_level_name_is_its_serde_name() {
    for (row, name) in CARE_LEVEL_ROWS {
        let written = serde_json::to_value(row).expect("a care level serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: CareLevel =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn every_care_level_name_reads_back_trimmed_in_any_case() {
    for (row, name) in CARE_LEVEL_ROWS {
        assert_eq!(CareLevel::from_token(name).ok(), Some(row), "{name}");
        let loud = format!(" {} ", name.to_ascii_uppercase());
        assert_eq!(CareLevel::from_token(&loud).ok(), Some(row), "{loud}");
    }
    assert!(CareLevel::from_token("not-a-name").is_err());
}

/// Every `CoordinationPattern` row, as the hand `as_str` table spelled it.
const COORDINATION_PATTERN_ROWS: [(CoordinationPattern, &str); 6] = [
    (CoordinationPattern::Solo, "solo"),
    (CoordinationPattern::CeoDecides, "ceo_decides"),
    (CoordinationPattern::Committee, "committee"),
    (CoordinationPattern::Vote, "vote"),
    (CoordinationPattern::Market, "market"),
    (CoordinationPattern::Rotation, "rotation"),
];

#[test]
fn every_coordination_pattern_keeps_its_name() {
    assert_eq!(CoordinationPattern::Solo.as_str(), "solo");
    assert_eq!(CoordinationPattern::CeoDecides.as_str(), "ceo_decides");
    assert_eq!(CoordinationPattern::Committee.as_str(), "committee");
    assert_eq!(CoordinationPattern::Vote.as_str(), "vote");
    assert_eq!(CoordinationPattern::Market.as_str(), "market");
    assert_eq!(CoordinationPattern::Rotation.as_str(), "rotation");
}

#[test]
fn every_coordination_pattern_name_is_its_serde_name() {
    for (row, name) in COORDINATION_PATTERN_ROWS {
        let written = serde_json::to_value(row).expect("a coordination pattern serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: CoordinationPattern =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

/// Every `TaskKind` row, as the hand `as_str` table spelled it.
const TASK_KIND_ROWS: [(TaskKind, &str); 3] = [
    (TaskKind::Standard, "standard"),
    (TaskKind::Consult, "consult"),
    (TaskKind::Reconciliation, "reconciliation"),
];

#[test]
fn every_task_kind_keeps_its_name() {
    assert_eq!(TaskKind::Standard.as_str(), "standard");
    assert_eq!(TaskKind::Consult.as_str(), "consult");
    assert_eq!(TaskKind::Reconciliation.as_str(), "reconciliation");
}

#[test]
fn every_task_kind_name_is_its_serde_name() {
    for (row, name) in TASK_KIND_ROWS {
        let written = serde_json::to_value(row).expect("a task kind serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: TaskKind =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}
