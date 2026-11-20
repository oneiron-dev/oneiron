//! Register names (oneiron-verb-wire, wave A4): the names each hand table below wrote before its type
//! became a Register (Fable pass 25, register conversion wave part A). Generated from
//! `scripts/ratchet/hand_name_tables.py --names --only <file>` on the base, one table per
//! type. Green on the base (the hand tables) and on the adoption (`#[derive(Register)]`), so
//! no stored, sent or parsed name changed (M-1 keep). The serde test pins each name to the
//! one serde writes and reads.

use std::fmt::Debug;

use oneiron_verb_wire::dreamer_runner::maintenance::agent_health::vocabulary::AgentHealthOutcome;
use oneiron_verb_wire::dreamer_runner::maintenance::agent_health::vocabulary::AgentHealthTone;
use oneiron_verb_wire::edit_distance::publisher::vocab::IssueCategory;
use oneiron_verb_wire::failure_ladder::task_terminal::TaskTerminalDisposition;
use oneiron_verb_wire::feedback::bundle::FeedbackCategory;
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

/// `AgentHealthTone`: every row as its hand `as_str` table spelled it.
const AGENT_HEALTH_TONE: [(AgentHealthTone, &str); 3] = [
    (AgentHealthTone::Struggling, "struggling"),
    (AgentHealthTone::OffCourse, "off_course"),
    (AgentHealthTone::Concern, "concern"),
];

#[test]
fn agent_health_tone_keeps_its_names() {
    for (row, name) in AGENT_HEALTH_TONE {
        assert_eq!(row.as_str(), name, "{row:?}");
    }
}

#[test]
fn agent_health_tone_names_are_serde_names() {
    serde_writes_and_reads(&AGENT_HEALTH_TONE);
}

/// `AgentHealthOutcome`: every row as its hand `as_str` table spelled it.
const AGENT_HEALTH_OUTCOME: [(AgentHealthOutcome, &str); 4] = [
    (AgentHealthOutcome::Open, "open"),
    (AgentHealthOutcome::Confirmed, "confirmed"),
    (AgentHealthOutcome::Dismissed, "dismissed"),
    (AgentHealthOutcome::Unresolved, "unresolved"),
];

#[test]
fn agent_health_outcome_keeps_its_names() {
    for (row, name) in AGENT_HEALTH_OUTCOME {
        assert_eq!(row.as_str(), name, "{row:?}");
        let expected = (!matches!(row, AgentHealthOutcome::Open)).then_some(row);
        assert_eq!(AgentHealthOutcome::from_wire(name), expected, "{name}");
    }
    assert_eq!(AgentHealthOutcome::from_wire("not_a_name"), None);
}

#[test]
fn agent_health_outcome_names_are_serde_names() {
    serde_writes_and_reads(&AGENT_HEALTH_OUTCOME);
}

/// `IssueCategory`: every row as its hand `as_str` table spelled it.
const ISSUE_CATEGORY: [(IssueCategory, &str); 6] = [
    (IssueCategory::SkillDefect, "skill_defect"),
    (IssueCategory::ExecutionLapse, "execution_lapse"),
    (IssueCategory::Discovery, "discovery"),
    (IssueCategory::Environment, "environment"),
    (IssueCategory::PreferenceShift, "preference_shift"),
    (IssueCategory::Unclear, "unclear"),
];

#[test]
fn issue_category_keeps_its_names() {
    for (row, name) in ISSUE_CATEGORY {
        assert_eq!(row.as_str(), name, "{row:?}");
    }
}

#[test]
fn issue_category_names_are_serde_names() {
    serde_writes_and_reads(&ISSUE_CATEGORY);
}

/// `TaskTerminalDisposition`: every row as its hand `as_str` table spelled it.
const TASK_TERMINAL_DISPOSITION: [(TaskTerminalDisposition, &str); 6] = [
    (TaskTerminalDisposition::Completed, "completed"),
    (TaskTerminalDisposition::Rejected, "rejected"),
    (TaskTerminalDisposition::Failed, "failed"),
    (TaskTerminalDisposition::Expired, "expired"),
    (TaskTerminalDisposition::Abandoned, "abandoned"),
    (TaskTerminalDisposition::Cancelled, "cancelled"),
];

#[test]
fn task_terminal_disposition_keeps_its_names() {
    for (row, name) in TASK_TERMINAL_DISPOSITION {
        assert_eq!(row.as_str(), name, "{row:?}");
        assert_eq!(
            TaskTerminalDisposition::from_token(name).ok(),
            Some(row),
            "{name}"
        );
    }
    assert!(TaskTerminalDisposition::from_token("not_a_name").is_err());
}

#[test]
fn task_terminal_disposition_names_are_serde_names() {
    serde_writes_and_reads(&TASK_TERMINAL_DISPOSITION);
}

/// `FeedbackCategory`: every row as its hand `as_str` table spelled it.
const FEEDBACK_CATEGORY: [(FeedbackCategory, &str); 4] = [
    (FeedbackCategory::Bug, "bug"),
    (FeedbackCategory::Papercut, "papercut"),
    (FeedbackCategory::Confusion, "confusion"),
    (FeedbackCategory::FeatureWish, "feature-wish"),
];

#[test]
fn feedback_category_keeps_its_names() {
    for (row, name) in FEEDBACK_CATEGORY {
        assert_eq!(row.as_str(), name, "{row:?}");
    }
}

#[test]
fn feedback_category_names_are_serde_names() {
    serde_writes_and_reads(&FEEDBACK_CATEGORY);
}
