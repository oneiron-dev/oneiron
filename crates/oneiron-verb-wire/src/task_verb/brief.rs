//! Moved from `crates/oneiron/src/task_verb/brief.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// Domain of [`brief_digest`].
pub const BRIEF_DIGEST_DOMAIN: &[u8] = b"oneiron.tasks.brief.digest.v1";

/// Domain of a pin's digest over the row it names.
pub const PIN_DIGEST_DOMAIN: &[u8] = b"oneiron.tasks.brief.pin.v1";

/// What a workflow handle starts with, before its record's 32 hex.
pub const WORKFLOW_HANDLE_PREFIX: &str = "workflow:";

/// The typed record slots of a brief (OF-063): each must resolve under the
/// writer's own read. The type ref is not among them: it names a node of the
/// team's type tree, not a record.
pub const BRIEF_RECORD_SLOTS: &[&str] = &[
    "/context/pack/pack_ref",
    "/context/read_first/*/target",
    "/success/criteria/yes_if_all/*/evidence_ref",
    "/success/criteria/no_if_any/*/evidence_ref",
    "/success/criteria/not_a_reason_to_say_no/*/evidence_ref",
    "/constraints/policy_refs/*",
    "/constraints/budget_ref",
    "/settled/*",
    "/project_ref",
    "/escalation/question_ref/claim",
    "/escalation/question_ref/turn",
];

/// The learned type a task instantiates: a node and the tree version it was
/// read at (ARCH-0079). Required: a missing type is invalid, never untyped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TypeRef {
    pub node_id: EntityId,
    pub tree_version: u64,
}

/// How much care the work needs; inferred by the planner when absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Care {
    Light,
    Medium,
    High,
    Xhigh,
    Max,
}

/// The task's intent: canon's `need`, apart from any prompt, and its `care`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BriefIntent {
    pub need: String,
    #[serde(default)]
    pub care: Option<Care>,
}

/// Spawn seeds a caller may pin; unset is planned.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpawnPins {
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub width: Option<u16>,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub budget: Option<u64>,
}

/// Constraints the work runs under. The refs describe policy and budget
/// rows; holding one authorizes nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BriefConstraints {
    #[serde(default)]
    pub notes: Vec<String>,
    #[serde(default)]
    pub policy_refs: Vec<EntityId>,
    #[serde(default)]
    pub budget_ref: Option<EntityId>,
    #[serde(default)]
    pub deadline: Option<u64>,
    #[serde(default)]
    pub pins: SpawnPins,
}

/// One criterion of the done-means question.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Criterion {
    pub text: String,
    #[serde(default)]
    pub evidence_ref: Option<EntityId>,
}

/// What makes the work ask up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EscalationTrigger {
    Blocked,
    CriteriaUnmet,
    ScopeWiden,
    SpendOver,
    Deadline,
    BriefRevised,
    RetryRequested,
}

impl EscalationTrigger {
    /// Stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::CriteriaUnmet => "criteria_unmet",
            Self::ScopeWiden => "scope_widen",
            Self::SpendOver => "spend_over",
            Self::Deadline => "deadline",
            Self::BriefRevised => "brief_revised",
            Self::RetryRequested => "retry_requested",
        }
    }
}

pub fn require_text(text: &str, what: &str) -> MemoryResult<()> {
    if text.trim().is_empty() {
        return Err(MemoryError::bad_request(format!(
            "task brief {what} must not be blank"
        )));
    }
    Ok(())
}
