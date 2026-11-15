//! Moved from `crates/oneiron/src/failure_ladder/lineage.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::failure_ladder::blocked_reports::BlockedReportRef;
use crate::failure_ladder::classify::FailureClass;
use crate::failure_ladder::scope::FailureScope;
use oneiron_store::attempt_id::AttemptId;
use serde::Deserialize;
use serde::Serialize;

/// A `retry_of` chain that cannot be read as a chain at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetryLineagePathology {
    MissingAncestor { missing_attempt_id: AttemptId },
    Cycle { repeated_attempt_id: AttemptId },
}

/// The healer's read-only view of one failure. Its identifiers are context;
/// the healer never writes them back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealerCase {
    /// Lowercase-hex deterministic correlation key; not a resolvable entity ref.
    pub case_ref: String,
    pub scope: FailureScope,
    pub failure_class: FailureClass,
    pub failing_attempt_id: AttemptId,
    #[serde(default)]
    pub task_ref: Option<String>,
    /// Lowercase-hex EntityId spelling.
    pub evidence_ref: String,
    #[serde(default)]
    pub blocked_reports: Vec<BlockedReportRef>,
    /// Lowercase-hex EntityId spelling.
    pub pre_fail_checkpoint_ref: String,
    /// Lowercase-hex EntityId spelling.
    pub qa_thread_ref: String,
    /// Always 0 for permanent/ambiguous by policy; never computed from lineage
    /// for those classes.
    pub consecutive_transients: u16,
}

/// The healer can target only agent-side artifacts. There is deliberately no
/// Task, task payload, or in-place Attempt target variant, so a task-targeted
/// "fix" is unrepresentable rather than merely rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "route", rename_all = "snake_case")]
pub enum HealerRepairRoute {
    SkillEdit {
        agent_ref: String,
        skill_ref: String,
        patch_ref: String,
        diagnosis_ref: String,
    },
    PromptInjectAndForkResume {
        agent_ref: String,
        prompt_ref: String,
        /// The PRE-FAIL checkpoint, never the terminal attempt: a failed row is
        /// never reopened, so a fork resumes from durable state that predates
        /// the failing work.
        checkpoint_ref: String,
        diagnosis_ref: String,
    },
    Environment {
        agent_ref: String,
        environment_ref: String,
        repair_ref: String,
        diagnosis_ref: String,
    },
    EscalateWithDiagnosis {
        agent_ref: String,
        diagnosis_ref: String,
    },
}
