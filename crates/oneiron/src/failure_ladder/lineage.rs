//! Retry-lineage walk/ordinal, healer case/route, and surfaced-failure outcome types.

use std::collections::HashSet;
use std::num::NonZeroU16;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::agent_dispatch::HealerSlotOutcome;
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::blocked_reports::BlockedReportRef;
use super::classify::{FailureClass, TypedFailureEvidence};
use super::scope::FailureScope;

/// One typed attempt-failure input, raised while the failing row is still the
/// authenticated leased ATTEMPT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleAttemptFailure {
    pub attempt_id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub evidence: TypedFailureEvidence,
    pub blocked_reports: Vec<BlockedReportRef>,
    /// Existing durable checkpoint immediately before the failing work.
    pub pre_fail_checkpoint_ref: EntityId,
    /// Existing referenced MESSAGE thread used by the healer/human Q&A feed.
    pub qa_thread_ref: EntityId,
    /// Existing retry policy chooses this instant. FailureLadder only forwards it.
    pub retry_at: u64,
    pub now: u64,
}

/// A `retry_of` chain that cannot be read as a chain at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetryLineagePathology {
    MissingAncestor { missing_attempt_id: AttemptId },
    Cycle { repeated_attempt_id: AttemptId },
}

/// Where the failing row sits in its `retry_of` chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryOrdinal {
    BelowLimit(NonZeroU16),
    AtLimit(NonZeroU16),
    Pathology(RetryLineagePathology),
}

/// Walks every class through the same bounded lineage proof.
///
/// The current row counts as ordinal one; at most `limit - 1` ancestors are
/// point-read. There is no list/scan and no use of `attempt_count`, which is
/// the per-row lease fence and not a logical retry count. A repeated pointer
/// is checked BEFORE the threshold return — that check needs no read, because
/// the cursor is already loaded and the repeated target is already in `seen` —
/// so a cycle sitting exactly on the threshold node is still a pathology.
/// Pathology deeper than the bound is intentionally undetectable: the
/// bounded-read law outranks completeness.
pub(super) fn retry_lineage_walk(
    queue: &AttemptQueue<'_>,
    current: &AttemptRecord,
    limit: NonZeroU16,
) -> Result<RetryOrdinal> {
    let mut seen = HashSet::new();
    let mut cursor = current.clone();
    let mut ordinal = 1_u16;
    seen.insert(cursor.id);

    loop {
        let next_parent = cursor.retry_of;

        if let Some(parent_id) = next_parent
            && !seen.insert(parent_id)
        {
            return Ok(RetryOrdinal::Pathology(RetryLineagePathology::Cycle {
                repeated_attempt_id: parent_id,
            }));
        }

        if ordinal >= limit.get() {
            return Ok(RetryOrdinal::AtLimit(limit));
        }

        let Some(parent_id) = next_parent else {
            return Ok(RetryOrdinal::BelowLimit(
                NonZeroU16::new(ordinal).expect("ordinal starts at one"),
            ));
        };
        let Some(parent) = queue.get(parent_id)? else {
            return Ok(RetryOrdinal::Pathology(
                RetryLineagePathology::MissingAncestor {
                    missing_attempt_id: parent_id,
                },
            ));
        };
        cursor = parent;
        ordinal = ordinal.saturating_add(1);
    }
}

/// Revalidates a public card's ordinal and pathology through the policy walker.
/// Requires a persisted Failed row here, not in the walker: the failure ladder
/// walks its still-leased row before committing the fail transition.
/// This is read-only and preserves the same threshold and every-link semantics.
/// The caller must supply the same policy bound used by the failure ladder;
/// this helper has no stored policy authority against which to verify it.
pub(crate) fn retry_lineage_ordinal(
    vault: &Vault,
    failing_attempt_id: AttemptId,
    limit: NonZeroU16,
) -> Result<RetryOrdinal> {
    let queue = AttemptQueue::new(vault);
    let current = queue.get(failing_attempt_id)?.ok_or_else(|| {
        Error::InvalidConfig("failure card lineage requires a stored failing attempt".to_owned())
    })?;
    if current.state != crate::attempt_queue::AttemptState::Failed {
        return Err(Error::InvalidConfig(
            "failure card lineage requires a stored Failed attempt".to_owned(),
        ));
    }
    retry_lineage_walk(&queue, &current, limit)
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

/// Everything the human surface needs about one terminalized failure.
#[derive(Debug, Clone, PartialEq)]
pub struct SurfacedFailure {
    pub failed_attempt: AttemptRecord,
    pub failure_class: FailureClass,
    /// Always 0 for permanent/ambiguous by policy; never computed from lineage
    /// for those classes.
    pub consecutive_transients: u16,
    /// Missing only for an Indeterminate verdict.
    pub evidence_ref: Option<EntityId>,
    pub blocked_reports: Vec<BlockedReportRef>,
    pub pre_fail_checkpoint_ref: EntityId,
    pub qa_thread_ref: EntityId,
    pub diagnosis: Option<HealerRepairRoute>,
    pub healer_slot: Option<HealerSlotOutcome>,
    pub pathology: Option<RetryLineagePathology>,
}

/// The typed result of one failure input.
///
/// Every `Healer` value sets `surface.diagnosis = None` and
/// `surface.healer_slot = Some(slot)`; a later healer-authored diagnosis
/// update rides the healer's own propose lane and is outside this ticket.
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum FailureLadderOutcome {
    Retried {
        source_attempt_id: AttemptId,
        scheduled_attempt: AttemptRecord,
        /// The failed source row's ordinal: failures so far, including current.
        consecutive_transients: NonZeroU16,
    },
    Healer {
        failed_attempt: AttemptRecord,
        case: HealerCase,
        slot: HealerSlotOutcome,
        surface: SurfacedFailure,
    },
    Human(SurfacedFailure),
}
