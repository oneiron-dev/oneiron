//! Retry-lineage walk/ordinal, healer case/route, and surfaced-failure outcome types.

use std::collections::HashSet;
use std::num::NonZeroU16;

use crate::Vault;
use crate::agent_dispatch::HealerSlotOutcome;
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::blocked_reports::BlockedReportRef;
use super::classify::{FailureClass, TypedFailureEvidence};

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

#[doc(hidden)]
pub use oneiron_records::failure_ladder::lineage::{
    HealerCase, HealerRepairRoute, RetryLineagePathology,
};

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
    vault: &Vault,
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

        let retained_failures = crate::agent_dispatch::AgentDispatcher::new(vault)
            .workflow_tool_failure_count(&cursor)?;
        ordinal = ordinal.saturating_add(u16::try_from(retained_failures).unwrap_or(u16::MAX));
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
    retry_lineage_walk(vault, &queue, &current, limit)
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

/// A reserved or dispatched healer slot with the case and surface it was
/// opened from.
///
/// `surface.failed_attempt` is the failing row, and `surface.healer_slot` is
/// `Some(slot)`; the surface is the single copy of both.
#[derive(Debug, Clone, PartialEq)]
pub struct HealerOutcome {
    pub case: HealerCase,
    pub slot: HealerSlotOutcome,
    pub surface: SurfacedFailure,
}

/// The typed result of one failure input.
///
/// Every `Healer` value sets `surface.diagnosis = None` and
/// `surface.healer_slot = Some(slot)`; a later healer-authored diagnosis
/// update rides the healer's own propose lane and is outside this ticket.
///
/// Each arm's payload is boxed, which is the trade-off this type takes
/// deliberately: an outcome is constructed once per failed attempt and
/// consumed immediately, so one allocation on a path that has already lost a
/// whole attempt is cheaper than moving three kilobytes of failure record
/// through every caller and `Result` in between.
#[derive(Debug, Clone, PartialEq)]
pub enum FailureLadderOutcome {
    Retried {
        source_attempt_id: AttemptId,
        scheduled_attempt: Box<AttemptRecord>,
        /// The failed source row's ordinal: failures so far, including current.
        consecutive_transients: NonZeroU16,
    },
    Healer(Box<HealerOutcome>),
    Human(Box<SurfacedFailure>),
}
