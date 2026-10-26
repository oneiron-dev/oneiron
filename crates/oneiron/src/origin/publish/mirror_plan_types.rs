//! The shapes of one automatic mirror push plan (FIX 6866 part 2; CALLS "FIX
//! 6866 automatic review record"): what a `schedule` or `full_auto` run froze
//! before anything went out, and where each of its refs stands.
//!
//! A plan is immutable once written: its destination and generation, the
//! strategy and revision it ran under, the exact `(ref, new object)` vector
//! and deletions, the tip an authenticated read saw at each ref, the batch
//! each ref goes in, each ref's review section and one digest over all of
//! it. What changes is kept beside it, one row a batch: the batch's claim
//! and each of its refs' outcomes.

use serde::{Deserialize, Serialize};

use super::types::{OriginPublishDestination, OriginPublishReview, OriginPublishReviewPage};
use crate::entity_id::EntityId;
use crate::origin::mirror_strategy::OriginMirrorSyncStrategy;

/// What one authenticated read saw at a mirror's ref before the plan froze.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum MirrorObservedTip {
    /// The mirror held no such ref: the push leases on its absence.
    Absent,
    /// The ref stood at this object, 40 lower hex: the push leases on it.
    At { oid: String },
    /// The read failed, with its redacted cause: the ref goes unleased, as
    /// the scheduled mirror always sent it, and its review covers the whole
    /// closure of what it pushes (CALLS "FIX 6866 automatic unknown tip").
    Unknown { cause: String },
}

impl MirrorObservedTip {
    /// The object the read saw, when it saw one.
    pub(crate) fn oid(&self) -> Option<&str> {
        match self {
            Self::At { oid } => Some(oid),
            Self::Absent | Self::Unknown { .. } => None,
        }
    }
}

/// Where one ref of a plan stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MirrorRefOutcome {
    /// In a batch not yet claimed.
    Pending,
    /// Its batch (or its same-plan resend) was claimed and its child may be
    /// running: never sent again until a reconcile reads it.
    Dispatched,
    /// The mirror acknowledged it.
    Applied,
    /// A reconcile read saw it there (a deletion: absent), without an
    /// acknowledgement. It is never sent again.
    ObservedApplied,
    /// The mirror refused it once; a reconcile decides.
    Rejected,
    /// The child named no outcome for it; a reconcile decides.
    Unknown,
    /// Its same-plan resend was refused as well: it ends here.
    Refused,
    /// A reconcile read saw neither the tip the plan leased on nor its new
    /// object (or the plan read no tip to lease on): someone else moved it.
    RemoteMoved,
    /// Never sent: the strategy moved to ask_me or to another revision, the
    /// destination or this host's origin authority changed, or the mirror
    /// was cleared.
    Paused,
    /// A full-auto ref the mirror already holds, or holds a descendant of:
    /// nothing to send, and never a rewind.
    Covered,
    /// Never sent: the mirror is public or unstated and the publication
    /// gate held the ref's history (FIX 7608 slice 9, A1; CALLS HOLD-AUTO).
    /// The plan stays open: each later run reads it at the mirror and asks
    /// the gate again before its same-plan send.
    Held,
}

impl MirrorRefOutcome {
    /// Whether the ref needs nothing more.
    pub(crate) const fn settled(self) -> bool {
        matches!(
            self,
            Self::Applied
                | Self::ObservedApplied
                | Self::Refused
                | Self::RemoteMoved
                | Self::Paused
                | Self::Covered
        )
    }

    /// Whether the mirror holds what the plan sent there.
    pub(crate) const fn landed(self) -> bool {
        matches!(self, Self::Applied | Self::ObservedApplied | Self::Covered)
    }

    /// Whether only a reconcile read can say what became of it (a held
    /// ref: what the mirror holds there before it asks the gate again).
    pub(crate) const fn unproven(self) -> bool {
        matches!(
            self,
            Self::Dispatched | Self::Rejected | Self::Unknown | Self::Held
        )
    }

    /// Whether the plan's later batches may go out past it: it needs
    /// nothing more, or only the publication gate holds it.
    pub(crate) const fn lets_plan_go_on(self) -> bool {
        self.settled() || matches!(self, Self::Held)
    }
}

/// One ref of a frozen plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MirrorPlanRef {
    /// The full ref at the mirror.
    pub(crate) ref_name: String,
    /// The object it is pushed to, 40 lower hex; `None` deletes it.
    pub(crate) new: Option<String>,
    pub(crate) observed: MirrorObservedTip,
    /// Its review section; `None` for a deletion, which exposes nothing.
    pub(crate) review: Option<OriginPublishReview>,
    /// The plan page its section starts at.
    pub(crate) first_page: u64,
    /// The batch it goes in; `None` when it needs no push (a deletion the
    /// mirror already lacks, a covered full-auto ref).
    pub(crate) batch: Option<u32>,
}

/// One full-auto head the plan held back for want of green evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MirrorPendingHead {
    pub(crate) ref_name: String,
    /// The published head.
    pub(crate) head: String,
    /// The newest green ancestor the plan pushes in its place, if any.
    pub(crate) sent: Option<String>,
}

/// One frozen plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MirrorPushPlan {
    pub(crate) plan_id: EntityId,
    /// The served name, and the object-store-derived repository id.
    pub(crate) repo: String,
    pub(crate) repo_id: EntityId,
    pub(crate) destination: OriginPublishDestination,
    pub(crate) strategy: OriginMirrorSyncStrategy,
    pub(crate) strategy_revision: u64,
    /// The owner whose push-now froze it; `None` for a cadence or an event,
    /// and once the actor is erased.
    pub(crate) requested_by: Option<EntityId>,
    /// Updates in published order, then deletions.
    pub(crate) refs: Vec<MirrorPlanRef>,
    pub(crate) batches: u32,
    pub(crate) pending_checks: Vec<MirrorPendingHead>,
    /// BLAKE3, 64 lower hex, over everything above and each section digest.
    pub(crate) digest: String,
    /// The vector's own digest, which a full-auto mirror compares its next
    /// selection with.
    pub(crate) vector: String,
    pub(crate) pages: u64,
    pub(crate) created_at: u64,
}

/// A batch's claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum MirrorBatchClaim {
    Pending,
    /// Claimed at `at`, before its child ran.
    Claimed {
        at: u64,
    },
    /// Its child ended at `at` and its outcomes are recorded.
    Sent {
        at: u64,
    },
    /// Never sent (see [`MirrorRefOutcome::Paused`]).
    Paused,
}

/// One batch's claim and its refs' outcomes, in batch order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MirrorBatchProgress {
    pub(crate) claim: MirrorBatchClaim,
    /// Indexes into the plan's refs.
    pub(crate) refs: Vec<u32>,
    pub(crate) outcomes: Vec<MirrorRefOutcome>,
    /// The redacted cause of its last child that did not succeed.
    pub(crate) detail: Option<String>,
}

/// How the plan a mirror settled last ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MirrorSettledPlan {
    pub(crate) plan_id: EntityId,
    /// Whether every ref landed.
    pub(crate) landed: bool,
    /// The plan's vector digest.
    pub(crate) vector: String,
    /// Whether the owner's clear of the mirror settled it.
    pub(crate) cleared: bool,
}

/// One mirror's work: its open plan, its reconcile reads that failed in a
/// row, and the settled plans it keeps.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MirrorWorkHead {
    pub(crate) open: Option<EntityId>,
    pub(crate) unread: u32,
    pub(crate) last: Option<MirrorSettledPlan>,
    /// Oldest first.
    pub(crate) kept: Vec<EntityId>,
}

/// One row of the store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) enum MirrorWorkRow {
    Head(MirrorWorkHead),
    Plan(Box<MirrorPushPlan>),
    Page(OriginPublishReviewPage),
    Batch(MirrorBatchProgress),
}
