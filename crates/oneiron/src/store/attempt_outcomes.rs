//! What the attempt queue's doors return and the two door inputs that are
//! only data: the typed enqueue, claim, complete, fail, abandon, retry and
//! intervention outcomes, each carrying the attempt row it produced, and the
//! abandon and intervention inputs. The attempt queue (`attempt_queue`)
//! builds them; the store layer's callers match on them.
use crate::store::attempt_id::AttemptId;
use crate::store::attempt_inputs::{AttemptInterventionEffect, AttemptInterventionKind};
use crate::store::attempt_record::AttemptRecord;
use crate::store::attempt_result::AttemptResultRef;

/// Typed enqueue outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnqueueOutcome {
    Enqueued(AttemptRecord),
    Existing(AttemptRecord),
}

/// Typed claim outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
pub enum ClaimOutcome {
    Empty,
    Claimed(AttemptRecord),
}

/// Typed complete outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompleteOutcome {
    Completed(AttemptRecord),
    AlreadyCompleted(AttemptRecord),
}

/// Typed fail outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FailOutcome {
    Failed(AttemptRecord),
    AlreadyFailed(AttemptRecord),
}

/// Input for abandoning a live attempt: it stopped without delivering, and
/// nobody stopped it.
///
/// The result reference is REQUIRED, not optional. An abandonment with nothing
/// to point at would be indistinguishable from a lost row, and the whole point
/// of the state is that the stop stays auditable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbandonAttempt {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub result_ref: AttemptResultRef,
    pub reason: String,
    pub now: u64,
}

/// Typed abandon outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AbandonOutcome {
    Abandoned(AttemptRecord),
    AlreadyAbandoned(AttemptRecord),
}

/// Typed retry outcome, carrying the newly scheduled try (not the finalized
/// source, which stays point-readable by its own id).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetryOutcome {
    Retried(AttemptRecord),
}

/// Input for interrupting, pausing, resuming, or cancelling an attempt row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterveneAttempt {
    pub id: AttemptId,
    pub kind: AttemptInterventionKind,
    pub actor: String,
    pub note: Option<String>,
    pub now: u64,
}

/// Typed intervention outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterveneOutcome {
    pub effect: AttemptInterventionEffect,
    pub record: AttemptRecord,
}
