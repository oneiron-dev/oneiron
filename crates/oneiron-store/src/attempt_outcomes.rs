//! What the attempt queue's doors return and the two door inputs that are
//! only data: the typed enqueue, claim, complete, fail, abandon, retry and
//! intervention outcomes, each carrying the attempt row it produced, and the
//! abandon and intervention inputs. The attempt queue (`attempt_queue`)
//! builds them; the store layer's callers match on them.
use crate::attempt_id::AttemptId;
use crate::attempt_inputs::AttemptInterventionEffect;
use crate::attempt_inputs::AttemptInterventionKind;
use crate::attempt_result::AttemptResultRef;

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

/// Input for interrupting, pausing, resuming, or cancelling an attempt row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterveneAttempt {
    pub id: AttemptId,
    pub kind: AttemptInterventionKind,
    pub actor: String,
    pub note: Option<String>,
    pub now: u64,
}

