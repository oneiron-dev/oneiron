//! Moved from `crates/oneiron/src/store/attempt_record.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::attempt_id::AttemptId;
use oneiron_store::attempt_result::AttemptResultRef;
use oneiron_wake_contract::store::attempt_cancel::AttemptResumePoint;
use serde::Deserialize;
use serde::Serialize;

/// The runtime's observation of one expired lease, captured in the writer
/// that requeues it, before its stored lease owner and clock are cleared.
/// This is not worker-authored output or a terminal outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptLeaseExpiry {
    pub attempt_count: u32,
    pub lease_owner: String,
    pub lease_updated_at: u64,
    pub observed_at: u64,
    pub lease_timeout_secs: u64,
}

/// Operator-selected worker and parent. An absent worker keeps ordinary claiming;
/// an absent parent makes the attempt a root. The executor kind never changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptPlacement {
    pub worker: Option<String>,
    pub parent: Option<AttemptId>,
}

/// A seatless planned child's binding (FIX 7720/7721/7723): its plan's pick,
/// the route it runs on and whether it runs that pick exactly, frozen once
/// beside the executor model it runs. Every later entry of the try reuses it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedBinding {
    pub pick: oneiron_model::llm::ModelId,
    pub locality: oneiron_model::llm::ModelLocality,
    pub exactness: PlannedExactness,
    /// The try whose run a continuation forks (FIX 3694), when it is one.
    pub source: Option<AttemptId>,
}

/// Whether a planned child runs its pick exactly, as its binding records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannedExactness {
    /// Its provider routes the pick exactly and its list holds it.
    Exact,
    /// Its provider's own model runs; a call another model answers is marked.
    NonExact,
    /// A continuation whose source recorded no exactness: run as not exact,
    /// never guessed from today's catalog.
    Inherited,
}

/// One failure, or a consecutive run of equal failures, a requeue kept.
/// The lease generation plus the count names every failed generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequeuedFailure {
    /// The vault's recorded instant of the first failure.
    pub at: u64,
    /// The vault's recorded instant of the latest failure.
    pub last_at: u64,
    /// The number of consecutive failures this entry records, at least one.
    pub count: u32,
    /// The owner of every lease this entry records.
    pub lease_owner: String,
    /// The first failed lease's generation within the row.
    pub attempt_count: u32,
    /// The worker's reason, as it gave it.
    pub reason: String,
}

/// Why a paused row is paused. A person's pause wins over every engine
/// hold: it replaces the hold on the row, so no hold's release resumes it,
/// and only a resume clears it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptPause {
    /// An intervention's pause by any actor other than an engine hold's.
    Person,
    /// OF-368: the TASK answers a comment thread that is unattached.
    Annotation {
        artifact_id: EntityId,
        thread_id: EntityId,
    },
    /// OF-541: the run reached its spend cap.
    Budget,
    /// OF-393: the cut waits on its launch approval.
    Fanout { launch_ref: EntityId },
    /// FIX 7114: a workflow tool waits on this verb-hook invocation.
    Hook { invocation: [u8; 16] },
}

/// A terminal try's durable exhaust: the output references it attached
/// before it settled, explicitly empty when it attached none, and the resume
/// point it recorded, when it recorded one. Nothing here is made up: an
/// empty list is the record that no output exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptTerminalExhaust {
    /// The output references the try attached, in attach order; empty when
    /// it attached none.
    pub outputs: Vec<AttemptResultRef>,
    /// The resume point the try recorded, when it recorded one.
    #[serde(default)]
    pub frontier: Option<AttemptResumePoint>,
}
