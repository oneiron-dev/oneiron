//! The host selection context and frozen parent binding of a reader job.

use serde::{Deserialize, Serialize};

use super::{DelegatedSource, ReaderActor, ReaderRoute, ReaderSpend, RunDeadline};
use crate::EntityId;
use crate::agent_def::AgentModel;
use crate::attempt_queue::BorrowedAttemptLease;

/// What the host lends a run that may spawn readers: what its children
/// spend on, its clock, what each child holds at its claim, the window of
/// the model its children and summaries run on, in tokens, the memory one
/// child may hold, in bytes, and the model list their seats are held to.
/// The run's actor and route are its dispatcher's own; the parent run is the
/// bridge call's, never guest text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnHostSeat {
    pub spend: ReaderSpend,
    pub deadline: RunDeadline,
    pub hold_units: u64,
    pub window_tokens: u64,
    pub memory_bytes: u64,
    /// The list the run's agent froze (FIX 4539); empty for a run of no
    /// agent, or of one that lists none.
    pub listed: Vec<AgentModel>,
    /// The spawning execution's project, frozen at its first reader spawn.
    /// Selection context only; not a read scope or a child's task type.
    pub project: Option<EntityId>,
    /// The lease of the attempt the run is, which a scoped child queued
    /// under this seat borrows (FIX 7507); never a read's or a summary's.
    pub parent_lease: Option<BorrowedAttemptLease>,
}

/// A parent run's reader row: its clock, fixed at its first spawn, what its
/// children spend on, what each holds at its claim, their model list and its counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReaderParent {
    pub deadline: RunDeadline,
    pub spend: ReaderSpend,
    pub hold_units: u64,
    pub listed: Vec<AgentModel>,
    /// The spawning execution's project, frozen at its first reader spawn.
    /// Selection context only; not a read scope or a child's task type.
    pub project: Option<EntityId>,
    pub next_ordinal: u64,
    pub queued: u64,
    pub active: u64,
}

/// What a child is bound to: its parent run, actor and route, the source it
/// reads, what it spends on, the clock it stops on and the model list its
/// seat is held to. Never the parent's door, credential or body bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpawnParentBinding {
    pub parent_run: EntityId,
    pub actor: ReaderActor,
    pub source: DelegatedSource,
    pub route: ReaderRoute,
    pub spend: ReaderSpend,
    pub deadline: RunDeadline,
    /// When this job stops (`reader_job_cutoff`): a summary may use the fold reserve.
    pub child_cutoff_unix_ms: u64,
    pub listed: Vec<AgentModel>,
    /// The spawning execution's project, frozen at its first reader spawn.
    /// Selection context only; not a read scope or a child's task type.
    pub project: Option<EntityId>,
    /// The parent attempt's lease a scoped child borrowed (FIX 7507).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_lease: Option<BorrowedAttemptLease>,
}
