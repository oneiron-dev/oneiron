//! The task highway's typed calls, durable handles, outcomes and status view
//! (OF-220).
//!
//! Every transport builds a [`TaskCall`] and nothing else. Every answer names
//! a durable handle whose truth is a vault row (the pending tray, the TASK,
//! the ATTEMPT or the ask group); a protocol session is correlation only and
//! never holds state (ARCH-0028).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;

use super::ask_types::{TaskAskHandle, TaskAskSpec, TaskAskStatus};
use super::brief::{BriefStamp, QueueTaskBrief, hex32};
use super::route_receipts::TaskRouteOutcome;
use super::task_actor::TaskActor;
use super::terminal_state::TaskTerminalDisposition;
use super::verb_kind::{TaskAssignee, TaskTtl};

/// Serde for an attempt id as 32 hex characters.
mod attempt_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::attempt_queue::AttemptId;

    pub(super) fn serialize<S: Serializer>(
        id: &AttemptId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&crate::entity_id::bytes_to_hex_lower(id.as_bytes()))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<AttemptId, D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = super::super::brief::decode_hex::<16>(&text)
            .ok_or_else(|| serde::de::Error::custom("expected a 32-character hex attempt id"))?;
        AttemptId::from_bytes(&bytes)
            .map_err(|_| serde::de::Error::custom("expected a 16-byte attempt id"))
    }
}

/// The door one call came through.
///
/// `Host` is sealed: its binding's fields are private and only the code-run
/// host constructs one, from the leased record it already holds. A wire
/// caller can name an attempt handle, never a lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskVia {
    Wire,
    Host(HostBinding),
}

/// The lease a host-bound call runs under: the parent attempt, its owner and
/// its generation, and the run it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostBinding {
    parent: AttemptId,
    lease_owner: String,
    attempt_count: u32,
    run_id: Option<EntityId>,
}

impl HostBinding {
    /// Built by the code-run host from the leased record it holds, never
    /// from caller text.
    pub(crate) fn new(
        parent: AttemptId,
        lease_owner: String,
        attempt_count: u32,
        run_id: Option<EntityId>,
    ) -> Self {
        Self {
            parent,
            lease_owner,
            attempt_count,
            run_id,
        }
    }

    pub(super) const fn parent(&self) -> AttemptId {
        self.parent
    }

    pub(super) fn lease_owner(&self) -> &str {
        &self.lease_owner
    }

    pub(super) const fn attempt_count(&self) -> u32 {
        self.attempt_count
    }

    pub(super) const fn run_id(&self) -> Option<EntityId> {
        self.run_id
    }

    /// The executor run the host runs this try as, when it sealed one
    /// (OF-181): the log a live-run action's fold verbs reach.
    pub(crate) const fn executor_run(&self) -> Option<EntityId> {
        self.run_id
    }

    /// The witness a call receipt states of the try this binding sealed
    /// (OF-568 L4): its attempt and lease generation, from the sealed
    /// fields, so a call that held this binding's run names that attempt.
    #[must_use]
    pub const fn call_attempt_witness(&self) -> crate::receipt::CallAttemptWitness {
        crate::receipt::CallAttemptWitness::sealed(self.parent, self.attempt_count)
    }

    /// The try this binding sealed, read live in `vault`: still leased, by
    /// the same owner, at the same generation. A lapsed lease lends nothing.
    ///
    /// # Errors
    ///
    /// [`crate::Error::InvalidClaimBody`] for a try that no longer holds this
    /// lease; storage errors.
    pub(crate) fn leased_record(
        &self,
        vault: &crate::Vault,
    ) -> crate::Result<crate::attempt_queue::AttemptRecord> {
        let txn = vault.store.env.read_txn()?;
        self.leased_record_in_txn(vault, &txn)?
            .ok_or(crate::Error::InvalidClaimBody(
                "the run's lease no longer holds",
            ))
    }

    /// The try this binding sealed, read in the caller's snapshot `txn`, so
    /// a writer judges the lease it commits under (FIX 6867): still leased,
    /// by the same owner, at the same generation. `None` once it lapsed.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn leased_record_in_txn(
        &self,
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
    ) -> crate::Result<Option<crate::attempt_queue::AttemptRecord>> {
        Ok(crate::attempt_queue::AttemptQueue::new(vault)
            .get_in_txn(txn, self.parent)?
            .filter(|record| {
                record.state == crate::attempt_queue::AttemptState::Leased
                    && record.lease_owner.as_deref() == Some(self.lease_owner.as_str())
                    && record.attempt_count == self.attempt_count
            }))
    }

    /// The sealed try and the TASK it realizes, read in `txn`, while both
    /// stand (FIX 6867): the lease holds, and the TASK is a live, uncancelled
    /// standard task on a runner lane. `None` otherwise; a TASK whose record
    /// does not read is one that does not stand.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn leased_task_in_txn(
        &self,
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
    ) -> crate::Result<Option<(crate::attempt_queue::AttemptRecord, EntityId)>> {
        let Some(record) = self.leased_record_in_txn(vault, txn)? else {
            return Ok(None);
        };
        let task = super::highway_runner::runner_task_in(vault, txn, &record)
            .ok()
            .flatten();
        Ok(task.map(|task| (record, task)))
    }
}

/// One task-domain call. Settlement is not an arm: it is the approval doors'
/// continuation, which no transport can select.
#[derive(Debug, Clone, PartialEq)]
pub enum TaskCall {
    Post(TaskPost),
    Accept(TaskAccept),
    Report(TaskReport),
    Status(TaskStatusQuery),
    Redo(TaskRedo),
}

/// Post work as a TASK with a typed brief and an explicit assignee.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskPost {
    /// The caller's idempotency key: one actor and key name one post.
    pub intent_key: String,
    pub brief: QueueTaskBrief,
    pub assignee: TaskAssignee,
    /// The route payload, e.g. a Dreamer realization input.
    #[serde(default)]
    #[schemars(with = "Option<serde_json::Value>")]
    pub spec: Option<rmpv::Value>,
    #[serde(default)]
    pub ttl: Option<TaskTtl>,
    #[serde(default)]
    pub label: Option<String>,
    /// DOOR-113: the TASK this one files under by a checked `ChildOf`
    /// edge; the nesting matrix decides, so a Task nests under a Milestone.
    #[serde(default)]
    pub parent_ref: Option<EntityId>,
}

/// Accept one TASK addressed to the caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskAccept {
    pub task_ref: EntityId,
    pub intent_key: String,
}

/// Redo one TASK (FIX 3153): post a new TASK from its current brief and its
/// assignee, spec, label and parent. The TASK named is never written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskRedo {
    /// The TASK whose content the new one copies.
    pub task_ref: EntityId,
    /// The caller's idempotency key: one actor, TASK and key name one redo.
    pub intent_key: String,
}

/// Report against a TASK, fenced by the attempt handle Accept returned.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskReport {
    pub task_ref: EntityId,
    #[serde(default)]
    pub attempt: Option<AttemptHandle>,
    pub report_key: String,
    pub body: TaskReportBody,
}

/// Status of any handle. A poll is Status with the last observation digest:
/// an unchanged answer is [`TaskOutcome::Unchanged`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskStatusQuery {
    pub handle: TaskHandle,
    #[serde(default, with = "hex32::option")]
    #[schemars(with = "Option<String>")]
    pub after: Option<[u8; 32]>,
}

/// A durable locator. It is not a capability: every use re-proves the actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TaskHandle {
    /// Truth: the Proposed CLAIM and its tray row, keyed by claim id. Stays
    /// valid after landing; Status resolves it to the TASK.
    Proposed { proposal_ref: EntityId },
    /// Truth: the synced TASK row.
    Task { task_ref: EntityId },
    /// Truth: the node-local ATTEMPT row.
    Attempt(AttemptHandle),
    /// Truth: the ask group; the same handle `tasks.wait` takes.
    Ask { group_ref: EntityId },
}

/// One try on one seat, on the node that leased it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AttemptHandle {
    pub task_ref: EntityId,
    #[serde(with = "attempt_hex")]
    #[schemars(with = "String")]
    pub attempt_ref: AttemptId,
    pub attempt_count: u32,
    /// The machine holding the attempt row, when this install has one.
    #[serde(default)]
    pub node_ref: Option<EntityId>,
}

/// What one report says. STUCK is `Blocked` and DONE is `Done` (ARCH-0079).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TaskReportBody {
    /// The owner's dismissal of a failed task.
    Ack,
    Progress {
        #[serde(default)]
        evidence_refs: Vec<EntityId>,
        /// Renewal is explicit: a note is never a hidden heartbeat.
        #[serde(default)]
        renew_lease: bool,
    },
    Blocked {
        #[serde(default)]
        on: Vec<TaskHandle>,
        #[serde(default)]
        note: Option<String>,
        #[serde(default)]
        ask: Option<Box<TaskAskSpec>>,
    },
    Done {
        result_ref: EntityId,
        /// Rides the attempt receipt (ARCH-0079).
        #[serde(default)]
        confession: Option<String>,
    },
    Failed {
        error: String,
        retryable: bool,
        /// The durable exhaust of the failed try, when there is one.
        #[serde(default)]
        result_ref: Option<EntityId>,
    },
    Release {
        reason: String,
    },
    /// A brief revision: parked as a `tasks.brief` proposal.
    Brief(Box<QueueTaskBrief>),
    /// The owner's title edit at the TASK revision the mirror read surface
    /// exposes (OF-427 C8); the next mirror pass carries it outward.
    Edit {
        expected_revision: u64,
        title: String,
    },
}

impl TaskReportBody {
    /// Stable receipt token.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Ack => "ack",
            Self::Progress { .. } => "progress",
            Self::Blocked { .. } => "blocked",
            Self::Done { .. } => "done",
            Self::Failed { .. } => "failed",
            Self::Release { .. } => "released",
            Self::Brief(_) => "brief",
            Self::Edit { .. } => "edit",
        }
    }
}

/// One highway answer: the durable handle, the handles it relates, and what
/// happened.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskCallReceipt {
    pub handle: TaskHandle,
    pub related: Vec<TaskHandle>,
    pub outcome: TaskOutcome,
    /// The id of the `TaskLifecycle` receipt this call's write kept (its
    /// replay names the first call's). `None` for a read, a fence refusal or
    /// a take another holds, and in an anonymous off-record session.
    pub receipt_ref: Option<String>,
    /// What happened, asked and resolved and why: the `TaskLifecycle`
    /// receipt body this call owes. `None` for a read.
    pub lifecycle: Option<TaskLifecycleRecord>,
    pub idempotent_replay: bool,
}

/// What one call did.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TaskOutcome {
    /// Parked for consent: no TASK, ATTEMPT or route exists yet.
    Proposed {
        decision_ref: Option<String>,
        reason_codes: Vec<String>,
    },
    Created {
        route: Option<TaskRouteOutcome>,
    },
    /// `None` on the human lane, which executes nothing.
    Accepted {
        attempt: Option<AttemptHandle>,
    },
    HeldByOther {
        since: u64,
    },
    /// The interim result of a sub-turn ask: answer it, then re-issue the
    /// same call with the same key (ARCH-0028).
    AskedUp {
        ask: TaskAskHandle,
    },
    Reported {
        phase: TaskPhase,
    },
    Snapshot(Box<TaskStatusView>),
    Unchanged,
    StaleFence,
    WrongNode,
    Rejected {
        decision_ref: Option<String>,
    },
}

/// Where one handle's work stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum TaskPhase {
    Proposed {
        pending: bool,
    },
    Rejected,
    Queued,
    Working {
        started_at: u64,
    },
    Blocked {
        since: u64,
        on: Vec<EntityId>,
    },
    Interrupted,
    Terminal {
        disposition: TaskTerminalDisposition,
    },
    /// An ask handle's group: waiting, or settled.
    Asked {
        settled: bool,
    },
}

/// One handle's status, computed per read. Nothing stores it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskStatusView {
    pub handle: TaskHandle,
    pub task_ref: Option<EntityId>,
    pub phase: TaskPhase,
    pub brief_current: Option<BriefStamp>,
    /// The stamp the live try was leased under.
    pub brief_running: Option<BriefStamp>,
    pub attempt: Option<AttemptView>,
    /// A consent row is waiting in the tray.
    pub pending: bool,
    pub asks: Vec<(TaskAskHandle, TaskAskStatus)>,
    pub last_receipt: Option<String>,
    /// A bound TASK's try and the library program it pinned (CUA E4): the
    /// try a handle names, else the TASK's newest bound one. Absent for an
    /// unbound TASK.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow: Option<TaskWorkflowStatus>,
    /// Digest of everything above; a poll passes it back as `after`.
    #[serde(with = "hex32")]
    pub observed: [u8; 32],
}

/// The live try a status read sees.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptView {
    pub attempt_ref: String,
    pub state: String,
    pub attempt_count: u32,
    pub yours: bool,
    pub claimed_at: Option<u64>,
    pub backoff_until: Option<u64>,
}

/// One bound try's library program (CUA E4): the record its TASK named, the
/// one its first lease resolved that to, the brief it was leased under, and
/// what its strict run came to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskWorkflowStatus {
    pub attempt_ref: String,
    /// The record the TASK's handle named.
    pub requested: EntityId,
    /// The live program the try pinned; `None` when the handle led to none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved: Option<EntityId>,
    pub brief: BriefStamp,
    pub outcome: TaskWorkflowOutcome,
}

/// What a bound try's strict library run came to (CUA E4). Each settled
/// outcome names the receipt NOTE that holds its whole evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskWorkflowOutcome {
    /// Not run yet.
    Pending,
    /// The strict program was started at `at`, under the try's lease, and
    /// its end is not recorded yet (FIX 8104). An entry that finds it hands
    /// the run off as [`TaskWorkflowHandoff::Interrupted`]; it never runs
    /// the program again.
    Started { at: u64 },
    /// The program met its postcondition and every TASK check held.
    Done { receipt_ref: EntityId },
    /// The try went on to its planner, for `cause`.
    Handoff {
        cause: TaskWorkflowHandoff,
        receipt_ref: EntityId,
    },
}

/// Why a bound try went on to its planner (CUA E4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskWorkflowHandoff {
    /// The strict program stopped short, for its own `stop_cause` (E2).
    Program {
        stop_cause: oneiron_browser::BatchStopCause,
    },
    /// The program met its postcondition and a TASK check did not hold
    /// (`task_goal_unmet`).
    GoalUnmet,
    /// The handle's lineage ends at `id`, retired with no successor.
    Retired {
        id: EntityId,
        reason: Option<String>,
    },
    /// No program was ever filed under `id`.
    Missing { id: EntityId },
    /// The library could not be read for `id` at the try's first lease; the
    /// error is in the receipt.
    Unreadable { id: EntityId },
    /// The strict program was started at an earlier entry and its end was
    /// never recorded (FIX 8104): what it did on the page is unknown.
    Interrupted,
}

impl TaskWorkflowHandoff {
    /// The stable code a planner reads the handoff by.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Program { .. } => "workflow_stopped",
            Self::GoalUnmet => "task_goal_unmet",
            Self::Retired { .. } => "workflow_retired",
            Self::Missing { .. } => "workflow_missing",
            Self::Unreadable { .. } => "workflow_unreadable",
            Self::Interrupted => "workflow_interrupted",
        }
    }
}

/// The body of the `TaskLifecycle` receipt one mutating call owes: the call,
/// what was asked, what resolved, and why (ARCH-0079).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskLifecycleRecord {
    pub call: String,
    pub outcome: String,
    pub occurred_at: u64,
    /// No one once the actor was erased (FIX 3520).
    pub actor: TaskActor,
    /// The parent attempt of a host-bound call.
    pub on_behalf_of: Option<String>,
    /// The attempt, in hex.
    pub job_ref: Option<String>,
    /// The TASK, in hex.
    pub trigger_ref: Option<String>,
    pub fields: BTreeMap<String, String>,
}
