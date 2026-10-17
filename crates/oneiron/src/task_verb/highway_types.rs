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
        crate::attempt_queue::AttemptQueue::new(vault)
            .get(self.parent)?
            .filter(|record| {
                record.state == crate::attempt_queue::AttemptState::Leased
                    && record.lease_owner.as_deref() == Some(self.lease_owner.as_str())
                    && record.attempt_count == self.attempt_count
            })
            .ok_or(crate::Error::InvalidClaimBody(
                "the run's lease no longer holds",
            ))
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
}

/// Accept one TASK addressed to the caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskAccept {
    pub task_ref: EntityId,
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
    /// The persisted lifecycle receipt's id, once the receipt store keeps it.
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

/// The body of the `TaskLifecycle` receipt one mutating call owes: the call,
/// what was asked, what resolved, and why (ARCH-0079).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskLifecycleRecord {
    pub call: String,
    pub outcome: String,
    pub occurred_at: u64,
    pub actor: EntityId,
    /// The parent attempt of a host-bound call.
    pub on_behalf_of: Option<String>,
    /// The attempt, in hex.
    pub job_ref: Option<String>,
    /// The TASK, in hex.
    pub trigger_ref: Option<String>,
    pub fields: BTreeMap<String, String>,
}
