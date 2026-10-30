//! The scheduling wire of a model worker (DESIGN-V2 R4, codec v1.3): the
//! order a host asks a worker to run its calls in, and what the worker says
//! it did. A host grants and yields work; it never schedules tokens. The
//! worker's engine chooses which Jobs each round runs: by work class,
//! foreground before background, then priority, then the earliest deadline,
//! then arrival.
//!
//! A worker advertises the wire in its hello as `capabilities.scheduling`
//! ([`SchedulingCapability`]); the session minor stays 1 or 2 on its own.
//! A call's scheduling rides at the body level of its `generate` or
//! `session.generate` frame ([`CallSchedule`]), never in its params, prompt
//! or conditioning. The `schedule` op ([`ScheduleUpdate`]), on the call's
//! own connection under its id and epoch, pauses, resumes or reprioritizes
//! it; the worker answers [`ScheduleAck`] once its owner thread has applied
//! it between rounds. A call's `final` or `released` carries its
//! [`SchedulingReceipt`].
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue};

/// The hello capability that advertises the scheduling wire.
pub const SCHEDULING_CAPABILITY: &str = "scheduling";

/// The codec minor of the scheduling wire (codec v1.3).
pub const SCHEDULING_SCHEMA_MINOR: u64 = 3;

/// The policy that orders a worker's Jobs by class, priority, deadline and
/// arrival; a worker under any other policy (`fifo`) reads the fields and
/// runs every admitted Job each round in arrival order.
pub const SCHEDULING_POLICY: &str = "class_deadline_v1";

/// What orders work: foreground before background.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkClass {
    /// The default: a call that names no class keeps the standing every
    /// call had before R4.
    #[default]
    Foreground,
    Background,
}

/// What groups device budgets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceClass {
    Chat,
    Encoder,
    Embedder,
    Asr,
    Tts,
}

/// A call's priority within its class: `0` on the wire, the default, or
/// `1`, raised.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub enum WorkPriority {
    #[default]
    Normal,
    Raised,
}

impl From<WorkPriority> for u8 {
    fn from(priority: WorkPriority) -> Self {
        match priority {
            WorkPriority::Normal => 0,
            WorkPriority::Raised => 1,
        }
    }
}

impl TryFrom<u8> for WorkPriority {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Normal),
            1 => Ok(Self::Raised),
            other => Err(format!("a work priority is 0 or 1, not {other}")),
        }
    }
}

/// The device grant a call runs under, as the worker checks it: for the
/// worker's resource class, at a revision no lower than one it holds for the
/// same grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionGrant {
    pub grant_id: u64,
    pub revision: u64,
    pub resource_class: ResourceClass,
    pub profile_id: String,
    pub envelope_mib: u64,
}

/// A call's scheduling, sent at the body level of its `generate` frame.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallSchedule {
    pub work_class: WorkClass,
    pub priority: WorkPriority,
    /// When the call's answer is due; sent as the microseconds left.
    pub deadline: Option<Instant>,
    /// The device grant; a call with none is admitted and counted.
    pub admission: Option<AdmissionGrant>,
}

impl CallSchedule {
    /// The body fields at `now`: `work_class`, `priority`, `deadline` (the
    /// microseconds left, null for none) and `admission` when there is one.
    #[must_use]
    pub fn body_fields(&self, now: Instant) -> JsonMap<String, JsonValue> {
        let mut fields = JsonMap::new();
        fields.insert("work_class".to_owned(), wire_value(self.work_class));
        fields.insert("priority".to_owned(), wire_value(self.priority));
        fields.insert("deadline".to_owned(), deadline_value(self.deadline, now));
        if let Some(admission) = &self.admission {
            fields.insert("admission".to_owned(), wire_value(admission));
        }
        fields
    }
}

/// What a `schedule` op asks of a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleAction {
    /// Pause it from the next engine round on; its pages, place and state
    /// stay.
    Yield,
    /// Run it again from the next round on.
    Resume,
    /// Change its class, priority or deadline.
    Reprioritize,
}

/// One `schedule` op: a revision above the call's, its action, and for
/// [`ScheduleAction::Reprioritize`] the fields it changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleUpdate {
    pub revision: u64,
    pub action: ScheduleAction,
    pub work_class: Option<WorkClass>,
    pub priority: Option<WorkPriority>,
    /// `None` keeps the deadline, `Some(None)` clears it.
    pub deadline: Option<Option<Instant>>,
}

impl ScheduleUpdate {
    /// The op's body at `now`.
    #[must_use]
    pub fn body(&self, now: Instant) -> JsonValue {
        let mut fields = JsonMap::new();
        fields.insert("revision".to_owned(), JsonValue::from(self.revision));
        fields.insert("action".to_owned(), wire_value(self.action));
        if let Some(work_class) = self.work_class {
            fields.insert("work_class".to_owned(), wire_value(work_class));
        }
        if let Some(priority) = self.priority {
            fields.insert("priority".to_owned(), wire_value(priority));
        }
        if let Some(deadline) = self.deadline {
            fields.insert("deadline".to_owned(), deadline_value(deadline, now));
        }
        JsonValue::Object(fields)
    }
}

/// Where a worker's change takes effect: its next engine round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleBoundary {
    pub kind: String,
    pub round: u64,
}

/// A worker's `schedule_ack`: whether its owner thread applied the update,
/// where the call stands, and from which round. `found` is false for a call
/// that was not open on that connection; `reason` names why an update did
/// not apply (`stale_revision`, `ended`, `invalid_request`, `closing`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ScheduleAck {
    pub found: bool,
    #[serde(default)]
    pub applied: bool,
    #[serde(default)]
    pub action: Option<ScheduleAction>,
    #[serde(default)]
    pub revision: Option<u64>,
    /// `accepted`, `queued`, `starting`, `prefill`, `decode`,
    /// `waiting_pages`, `custody` or `ended`.
    #[serde(default)]
    pub phase: Option<String>,
    /// Paused by the host's yield.
    #[serde(default)]
    pub paused: Option<bool>,
    /// Left out of the last round by the policy.
    #[serde(default)]
    pub withheld: Option<bool>,
    #[serde(default)]
    pub work_class: Option<WorkClass>,
    #[serde(default)]
    pub priority: Option<WorkPriority>,
    /// Negative once the deadline has passed.
    #[serde(default)]
    pub deadline_remaining_us: Option<i64>,
    #[serde(default)]
    pub next_boundary: Option<ScheduleBoundary>,
    #[serde(default)]
    pub reason: Option<String>,
    /// The worker's cheap stats when it applied the update.
    #[serde(default)]
    pub stats: Option<JsonValue>,
}

/// A worker's `capabilities.scheduling`: only what its policy does.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SchedulingCapability {
    pub minor: u64,
    pub policy: String,
    /// Background prefill runs in bounded chunks.
    pub chunked_prefill: bool,
    /// The worker takes the `schedule` op.
    pub update: bool,
}

impl SchedulingCapability {
    /// Whether the worker orders its Jobs by class, priority and deadline.
    #[must_use]
    pub fn prioritized(&self) -> bool {
        self.minor >= SCHEDULING_SCHEMA_MINOR && self.policy == SCHEDULING_POLICY
    }

    /// Whether the worker takes the `schedule` op.
    #[must_use]
    pub fn takes_updates(&self) -> bool {
        self.prioritized() && self.update
    }
}

/// A call's `scheduling` receipt in its `final` or `released`: its context
/// at its end, and what the worker's executor did with its Jobs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulingReceipt {
    pub policy: String,
    pub work_class: WorkClass,
    pub priority: WorkPriority,
    pub revision: u64,
    pub paused: bool,
    #[serde(default)]
    pub deadline_remaining_us: Option<i64>,
    #[serde(default)]
    pub grant_id: Option<u64>,
    #[serde(default)]
    pub profile_id: Option<String>,
    #[serde(default)]
    pub envelope_mib: Option<u64>,
    pub rounds_run: u64,
    /// Rounds the policy left its Jobs out.
    pub rounds_withheld: u64,
    /// Rounds the host's yield paused them.
    pub rounds_yielded: u64,
    pub paused_us: u64,
    pub prefill_chunks: u64,
    pub prefill_chunk_tokens_max: u64,
    /// Its wait behind a solo call, which nothing preempts.
    pub solo_wait_us: u64,
    /// Its Job could not be cancelled: the worker keeps its charges until
    /// the Job ends there.
    #[serde(default)]
    pub custody: bool,
}

fn wire_value(value: impl Serialize) -> JsonValue {
    serde_json::to_value(value).unwrap_or(JsonValue::Null)
}

/// A deadline as the wire carries it: the whole microseconds left at `now`,
/// zero once it has passed, or null for none.
fn deadline_value(deadline: Option<Instant>, now: Instant) -> JsonValue {
    deadline.map_or(JsonValue::Null, |deadline| {
        let left = deadline.saturating_duration_since(now).as_micros();
        JsonValue::from(u64::try_from(left).unwrap_or(u64::MAX))
    })
}
