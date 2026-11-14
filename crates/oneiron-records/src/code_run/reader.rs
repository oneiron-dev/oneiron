//! Moved from `crates/oneiron/src/code_run/reader.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub(crate) use crate::code_run::reader::coverage::merge_ranges;
pub use crate::code_run::reader::origins::DelegatedSource;
pub use crate::code_run::reader::origins::ReaderFindingRef;
pub use crate::code_run::reader::origins::ResultOrigins;
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::write_envelope::WriteActor;
use serde::Deserialize;
use serde::Serialize;
use std::sync::Arc;

/// What the parent keeps back of its own window for the fold that reads its
/// children's findings: the fold's code-first dedupe plus two staged
/// summarize rounds at ~20 s a model call.
pub const DEFAULT_READER_FOLD_RESERVE_MS: u64 = 60_000;

/// The one clock a parent's children run on: its cutoff, and the part of its
/// window kept back for its fold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunDeadline {
    pub cutoff_unix_ms: u64,
    pub fold_reserve_ms: u64,
}

impl RunDeadline {
    /// A cutoff with the default fold reserve, cut to the last quarter of
    /// what is left of the window at `now_ms` (the decision ladder's
    /// last-quarter rule), so a short window still leaves children three
    /// quarters of it.
    #[must_use]
    pub fn with_default_reserve(cutoff_unix_ms: u64, now_ms: u64) -> Self {
        let left = cutoff_unix_ms.saturating_sub(now_ms);
        Self {
            cutoff_unix_ms,
            fold_reserve_ms: DEFAULT_READER_FOLD_RESERVE_MS.min(left / 4),
        }
    }

    /// When every child of the parent stops: its cutoff less its fold
    /// reserve.
    #[must_use]
    pub const fn child_cutoff(&self) -> u64 {
        self.cutoff_unix_ms.saturating_sub(self.fold_reserve_ms)
    }
}

/// How hard one `summarize` works.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SummarizeEffort {
    Low,
    #[default]
    Medium,
    High,
}

impl SummarizeEffort {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// What a `summarize` answers: the summary's card once it is made (a memo
/// hit), its task and state while it is made (`defer`), or the reply a
/// withheld member answers in its place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SummarizeReply {
    Done {
        task: EntityId,
        card: serde_json::Value,
    },
    Pending {
        task: EntityId,
        job: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    Withheld {
        reply: serde_json::Value,
    },
}

impl SummarizeReply {
    /// What the guest reads: the card, `{task, state}`, or the withheld
    /// reply.
    #[must_use]
    pub fn output(&self) -> serde_json::Value {
        match self {
            Self::Done { card, .. } => card.clone(),
            Self::Pending { task, job, reason } => {
                let mut pending = serde_json::json!({"task": task.to_hex(), "state": job});
                if let Some(reason) = reason {
                    pending["reason"] = serde_json::json!(reason);
                }
                pending
            }
            Self::Withheld { reply } => reply.clone(),
        }
    }
}

/// `tasks.wait({tasks, all?, n_of?, until?, step_key})`, as the guest wrote
/// it; the dispatcher normalises it against the run's children. One naming
/// `request` waits on that world-privacy request instead (FIX 4706), and one
/// naming `agents` waits on those AGENT children of the run (slice 6.5b).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskWaitSetCall {
    pub tasks: Vec<String>,
    #[serde(default)]
    pub all: Option<bool>,
    #[serde(default)]
    pub n_of: Option<u32>,
    #[serde(default)]
    pub until: Option<u64>,
    pub step_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
    /// The AGENT children's attempt ids, hex, as `self.agents.spawn`
    /// answered them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agents: Option<Vec<String>>,
}

/// What a spawn answers: the child's task, the attempt its spend is keyed
/// by, its run, its cutoff, and whether the same key had already spawned it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReaderSpawnReceipt {
    pub task: EntityId,
    pub attempt: String,
    pub run: EntityId,
    pub cutoff_unix_ms: u64,
    pub state: String,
    pub replay: bool,
}

/// What a child's report answers: its task, its finding's occurrence ref,
/// and whether the same finding was already its latest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReaderReportReceipt {
    pub task: EntityId,
    #[serde(rename = "ref")]
    pub finding: String,
    pub replay: bool,
}

/// A child whose finding a wait counts: its task, its finding's occurrence
/// ref and size, and why it settled short, for a partial one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskWaitFinding {
    pub task: EntityId,
    #[serde(rename = "ref")]
    pub finding: String,
    pub bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A child a wait cannot count, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskWaitFailure {
    pub task: String,
    pub reason: String,
}

/// One reduction of a wait set over its children; an answer adds their steps' type feedback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskWaitSetResult {
    pub ready: Vec<TaskWaitFinding>,
    pub partial: Vec<TaskWaitFinding>,
    pub failed: Vec<TaskWaitFailure>,
    pub pending: Vec<EntityId>,
    pub done: bool,
    /// Why it is done: `all`, `quorum`, `cutoff` or `impossible`; `None`
    /// while it is not.
    pub reason: Option<String>,
    pub until: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub program_steps: Vec<super::ProgramStepFeedback>,
}

/// How many children a wait set waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TaskWaitPolicy {
    All,
    NOf { n: u32 },
}

/// One wait over a parent's children, keyed by the parent and its step key.
/// Its first done reduction is kept and answers every later call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskWaitSet {
    pub id: EntityId,
    pub parent_run: EntityId,
    pub tasks: Vec<EntityId>,
    pub policy: TaskWaitPolicy,
    pub until_ms: u64,
    pub step_key: String,
    pub settled_at_ms: Option<u64>,
    pub settled: Option<TaskWaitSetResult>,
}

/// The actor a parent runs as, as its children's rows keep it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReaderActor {
    pub entity: EntityId,
    /// [`EdgeActorClass`] as its stored byte.
    pub class: u8,
}

impl ReaderActor {
    #[must_use]
    pub const fn of(actor: WriteActor) -> Self {
        Self {
            entity: actor.entity_ref(),
            class: actor.actor_class() as u8,
        }
    }

    /// The parent's actor again.
    ///
    /// # Errors
    ///
    /// [`Error::CorruptedIndex`] for a class byte no actor class has.
    pub fn write_actor(&self) -> Result<WriteActor> {
        let class = EdgeActorClass::try_from_u8(self.class)
            .ok_or(Error::CorruptedIndex("reader job actor class"))?;
        Ok(WriteActor::new(self.entity, class))
    }
}

/// Where a child's rows and run live: its parent's vault store (its id, hex),
/// and the parent's session and participant when the parent runs off record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReaderRoute {
    pub vault: String,
    pub session_ref: Option<String>,
    pub participant: Option<EntityId>,
}

/// Where a child stands. A settled one (`Done`, `Partial`, `Failed`) never
/// moves again. `Done` is completed with a committed finding: it proves no
/// read of any input (FIX 7735).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ReaderJobState {
    Queued,
    Active,
    Done,
    Partial { reason: String },
    Failed { reason: String },
}

impl ReaderJobState {
    #[must_use]
    pub const fn is_settled(&self) -> bool {
        matches!(
            self,
            Self::Done | Self::Partial { .. } | Self::Failed { .. }
        )
    }

    /// The state's wire word.
    #[must_use]
    pub const fn word(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Active => "active",
            Self::Done => "done",
            Self::Partial { .. } => "partial",
            Self::Failed { .. } => "failed",
        }
    }
}
pub mod coverage;
pub mod origins;
