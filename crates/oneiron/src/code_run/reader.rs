//! Reader forks (ARCH-0079 #reader-forks): a code run hands one of its
//! results to a child run that reads it and answers with a finding.
//!
//! A child is a routed job row of its parent run, not a highway TASK: a
//! session's children live in its overlay and evaporate with it, and a read
//! split ten thousand ways mints no synced entity. The row keeps a terminal
//! report's discipline all the same: one fenced settle, a replay of the same
//! finding answered as one, and a refusal once the job is settled.
//!
//! Every time here is unix milliseconds on one clock: the parent's cutoff,
//! fixed in its parent row at its first spawn.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::agent_dispatch::SpendScopeId;
use crate::attempt_queue::AttemptId;
use crate::vault::VaultId;
use crate::{EdgeActorClass, EntityId, Error, Result, Vault, WriteActor};

/// What the parent keeps back of its own window for the fold that reads its
/// children's findings: the fold's code-first dedupe plus two staged
/// summarize rounds at ~20 s a model call.
pub const DEFAULT_READER_FOLD_RESERVE_MS: u64 = 60_000;

/// The longest spawn or wait key, in bytes.
pub(crate) const READER_KEY_MAX_BYTES: usize = 256;

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

/// What the host lends a run that may spawn readers: the scope its children
/// spend under, its clock, and what each child holds at its claim. The run's
/// actor and route are its dispatcher's own; the parent run is the bridge
/// call's, never guest text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnHostSeat {
    pub spend: SpendScopeId,
    pub deadline: RunDeadline,
    pub hold_units: u64,
}

/// The result one child reads, as its parent's spawn resolved it: the
/// parent's occurrence of it (`owner` and `path`), its handle, the range of
/// its body the child may read, in the parent's offsets, and the rows the
/// parent's results were served from (`None` when one answer kept no set).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegatedSource {
    pub owner: EntityId,
    pub path: String,
    pub handle: String,
    pub range: (u64, u64),
    pub rows: Option<Vec<EntityId>>,
}

/// A child's finding: one of its own stored JSON results, by its occurrence
/// in the child run and its handle, its size, and the rows the child's
/// results were served from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReaderFindingRef {
    pub owner: EntityId,
    pub path: String,
    pub handle: String,
    pub bytes: u64,
    pub rows: Option<Vec<EntityId>>,
}

/// `self.spawn(...)`: the guest's source, ask and key. `bound` is the source
/// as the host resolved it in the parent run; it is the host's, never the
/// guest's, and the run's record keeps the guest's call without it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfReaderSpawnCall {
    pub source: String,
    pub ask: String,
    pub intent_key: String,
    pub bound: Option<DelegatedSource>,
}

/// `tasks.update({task_ref, resultRef})` from a reader child: its task and
/// the result name of its finding. `bound` is the finding as the host
/// resolved it among the child's own results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfReaderReportCall {
    pub task: EntityId,
    pub result_ref: String,
    pub bound: Option<ReaderFindingRef>,
}

/// `tasks.wait({tasks, all?, n_of?, until?, step_key})`, as the guest wrote
/// it; the dispatcher normalises it against the run's children.
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

/// What a child's report answers: its task, its finding's handle, and
/// whether the same finding was already its latest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReaderReportReceipt {
    pub task: EntityId,
    #[serde(rename = "ref")]
    pub finding: String,
    pub replay: bool,
}

/// A child whose finding a wait counts: its task, its finding's handle (the
/// `ref` the parent reads it by) and size, and why it settled short, for a
/// partial one.
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

/// One reduction of a wait set over its children.
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

/// A parent run's reader row: its clock, fixed at its first spawn, the scope
/// its children spend under, what each holds at its claim, and its counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReaderParent {
    pub deadline: RunDeadline,
    pub spend: SpendScopeId,
    pub hold_units: u64,
    pub next_ordinal: u64,
    pub queued: u64,
    pub active: u64,
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

/// What a child is bound to: its parent run, actor and route, the source it
/// reads, the scope it spends under and the clock it stops on. Never the
/// parent's door, credential or body bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpawnParentBinding {
    pub parent_run: EntityId,
    pub actor: ReaderActor,
    pub source: DelegatedSource,
    pub route: ReaderRoute,
    pub spend: SpendScopeId,
    pub deadline: RunDeadline,
    pub child_cutoff_unix_ms: u64,
}

/// Where a child stands. A settled one (`Done`, `Partial`, `Failed`) never
/// moves again.
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

/// One reader child. `generation` counts its claims and fences: a report or
/// a read made under an older one is refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReaderJob {
    pub task: EntityId,
    pub attempt: AttemptId,
    pub run: EntityId,
    pub binding: SpawnParentBinding,
    pub ask: String,
    pub state: ReaderJobState,
    pub generation: u32,
    pub finding: Option<ReaderFindingRef>,
    pub enqueued_at_ms: u64,
    pub settled_at_ms: Option<u64>,
}

/// How a child's run ended, as its runner tells it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReaderRunEnd {
    Completed,
    Failed(String),
    Cutoff,
    SpendExhausted,
}

impl ReaderRunEnd {
    /// Why a run that did not complete stopped.
    pub(crate) fn reason(&self) -> &str {
        match self {
            Self::Completed => "completed",
            Self::Failed(reason) => reason,
            Self::Cutoff => "cutoff",
            Self::SpendExhausted => "spend",
        }
    }
}

/// What a claim of a queued child came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// The child is the runner's to run, at its new generation.
    Claimed(Box<ReaderJob>),
    /// Its parent's scope has nothing left to hold; it stays queued until a
    /// sibling settles or its cutoff settles it.
    WaitingForSpend,
    /// Its source is not yet in its parent's committed record; the runner
    /// tries again on its tick.
    SourceNotReady,
    /// It is settled, or its cutoff settled it now.
    Settled,
}

/// What the runner is told when a child is queued. It must not block or
/// touch storage: it only notes the job, as a [`crate::limit_ask::LimitAsk`]
/// port only notes a crossing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReaderJobWake {
    /// The vault store's id, hex, as [`ReaderRoute::vault`] names it.
    pub vault: String,
    pub task: EntityId,
    pub session_ref: Option<String>,
}

/// Where a vault's queued reader children go to run. With none installed,
/// they stay queued and the due sweep settles them at their cutoff.
pub trait ReaderJobRunner: Send + Sync {
    fn wake(&self, wake: ReaderJobWake);
}

impl Vault {
    /// Installs the runner this vault's reader children are woken through,
    /// in place of any before it.
    pub fn set_reader_job_runner(&self, runner: Arc<dyn ReaderJobRunner>) {
        *self
            .store
            .reader_job_runner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(runner);
    }

    /// The runner installed for this vault's reader children, if any.
    pub(crate) fn reader_job_runner(&self) -> Option<Arc<dyn ReaderJobRunner>> {
        self.store
            .reader_job_runner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// A vault store's id as a child's route names it.
pub(crate) fn vault_ref(vault: VaultId) -> String {
    crate::entity_id::bytes_to_hex_lower(vault.as_bytes())
}

/// The child task a parent's spawn key names: the same key is the same
/// child.
pub(crate) fn reader_task_id(parent_run: EntityId, intent_key: &str) -> Result<EntityId> {
    EntityId::derive(
        b"oneiron:code-reader-task:v1",
        &[parent_run.as_bytes().as_slice(), intent_key.as_bytes()],
    )
}

/// The run a child task runs as.
pub(crate) fn reader_run_id(task: EntityId) -> Result<EntityId> {
    EntityId::derive(
        b"oneiron:code-reader-run:v1",
        &[task.as_bytes().as_slice()],
    )
}

/// The attempt a child's spend scope is keyed by (OF-532). It has no queue
/// row: a scope with no queued attempt is found by its own id.
pub(crate) fn reader_attempt_id(task: EntityId) -> Result<AttemptId> {
    let id = EntityId::derive(
        b"oneiron:code-reader-attempt:v1",
        &[task.as_bytes().as_slice()],
    )?;
    AttemptId::from_bytes(id.as_bytes())
}

/// The wait set a parent's step key names.
pub(crate) fn reader_wait_id(parent_run: EntityId, step_key: &str) -> Result<EntityId> {
    EntityId::derive(
        b"oneiron:code-reader-wait:v1",
        &[parent_run.as_bytes().as_slice(), step_key.as_bytes()],
    )
}

/// Whether `key` is a spawn or wait key: not blank, and at most
/// [`READER_KEY_MAX_BYTES`] bytes.
pub(crate) fn valid_reader_key(key: &str) -> bool {
    !key.trim().is_empty() && key.len() <= READER_KEY_MAX_BYTES
}

/// Reduces a wait set over its children's rows as they stand at `now_ms`.
/// `jobs` is each of the set's tasks with its row when the parent spawned
/// it; a task the parent did not spawn reads as unknown, as a task with no
/// row does. A failed child never counts as a finding.
pub(crate) fn reduce_task_wait_set(
    set: &TaskWaitSet,
    jobs: &[(EntityId, Option<ReaderJob>)],
    now_ms: u64,
) -> TaskWaitSetResult {
    let mut result = TaskWaitSetResult {
        ready: Vec::new(),
        partial: Vec::new(),
        failed: Vec::new(),
        pending: Vec::new(),
        done: false,
        reason: None,
        until: set.until_ms,
    };
    let finding = |task: EntityId, finding: &ReaderFindingRef, reason: Option<&str>| TaskWaitFinding {
        task,
        finding: finding.handle.clone(),
        bytes: finding.bytes,
        reason: reason.map(str::to_owned),
    };
    for (task, job) in jobs {
        let failed = |reason: &str| TaskWaitFailure {
            task: task.to_hex(),
            reason: reason.to_owned(),
        };
        let Some(job) = job.as_ref().filter(|job| job.binding.parent_run == set.parent_run) else {
            result.failed.push(failed("unknown_task"));
            continue;
        };
        match (&job.state, &job.finding) {
            (ReaderJobState::Queued | ReaderJobState::Active, _) => result.pending.push(*task),
            (ReaderJobState::Done, Some(found)) => result.ready.push(finding(*task, found, None)),
            (ReaderJobState::Partial { reason }, Some(found)) => {
                result.partial.push(finding(*task, found, Some(reason)));
            }
            (ReaderJobState::Done, None) => result.failed.push(failed("no_finding")),
            (ReaderJobState::Partial { reason } | ReaderJobState::Failed { reason }, _) => {
                result.failed.push(failed(reason));
            }
        }
    }
    let usable = (result.ready.len() + result.partial.len()) as u64;
    let pending = result.pending.len() as u64;
    let reason = match set.policy {
        TaskWaitPolicy::All if pending == 0 => Some("all"),
        TaskWaitPolicy::NOf { n } if usable >= u64::from(n) => Some("quorum"),
        TaskWaitPolicy::NOf { n } if usable + pending < u64::from(n) => Some("impossible"),
        _ if now_ms >= set.until_ms => Some("cutoff"),
        _ => None,
    };
    result.done = reason.is_some();
    result.reason = reason.map(str::to_owned);
    result
}

/// The child's task text: its ask, its source, the protocol it answers by,
/// the shape of its finding, and its cutoff.
#[must_use]
pub fn reader_task_brief(job: &ReaderJob) -> String {
    let source = &job.binding.source;
    let (start, end) = source.range;
    format!(
        "You are a reader child of a code run. Read one result of your parent and answer \
         one question about it.\n\
         Question: {ask}\n\
         Source: the result named `src` (handle {handle}), bytes {start} to {end} of your \
         parent's body. Read it with describe, slice, search, query and chunks on `src` or on a \
         range ref inside it, `{handle}#<start>-<end>`; every offset is your parent's. No other \
         result, verb or write is yours.\n\
         Protocol: store your finding with `store(finding)`, then call \
         `tasks.update({{task_ref: \"{task}\", resultRef: <its name>}})`. A later report \
         replaces an earlier one; the latest one stands when your run ends.\n\
         Finding: one JSON object, {{\"answer\": ..., \"cites\": [[start, end], ...], \
         \"coverage\": [[start, end], ...], \"partial\": true|false}}, its spans in your \
         parent's byte offsets: `cites` what the answer rests on, `coverage` what you read. Set \
         `partial` when you did not read the whole source.\n\
         Cutoff: unix ms {cutoff}. Report before it; a report after it is refused.",
        ask = job.ask,
        handle = source.handle,
        task = job.task.to_hex(),
        cutoff = job.binding.child_cutoff_unix_ms,
    )
}
