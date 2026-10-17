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

/// What a run's reader children spend on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReaderSpend {
    /// Under this scope: each child holds a child scope of it from its
    /// claim, spends on that scope's guard and records what it used there
    /// once its run ends. A scope that is not open refuses every spawn as
    /// unmetered.
    Scope(SpendScopeId),
    /// On the meter the host runs the parent's own model calls on: served
    /// code mode's shared guard (`models.code_mode.budget_units`). No ledger
    /// scope and no hold at the claim; the guard settles each call itself,
    /// as it does the parent's, and its exhaustion suspends them all alike.
    Host,
}

impl ReaderSpend {
    /// The one choice of what a run's children spend on, from the scope the
    /// run's own model calls spend under: that scope when it has one, else
    /// the host's meter its own calls run on (`execute_code` runs and
    /// unmetered resident attempts). There is no per-run cap on the host's
    /// meter until a run carries a shown maximum.
    #[must_use]
    pub fn for_run_scope(scope: Option<SpendScopeId>) -> Self {
        scope.map_or(Self::Host, Self::Scope)
    }

    /// The scope the children spend under, when they spend under one.
    #[must_use]
    pub const fn scope(&self) -> Option<&SpendScopeId> {
        match self {
            Self::Scope(scope) => Some(scope),
            Self::Host => None,
        }
    }
}

/// What the host lends a run that may spawn readers: what its children
/// spend on, its clock, what each child holds at its claim, the window of
/// the model its children and summaries run on, in tokens, and the memory one
/// child may hold, in bytes. The run's actor and route are its dispatcher's
/// own; the parent run is the bridge call's, never guest text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnHostSeat {
    pub spend: ReaderSpend,
    pub deadline: RunDeadline,
    pub hold_units: u64,
    pub window_tokens: u64,
    pub memory_bytes: u64,
}

/// The window a seat names when its host knows none, in tokens.
pub const DEFAULT_READER_WINDOW_TOKENS: u64 = 32_768;

/// Why a summary job's group did not fit its model's window: the bundled
/// `readAll` splits a group that settles with a reason starting with it.
pub const SUMMARY_GROUP_EXCEEDS_WINDOW: &str = "group_exceeds_window";

/// The share of its model's window one summary's input may fill: one part
/// in this many.
pub const SUMMARY_WINDOW_DIVISOR: u64 = 2;

/// The bytes a token is taken to stand for when a summary's group is sized
/// before it is read: a group whose bytes pass its window share at this
/// many bytes a token is refused unread, as too big for it.
pub const SUMMARY_READ_BYTES_PER_TOKEN: u64 = 8;

/// The tokens one summary's input may take on a model of `window_tokens`.
#[must_use]
pub const fn summary_token_budget(window_tokens: u64) -> u64 {
    window_tokens / SUMMARY_WINDOW_DIVISOR
}

/// The reason a summary whose input took `tokens` of a `window_tokens`
/// window settles with.
#[must_use]
pub fn summary_exceeds_window(tokens: u64, window_tokens: u64) -> String {
    format!("{SUMMARY_GROUP_EXCEEDS_WINDOW} tokens={tokens} window_tokens={window_tokens}")
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

/// What one summary is made by: its prompt's version and its effort. Two
/// summaries of the same members by the same recipe are one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummarizeRecipe {
    pub version: u32,
    pub effort: SummarizeEffort,
}

impl SummarizeRecipe {
    /// The prompt version every summary is made by now.
    pub const VERSION: u32 = 1;

    #[must_use]
    pub const fn new(effort: SummarizeEffort) -> Self {
        Self {
            version: Self::VERSION,
            effort,
        }
    }

    /// The recipe's bytes, as its memo key hashes them.
    #[must_use]
    pub fn key_bytes(&self) -> Vec<u8> {
        let mut bytes = self.version.to_be_bytes().to_vec();
        bytes.extend_from_slice(self.effort.as_str().as_bytes());
        bytes
    }
}

/// What a reader job does: a child run that reads its source, or one model
/// call that summarizes its members, in order, by its recipe. `memo` is the
/// summary's memo key; `window_tokens` the window of the model it runs on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReaderJobKind {
    Read,
    Summarize {
        members: Vec<DelegatedSource>,
        recipe: SummarizeRecipe,
        memo: [u8; 32],
        window_tokens: u64,
    },
}

/// `summarize(r, {effort?, group?, defer?})`: the guest's ref, the members
/// after it, its effort and whether it answers at once. `bound` is every
/// member as the host resolved it in the run, in order; it is the host's,
/// never the guest's, and the run's record keeps the guest's call without
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfSummarizeCall {
    pub reference: String,
    pub effort: Option<SummarizeEffort>,
    pub group: Option<Vec<String>>,
    pub defer: bool,
    pub bound: Option<Vec<DelegatedSource>>,
}

impl SelfSummarizeCall {
    /// Every member the call names, in order: its ref, then its group.
    #[must_use]
    pub fn members(&self) -> Vec<&str> {
        std::iter::once(self.reference.as_str())
            .chain(self.group.iter().flatten().map(String::as_str))
            .collect()
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

/// The memo key of a summary of `members` by `recipe`: each member's
/// occurrence and range, in order, then the recipe, so authority and taint
/// stay per occurrence.
pub(crate) fn summary_memo_key(
    members: &[DelegatedSource],
    recipe: &SummarizeRecipe,
) -> Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron:reader-summarize:v1");
    for member in members {
        let occurrence = crate::code_run::ResultOccurrence::owned(member.owner, &member.path)?;
        hasher.update(occurrence.id().as_bytes());
        hasher.update(&member.range.0.to_be_bytes());
        hasher.update(&member.range.1.to_be_bytes());
    }
    hasher.update(&recipe.key_bytes());
    Ok(*hasher.finalize().as_bytes())
}

/// The summary task a parent's memo key names: the same members by the same
/// recipe are the same task.
pub(crate) fn summary_task_id(parent_run: EntityId, memo: &[u8; 32]) -> Result<EntityId> {
    EntityId::derive(
        b"oneiron:code-reader-summary:v1",
        &[parent_run.as_bytes().as_slice(), memo.as_slice()],
    )
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

/// A parent run's reader row: its clock, fixed at its first spawn, what its
/// children spend on, what each holds at its claim, and its counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReaderParent {
    pub deadline: RunDeadline,
    pub spend: ReaderSpend,
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
/// reads, what it spends on and the clock it stops on. Never the parent's
/// door, credential or body bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpawnParentBinding {
    pub parent_run: EntityId,
    pub actor: ReaderActor,
    pub source: DelegatedSource,
    pub route: ReaderRoute,
    pub spend: ReaderSpend,
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
    pub kind: ReaderJobKind,
    pub ask: String,
    pub state: ReaderJobState,
    pub generation: u32,
    pub finding: Option<ReaderFindingRef>,
    pub enqueued_at_ms: u64,
    pub settled_at_ms: Option<u64>,
}

impl ReaderJob {
    /// Every source the job reads, as its parent delegated it: a child's
    /// one source, or a summary's members.
    #[must_use]
    pub fn sources(&self) -> Vec<&DelegatedSource> {
        match &self.kind {
            ReaderJobKind::Read => vec![&self.binding.source],
            ReaderJobKind::Summarize { members, .. } => members.iter().collect(),
        }
    }
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
    /// The participant the parent ran as in its session, which the runner
    /// reads the session's children as.
    pub participant: Option<EntityId>,
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
    EntityId::derive(b"oneiron:code-reader-run:v1", &[task.as_bytes().as_slice()])
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
    let finding =
        |task: EntityId, finding: &ReaderFindingRef, reason: Option<&str>| TaskWaitFinding {
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
        let Some(job) = job
            .as_ref()
            .filter(|job| job.binding.parent_run == set.parent_run)
        else {
            result.failed.push(failed("unknown_task"));
            continue;
        };
        match (&job.state, &job.finding) {
            (ReaderJobState::Queued | ReaderJobState::Active, _) => result.pending.push(*task),
            (ReaderJobState::Done, Some(found)) => result.ready.push(finding(*task, found, None)),
            (ReaderJobState::Partial { reason }, Some(found)) => {
                result
                    .partial
                    .push(finding(*task, found, Some(reason.as_str())));
            }
            (ReaderJobState::Done, None) => result.failed.push(failed("no_finding")),
            (ReaderJobState::Partial { reason } | ReaderJobState::Failed { reason }, _) => {
                result.failed.push(failed(reason.as_str()));
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
