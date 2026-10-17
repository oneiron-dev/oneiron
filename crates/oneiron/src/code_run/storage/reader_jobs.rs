//! One run's reader children (ARCH-0079 #reader-forks), where the run's rows
//! are: base, or its off-record room's overlay, through the route it captured
//! at entry. Every job, wait set and finding row goes through one transaction
//! door, so a session's children evaporate with its room. Only their spend
//! scopes are base rows, as the parent's own scope is: units and ids, no
//! content.

use std::collections::BTreeMap;

use heed::{RoTxn, RwTxn};

use super::reader_folds::{MEMOS, SummaryMemo};
use super::records::REPLAY_RECORDS;
use super::wait_delivery::deliver_wait_in_txn;
use crate::agent_dispatch::{AgentDispatcher, ChildSpend, SpendScope, SpendScopeId, SpendState};
use crate::attempt_queue::AttemptId;
use crate::code_run::CodeRunRawOutput;
use crate::code_run::{
    ClaimOutcome, DelegatedSource, ExecutorStorage, ReaderActor, ReaderFindingRef, ReaderJob,
    ReaderJobKind, ReaderJobState, ReaderParent, ReaderRoute, ReaderRunEnd, SpawnHostSeat,
    SpawnParentBinding, TaskWaitSet, TaskWaitSetResult, reduce_task_wait_set,
};
use crate::side_table::{
    self, CodecError, Raw, RawValue, RoutedDbs, SideCodec, SideKey, SideTable,
};
use crate::{EntityId, Error, Result, Vault};

/// One row per child, keyed by its task.
const JOBS: SideTable<EntityId, ReaderJob, Raw> = SideTable::new(&side_table::CODE_RUN_READER_JOB);
/// One row per parent run.
const PARENTS: SideTable<EntityId, ReaderParent, Raw> =
    SideTable::new(&side_table::CODE_RUN_READER_PARENT);
/// One row per wait set.
const WAITS: SideTable<EntityId, TaskWaitSet, Raw> =
    SideTable::new(&side_table::CODE_RUN_READER_WAIT);
/// The tagged index rows (`c`, `f`, `q`, `w`, `d`) the declaration names.
const INDEX: SideTable<Vec<u8>, Vec<u8>, Raw> = SideTable::new(&side_table::CODE_RUN_READER_INDEX);

/// A `d` row's value: the id after its due time is a wait set's.
const DUE_SET: &[u8] = b"s";
/// A `d` row's value: the id after its due time is a child's task.
const DUE_JOB: &[u8] = b"j";

/// The one name a summary job's run binds its text to.
const SUMMARY_RESULT_NAME: &str = "summary";

macro_rules! json_row {
    ($row:ty, $what:literal) => {
        impl RawValue for $row {
            fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
                serde_json::to_vec(self).map_err(|_| Error::CorruptedIndex($what).into())
            }

            fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
                serde_json::from_slice(bytes).map_err(|_| Error::CorruptedIndex($what).into())
            }
        }
    };
}

json_row!(ReaderJob, "code-run reader job");
json_row!(ReaderParent, "code-run reader parent");
json_row!(TaskWaitSet, "code-run reader wait set");

fn tagged(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    let mut key = vec![tag];
    for part in parts {
        key.extend_from_slice(part);
    }
    key
}

fn child_key(parent: EntityId, ordinal: u64, task: EntityId) -> Vec<u8> {
    tagged(
        b'c',
        &[parent.as_bytes(), &ordinal.to_be_bytes(), task.as_bytes()],
    )
}

fn finding_key(parent: EntityId, handle: &str) -> Vec<u8> {
    tagged(b'f', &[parent.as_bytes(), handle.as_bytes()])
}

fn queued_key(enqueued_ms: u64, task: EntityId) -> Vec<u8> {
    tagged(b'q', &[&enqueued_ms.to_be_bytes(), task.as_bytes()])
}

fn waiter_key(task: EntityId, set: EntityId) -> Vec<u8> {
    tagged(b'w', &[task.as_bytes(), set.as_bytes()])
}

fn due_key(due_ms: u64, id: EntityId) -> Vec<u8> {
    tagged(b'd', &[&due_ms.to_be_bytes(), id.as_bytes()])
}

/// The id at `at` in an index key, 16 bytes.
fn id_at(key: &[u8], at: usize) -> Result<EntityId> {
    let bytes: [u8; 16] = key
        .get(at..at + 16)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(Error::CorruptedIndex("code-run reader index key"))?;
    EntityId::from_bytes(bytes)
}

/// The big-endian time at `at` in an index key.
fn time_at(key: &[u8], at: usize) -> Result<u64> {
    let bytes: [u8; 8] = key
        .get(at..at + 8)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(Error::CorruptedIndex("code-run reader index key"))?;
    Ok(u64::from_be_bytes(bytes))
}

/// The base spend scopes a run's children spend under (OF-532): the one
/// part of the base vault a session's reader rows reach, and only for units
/// and ids.
#[derive(Clone, Copy)]
pub(crate) struct SpendBook<'v>(&'v Vault);

impl<'v> SpendBook<'v> {
    pub(crate) const fn new(vault: &'v Vault) -> Self {
        Self(vault)
    }

    fn spend(self) -> AgentDispatcher<'v> {
        AgentDispatcher::new(self.0)
    }

    /// `scope`'s row while it is open.
    fn open_scope_in_txn(
        self,
        txn: &RoTxn<'_>,
        scope: &SpendScopeId,
    ) -> Result<Option<SpendScope>> {
        Ok(self
            .spend()
            .scope_with_root_in_txn(txn, scope)?
            .map(|(row, _)| row)
            .filter(|row| row.state == SpendState::Open))
    }

    /// What `scope` may still spend, in the caller's snapshot.
    fn available_in_txn(self, txn: &RoTxn<'_>, scope: &SpendScopeId) -> Result<u64> {
        self.spend().available_units_in_txn(txn, scope)
    }

    /// `scope`'s row while it is open, and what it may still spend.
    pub(crate) fn open_scope(self, scope: &SpendScopeId) -> Result<Option<(SpendScope, u64)>> {
        let txn = self.0.store.env.read_txn()?;
        let Some(row) = self.open_scope_in_txn(&txn, scope)? else {
            return Ok(None);
        };
        Ok(Some((row, self.available_in_txn(&txn, scope)?)))
    }
}

/// One transaction of a run's reader rows: read through the route's
/// composed view, written along it, with the base spend scopes beside them.
///
/// A session's view composes the overlay snapshot it was opened on, which
/// the rows this transaction stages do not change, so every row it writes
/// is kept here too and read back from here: a transaction reads its own
/// writes on every route.
pub(crate) struct ReaderTxn<'t, 'e> {
    txn: &'t mut RwTxn<'e>,
    read: RoutedDbs<'t>,
    write: RoutedDbs<'t>,
    spend: SpendBook<'t>,
    /// Rows written in this transaction by their full key: the encoded
    /// value, or `None` for a deleted row.
    staged: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    /// The canonical vault, whose wait deliveries commit in this
    /// transaction; `None` on a session's route.
    vault: Option<&'t Vault>,
    /// The wait sets this transaction settled on a session's route, each
    /// delivered along it once the transaction commits: its id, its reply
    /// and when it settled.
    settled: Vec<(EntityId, serde_json::Value, u64)>,
}

impl ReaderTxn<'_, '_> {
    fn get_row<K: SideKey, V, C: SideCodec<V>>(
        &self,
        table: &SideTable<K, V, C>,
        key: &K,
    ) -> Result<Option<V>> {
        match self.staged.get(&table.key_bytes(key)) {
            Some(staged) => staged
                .as_deref()
                .map(|bytes| table.decode_value(bytes))
                .transpose(),
            None => table.get(&self.read, &*self.txn, key),
        }
    }

    fn put_row<K: SideKey, V, C: SideCodec<V>>(
        &mut self,
        table: &SideTable<K, V, C>,
        key: &K,
        value: &V,
    ) -> Result<()> {
        table.put(&self.write, self.txn, key, value)?;
        self.staged
            .insert(table.key_bytes(key), Some(table.encode_value(value)?));
        Ok(())
    }

    fn job(&self, task: EntityId) -> Result<Option<ReaderJob>> {
        self.get_row(&JOBS, &task)
    }

    fn put_job(&mut self, job: &ReaderJob) -> Result<()> {
        self.put_row(&JOBS, &job.task, job)
    }

    fn parent(&self, run: EntityId) -> Result<Option<ReaderParent>> {
        self.get_row(&PARENTS, &run)
    }

    fn put_parent(&mut self, run: EntityId, parent: &ReaderParent) -> Result<()> {
        self.put_row(&PARENTS, &run, parent)
    }

    fn wait(&self, set: EntityId) -> Result<Option<TaskWaitSet>> {
        self.get_row(&WAITS, &set)
    }

    fn put_wait(&mut self, set: &TaskWaitSet) -> Result<()> {
        self.put_row(&WAITS, &set.id, set)
    }

    fn index(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.get_row(&INDEX, &key.to_vec())
    }

    fn put_index(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        self.put_row(&INDEX, &key.to_vec(), &value.to_vec())
    }

    fn delete_index(&mut self, key: &[u8]) -> Result<()> {
        let key = key.to_vec();
        INDEX.delete(&self.write, self.txn, &key)?;
        self.staged.insert(INDEX.key_bytes(&key), None);
        Ok(())
    }

    /// The index rows under `prefix` in key order, this transaction's own
    /// writes and deletes over what the view held.
    fn scan_index(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut rows: BTreeMap<Vec<u8>, Vec<u8>> = INDEX
            .iter_from(&self.read, &*self.txn, prefix)?
            .collect::<Result<_>>()?;
        let table = INDEX.key_bytes(&Vec::new());
        for (full, staged) in &self.staged {
            let Some(key) = full
                .strip_prefix(table.as_slice())
                .filter(|key| key.starts_with(prefix))
            else {
                continue;
            };
            match staged {
                Some(value) => rows.insert(key.to_vec(), value.clone()),
                None => rows.remove(key),
            };
        }
        Ok(rows.into_iter().collect())
    }

    /// Whether `run`'s committed record holds the output at `path` with
    /// `handle`.
    fn committed(&self, run: EntityId, path: &str, handle: &str) -> Result<bool> {
        Ok(self.get_row(&REPLAY_RECORDS, &run)?.is_some_and(|record| {
            record
                .outputs
                .iter()
                .any(|output| output.path == path && output.handle == handle)
        }))
    }

    /// `job`'s latest finding while it is in the child's committed record:
    /// one cut mid-step settles as no finding.
    fn committed_finding(&self, job: &ReaderJob) -> Result<Option<ReaderFindingRef>> {
        let Some(finding) = &job.finding else {
            return Ok(None);
        };
        Ok(self
            .committed(job.run, &finding.path, &finding.handle)?
            .then(|| finding.clone()))
    }

    /// Settles `job` into `state` with `finding` at `now_ms`: its queue,
    /// due and finding rows, its spend scope and its parent's counts move in
    /// this transaction, and so does every wait set over it that it settles.
    fn settle(
        &mut self,
        mut job: ReaderJob,
        state: ReaderJobState,
        finding: Option<ReaderFindingRef>,
        now_ms: u64,
    ) -> Result<ReaderJob> {
        let parent_run = job.binding.parent_run;
        match job.state {
            ReaderJobState::Queued => {
                self.delete_index(&queued_key(job.enqueued_at_ms, job.task))?;
            }
            ReaderJobState::Active => {}
            _ => return Ok(job),
        }
        if let Some(mut parent) = self.parent(parent_run)? {
            match job.state {
                ReaderJobState::Queued => parent.queued = parent.queued.saturating_sub(1),
                _ => parent.active = parent.active.saturating_sub(1),
            }
            self.put_parent(parent_run, &parent)?;
        }
        if let Some(dropped) = job.finding.as_ref().filter(|_| finding.is_none()) {
            self.drop_finding_row(parent_run, dropped, job.task)?;
        }
        self.delete_index(&due_key(job.binding.child_cutoff_unix_ms, job.task))?;
        self.spend
            .spend()
            .settle_child_in_txn(self.txn, &job.attempt, now_ms / 1000)?;
        job.state = state;
        job.finding = finding;
        job.settled_at_ms = Some(now_ms);
        self.put_job(&job)?;
        self.reduce_waiters(job.task, now_ms)?;
        if let ReaderJobKind::Summarize { memo, .. } = &job.kind {
            self.settle_summary(&job, *memo, now_ms)?;
        }
        Ok(job)
    }

    /// A summary job settled: its memo row once it is done, then its reply
    /// to the call parked on its task, a card of its text or why it was not
    /// made. The call made again later is the memo's hit.
    fn settle_summary(&mut self, job: &ReaderJob, memo: [u8; 32], now_ms: u64) -> Result<()> {
        let reply = match (&job.state, &job.finding) {
            (ReaderJobState::Done, Some(found)) => {
                self.put_row(
                    &MEMOS,
                    &memo,
                    &SummaryMemo {
                        task: job.task,
                        owner: found.owner,
                        path: found.path.clone(),
                        handle: found.handle.clone(),
                    },
                )?;
                serde_json::json!({
                    "task": job.task.to_hex(),
                    "state": job.state.word(),
                    "ref": found.handle,
                    "handle": found.handle,
                    "bytes": found.bytes,
                })
            }
            (ReaderJobState::Partial { reason } | ReaderJobState::Failed { reason }, _) => {
                serde_json::json!({
                    "task": job.task.to_hex(),
                    "state": "failed",
                    "reason": reason,
                })
            }
            _ => {
                serde_json::json!({"task": job.task.to_hex(), "state": "failed", "reason": "no_finding"})
            }
        };
        self.deliver_reply(job.task, reply, now_ms)
    }

    /// Deletes the `f` row of `finding` while it names `task`: the first
    /// child to report a handle keeps its row.
    fn drop_finding_row(
        &mut self,
        parent_run: EntityId,
        finding: &ReaderFindingRef,
        task: EntityId,
    ) -> Result<()> {
        let key = finding_key(parent_run, &finding.handle);
        if self.index(&key)?.as_deref() == Some(task.as_bytes().as_slice()) {
            self.delete_index(&key)?;
        }
        Ok(())
    }

    /// The jobs a set reduces over, each as its parent spawned it.
    fn set_jobs(&self, set: &TaskWaitSet) -> Result<Vec<(EntityId, Option<ReaderJob>)>> {
        set.tasks
            .iter()
            .map(|task| Ok((*task, self.job(*task)?)))
            .collect()
    }

    /// Reduces `set` now and keeps its first done reduction, whose due row
    /// then goes, and delivers it to the parent parked on the set (5B-0's
    /// resumable wait): one delivery for all its children.
    fn reduce_set(&mut self, mut set: TaskWaitSet, now_ms: u64) -> Result<TaskWaitSetResult> {
        if let Some(settled) = set.settled.clone() {
            return Ok(settled);
        }
        let jobs = self.set_jobs(&set)?;
        let result = reduce_task_wait_set(&set, &jobs, now_ms);
        if result.done {
            set.settled_at_ms = Some(now_ms);
            set.settled = Some(result.clone());
            self.put_wait(&set)?;
            self.delete_index(&due_key(set.until_ms, set.id))?;
            self.deliver_settled_task_wait(set.id, &result, now_ms)?;
        }
        Ok(result)
    }

    /// The settled reduction of wait set `wait`, as the reply of the wait a
    /// parent parked on it: in this transaction on the canonical vault, so a
    /// resident parent's trap wakes in the commit that settles it; along the
    /// session's route once this transaction commits otherwise.
    fn deliver_settled_task_wait(
        &mut self,
        wait: EntityId,
        result: &TaskWaitSetResult,
        now_ms: u64,
    ) -> Result<()> {
        let reply = serde_json::to_value(result)
            .map_err(|_| Error::InvariantViolation("a wait set reduction is plain data"))?;
        self.deliver_reply(wait, reply, now_ms)
    }

    /// `reply` as the reply of wait `wait`: in this transaction on the
    /// canonical vault, along the session's route once it commits otherwise.
    fn deliver_reply(
        &mut self,
        wait: EntityId,
        reply: serde_json::Value,
        now_ms: u64,
    ) -> Result<()> {
        match self.vault {
            Some(vault) => {
                deliver_wait_in_txn(vault, self.txn, wait, &reply, now_ms)?;
            }
            None => self.settled.push((wait, reply, now_ms)),
        }
        Ok(())
    }

    /// Reduces every wait set over `task` that is not settled yet.
    fn reduce_waiters(&mut self, task: EntityId, now_ms: u64) -> Result<()> {
        let prefix = tagged(b'w', &[task.as_bytes()]);
        for (key, _) in self.scan_index(&prefix)? {
            let set = id_at(&key, 17)?;
            if let Some(set) = self.wait(set)?.filter(|set| set.settled.is_none()) {
                self.reduce_set(set, now_ms)?;
            }
        }
        Ok(())
    }

    /// Settles `job` at its cutoff: a queued one with no finding, an active
    /// one with its latest committed finding, fenced past its generation so a
    /// late report or read is refused.
    fn settle_at_cutoff(&mut self, mut job: ReaderJob, now_ms: u64) -> Result<ReaderJob> {
        let finding = self.committed_finding(&job)?;
        if job.state == ReaderJobState::Active {
            job.generation = job.generation.saturating_add(1);
        }
        let state = ReaderJobState::Partial {
            reason: "cutoff".to_owned(),
        };
        self.settle(job, state, finding, now_ms)
    }
}

/// A spawn's new child, before its parent row admits it.
pub(crate) struct NewReaderJob {
    pub(crate) task: EntityId,
    pub(crate) attempt: AttemptId,
    pub(crate) run: EntityId,
    pub(crate) parent_run: EntityId,
    pub(crate) actor: ReaderActor,
    pub(crate) source: DelegatedSource,
    pub(crate) route: ReaderRoute,
    pub(crate) kind: ReaderJobKind,
    pub(crate) ask: String,
}

/// What one spawn came to.
pub(crate) enum SpawnAdmission {
    /// Queued, with how many of its parent's children are queued now.
    Queued { job: Box<ReaderJob>, queued: u64 },
    /// The same key had spawned it already.
    Existing(Box<ReaderJob>),
    /// The parent's children's cutoff has passed; nothing was created.
    PastCutoff,
    /// The parent's scope is gone or closed; nothing was created.
    Unmetered,
}

/// What one child's report came to.
pub(crate) enum ReportOutcome {
    Kept,
    Replay,
    Settled,
}

/// What one wait-set call came to.
pub(crate) enum WaitSetOutcome {
    Reduced(TaskWaitSetResult),
    /// The step key names a wait over other children or another policy.
    Changed,
}

impl ExecutorStorage<'_> {
    /// One transaction of the run's reader rows on its route: a canonical
    /// run's in one vault write transaction, a session-bound run's in its
    /// room's routed one, answered as its participant stands. Nothing the
    /// closure holds outlives the transaction, as the vault's grouped write
    /// door requires.
    pub(crate) fn reader_txn<T>(
        &self,
        f: impl FnOnce(&mut ReaderTxn<'_, '_>) -> Result<T>,
    ) -> Result<T> {
        match self {
            Self::Canonical(vault) => {
                let vault: &Vault = vault;
                vault.with_write_txn_grouped(|txn| {
                    f(&mut ReaderTxn {
                        txn,
                        read: RoutedDbs::Base(&vault.store),
                        write: RoutedDbs::Base(&vault.store),
                        spend: SpendBook::new(vault),
                        staged: BTreeMap::new(),
                        vault: Some(vault),
                        settled: Vec::new(),
                    })
                })
            }
            Self::Session(binding) => {
                let spend = binding.session.spend_book();
                let (answer, settled) = binding.answered(|| {
                    binding
                        .session
                        .routed_side_txn(&binding.route, |txn, read, write| {
                            let mut tx = ReaderTxn {
                                txn,
                                read,
                                write,
                                spend,
                                staged: BTreeMap::new(),
                                vault: None,
                                settled: Vec::new(),
                            };
                            let answer = f(&mut tx)?;
                            Ok((answer, tx.settled))
                        })
                })?;
                for (wait, reply, now_ms) in settled {
                    self.deliver_wait(wait, &reply, now_ms)?;
                }
                Ok(answer)
            }
        }
    }

    /// One read of the run's reader rows through its route's view.
    pub(super) fn reader_read<T>(
        &self,
        f: impl FnOnce(&RoTxn<'_>, RoutedDbs<'_>) -> Result<T>,
    ) -> Result<T> {
        match self {
            Self::Canonical(vault) => {
                let txn = vault.store.env.read_txn()?;
                f(&txn, RoutedDbs::Base(&vault.store))
            }
            Self::Session(binding) => binding.answered(|| binding.session.routed_side_read(f)),
        }
    }

    /// The base spend scopes the run's children spend under.
    pub(crate) fn spend_book(&self) -> SpendBook<'_> {
        match self {
            Self::Canonical(vault) => SpendBook::new(vault),
            Self::Session(binding) => binding.session.spend_book(),
        }
    }

    /// Tells the runner installed for the run's vault that `task` is queued.
    pub(crate) fn wake_reader_runner(&self, task: EntityId) {
        let runner = match self {
            Self::Canonical(vault) => vault.reader_job_runner(),
            Self::Session(binding) => binding.session.reader_job_runner(),
        };
        if let Some(runner) = runner {
            runner.wake(crate::code_run::ReaderJobWake {
                vault: crate::code_run::vault_ref(self.vault_id()),
                task,
                session_ref: self.session_ref().map(str::to_owned),
                participant: self.participant(),
            });
        }
    }

    pub(crate) fn reader_job(&self, task: EntityId) -> Result<Option<ReaderJob>> {
        self.reader_read(|txn, dbs| JOBS.get(&dbs, txn, &task))
    }

    pub(crate) fn reader_parent(&self, run: EntityId) -> Result<Option<ReaderParent>> {
        self.reader_read(|txn, dbs| PARENTS.get(&dbs, txn, &run))
    }

    /// The child of `parent_run` whose settled finding is `handle`: the
    /// first to report it, while it is done or partial.
    pub(crate) fn reader_finding(
        &self,
        parent_run: EntityId,
        handle: &str,
    ) -> Result<Option<ReaderJob>> {
        self.reader_read(|txn, dbs| {
            let Some(task) = INDEX.get(&dbs, txn, &finding_key(parent_run, handle))? else {
                return Ok(None);
            };
            let task = id_at(&task, 0)?;
            Ok(JOBS.get(&dbs, txn, &task)?.filter(|job| {
                job.binding.parent_run == parent_run
                    && matches!(
                        job.state,
                        ReaderJobState::Done | ReaderJobState::Partial { .. }
                    )
                    && job
                        .finding
                        .as_ref()
                        .is_some_and(|finding| finding.handle == handle)
            }))
        })
    }

    /// Queues one child of `new.parent_run`, its parent row made from `seat`
    /// at its first spawn and read from there after: the clock is fixed
    /// once. A child past the cutoff, or under a scope that is gone, is
    /// refused with nothing written.
    pub(crate) fn spawn_reader_job(
        &self,
        seat: &SpawnHostSeat,
        new: NewReaderJob,
        now_ms: u64,
    ) -> Result<SpawnAdmission> {
        self.reader_txn(|tx| {
            if let Some(job) = tx.job(new.task)? {
                return Ok(SpawnAdmission::Existing(Box::new(job)));
            }
            let mut parent = tx.parent(new.parent_run)?.unwrap_or_else(|| ReaderParent {
                deadline: seat.deadline,
                spend: seat.spend.clone(),
                hold_units: seat.hold_units,
                next_ordinal: 0,
                queued: 0,
                active: 0,
            });
            let child_cutoff = parent.deadline.child_cutoff();
            if now_ms >= child_cutoff {
                return Ok(SpawnAdmission::PastCutoff);
            }
            if tx
                .spend
                .open_scope_in_txn(&*tx.txn, &parent.spend)?
                .is_none()
            {
                return Ok(SpawnAdmission::Unmetered);
            }
            let job = ReaderJob {
                task: new.task,
                attempt: new.attempt,
                run: new.run,
                binding: SpawnParentBinding {
                    parent_run: new.parent_run,
                    actor: new.actor,
                    source: new.source,
                    route: new.route,
                    spend: parent.spend.clone(),
                    deadline: parent.deadline,
                    child_cutoff_unix_ms: child_cutoff,
                },
                kind: new.kind,
                ask: new.ask,
                state: ReaderJobState::Queued,
                generation: 0,
                finding: None,
                enqueued_at_ms: now_ms,
                settled_at_ms: None,
            };
            let ordinal = parent.next_ordinal;
            parent.next_ordinal = parent.next_ordinal.saturating_add(1);
            parent.queued = parent.queued.saturating_add(1);
            tx.put_job(&job)?;
            tx.put_index(&child_key(new.parent_run, ordinal, job.task), &[])?;
            tx.put_index(&queued_key(now_ms, job.task), &[])?;
            tx.put_index(&due_key(child_cutoff, job.task), DUE_JOB)?;
            tx.put_parent(new.parent_run, &parent)?;
            Ok(SpawnAdmission::Queued {
                job: Box::new(job),
                queued: parent.queued,
            })
        })
    }

    /// Claims queued child `task` for its runner: it becomes active at its
    /// next generation, its spend held from its parent's scope in the same
    /// transaction. A child past its cutoff settles instead.
    pub(crate) fn claim_reader_job(&self, task: EntityId, now_ms: u64) -> Result<ClaimOutcome> {
        self.reader_txn(|tx| {
            let mut job = tx
                .job(task)?
                .ok_or(Error::InvalidConfig("unknown reader job".to_owned()))?;
            match job.state {
                ReaderJobState::Queued => {}
                ReaderJobState::Active => {
                    return Err(Error::InvalidConfig(
                        "reader job is already active".to_owned(),
                    ));
                }
                _ => return Ok(ClaimOutcome::Settled),
            }
            if now_ms >= job.binding.child_cutoff_unix_ms {
                tx.settle_at_cutoff(job, now_ms)?;
                return Ok(ClaimOutcome::Settled);
            }
            for source in job.sources() {
                if !tx.committed(source.owner, &source.path, &source.handle)? {
                    return Ok(ClaimOutcome::SourceNotReady);
                }
            }
            let parent_run = job.binding.parent_run;
            let mut parent = tx
                .parent(parent_run)?
                .ok_or(Error::CorruptedIndex("code-run reader parent"))?;
            // A requeued child keeps the scope its first claim reserved.
            let reserved = tx
                .spend
                .spend()
                .scope_with_root_in_txn(&*tx.txn, &SpendScopeId::for_attempt(&job.attempt))?
                .is_some();
            if !reserved {
                if tx.spend.available_in_txn(&*tx.txn, &job.binding.spend)? == 0 {
                    return Ok(ClaimOutcome::WaitingForSpend);
                }
                tx.spend
                    .spend()
                    .reserve_child_in_txn(
                        tx.txn,
                        &job.binding.spend,
                        &job.attempt,
                        ChildSpend::Hold {
                            expected_units: parent.hold_units,
                        },
                        now_ms / 1000,
                    )
                    .map_err(Error::from)?;
            }
            tx.delete_index(&queued_key(job.enqueued_at_ms, job.task))?;
            job.state = ReaderJobState::Active;
            job.generation = job.generation.saturating_add(1);
            parent.queued = parent.queued.saturating_sub(1);
            parent.active = parent.active.saturating_add(1);
            tx.put_job(&job)?;
            tx.put_parent(parent_run, &parent)?;
            Ok(ClaimOutcome::Claimed(Box::new(job)))
        })
    }

    /// Settles active child `task` at `generation` as its run ended: done
    /// with a committed finding, failed with none, partial with one when the
    /// run stopped short. A stale generation changes nothing.
    pub(crate) fn complete_reader_job(
        &self,
        task: EntityId,
        generation: u32,
        end: &ReaderRunEnd,
        now_ms: u64,
    ) -> Result<ReaderJobState> {
        self.reader_txn(|tx| {
            let job = tx
                .job(task)?
                .ok_or(Error::InvalidConfig("unknown reader job".to_owned()))?;
            if job.state != ReaderJobState::Active || job.generation != generation {
                return Ok(job.state);
            }
            let finding = tx.committed_finding(&job)?;
            let state = match (end, &finding) {
                (ReaderRunEnd::Completed, Some(_)) => ReaderJobState::Done,
                (ReaderRunEnd::Completed, None) => ReaderJobState::Failed {
                    reason: "no_finding".to_owned(),
                },
                (end, Some(_)) => ReaderJobState::Partial {
                    reason: end.reason().to_owned(),
                },
                (end, None) => ReaderJobState::Failed {
                    reason: end.reason().to_owned(),
                },
            };
            Ok(tx.settle(job, state, finding, now_ms)?.state)
        })
    }

    /// Requeues every active child at its next generation, so a run that
    /// was cut is claimed again and a late report of the cut one is refused;
    /// one past its cutoff at `now_ms` settles partial instead. One runner
    /// per vault process calls it at its start.
    pub(crate) fn recover_reader_jobs(&self, now_ms: u64) -> Result<usize> {
        self.reader_txn(|tx| {
            let active: Vec<ReaderJob> = JOBS
                .iter_from(&tx.read, &*tx.txn, &[])?
                .map(|row| row.map(|(_, job)| job))
                .filter(|job| {
                    job.as_ref()
                        .map_or(true, |job| job.state == ReaderJobState::Active)
                })
                .collect::<Result<_>>()?;
            for mut job in active.iter().cloned() {
                if now_ms >= job.binding.child_cutoff_unix_ms {
                    tx.settle_at_cutoff(job, now_ms)?;
                    continue;
                }
                let parent_run = job.binding.parent_run;
                if let Some(mut parent) = tx.parent(parent_run)? {
                    parent.active = parent.active.saturating_sub(1);
                    parent.queued = parent.queued.saturating_add(1);
                    tx.put_parent(parent_run, &parent)?;
                }
                job.state = ReaderJobState::Queued;
                job.generation = job.generation.saturating_add(1);
                tx.put_index(&queued_key(job.enqueued_at_ms, job.task), &[])?;
                tx.put_job(&job)?;
            }
            Ok(active.len())
        })
    }

    /// Up to `limit` queued children, oldest first.
    pub(crate) fn queued_reader_jobs(&self, limit: usize) -> Result<Vec<ReaderJob>> {
        self.reader_read(|txn, dbs| {
            let mut jobs = Vec::new();
            for row in INDEX.iter_from(&dbs, txn, b"q")? {
                if jobs.len() >= limit {
                    break;
                }
                let (key, _) = row?;
                if let Some(job) = JOBS.get(&dbs, txn, &id_at(&key, 9)?)? {
                    jobs.push(job);
                }
            }
            Ok(jobs)
        })
    }

    /// A child's finding report, fenced by its generation: it replaces the
    /// child's latest finding, and the same finding again is a replay. A
    /// settled child, or one claimed again since, keeps what it has.
    pub(crate) fn report_reader_finding(
        &self,
        task: EntityId,
        generation: u32,
        finding: &ReaderFindingRef,
    ) -> Result<ReportOutcome> {
        self.reader_txn(|tx| {
            let Some(mut job) = tx.job(task)? else {
                return Ok(ReportOutcome::Settled);
            };
            if job.state != ReaderJobState::Active || job.generation != generation {
                return Ok(ReportOutcome::Settled);
            }
            if job.finding.as_ref() == Some(finding) {
                return Ok(ReportOutcome::Replay);
            }
            let parent_run = job.binding.parent_run;
            if let Some(previous) = job.finding.take() {
                tx.drop_finding_row(parent_run, &previous, task)?;
            }
            let key = finding_key(parent_run, &finding.handle);
            if tx.index(&key)?.is_none() {
                tx.put_index(&key, task.as_bytes())?;
            }
            job.finding = Some(finding.clone());
            tx.put_job(&job)?;
            Ok(ReportOutcome::Kept)
        })
    }

    /// One call of a wait set: written at its first call with its child and
    /// due rows, then reduced. Its first done reduction answers every later
    /// call; the same key over other children or another policy is refused.
    pub(crate) fn reduce_reader_wait(
        &self,
        set: TaskWaitSet,
        now_ms: u64,
    ) -> Result<WaitSetOutcome> {
        self.reader_txn(|tx| {
            let set = match tx.wait(set.id)? {
                Some(held) if held.tasks != set.tasks || held.policy != set.policy => {
                    return Ok(WaitSetOutcome::Changed);
                }
                Some(held) => held,
                None => {
                    tx.put_wait(&set)?;
                    for task in &set.tasks {
                        tx.put_index(&waiter_key(*task, set.id), &[])?;
                    }
                    tx.put_index(&due_key(set.until_ms, set.id), DUE_SET)?;
                    set
                }
            };
            Ok(WaitSetOutcome::Reduced(tx.reduce_set(set, now_ms)?))
        })
    }

    /// The due sweep at `now_ms`: every wait set due settles (at its cutoff,
    /// when nothing settled it first), and every child past its cutoff
    /// settles partial. Answers how many rows came due.
    pub(crate) fn settle_due_task_waits(&self, now_ms: u64) -> Result<usize> {
        self.reader_txn(|tx| {
            let mut due = Vec::new();
            for (key, value) in tx.scan_index(b"d")? {
                if time_at(&key, 1)? > now_ms {
                    break;
                }
                due.push((key, value));
            }
            for (key, value) in &due {
                let id = id_at(key, 9)?;
                if value.as_slice() == DUE_JOB {
                    if let Some(job) = tx.job(id)?.filter(|job| !job.state.is_settled()) {
                        tx.settle_at_cutoff(job, now_ms)?;
                    }
                } else if let Some(set) = tx.wait(id)? {
                    for (_, job) in tx.set_jobs(&set)? {
                        if let Some(job) = job.filter(|job| {
                            job.binding.parent_run == set.parent_run
                                && !job.state.is_settled()
                                && job.binding.child_cutoff_unix_ms <= now_ms
                        }) {
                            tx.settle_at_cutoff(job, now_ms)?;
                        }
                    }
                    if let Some(set) = tx.wait(id)? {
                        tx.reduce_set(set, now_ms)?;
                    }
                }
                tx.delete_index(key)?;
            }
            Ok(due.len())
        })
    }

    /// When the due sweep next has work, unix milliseconds.
    pub(crate) fn next_task_wait_due(&self) -> Result<Option<u64>> {
        self.reader_read(|txn, dbs| {
            INDEX
                .iter_from(&dbs, txn, b"d")?
                .next()
                .transpose()?
                .map(|(key, _)| time_at(&key, 1))
                .transpose()
        })
    }
}

/// One member of a summary job as its runner reads it: its handle, the
/// range of it read, the rows its parent's read of it was checked against
/// (`None` when one answer kept no set), and its text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryMember {
    pub handle: String,
    pub range: (u64, u64),
    pub rows: Option<Vec<EntityId>>,
    pub text: String,
}

/// What a summary job's read of its members came to: the members, or why
/// the job reads nothing (`reader_task_settled`, `group_exceeds_window`,
/// `tainted`, `member_gone`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SummaryRead {
    Members(Vec<SummaryMember>),
    Refused(String),
}

impl ExecutorStorage<'_> {
    /// Summary job `task` while it is active at `generation`, with its
    /// members.
    fn live_summary(
        &self,
        task: EntityId,
        generation: u32,
    ) -> Result<Option<(ReaderJob, Vec<DelegatedSource>)>> {
        let Some(job) = self
            .reader_job(task)?
            .filter(|job| job.state == ReaderJobState::Active && job.generation == generation)
        else {
            return Ok(None);
        };
        let ReaderJobKind::Summarize { members, .. } = &job.kind else {
            return Ok(None);
        };
        let members = members.clone();
        Ok(Some((job, members)))
    }

    /// The output at `path` with `handle` in `run`'s committed record.
    fn recorded(
        &self,
        run: EntityId,
        path: &str,
        handle: &str,
    ) -> Result<Option<CodeRunRawOutput>> {
        Ok(self.get_code_run_replay_record(&run)?.and_then(|record| {
            record
                .outputs
                .into_iter()
                .find(|output| output.path == path && output.handle == handle)
        }))
    }

    /// Every member of summary job `task`, read as a child's `src` read is
    /// while the job is live at `generation`: in its owner's committed
    /// record, clean now, inside its range. Members past `max_bytes`
    /// together are refused unread.
    pub(crate) fn summary_job_members(
        &self,
        task: EntityId,
        generation: u32,
        max_bytes: u64,
    ) -> Result<SummaryRead> {
        let refused = |reason: &str| Ok(SummaryRead::Refused(reason.to_owned()));
        let Some((_, members)) = self.live_summary(task, generation)? else {
            return refused("reader_task_settled");
        };
        let total = members
            .iter()
            .map(|member| member.range.1.saturating_sub(member.range.0))
            .fold(0_u64, u64::saturating_add);
        if total > max_bytes {
            return refused(crate::code_run::SUMMARY_GROUP_EXCEEDS_WINDOW);
        }
        let mut read = Vec::with_capacity(members.len());
        for member in members {
            let Some(output) = self.recorded(member.owner, &member.path, &member.handle)? else {
                return refused("member_gone");
            };
            if self
                .code_run_result_taint(Some(member.owner), &output)?
                .0
                .is_tainted()
            {
                return refused("tainted");
            }
            let (start, end) = member.range;
            if start > end || end > output.raw_len {
                return refused("member_gone");
            }
            let len = usize::try_from(end - start)
                .map_err(|_| Error::ArithmeticOverflow("summary member length"))?;
            let bytes = self
                .read_code_run_raw_output_range(&output, start, len)?
                .ok_or(Error::CorruptedIndex("executor replay output bytes"))?;
            // A body stored before its scan read every rule may hold a secret
            // no mark names (OF-067); the model is shown none of it.
            if crate::batch::secret_scan::write_payload_hit(&bytes).is_some() {
                return refused("tainted");
            }
            read.push(SummaryMember {
                handle: member.handle,
                range: member.range,
                rows: member.rows,
                text: String::from_utf8_lossy(&bytes).into_owned(),
            });
        }
        Ok(SummaryRead::Members(read))
    }

    /// Stores `text` as summary job `task`'s finding while it is live at
    /// `generation`: a stored value of the job's own run (a record with no
    /// executor, its one name `summary`), marked with its members' taint,
    /// then reported as the job's finding. The run's end settles it.
    pub(crate) fn store_summary_job_text(
        &self,
        task: EntityId,
        generation: u32,
        text: &str,
    ) -> Result<std::result::Result<(), String>> {
        let Some((job, members)) = self.live_summary(task, generation)? else {
            return Ok(Err("reader_task_settled".to_owned()));
        };
        let mut sink = self.code_run_output_sink()?;
        sink.write(text.as_bytes())?;
        let path = crate::engine_executor::store_result_output_path(&sink.digest()?);
        let output = self.publish_code_run_output(path, sink, true, job.run)?;
        let mut from = Vec::with_capacity(members.len());
        for member in &members {
            if let Some(held) = self.recorded(member.owner, &member.path, &member.handle)? {
                from.push((member.owner, held));
            }
        }
        self.inherit_code_run_result_marks(job.run, &output, &from)?;
        let held = self.get_code_run_replay_record(&job.run)?;
        let expected = held
            .as_ref()
            .map(crate::code_run::CodeRunReplayRecord::generation)
            .transpose()?;
        let mut record = held.unwrap_or_else(|| {
            crate::code_run::CodeRunReplayRecord::new(
                job.run,
                crate::code_run::CodeRunDeterminism::new(
                    0,
                    [0; crate::code_run::CODE_RUN_RNG_SEED_LEN],
                ),
            )
        });
        if !record.outputs.iter().any(|held| held.path == output.path) {
            record.outputs.push(output.clone());
        }
        let binding =
            crate::code_run::CodeRunResultBinding::new(SUMMARY_RESULT_NAME, output.handle.clone());
        match record
            .bindings
            .iter_mut()
            .find(|held| held.name == binding.name)
        {
            Some(held) => *held = binding,
            None => record.bindings.push(binding),
        }
        self.put_code_run_replay_record_if_generation_with_heal(&record, expected, None)?;
        let rows = members.iter().try_fold(Vec::new(), |mut all, member| {
            all.extend(member.rows.clone()?);
            Some(all)
        });
        let finding = ReaderFindingRef {
            owner: job.run,
            path: output.path,
            handle: output.handle,
            bytes: output.raw_len,
            rows,
        };
        Ok(
            match self.report_reader_finding(task, generation, &finding)? {
                ReportOutcome::Kept | ReportOutcome::Replay => Ok(()),
                ReportOutcome::Settled => Err("reader_task_settled".to_owned()),
            },
        )
    }
}

/// The reader children of one vault, or of one off-record session, as their
/// runner drives them: the queue, claims, completions, the restart recovery
/// and the due sweep. Every time is unix milliseconds.
pub struct ReaderJobs<'a> {
    storage: ExecutorStorage<'a>,
}

impl<'a> ReaderJobs<'a> {
    #[must_use]
    pub fn canonical(vault: &'a Vault) -> Self {
        Self {
            storage: ExecutorStorage::Canonical(vault),
        }
    }

    /// The children of `session`, acting as the participant their parents
    /// ran as.
    ///
    /// # Errors
    ///
    /// The session's own refusals when the room is closing or gone, or
    /// `participant` is not in it.
    pub fn for_session(
        session: &crate::off_record::OffRecordSession<'a>,
        participant: EntityId,
    ) -> Result<Self> {
        Ok(Self {
            storage: ExecutorStorage::for_session(session, participant)?,
        })
    }

    /// Up to `limit` queued children, oldest first.
    pub fn queued(&self, limit: usize) -> Result<Vec<ReaderJob>> {
        self.storage.queued_reader_jobs(limit)
    }

    pub fn job(&self, task: EntityId) -> Result<Option<ReaderJob>> {
        self.storage.reader_job(task)
    }

    /// Claims queued child `task` to run it.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for a task with no row, or one already
    /// active.
    pub fn claim(&self, task: EntityId, now_ms: u64) -> Result<ClaimOutcome> {
        self.storage.claim_reader_job(task, now_ms)
    }

    /// Settles child `task`, claimed at `generation`, as its run ended; the
    /// state it is in after.
    pub fn complete(
        &self,
        task: EntityId,
        generation: u32,
        end: ReaderRunEnd,
        now_ms: u64,
    ) -> Result<ReaderJobState> {
        self.storage
            .complete_reader_job(task, generation, &end, now_ms)
    }

    /// Requeues every child a stopped runner left active, or settles it
    /// when its cutoff has passed at `now_ms`; how many.
    pub fn recover(&self, now_ms: u64) -> Result<usize> {
        self.storage.recover_reader_jobs(now_ms)
    }

    /// Settles every wait set and child due at `now_ms`; how many rows were
    /// due.
    pub fn settle_due(&self, now_ms: u64) -> Result<usize> {
        self.storage.settle_due_task_waits(now_ms)
    }

    /// When [`Self::settle_due`] next has work.
    pub fn next_due(&self) -> Result<Option<u64>> {
        self.storage.next_task_wait_due()
    }

    /// The members of summary job `task`, claimed at `generation`, read as
    /// a child's source is; past `max_bytes` together, refused unread.
    pub fn summary_members(
        &self,
        task: EntityId,
        generation: u32,
        max_bytes: u64,
    ) -> Result<SummaryRead> {
        self.storage
            .summary_job_members(task, generation, max_bytes)
    }

    /// Stores `text` as summary job `task`'s finding, claimed at
    /// `generation`; `Err` names why it was not kept.
    pub fn store_summary(
        &self,
        task: EntityId,
        generation: u32,
        text: &str,
    ) -> Result<std::result::Result<(), String>> {
        self.storage.store_summary_job_text(task, generation, text)
    }
}
