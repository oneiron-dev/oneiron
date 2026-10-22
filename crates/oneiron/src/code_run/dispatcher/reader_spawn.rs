//! Reader forks at the dispatcher (ARCH-0079 #reader-forks): the seat a host
//! lends a run that may spawn readers, the binding of a dispatcher to one
//! reader child's job, and the three reader effects. Every row they write
//! goes through the run's own route ([`ExecutorStorage::reader_txn`]); the
//! parent run is the bridge call's, never guest text.
//!
//! [`ExecutorStorage::reader_txn`]: crate::code_run::ExecutorStorage::reader_txn

use std::collections::HashSet;
use std::sync::Arc;

use super::{ExecutorCallSite, HostSelfDispatcher};
use crate::code_run::scoped_child::{
    READER_SOURCE_NAME, SCOPED_CHILD_PORT_NOT_LENT, scoped_child_call_allowed, scoped_child_input,
};
use crate::code_run::storage::{
    NewReaderJob, ReportOutcome, SpawnAdmission, WaitSetOutcome, runs_program_steps,
};
use crate::code_run::types::{
    SelfCall, SelfDeniedResult, SelfDispatchOutcome, SelfDurableWait, SelfDurableWaitReason,
    SelfEffect, SelfFailedResult,
};
use crate::code_run::{
    DelegatedSource, ReaderActor, ReaderJobState, ReaderReportReceipt, ReaderRoute,
    ReaderSpawnReceipt, ScopedChildPorts, ScopedChildSpec, SelfReaderReportCall,
    SelfReaderSpawnCall, SpawnHostSeat, TaskWaitPolicy, TaskWaitSet, TaskWaitSetCall,
    reader_attempt_id, reader_run_id, reader_task_id, reader_wait_cutoff, reader_wait_id,
    valid_reader_key, vault_ref,
};
use crate::limit_ask::EngineLimit;
use crate::{EntityId, Error, Result};

/// The refusal a reader child meets at every call but its report,
/// `self.context` and `self.think`: no verbs, writes, ambient reads or
/// children of its own.
pub(crate) const READER_CHILD_READ_ONLY: &str = "reader_child_read_only";

/// What the wait a not-done `tasks.wait` parks on says, before its set's id.
const TASK_WAIT_SET_PROMPT: &str = "task_wait_set:";

/// What binds a dispatcher to one reader child's job: its task, the
/// generation its runner claimed it at, the source it reads, and what its
/// parent lent it when it is a scoped child (FIX 7507).
pub(crate) struct ReaderChildBinding {
    pub(crate) task: EntityId,
    pub(crate) generation: u32,
    pub(crate) source: DelegatedSource,
    pub(crate) scoped: Option<ScopedChildSpec>,
}

impl ReaderChildBinding {
    /// The input `reference` names for this child, by its name (`by_name`)
    /// or by its handle, with the name it is read by: a read child's one
    /// source as `src`; a scoped child's lent inputs only
    /// (`scoped_child_input`). Any other reference names nothing.
    pub(crate) fn delegated(
        &self,
        by_name: bool,
        reference: &str,
    ) -> Option<(&str, &DelegatedSource)> {
        if let Some(spec) = &self.scoped {
            return scoped_child_input(spec, by_name, reference);
        }
        let names = if by_name {
            reference == READER_SOURCE_NAME
        } else {
            reference == self.source.handle
        };
        names.then_some((READER_SOURCE_NAME, &self.source))
    }
}

impl HostSelfDispatcher<'_> {
    /// Lends the run a seat to spawn reader children under: the scope they
    /// spend under, their clock and what each holds at its claim. Without
    /// one, `self.spawn` answers `reader_spawn_unbound`.
    #[must_use]
    pub fn with_reader_spawn(mut self, seat: SpawnHostSeat) -> Self {
        self.reader_spawn = Some(seat);
        self
    }

    /// Binds this dispatcher to reader child `task`, as its runner claimed
    /// it at `generation`: the run reads its parent's source as `src`, and
    /// makes no call but its report, `self.context` and `self.think`. The
    /// job's run is the run it is bound to.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the job is not active at `generation`,
    /// or this dispatcher's run, vault, session or participant is not the
    /// job's.
    pub fn with_reader_child(mut self, task: EntityId, generation: u32) -> Result<Self> {
        let mismatch = || Error::InvalidConfig("reader child binding mismatch".to_owned());
        let job = self.storage.reader_job(task)?.ok_or_else(mismatch)?;
        let route = &job.binding.route;
        if job.state != ReaderJobState::Active
            || job.generation != generation
            || self.run_ref != job.run.to_hex()
            || route.vault != vault_ref(self.vault_id())
            || route.session_ref.as_deref() != self.session_ref()
            || route.participant != self.participant()
        {
            return Err(mismatch());
        }
        let scoped = job.scoped_spec().cloned();
        self.reader_child = Some(ReaderChildBinding {
            task,
            generation,
            source: job.binding.source,
            scoped,
        });
        self.bound_run = Some(job.run);
        Ok(self)
    }

    /// Lends the bound scoped child the ports its host registered (FIX
    /// 7507): its lent verbs run on them, each checked against its loan at
    /// every call. Without them, a lent verb answers
    /// `scoped_child_service_unbound`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when this dispatcher is bound to no scoped
    /// child.
    pub fn with_scoped_child_ports(mut self, ports: Arc<dyn ScopedChildPorts>) -> Result<Self> {
        if self.scoped_child_spec().is_none() {
            return Err(Error::InvalidConfig(
                "scoped ports need a scoped child".to_owned(),
            ));
        }
        self.scoped_ports = Some(ports);
        Ok(self)
    }

    /// What the bound scoped child was lent, if this dispatcher is bound to
    /// one.
    pub(crate) fn scoped_child_spec(&self) -> Option<&ScopedChildSpec> {
        self.reader_child.as_ref()?.scoped.as_ref()
    }

    /// The resource scope a scoped child's model calls carry: its loan's
    /// (FIX 7507). `None` for every other run, whose calls keep theirs.
    pub(crate) fn scoped_child_scope(&self) -> Option<&crate::llm::Scope> {
        self.scoped_child_spec().map(|spec| &spec.scope)
    }

    /// The seat the host lent this run to spawn readers under, if any.
    pub(crate) fn reader_spawn_seat(&self) -> Option<&SpawnHostSeat> {
        self.reader_spawn.as_ref()
    }

    /// The reader child this dispatcher is bound to, if any.
    pub(crate) fn reader_child(&self) -> Option<&ReaderChildBinding> {
        self.reader_child.as_ref()
    }

    /// Whether the bound reader child's job is still active at the
    /// generation it was claimed at: a child its cutoff settled, or one
    /// claimed again since, reads nothing more. A scoped child (FIX 7507)
    /// reads and calls its ports only before its cutoff, not just until its
    /// run's next await, and, when it borrowed its parent attempt's lease,
    /// only while that lease holds (`scoped_parent_lease_holds`).
    pub(crate) fn reader_job_live(&self) -> Result<bool> {
        let Some(child) = &self.reader_child else {
            return Ok(false);
        };
        let Some(job) = self.storage.reader_job(child.task)?.filter(|job| {
            job.state == ReaderJobState::Active && job.generation == child.generation
        }) else {
            return Ok(false);
        };
        if job.scoped_spec().is_some()
            && crate::unix_millis_now() >= job.binding.child_cutoff_unix_ms
        {
            return Ok(false);
        }
        self.storage.scoped_parent_lease_holds(&job)
    }

    /// A bound reader child's refusal of `effect`, when it is one it may
    /// not make. A scoped child's verb calls meet its exact port loan
    /// instead ([`Self::scoped_child_refusal`]); it makes no other call a
    /// read child does not.
    pub(super) fn reader_child_refusal(&self, effect: SelfEffect) -> Option<SelfDispatchOutcome> {
        let admitted = matches!(
            effect,
            SelfEffect::ReaderReport | SelfEffect::Context | SelfEffect::Think
        ) || (effect == SelfEffect::AgentVerb && self.scoped_child_spec().is_some());
        (self.reader_child.is_some() && !admitted).then(|| {
            SelfDispatchOutcome::Denied(SelfDeniedResult {
                effect,
                outcome: READER_CHILD_READ_ONLY.to_owned(),
                reason_codes: Vec::new(),
            })
        })
    }

    /// A bound scoped child's refusal of `call` (FIX 7507): a verb call its
    /// loan did not lend by name (`scoped_child_call_allowed`). `None` for
    /// every other call, and for every run that is no scoped child.
    pub(super) fn scoped_child_refusal(&self, call: &SelfCall) -> Option<SelfDispatchOutcome> {
        let spec = self.scoped_child_spec()?;
        let SelfCall::AgentVerb(call) = call else {
            return None;
        };
        (!scoped_child_call_allowed(spec, call.verb)).then(|| {
            SelfDispatchOutcome::Denied(SelfDeniedResult {
                effect: SelfEffect::AgentVerb,
                outcome: SCOPED_CHILD_PORT_NOT_LENT.to_owned(),
                reason_codes: Vec::new(),
            })
        })
    }

    /// A spawn's admission at `now_ms` with nothing written: the children's
    /// cutoff and what their scope may still spend (`None` when they spend
    /// on the host's meter, which is never looked up here), or why a spawn
    /// would be refused (`spawn_unbound`, `past_cutoff`, `unmetered`).
    pub(crate) fn preflight_reader_spawn(
        &self,
        parent_run: EntityId,
        now_ms: u64,
    ) -> Result<std::result::Result<(u64, Option<u64>), &'static str>> {
        let Some(seat) = &self.reader_spawn else {
            return Ok(Err("spawn_unbound"));
        };
        let (deadline, spend) = match self.storage.reader_parent(parent_run)? {
            Some(parent) => (parent.deadline, parent.spend),
            None => (seat.deadline, seat.spend.clone()),
        };
        let cutoff = deadline.child_cutoff();
        if now_ms >= cutoff {
            return Ok(Err("past_cutoff"));
        }
        let Some(scope) = spend.scope() else {
            return Ok(Ok((cutoff, None)));
        };
        Ok(match self.storage.spend_book().open_scope(scope)? {
            Some((_, available)) => Ok((cutoff, Some(available))),
            None => Err("unmetered"),
        })
    }

    /// `self.spawn`: queues one reader child of the call's run over the
    /// source the host bound, and answers at once; the child never runs
    /// inline. The same key answers the child it already spawned.
    pub(super) fn dispatch_reader_spawn(
        &self,
        call: SelfReaderSpawnCall,
        site: Option<ExecutorCallSite<'_>>,
    ) -> Result<SelfDispatchOutcome> {
        let failed = |code: &str| {
            SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: SelfEffect::ReaderSpawn,
                error: code.to_owned(),
            })
        };
        let (Some(seat), Some(site)) = (&self.reader_spawn, site) else {
            return Ok(failed("reader_spawn_unbound"));
        };
        let Some(source) = call.bound else {
            return Ok(failed("reader_spawn_unresolved"));
        };
        if !valid_reader_key(&call.intent_key) {
            return Ok(failed("reader_spawn_invalid_intent_key"));
        }
        let parent_run = site.run_id;
        let task = reader_task_id(parent_run, &call.intent_key)?;
        let new = NewReaderJob {
            task,
            attempt: reader_attempt_id(task)?,
            run: reader_run_id(task)?,
            parent_run,
            actor: ReaderActor::of(self.actor),
            source,
            route: ReaderRoute {
                vault: vault_ref(self.vault_id()),
                session_ref: self.session_ref().map(str::to_owned),
                participant: self.participant(),
            },
            kind: crate::code_run::ReaderJobKind::Read,
            ask: call.ask,
            parent_lease: None,
        };
        let (job, replay) =
            match self
                .storage
                .spawn_reader_job(seat, new, crate::unix_millis_now())?
            {
                SpawnAdmission::Queued { job, queued } => {
                    // The backlog row asks on its crossing edge and keeps
                    // queueing: it never refuses and never bounds the window.
                    let watch = self.storage.limit_watch();
                    let bound = watch.bound(EngineLimit::CodeReaderBacklog);
                    if queued == bound.saturating_add(1) {
                        watch.crossed(EngineLimit::CodeReaderBacklog, bound, queued);
                    }
                    self.storage.wake_reader_runner(job.task);
                    (job, false)
                }
                SpawnAdmission::Existing(job) => (job, true),
                SpawnAdmission::PastCutoff => return Ok(failed("reader_spawn_past_cutoff")),
                SpawnAdmission::Unmetered => return Ok(failed("reader_spawn_unmetered")),
            };
        Ok(SelfDispatchOutcome::ReaderSpawn(ReaderSpawnReceipt {
            task: job.task,
            attempt: crate::entity_id::bytes_to_hex_lower(job.attempt.as_bytes()),
            run: job.run,
            cutoff_unix_ms: job.binding.child_cutoff_unix_ms,
            state: job.state.word().to_owned(),
            replay,
        }))
    }

    /// `tasks.update({task_ref, resultRef})` from a reader child: keeps the
    /// finding the host bound as its latest, fenced by the generation it was
    /// claimed at. A report never settles the child; its run's end does.
    pub(super) fn dispatch_reader_report(
        &self,
        call: SelfReaderReportCall,
    ) -> Result<SelfDispatchOutcome> {
        let failed = |code: &str| {
            SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: SelfEffect::ReaderReport,
                error: code.to_owned(),
            })
        };
        let Some(child) = self
            .reader_child
            .as_ref()
            .filter(|child| child.task == call.task)
        else {
            return Ok(failed("not_reader_task"));
        };
        let Some(finding) = call.bound else {
            return Ok(failed("finding_not_own"));
        };
        let reported = self.storage.report_reader_finding(
            call.task,
            child.generation,
            &finding,
            crate::unix_millis_now(),
        )?;
        let replay = match reported {
            ReportOutcome::Kept => false,
            ReportOutcome::Replay => true,
            ReportOutcome::Settled => return Ok(failed("reader_task_settled")),
        };
        Ok(SelfDispatchOutcome::ReaderReport(ReaderReportReceipt {
            task: call.task,
            finding: finding.handle,
            replay,
        }))
    }

    /// `tasks.wait({tasks, ...})`: one wait over children of the call's run,
    /// reduced now. A wait that is done answers its reduction, and its first
    /// done reduction answers every later call of the same step key. One that
    /// is not parks the run on the set: the set's id is the wait's, its
    /// settling delivers the reduction as the wait's reply, and the run
    /// resumes from it.
    ///
    /// The wait keeps the `tasks.wait` marker a parked step records, as a
    /// verb hook's ask does, its prompt naming the set. One naming a
    /// world-privacy request waits on it instead (FIX 4706).
    pub(super) fn dispatch_task_wait_set(
        &self,
        call: TaskWaitSetCall,
        site: Option<ExecutorCallSite<'_>>,
    ) -> Result<SelfDispatchOutcome> {
        let failed = |code: &str| {
            SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: SelfEffect::TasksWaitSet,
                error: code.to_owned(),
            })
        };
        // FIX 4706: a wait on a world-privacy request, no children.
        if let Some(request) = &call.request {
            return self.dispatch_world_privacy_wait(&call, request);
        }
        let Some(site) = site else {
            return Ok(failed("task_wait_unbound"));
        };
        let parent_run = site.run_id;
        let Some(parent) = self.storage.reader_parent(parent_run)? else {
            return Ok(failed("task_wait_unbound"));
        };
        let mut seen = HashSet::with_capacity(call.tasks.len());
        let mut tasks = Vec::with_capacity(call.tasks.len());
        for task in &call.tasks {
            match EntityId::from_hex(task) {
                Ok(task) if seen.insert(task) => tasks.push(task),
                _ => return Ok(failed("task_wait_invalid")),
            }
        }
        let policy = match (call.all, call.n_of) {
            (None | Some(true), None) => TaskWaitPolicy::All,
            (None | Some(false), Some(n)) if n >= 1 && n as usize <= tasks.len() => {
                TaskWaitPolicy::NOf { n }
            }
            _ => return Ok(failed("task_wait_invalid")),
        };
        if tasks.is_empty() || !valid_reader_key(&call.step_key) {
            return Ok(failed("task_wait_invalid"));
        }
        // It lasts as long as the latest of the named jobs that are its own,
        // never past the parent's outer cutoff (`reader_wait_cutoff`): a
        // summary's wait may run into the fold reserve, a read's may not.
        let own = self.storage.own_reader_jobs(parent_run, &tasks)?;
        let cutoff = reader_wait_cutoff(&parent, &own);
        let wait = reader_wait_id(parent_run, &call.step_key)?;
        let set = TaskWaitSet {
            id: wait,
            parent_run,
            tasks,
            policy,
            until_ms: call.until.map_or(cutoff, |until| until.min(cutoff)),
            step_key: call.step_key,
            settled_at_ms: None,
            settled: None,
        };
        Ok(
            match self
                .storage
                .reduce_reader_wait(set, crate::unix_millis_now())?
            {
                WaitSetOutcome::Reduced(mut result) if result.done => {
                    // The settled children's type feedback as it stands,
                    // beside the reduction, never kept in it (FIX 8277).
                    let settled: Vec<EntityId> = own
                        .iter()
                        .filter(|job| !result.pending.contains(&job.task))
                        .map(|job| job.run)
                        .collect();
                    result.program_steps = runs_program_steps(&self.storage, &settled);
                    SelfDispatchOutcome::TaskWaitSet(result)
                }
                WaitSetOutcome::Reduced(_) => SelfDispatchOutcome::DurableWait(SelfDurableWait {
                    wait_id: wait,
                    effect: SelfEffect::TasksWait,
                    reason: SelfDurableWaitReason::PeerResult,
                    prompt: Some(format!("{TASK_WAIT_SET_PROMPT}{}", wait.to_hex())),
                }),
                WaitSetOutcome::Changed => failed("task_wait_changed"),
            },
        )
    }
}
