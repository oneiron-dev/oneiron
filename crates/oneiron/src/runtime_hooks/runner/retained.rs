//! Owned background fact evaluations. No borrowed lane or callback escapes
//! its job; its parent keeps the result until the existing completion lands.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;

use crate::claim::{ClaimReadStatus, ScopedReadActorKey};
use crate::runtime_hooks::body::{HookBodyRuntime, HookVerdict};
use crate::skill_hub::pack_catalog::{HookActorClass, PackHookBinding};
use crate::{EntityId, Result, Vault};

use super::evaluation::{PreparedRun, evaluate};
use super::grant::HookGrant;
use super::source::FactEntry;
use super::store::RunKey;
use super::{FactHookRunner, HookPassReport, Pass, Run, apply};

type SharedAdmission = Arc<Mutex<Box<dyn Send>>>;

pub(super) struct RetainedPass<'a> {
    pub(super) runs: &'a mut RetainedRuns,
    admission: SharedAdmission,
}

#[derive(Clone)]
struct OwnedRun {
    binding_id: EntityId,
    binding: PackHookBinding,
    entry: FactEntry,
    key: RunKey,
    grant: HookGrant,
    actor: HookActorClass,
}

impl OwnedRun {
    fn borrowed(&self) -> Run<'_> {
        Run {
            binding_id: self.binding_id,
            binding: &self.binding,
            entry: &self.entry,
            key: self.key,
            grant: &self.grant,
            actor: self.actor,
        }
    }
}

struct PendingRun {
    run: OwnedRun,
    all: Vec<(EntityId, PackHookBinding)>,
    answer: mpsc::Receiver<PreparedRun>,
    worker: Option<JoinHandle<()>>,
    prepared: Option<PreparedRun>,
    committed: Option<bool>,
    report: HookPassReport,
    // The original pass stays admitted through the callback AND its tail.
    _admission: SharedAdmission,
}

pub(super) struct RetainedRuns {
    vault: Arc<Vault>,
    runtime: Arc<dyn HookBodyRuntime>,
    verdict: Option<Arc<dyn HookVerdict>>,
    wake: Arc<dyn Fn() + Send + Sync>,
    pending: HashMap<EntityId, PendingRun>,
    next_source: HashMap<EntityId, super::FactSource>,
}

impl RetainedRuns {
    pub(super) fn new(
        vault: Arc<Vault>,
        runtime: Arc<dyn HookBodyRuntime>,
        verdict: Option<Arc<dyn HookVerdict>>,
        wake: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        Self {
            vault,
            runtime,
            verdict,
            wake,
            pending: HashMap::new(),
            next_source: HashMap::new(),
        }
    }

    /// Prefer the other existing source after each completed evaluation,
    /// so a continuous claim feed cannot starve settlement hooks.
    pub(super) fn sources(&self, binding: EntityId) -> [super::FactSource; 2] {
        let mut sources = super::FactSource::ALL;
        if self.next_source.get(&binding) == Some(&sources[1]) {
            sources.reverse();
        }
        sources
    }

    pub(super) fn is_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    pub(super) fn keep_source_order_for(&mut self, bindings: &[(EntityId, PackHookBinding)]) {
        self.next_source
            .retain(|id, _| bindings.iter().any(|(binding, _)| binding == id));
    }

    pub(super) fn bindings(&self) -> HashSet<EntityId> {
        self.pending.keys().copied().collect()
    }

    pub(super) fn drive(
        &mut self,
        runner: &FactHookRunner,
        admission: Option<Box<dyn Send>>,
    ) -> Result<HookPassReport> {
        let mut report = self.finish_ready(runner);
        if let Some(admission) = admission {
            let (vault, runtime) = (Arc::clone(&self.vault), Arc::clone(&self.runtime));
            let next = runner.pass_with(
                &vault,
                runtime.as_ref(),
                super::HOOK_PASS_ENTRIES,
                Some(RetainedPass {
                    runs: self,
                    admission: Arc::new(Mutex::new(admission)),
                }),
            )?;
            report.append(next);
        }
        Ok(report)
    }

    fn finish_ready(&mut self, runner: &FactHookRunner) -> HookPassReport {
        let mut report = HookPassReport::default();
        let bindings: Vec<_> = self.pending.keys().copied().collect();
        for binding in bindings {
            let mut pending = self.pending.remove(&binding).expect("pending fact binding");
            if pending.prepared.is_none() {
                match pending.answer.try_recv() {
                    Ok(prepared) => {
                        if let Some(worker) = pending.worker.take() {
                            let _ = worker.join();
                        }
                        pending.prepared = Some(prepared);
                    }
                    Err(mpsc::TryRecvError::Empty) => {
                        self.pending.insert(binding, pending);
                        continue;
                    }
                    Err(mpsc::TryRecvError::Disconnected) => {
                        // Never repeat an entered job of unknown completion.
                        tracing::error!(binding = %binding.to_hex(), "fact hook job lost its completion");
                        self.pending.insert(binding, pending);
                        continue;
                    }
                }
            }
            match self.finish(&mut pending) {
                Ok(()) => {
                    let source = pending.run.entry.position.source();
                    let next = super::FactSource::ALL
                        .into_iter()
                        .find(|next| *next != source)
                        .expect("two fact sources");
                    self.next_source.insert(binding, next);
                    report.append(pending.report);
                }
                Err(error) => {
                    runner
                        .drained
                        .store(false, std::sync::atomic::Ordering::Release);
                    tracing::warn!(%error, "retained fact hook completion waits for the next pass");
                    self.pending.insert(binding, pending);
                }
            }
        }
        report
    }

    fn finish(&self, pending: &mut PendingRun) -> Result<()> {
        let prepared = pending.prepared.as_ref().expect("answered fact job");
        let run = pending.run.borrowed();
        let mut pass = Pass {
            vault: &self.vault,
            runtime: self.runtime.as_ref(),
            verdict: self.verdict.as_deref(),
            all: &pending.all,
            bodies: HashMap::new(),
            classes: HashMap::new(),
            report: std::mem::take(&mut pending.report),
            retained: None,
            blocked: HashSet::new(),
        };
        let result = (|| {
            let queued = match pending.committed {
                Some(queued) => queued,
                None => {
                    let memo = prepared.memo(&self.vault, &run)?;
                    let queued = pass.commit(&run, memo, &prepared.verdict)?;
                    pass.report.count(&prepared.verdict);
                    pending.committed = Some(queued);
                    queued
                }
            };
            if queued {
                apply::drain_one_current(&self.vault, &run.key, &mut pass.report)?;
            }
            Ok(())
        })();
        pending.report = pass.report;
        result
    }
}

impl RetainedPass<'_> {
    pub(super) fn enqueue(
        &mut self,
        run: &Run<'_>,
        all: &[(EntityId, PackHookBinding)],
        read_key: ScopedReadActorKey,
        body: std::result::Result<String, String>,
        input: String,
        now: u64,
    ) -> Result<()> {
        let owned = OwnedRun {
            binding_id: run.binding_id,
            binding: run.binding.clone(),
            entry: run.entry.clone(),
            key: run.key,
            grant: run.grant.clone(),
            actor: run.actor,
        };
        let job = owned.clone();
        let (vault, runtime, verdict, wake, admission) = (
            Arc::clone(&self.runs.vault),
            Arc::clone(&self.runs.runtime),
            self.runs.verdict.clone(),
            Arc::clone(&self.runs.wake),
            Arc::clone(&self.admission),
        );
        let (answer, receiver) = mpsc::channel();
        let worker = std::thread::Builder::new()
            .name("fact-hook".to_owned())
            .spawn(move || {
                let _admission = admission;
                let lane = vault
                    .scoped_read(read_key)
                    .with_claim_status(ClaimReadStatus::Recorded);
                let result = evaluate(
                    runtime.as_ref(),
                    verdict.as_deref(),
                    &job.borrowed(),
                    &lane,
                    body,
                    input,
                    now,
                    true,
                );
                let _ = answer.send(result);
                wake();
            })?;
        self.runs.pending.insert(
            run.binding_id,
            PendingRun {
                run: owned,
                all: all.to_vec(),
                answer: receiver,
                worker: Some(worker),
                prepared: None,
                committed: None,
                report: HookPassReport::default(),
                _admission: Arc::clone(&self.admission),
            },
        );
        Ok(())
    }
}
