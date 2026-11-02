//! The turn program runtime around a host's executor factory (DOOR-141 PR2).
use std::sync::Arc;

use oneiron::dreamer_runner::maintenance::ContributionReplayHost;
use oneiron::dreamer_wake::{ClaimAuthoringSelection, TurnProgramExecutor, TurnProgramRuntime};
use oneiron::fanout_auto::FanoutDecisions;
use oneiron::{BudgetGuard, EntityId, Result, Vault, WavePlanner, WriteActor};

use super::attachment::{LinkedShutdown, PassAttachment};
use super::factory::{PassExecutorFactory, SkillOptimizerLoan};
use crate::wave_dispatch::{WaveDispatchCandidate, WaveHandoffOutcome};

/// [`PassExecutorFactory`] around a host's own factory, whose executors also
/// run the turn programs landed turns wake (DOOR-141 PR2). Each executor is
/// the host's, wrapped; the program runtime goes with the pass's first one
/// alone. Every other hook is the host factory's own, and the host's
/// executor type stays its own alias. Without a runtime no program is
/// admitted, and nothing else changes.
pub struct ProgramExecutorFactory<F> {
    inner: F,
    runtime: Option<Box<dyn TurnProgramRuntime>>,
}

impl<F> ProgramExecutorFactory<F> {
    #[must_use]
    pub fn new(inner: F, runtime: Option<Box<dyn TurnProgramRuntime>>) -> Self {
        Self { inner, runtime }
    }
}

impl<F: PassExecutorFactory> PassExecutorFactory for ProgramExecutorFactory<F> {
    type Exec<'p>
        = TurnProgramExecutor<'p, F::Exec<'p>>
    where
        Self: 'p;

    fn executor<'p>(&'p mut self, guard: &'p BudgetGuard) -> Result<Self::Exec<'p>> {
        let inner = self.inner.executor(guard)?;
        Ok(TurnProgramExecutor::new(
            inner,
            self.runtime.as_deref_mut(),
            guard,
        ))
    }

    fn macro_executors<'p>(
        &'p mut self,
        guard: &'p BudgetGuard,
        buckets: usize,
    ) -> Result<Vec<Self::Exec<'p>>> {
        let executors = self.inner.macro_executors(guard, buckets)?;
        let mut runtime = self.runtime.as_deref_mut();
        Ok(executors
            .into_iter()
            .map(|inner| TurnProgramExecutor::new(inner, runtime.take(), guard))
            .collect())
    }

    fn actor(&self) -> Option<WriteActor> {
        self.inner.actor()
    }

    fn wave_planner(&self) -> Option<Arc<dyn WavePlanner + Send + Sync>> {
        self.inner.wave_planner()
    }

    fn wave_fanout_decisions<R, G>(&self, principal: EntityId, rule: G) -> R
    where
        G: FnOnce(Option<&FanoutDecisions<'_>>) -> R,
    {
        self.inner.wave_fanout_decisions(principal, rule)
    }

    fn dispatch_wave_candidate(
        &mut self,
        vault: &Vault,
        candidate: WaveDispatchCandidate,
    ) -> Result<WaveHandoffOutcome> {
        self.inner.dispatch_wave_candidate(vault, candidate)
    }

    fn pass_attachment(
        &self,
        vault: &Vault,
        guard: &BudgetGuard,
    ) -> Result<Option<Box<dyn PassAttachment>>> {
        self.inner.pass_attachment(vault, guard)
    }

    fn pass_pause(&self) -> Option<tokio::sync::watch::Receiver<bool>> {
        self.inner.pass_pause()
    }

    fn skill_optimizer(
        &self,
        vault: &Vault,
        guard: &BudgetGuard,
    ) -> Result<Option<SkillOptimizerLoan>> {
        self.inner.skill_optimizer(vault, guard)
    }

    fn contribution_replay_host(
        &self,
        vault: &Vault,
        guard: &BudgetGuard,
    ) -> Result<Option<Box<dyn ContributionReplayHost + Send + Sync>>> {
        self.inner.contribution_replay_host(vault, guard)
    }

    fn claim_authoring_selector(&self, vault: &Vault) -> Result<ClaimAuthoringSelection> {
        self.inner.claim_authoring_selector(vault)
    }

    fn linked_shutdown(&self) -> Option<Arc<dyn LinkedShutdown>> {
        self.inner.linked_shutdown()
    }

    fn run_home_timer(&mut self, vault: &Vault, now_secs: u64, local_node_id: u64) -> Result<()> {
        self.inner.run_home_timer(vault, now_secs, local_node_id)
    }
}
