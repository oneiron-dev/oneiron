//! Per-pass attempt-executor factory trait and default implementation.
use std::sync::Arc;

use crate::wave_dispatch::{WaveDispatchCandidate, WaveHandoffOutcome};
use oneiron::dreamer_consolidation::{
    DREAMER_NARRATIVE_ROLE, PersonAboutExecutor, RoleBackends, RoleCall, ScopeSummaryExecutor,
};
use oneiron::dreamer_runner::connector_event::{ConnectorEventExecutor, ConnectorEventResponder};
use oneiron::dreamer_runner::maintenance::{CoachLiveSlice, CoachSkillOptimizer};
use oneiron::dreamer_wake::{WeaveRecipeExecutor, WeaveRecipeRuntime};
use oneiron::edge::EdgeActorClass;
use oneiron::llm::{ExtractionEgressPredicate, HostInferenceBinding, HostInferenceContext};
use oneiron::skill_optimize::{HeldOutReplayNotes, SkillOptimizeAuthor};
use oneiron::{
    BudgetGuard, CommitmentWakeExecutor, CommitmentWakeProposalPlanner, ConsolidationDecisions,
    ConsolidationExecutor, ConsolidationSink, DreamerAttemptExecutor,
    DreamerClaimAuthoringStrategy, LlmBackend, ModelId, Result, WriteActor,
};
use oneiron::{Vault, WavePlanner};
use oneiron_llm_local::{LocalLlmBackend, LocalLlmRuntime};

use super::attachment::{LinkedShutdown, PassAttachment, PassAttachmentSource};

/// Host-supplied consumer of the live ready TASK subset.
pub type WaveReadyDispatcher =
    Box<dyn FnMut(&Vault, WaveDispatchCandidate) -> Result<WaveHandoffOutcome> + Send>;

/// The Coach's skill optimizer for one pass, owned by the pass: the host's
/// drafting author, its independent held-out judge and the live slice that
/// judge's arms fund. The supervisor lends it to the pass's wake driver.
pub struct SkillOptimizerLoan {
    pub author: Box<dyn SkillOptimizeAuthor + Send + Sync>,
    pub scorer: &'static (dyn HeldOutReplayNotes + Send + Sync),
    pub live: Option<CoachLiveSlice<'static>>,
}

impl SkillOptimizerLoan {
    /// The optimizer the wake driver borrows for the pass.
    #[must_use]
    pub fn optimizer(&self) -> CoachSkillOptimizer<'_> {
        CoachSkillOptimizer {
            author: &*self.author,
            scorer: self.scorer,
            live: self.live,
        }
    }
}

/// Builds the per-pass attempt executor. Generic-associated so executors may
/// borrow factory-owned state (the backend constructed at startup, the
/// promotion sink) and per-pass state (the fresh [`BudgetGuard`]).
pub trait PassExecutorFactory {
    type Exec<'p>: DreamerAttemptExecutor
    where
        Self: 'p;

    /// Builds the executor for one pass. `guard` is the pass's wake-budget
    /// counter — the same counter the driver reads for legibility, never a
    /// second one.
    fn executor<'p>(&'p mut self, guard: &'p BudgetGuard) -> Result<Self::Exec<'p>>;

    /// Independent executors for disjoint home-owned MACRO buckets, all on
    /// this pass's meter. A host with a non-shareable sink lends one executor.
    fn macro_executors<'p>(
        &'p mut self,
        guard: &'p BudgetGuard,
        _buckets: usize,
    ) -> Result<Vec<Self::Exec<'p>>> {
        Ok(vec![self.executor(guard)?])
    }

    /// The engine-stamped actor for policy-aware budget construction;
    /// `None` selects the legacy single-pool guard.
    fn actor(&self) -> Option<WriteActor> {
        None
    }

    /// Agent-authored wave planner registered by the host, if any. No
    /// hardcoded plan or default external effect is supplied by the driver.
    fn wave_planner(&self) -> Option<Arc<dyn WavePlanner + Send + Sync>> {
        None
    }

    /// The existing host TASK dispatch path receives only the live ready set.
    /// A factory that registers a planner must also supply this consumer.
    fn dispatch_wave_candidate(
        &mut self,
        _vault: &Vault,
        _candidate: WaveDispatchCandidate,
    ) -> Result<WaveHandoffOutcome> {
        Err(oneiron::Error::InvalidConfig(
            "wave dispatcher not registered".into(),
        ))
    }

    /// Optional host attachment for one pass, asked after the supervisor
    /// creates the pass meter. The default is inert, including for existing
    /// custom executor factories.
    fn pass_attachment(
        &self,
        _vault: &Vault,
        _guard: &BudgetGuard,
    ) -> Result<Option<Box<dyn PassAttachment>>> {
        Ok(None)
    }

    /// The Coach's skill optimizer for one pass, asked once the pass meter
    /// exists. The default has none, and a skill-optimize attempt parks for
    /// want of a host author.
    fn skill_optimizer(
        &self,
        _vault: &Vault,
        _guard: &BudgetGuard,
    ) -> Result<Option<SkillOptimizerLoan>> {
        Ok(None)
    }

    /// The attachment host's lifecycle signal, not another shutdown owner.
    fn linked_shutdown(&self) -> Option<Arc<dyn LinkedShutdown>> {
        None
    }

    /// The host's home-timer work, run once a Deadline pass is done: the
    /// standing-question pump (OF-506). The default has none.
    fn run_home_timer(
        &mut self,
        _vault: &Vault,
        _now_secs: u64,
        _local_node_id: u64,
    ) -> Result<()> {
        Ok(())
    }
}

/// [`PassExecutorFactory`] over the landed [`ConsolidationExecutor`]: owns
/// the [`LlmBackend`] the supervisor constructed at startup plus the
/// promotion sink, and lends both to each pass.
pub struct ConsolidationExecutorFactory {
    backend: Arc<dyn LlmBackend>,
    strategy: DreamerClaimAuthoringStrategy,
    pub(super) actor: WriteActor,
    model: ModelId,
    binding: HostInferenceBinding,
    extraction_egress: Option<Arc<dyn ExtractionEgressPredicate>>,
    /// The backend each Dreamer role calls out on; a role it does not name
    /// calls `backend`.
    roles: RoleBackends,
    sink: Box<dyn ConsolidationSink>,
    parallel_sinks: Vec<Box<dyn ConsolidationSink>>,
    /// CMT-3 (ONE-1540). `None` by DEFAULT, and the wrapper is installed
    /// either way: a tagged commitment event that reached the partition
    /// decoder would be a decode error and a parked driver, so "install the
    /// handler only when a planner is configured" is the one wiring this
    /// factory must not offer.
    commitment_wake_planner: Option<Box<dyn CommitmentWakeProposalPlanner>>,
    weave_recipe_runtime: Option<Box<dyn WeaveRecipeRuntime>>,
    /// OF-218. `None` by default, and the connector-event wrapper is
    /// installed either way: with no responder a wake is delivered and
    /// settled, never fed to the partition decoder.
    connector_event_responder: Option<Box<dyn ConnectorEventResponder>>,
    /// The host's instruction for declared scope summaries. `None` leaves a
    /// declaration unable to run; the host refuses declarations up front.
    summary_instruction: Option<String>,
    /// The host's wording for PERSON `about` lines. `None` writes them with
    /// the engine's own.
    person_about_instruction: Option<String>,
    wave_planner: Option<Arc<dyn WavePlanner + Send + Sync>>,
    wave_dispatch: Option<WaveReadyDispatcher>,
    attachment: Option<Box<dyn PassAttachmentSource>>,
    /// The host's ladder for the Dreamer's typed questions. `None` asks them
    /// with the shipped wording, the verdict role's read the only rung.
    decisions: Option<ConsolidationDecisions>,
}

impl ConsolidationExecutorFactory {
    /// Wraps a host-injected backend (any adapter).
    #[must_use]
    pub fn new(
        backend: Arc<dyn LlmBackend>,
        strategy: DreamerClaimAuthoringStrategy,
        actor: WriteActor,
        model: ModelId,
        binding: HostInferenceBinding,
        extraction_egress: Option<Arc<dyn ExtractionEgressPredicate>>,
        sink: Box<dyn ConsolidationSink>,
    ) -> Self {
        Self {
            backend,
            strategy,
            actor,
            model,
            binding,
            extraction_egress,
            roles: RoleBackends::default(),
            sink,
            parallel_sinks: Vec::new(),
            commitment_wake_planner: None,
            weave_recipe_runtime: None,
            connector_event_responder: None,
            summary_instruction: None,
            person_about_instruction: None,
            wave_planner: None,
            wave_dispatch: None,
            attachment: None,
            decisions: None,
        }
    }

    /// The host's ladder, dial, bands and wording for the Dreamer's typed
    /// questions: how a conflict resolves, and which listed claim a candidate
    /// corrects.
    #[must_use]
    pub fn with_decisions(mut self, decisions: ConsolidationDecisions) -> Self {
        self.decisions = Some(decisions);
        self
    }

    /// Opts into a pass-scoped host attachment (the server's voice host is
    /// one). No provider or meter is built here; `new` and
    /// `with_local_runtime` both leave it unconfigured.
    #[must_use]
    pub fn with_pass_attachment(mut self, source: Box<dyn PassAttachmentSource>) -> Self {
        self.attachment = Some(source);
        self
    }

    /// Routes each Dreamer role to its own backend (ARCH-0036 roles); a role
    /// `roles` does not name keeps this factory's backend.
    #[must_use]
    pub fn with_role_backends(mut self, roles: RoleBackends) -> Self {
        self.roles = roles;
        self
    }

    /// The backend this factory lends to every pass.
    #[must_use]
    pub fn backend(&self) -> &Arc<dyn LlmBackend> {
        &self.backend
    }

    /// Opt-in CMT-3 (ONE-1540) proposal planner.
    ///
    /// FALLIBLE on purpose: a planner authors a gated `commitment.wake_proposal`
    /// claim, which requires an Agent or the vault Dreamer's System actor.
    /// Refusing here means the host
    /// fails at CONFIGURATION time rather than spinning permanently inside
    /// [`PassExecutorFactory::executor`], which is where the same refusal would
    /// otherwise surface once per pass forever.
    ///
    /// # Errors
    ///
    /// [`oneiron::Error::InvalidClaimBody`] when this factory's actor is
    /// neither Agent nor System.
    pub fn with_commitment_wake_planner(
        mut self,
        planner: Box<dyn CommitmentWakeProposalPlanner>,
    ) -> Result<Self> {
        if !matches!(
            self.actor.actor_class(),
            EdgeActorClass::Agent | EdgeActorClass::System
        ) {
            return Err(oneiron::Error::InvalidClaimBody(
                "commitment wake planner requires agent or Dreamer system actor",
            ));
        }
        self.commitment_wake_planner = Some(planner);
        Ok(self)
    }

    /// The instruction the Dreamer composes declared scope summaries with
    /// (ARCH-0006a). Host configuration; the engine ships no summary prompt.
    #[must_use]
    pub fn with_scope_summary_instruction(mut self, instruction: String) -> Self {
        self.summary_instruction = Some(instruction);
        self
    }

    /// The instruction PERSON `about` lines are written with (ARCH-0067).
    /// Host configuration; without it the engine's own applies.
    #[must_use]
    pub fn with_person_about_instruction(mut self, instruction: String) -> Self {
        self.person_about_instruction = Some(instruction);
        self
    }

    /// Enables the per-vault owner-admitted weave recipe executor. Without a
    /// host interpreter recipe attempts park; no model or prompt is implicit.
    #[must_use]
    pub fn with_weave_recipe_runtime(mut self, runtime: Box<dyn WeaveRecipeRuntime>) -> Self {
        self.weave_recipe_runtime = Some(runtime);
        self
    }

    /// Runs the target agent on each connector wake and sends its reply
    /// through the ordinary outbound pipeline (OF-218).
    #[must_use]
    pub fn with_connector_event_responder(
        mut self,
        responder: Box<dyn ConnectorEventResponder>,
    ) -> Self {
        self.connector_event_responder = Some(responder);
        self
    }

    /// Register the host's agent-side planner AND TASK dispatcher together.
    /// A plan cut is agent policy; the supervisor owns only durable admission
    /// and the computed-ready handoff, never a built-in plan or work DSL.
    #[must_use]
    pub fn with_wave_planner(
        mut self,
        planner: Arc<dyn WavePlanner + Send + Sync>,
        dispatch: WaveReadyDispatcher,
    ) -> Self {
        self.wave_planner = Some(planner);
        self.wave_dispatch = Some(dispatch);
        self
    }

    /// Constructs the crate's DEFAULT backend: the LOCAL adapter over a
    /// host-supplied runtime. Local on purpose — the default driver wiring
    /// must not imply network egress; hosts pick a remote adapter only by
    /// explicitly injecting one via [`Self::new`].
    pub fn with_local_runtime<R>(
        vault: &Vault,
        runtime: R,
        strategy: DreamerClaimAuthoringStrategy,
        actor: WriteActor,
        model: ModelId,
        sink: Box<dyn ConsolidationSink>,
    ) -> Result<Self>
    where
        R: LocalLlmRuntime + 'static,
    {
        Ok(Self::new(
            Arc::new(LocalLlmBackend::from_registry(runtime, vault)?),
            strategy,
            actor,
            model.clone(),
            HostInferenceBinding::Advertised {
                model,
                locality: oneiron::ModelLocality::OnDevice,
            },
            None,
            sink,
        ))
    }
}

impl ConsolidationExecutorFactory {
    fn build_executors<'p>(
        &'p mut self,
        guard: &'p BudgetGuard,
        buckets: usize,
    ) -> Result<Vec<<Self as PassExecutorFactory>::Exec<'p>>> {
        self.parallel_sinks.clear();
        for _ in 1..buckets {
            let Some(sink) = self.sink.fork() else {
                break;
            };
            self.parallel_sinks.push(sink);
        }
        let mut planner = match self.commitment_wake_planner.as_mut() {
            Some(planner) => {
                let planner: &mut dyn CommitmentWakeProposalPlanner = planner.as_mut();
                Some(planner)
            }
            None => None,
        };
        let mut runtime = self.weave_recipe_runtime.as_mut().map(|runtime| {
            let runtime: &mut dyn WeaveRecipeRuntime = runtime.as_mut();
            runtime
        });
        let mut responder = self.connector_event_responder.as_mut().map(|responder| {
            let responder: &mut dyn ConnectorEventResponder = responder.as_mut();
            responder
        });
        let narrative = RoleCall::resolve(
            &self.roles,
            DREAMER_NARRATIVE_ROLE,
            self.backend.as_ref(),
            &self.model,
            &self.binding,
            self.extraction_egress.as_deref(),
        );
        let decisions = match &self.decisions {
            Some(decisions) => decisions.clone(),
            None => ConsolidationDecisions::shipped()?,
        };
        let mut executors = Vec::new();
        for sink in std::iter::once(&mut self.sink).chain(self.parallel_sinks.iter_mut()) {
            let inner = ConsolidationExecutor {
                backend: self.backend.as_ref(),
                guard,
                strategy: self.strategy,
                actor: self.actor,
                model: self.model.clone(),
                inference: HostInferenceContext {
                    binding: self.binding.clone(),
                    extraction_egress: self.extraction_egress.as_deref(),
                },
                roles: self.roles.clone(),
                sink: sink.as_mut(),
                scope: None,
                decisions: decisions.clone(),
            };
            // Only the first worker admits non-consolidation priority work.
            let inner = CommitmentWakeExecutor::new(inner, planner.take(), self.actor)?;
            let inner = ScopeSummaryExecutor::new(
                inner,
                narrative.backend,
                guard,
                self.actor,
                narrative.model.clone(),
                HostInferenceContext {
                    binding: narrative.inference.binding.clone(),
                    extraction_egress: narrative.inference.extraction_egress,
                },
                self.summary_instruction.as_deref(),
            );
            // PEOPLE `about` lines ride the same narrative role.
            let inner = PersonAboutExecutor::new(
                inner,
                narrative.backend,
                guard,
                self.actor,
                narrative.model.clone(),
                HostInferenceContext {
                    binding: narrative.inference.binding.clone(),
                    extraction_egress: narrative.inference.extraction_egress,
                },
                self.person_about_instruction.as_deref(),
            );
            let inner = WeaveRecipeExecutor {
                inner,
                runtime: runtime.take(),
            };
            executors.push(ConnectorEventExecutor::new(inner, responder.take()));
        }
        Ok(executors)
    }
}

impl PassExecutorFactory for ConsolidationExecutorFactory {
    type Exec<'p> = ConnectorEventExecutor<
        'p,
        WeaveRecipeExecutor<
            PersonAboutExecutor<
                'p,
                ScopeSummaryExecutor<'p, CommitmentWakeExecutor<'p, ConsolidationExecutor<'p>>>,
            >,
            Option<&'p mut dyn WeaveRecipeRuntime>,
        >,
    >;

    fn executor<'p>(&'p mut self, guard: &'p BudgetGuard) -> Result<Self::Exec<'p>> {
        Ok(self.build_executors(guard, 1)?.remove(0))
    }

    fn macro_executors<'p>(
        &'p mut self,
        guard: &'p BudgetGuard,
        buckets: usize,
    ) -> Result<Vec<Self::Exec<'p>>> {
        self.build_executors(guard, buckets)
    }

    fn actor(&self) -> Option<WriteActor> {
        Some(self.actor)
    }

    fn wave_planner(&self) -> Option<Arc<dyn WavePlanner + Send + Sync>> {
        self.wave_planner.clone()
    }

    fn dispatch_wave_candidate(
        &mut self,
        vault: &Vault,
        candidate: WaveDispatchCandidate,
    ) -> Result<WaveHandoffOutcome> {
        self.wave_dispatch
            .as_mut()
            .ok_or_else(|| oneiron::Error::InvalidConfig("wave dispatcher not registered".into()))?(
            vault, candidate,
        )
    }

    fn pass_attachment(
        &self,
        vault: &Vault,
        guard: &BudgetGuard,
    ) -> Result<Option<Box<dyn PassAttachment>>> {
        match &self.attachment {
            Some(source) => source.attach(vault, &self.backend, guard),
            None => Ok(None),
        }
    }

    fn linked_shutdown(&self) -> Option<Arc<dyn LinkedShutdown>> {
        self.attachment
            .as_ref()
            .and_then(|source| source.linked_shutdown())
    }
}
