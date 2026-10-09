//! Per-pass attempt-executor factory trait and default implementation.
use std::sync::Arc;

use crate::wave_dispatch::{WaveDispatchCandidate, WaveHandoffOutcome};
use oneiron::dreamer_wake::{WeaveRecipeExecutor, WeaveRecipeRuntime};
use oneiron::edge::EdgeActorClass;
use oneiron::llm::{ExtractionEgressPredicate, HostInferenceBinding, HostInferenceContext};
use oneiron::{
    BudgetGuard, CommitmentWakeExecutor, CommitmentWakeProposalPlanner, ConsolidationExecutor,
    ConsolidationSink, DreamerAttemptExecutor, DreamerClaimAuthoringStrategy, LlmBackend, ModelId,
    Result, WriteActor,
};
use oneiron::{Vault, WavePlanner};
use oneiron_llm_local::{LocalLlmBackend, LocalLlmRuntime};

use super::attachment::{LinkedShutdown, PassAttachment, PassAttachmentSource};

/// Host-supplied consumer of the live ready TASK subset.
pub type WaveReadyDispatcher =
    Box<dyn FnMut(&Vault, WaveDispatchCandidate) -> Result<WaveHandoffOutcome> + Send>;

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

    /// The attachment host's lifecycle signal, not another shutdown owner.
    fn linked_shutdown(&self) -> Option<Arc<dyn LinkedShutdown>> {
        None
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
    sink: Box<dyn ConsolidationSink>,
    /// CMT-3 (ONE-1540). `None` by DEFAULT, and the wrapper is installed
    /// either way: a tagged commitment event that reached the partition
    /// decoder would be a decode error and a parked driver, so "install the
    /// handler only when a planner is configured" is the one wiring this
    /// factory must not offer.
    commitment_wake_planner: Option<Box<dyn CommitmentWakeProposalPlanner>>,
    weave_recipe_runtime: Option<Box<dyn WeaveRecipeRuntime>>,
    wave_planner: Option<Arc<dyn WavePlanner + Send + Sync>>,
    wave_dispatch: Option<WaveReadyDispatcher>,
    attachment: Option<Box<dyn PassAttachmentSource>>,
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
            sink,
            commitment_wake_planner: None,
            weave_recipe_runtime: None,
            wave_planner: None,
            wave_dispatch: None,
            attachment: None,
        }
    }

    /// Opts into a pass-scoped host attachment (the server's voice host is
    /// one). No provider or meter is built here; `new` and
    /// `with_local_runtime` both leave it unconfigured.
    #[must_use]
    pub fn with_pass_attachment(mut self, source: Box<dyn PassAttachmentSource>) -> Self {
        self.attachment = Some(source);
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

    /// Enables the per-vault owner-admitted weave recipe executor. Without a
    /// host interpreter recipe attempts park; no model or prompt is implicit.
    #[must_use]
    pub fn with_weave_recipe_runtime(mut self, runtime: Box<dyn WeaveRecipeRuntime>) -> Self {
        self.weave_recipe_runtime = Some(runtime);
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

impl PassExecutorFactory for ConsolidationExecutorFactory {
    type Exec<'p> = WeaveRecipeExecutor<
        CommitmentWakeExecutor<'p, ConsolidationExecutor<'p>>,
        Option<&'p mut dyn WeaveRecipeRuntime>,
    >;

    fn executor<'p>(&'p mut self, guard: &'p BudgetGuard) -> Result<Self::Exec<'p>> {
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
            sink: self.sink.as_mut(),
            scope: None,
        };
        // The trait-object lifetime is shortened HERE, one reference at a time:
        // `&mut` is invariant in its pointee, so the coercion cannot happen
        // through the `Option` and `as_deref_mut()` alone would pin the pass
        // lifetime to `'static`.
        let planner = match self.commitment_wake_planner.as_mut() {
            Some(planner) => {
                let planner: &mut dyn CommitmentWakeProposalPlanner = planner.as_mut();
                Some(planner)
            }
            None => None,
        };
        // Always wrapped. With no planner the wrapper never reads the actor, so
        // this stays infallible for every legal existing host — including a
        // System-class one — and a tagged event completes as a typed no-planner
        // skip instead of reaching the partition decoder.
        let inner = CommitmentWakeExecutor::new(inner, planner, self.actor)?;
        let runtime = self.weave_recipe_runtime.as_mut().map(|runtime| {
            let runtime: &mut dyn WeaveRecipeRuntime = runtime.as_mut();
            runtime
        });
        Ok(WeaveRecipeExecutor { inner, runtime })
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
