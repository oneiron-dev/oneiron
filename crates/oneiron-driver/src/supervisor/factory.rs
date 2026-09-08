//! Per-pass attempt-executor factory trait and default implementation.
use std::sync::Arc;

use oneiron::edge::EdgeActorClass;
use oneiron::{
    BudgetGuard, CommitmentWakeExecutor, CommitmentWakeProposalPlanner, ConsolidationExecutor,
    ConsolidationSink, DreamerAttemptExecutor, DreamerClaimAuthoringStrategy, LlmBackend, ModelId,
    Result, Vault, WriteActor,
};
use oneiron_llm_local::{LocalLlmBackend, LocalLlmRuntime};
#[cfg(all(unix, feature = "voice"))]
use oneiron_server::{
    managed::ManagedShutdown,
    voice_host::{VoiceHost, VoiceHostBindings, VoiceHostConfig, VoiceServeConnection},
};

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

    /// Optional process-local attachment, after the supervisor creates its guard.
    /// The default is inert, including for existing custom executor factories.
    #[cfg(all(unix, feature = "voice"))]
    fn voice_host(&self, _vault: &Vault, _guard: &BudgetGuard) -> Result<Option<VoiceHost>> {
        Ok(None)
    }

    /// Claims optional, owner-supplied serve bindings. No connection is invented.
    #[cfg(all(unix, feature = "voice"))]
    fn voice_serve_bindings(&self) -> Result<Option<VoiceServeConnection>> {
        Ok(None)
    }

    /// The configured lifecycle signal, not another shutdown owner.
    #[cfg(all(unix, feature = "voice"))]
    fn voice_shutdown(&self) -> Option<ManagedShutdown> {
        None
    }
}

/// [`PassExecutorFactory`] over the landed [`ConsolidationExecutor`]: owns
/// the [`LlmBackend`] the supervisor constructed at startup plus the
/// promotion sink, and lends both to each pass.
pub struct ConsolidationExecutorFactory {
    pub(super) backend: Arc<dyn LlmBackend>,
    strategy: DreamerClaimAuthoringStrategy,
    pub(super) actor: WriteActor,
    model: ModelId,
    sink: Box<dyn ConsolidationSink>,
    /// CMT-3 (ONE-1540). `None` by DEFAULT, and the wrapper is installed
    /// either way: a tagged commitment event that reached the partition
    /// decoder would be a decode error and a parked driver, so "install the
    /// handler only when a planner is configured" is the one wiring this
    /// factory must not offer.
    commitment_wake_planner: Option<Box<dyn CommitmentWakeProposalPlanner>>,
    #[cfg(all(unix, feature = "voice"))]
    pub(super) voice: Option<VoiceHostConfig>,
}

impl ConsolidationExecutorFactory {
    /// Wraps a host-injected backend (any adapter).
    #[must_use]
    pub fn new(
        backend: Arc<dyn LlmBackend>,
        strategy: DreamerClaimAuthoringStrategy,
        actor: WriteActor,
        model: ModelId,
        sink: Box<dyn ConsolidationSink>,
    ) -> Self {
        Self {
            backend,
            strategy,
            actor,
            model,
            sink,
            commitment_wake_planner: None,
            #[cfg(all(unix, feature = "voice"))]
            voice: None,
        }
    }

    /// Opts into a pass-scoped voice attachment. No provider or meter is built.
    /// `new` and `with_local_runtime` both leave voice unconfigured by default.
    #[cfg(all(unix, feature = "voice"))]
    #[must_use]
    pub fn with_voice(mut self, config: VoiceHostConfig) -> Self {
        self.voice = Some(config);
        self
    }

    /// Opt-in CMT-3 (ONE-1540) proposal planner.
    ///
    /// FALLIBLE on purpose: a planner authors a gated `commitment.wake_proposal`
    /// claim, which requires an Agent-class actor. Refusing here means the host
    /// fails at CONFIGURATION time rather than spinning permanently inside
    /// [`PassExecutorFactory::executor`], which is where the same refusal would
    /// otherwise surface once per pass forever.
    ///
    /// # Errors
    ///
    /// [`oneiron::Error::InvalidClaimBody`] when this factory's actor is not
    /// Agent-class.
    pub fn with_commitment_wake_planner(
        mut self,
        planner: Box<dyn CommitmentWakeProposalPlanner>,
    ) -> Result<Self> {
        if self.actor.actor_class() != EdgeActorClass::Agent {
            return Err(oneiron::Error::InvalidClaimBody(
                "commitment wake planner requires agent actor",
            ));
        }
        self.commitment_wake_planner = Some(planner);
        Ok(self)
    }

    /// Constructs the crate's DEFAULT backend: the LOCAL adapter over a
    /// host-supplied runtime. Local on purpose — the default driver wiring
    /// must not imply network egress; hosts pick a remote adapter only by
    /// explicitly injecting one via [`Self::new`].
    #[must_use]
    pub fn with_local_runtime<R>(
        runtime: R,
        strategy: DreamerClaimAuthoringStrategy,
        actor: WriteActor,
        model: ModelId,
        sink: Box<dyn ConsolidationSink>,
    ) -> Self
    where
        R: LocalLlmRuntime + 'static,
    {
        Self::new(
            Arc::new(LocalLlmBackend::new(runtime)),
            strategy,
            actor,
            model,
            sink,
        )
    }
}

impl PassExecutorFactory for ConsolidationExecutorFactory {
    type Exec<'p> = CommitmentWakeExecutor<'p, ConsolidationExecutor<'p>>;

    fn executor<'p>(&'p mut self, guard: &'p BudgetGuard) -> Result<Self::Exec<'p>> {
        let inner = ConsolidationExecutor {
            backend: self.backend.as_ref(),
            guard,
            strategy: self.strategy,
            actor: self.actor,
            model: self.model.clone(),
            sink: self.sink.as_mut(),
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
        CommitmentWakeExecutor::new(inner, planner, self.actor)
    }

    fn actor(&self) -> Option<WriteActor> {
        Some(self.actor)
    }

    #[cfg(all(unix, feature = "voice"))]
    fn voice_host(&self, vault: &Vault, guard: &BudgetGuard) -> Result<Option<VoiceHost>> {
        let Some(config) = &self.voice else {
            return Ok(None);
        };
        if !std::ptr::eq(vault, config.vault.as_ref()) {
            return Err(oneiron::Error::InvalidConfig(
                "voice attachment must use the supervisor vault".into(),
            ));
        }
        VoiceHost::new(
            Arc::clone(&config.vault),
            &config.runtime,
            VoiceHostBindings {
                backend: Arc::clone(&self.backend),
                budget: guard.clone(),
                extraction_prompt: config.extraction_prompt.clone(),
                session: config.session.clone(),
                shutdown: config.shutdown.clone(),
            },
        )
        .map(Some)
        .map_err(|error| {
            oneiron::Error::InvalidConfig(format!("voice attachment refused: {error}"))
        })
    }

    #[cfg(all(unix, feature = "voice"))]
    fn voice_serve_bindings(&self) -> Result<Option<VoiceServeConnection>> {
        let Some(bindings) = self
            .voice
            .as_ref()
            .and_then(|config| config.serve_bindings.as_ref())
        else {
            return Ok(None);
        };
        bindings.take().map_err(|error| {
            oneiron::Error::InvalidConfig(format!("voice serve bindings refused: {error}"))
        })
    }

    #[cfg(all(unix, feature = "voice"))]
    fn voice_shutdown(&self) -> Option<ManagedShutdown> {
        self.voice.as_ref().map(|config| config.shutdown.clone())
    }
}
