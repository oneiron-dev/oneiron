//! The handle request handlers hold (`AiHandle`): its seats, settings,
//! status, turn tracking and Dreamer hints. Its struct and fields stay in
//! the facade; these are its methods.

use super::*;

impl AiHandle {
    /// The control the Dreamer's passes read their pause through, when this
    /// host attached under one: `None` where no owner pause can hold a pass.
    pub(crate) fn dreamer_control(&self) -> Option<DreamerControl> {
        self.dreamer_control.clone()
    }

    pub(crate) fn host_compaction(
        &self,
    ) -> Option<(
        Arc<dyn oneiron::compaction::CompactionBackend>,
        oneiron::compaction::CompactionGatePolicy,
    )> {
        self.host_compaction.get().cloned()
    }

    /// No `[models]`: every seat empty, every worker idle for want of one.
    #[must_use]
    pub fn inert() -> Self {
        Self::unstarted(Arc::new(ModelRuntime::unconfigured()), None)
    }

    pub(super) fn unstarted(runtime: Arc<ModelRuntime>, models: Option<&ModelsConfig>) -> Self {
        let idle = || WorkStatus::idle(IdleReason::NoModelConfigured);
        let chat = if runtime.seat(CHAT_ROLE).is_some() {
            WorkStatus::waiting()
        } else {
            idle()
        };
        Self {
            runtime,
            status: Arc::new(StatusCell::new(AiStatus {
                dreamer: idle(),
                workflows: idle(),
                chat,
                compaction: CompactionStatus::off(match models {
                    None => oneiron::compaction::CompactionOff::NoModels.as_str(),
                    Some(_) => status::CODE_MODE_OFF,
                }),
            })),
            hints: None,
            chat: models.map_or(
                ChatSettings {
                    history_turns: 0,
                    turn_budget_units: 0,
                },
                |models| models.chat,
            ),
            prompt_layout: models.and_then(|models| models.prompt_layout),
            voice: models.map(|models| models.voice.clone()),
            raw_budget_units: models
                .map_or(crate::config::models::DEFAULT_RAW_BUDGET_UNITS, |models| {
                    models.raw_budget_units
                }),
            rerank_budget_units: models.map_or(0, |models| models.recall.rerank_budget_units),
            turns: TurnTracker::new(),
            inbound: Arc::new(AtomicU64::new(unix_now())),
            summaries: false,
            decisions: Arc::default(),
            host_compaction: Arc::default(),
            device: false,
            writer_compaction: Arc::default(),
            confession: confession_wording::of(models),
            dreamer_control: None,
        }
    }

    /// What the Dreamer's wake policy samples before each decision (ARCH-0026
    /// #wake): running chat turns, live workflow work and the last landed
    /// turn. The Dreamer runs only on a seat, so compute is there.
    pub(super) fn idle_sample(&self) -> IdleSample {
        let turns = self.turns.clone();
        let status = Arc::clone(&self.status);
        let inbound = Arc::clone(&self.inbound);
        Arc::new(move || WakeIdleState {
            running_turns: turns.running(),
            live_background_work: status.snapshot().workflows.state == WorkState::Working,
            compute_available: true,
            last_inbound_at: inbound.load(Ordering::Acquire),
        })
    }

    /// Whether a declared scope summary will be written: only the Dreamer
    /// writes a summary body (ARCH-0006a), so without a running Dreamer and
    /// its summary instruction a declaration is refused, never parked.
    pub fn summary_writer(&self) -> Result<(), String> {
        if self.summaries {
            return Ok(());
        }
        Err(match self.status().dreamer.reason {
            Some(reason) if self.hints.is_none() => {
                let reason = serde_json::to_value(reason)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_default();
                format!("the Dreamer is idle: {reason}")
            }
            _ => "the Dreamer has no summary instruction ([models.dreamer] summary_prompt)"
                .to_owned(),
        })
    }

    #[must_use]
    pub fn seat(&self, role: ModelRole) -> Option<&Seat> {
        self.runtime.seat(role)
    }

    /// The seat chat turns run on.
    #[must_use]
    pub fn chat_seat(&self) -> Option<&Seat> {
        self.runtime.seat(CHAT_ROLE)
    }

    #[must_use]
    pub fn chat_settings(&self) -> ChatSettings {
        self.chat
    }

    /// The layout a turn assembled now takes (FIX 6676): the vault's
    /// `[models] prompt_layout` when it sets one, else the host's
    /// `ONEIRON_PROMPT_LAYOUT`, else today's order. Read once per turn.
    #[must_use]
    pub(crate) fn prompt_layout(&self) -> oneiron::prompt::PromptLayout {
        oneiron::prompt::effective_prompt_layout(self.prompt_layout)
    }

    /// The resolved voice settings; absent when no models are configured.
    pub(crate) fn voice_settings(&self) -> Option<&VoiceSettings> {
        self.voice.as_ref()
    }

    /// The line each recall at high, xhigh or max spends its rerank calls
    /// on.
    #[must_use]
    pub fn rerank_budget_units(&self) -> u64 {
        self.rerank_budget_units
    }

    /// Whether the host syncs as a device of another home (`[device_sync]`),
    /// so its home-gated work defers to the elected home.
    #[must_use]
    pub(crate) fn device(&self) -> bool {
        self.device
    }

    /// Whether this host's Dreamer runs, so it can take MACRO work: what its
    /// home candidacy declares (FIX 4898).
    #[must_use]
    pub(crate) fn dreamer_runs(&self) -> bool {
        self.hints.is_some()
    }

    /// Admits a call of `role` against the vault's live model policy: its
    /// manifest and route when it has one, the role's seat otherwise.
    pub fn admit_role(
        &self,
        vault: &Vault,
        role: ModelRole,
        request: oneiron::LlmRequest,
    ) -> Result<RoleCall, RoleRefusal> {
        self.runtime.admit_role(vault, role, request)
    }

    /// A run that declares nothing on `meter` (a chat turn's line), with this
    /// server's run receipts.
    pub(crate) fn undeclared_run(
        &self,
        run: impl Into<String>,
        meter: oneiron::BudgetGuard,
    ) -> oneiron::llm::run_admission::RunAdmission {
        self.runtime.undeclared_run(run, meter)
    }

    /// A declared run on this server's models, for the host that states a
    /// run's teachers and budget (a training loop). Nothing on the server
    /// declares a run yet.
    #[must_use]
    pub fn declared_run(
        &self,
        run: impl Into<String>,
        declaration: oneiron::llm::run_admission::RunDeclaration,
        host: Option<Arc<oneiron::llm::run_admission::HostAccount>>,
    ) -> crate::models::DeclaredRun {
        self.runtime.declared_run(run, declaration, host)
    }

    /// Registers a running chat turn with shutdown.
    pub(crate) fn enter_turn(&self) -> TurnGuard {
        self.turns.enter()
    }

    /// Where a configured model runs: the host's attestation for raw calls.
    #[must_use]
    pub fn model_locality(&self, model: &ModelId) -> Option<ModelLocality> {
        self.runtime
            .router()
            .and_then(|router| router.locality(model))
    }

    /// The catalog entry of every configured chat model served by its own
    /// id.
    #[must_use]
    pub fn chat_catalog(&self) -> Vec<oneiron::LlmCatalogEntry> {
        self.runtime
            .router()
            .map(|router| router.chat_catalog().cloned().collect())
            .unwrap_or_default()
    }

    #[must_use]
    pub fn status(&self) -> AiStatus {
        self.status.snapshot()
    }

    #[must_use]
    pub fn models_status(&self) -> &ModelsStatus {
        self.runtime.status()
    }

    /// [`Self::models_status`] with each offer's live health (OF-305).
    #[must_use]
    pub fn models_live_status(&self) -> ModelsStatus {
        self.runtime.live_status()
    }

    /// The models this server serves, for the `ai.*` verbs.
    #[must_use]
    pub(crate) fn model_runtime(&self) -> &ModelRuntime {
        &self.runtime
    }

    /// Whether a running Dreamer takes session hints.
    pub(crate) fn takes_session_hints(&self) -> bool {
        self.hints.is_some()
    }

    /// Tells the Dreamer's session policy what the app saw, in arrival order
    /// (FIX 8602): under real memory pressure the call waits its turn, off
    /// the runtime's workers, until the fact is kept, the Dreamer is gone, or
    /// `deadline` passes — the caller's own, never one started here. A no-op
    /// without a running Dreamer: no session is opened that nothing would
    /// close.
    pub fn session_hint(
        &self,
        key: oneiron::session_lifecycle::SessionKey,
        hint: SessionHint,
        deadline: Option<std::time::Instant>,
    ) {
        let Some(hints) = &self.hints else {
            return;
        };
        let kept = match hints.push_session_hint(key, hint, None) {
            Err(oneiron_driver::TickPushError::MemoryPressure) => crate::server::blocking(|| {
                hints.push_session_hint_waiting(key, hint, None, deadline)
            }),
            kept => kept,
        };
        if let Err(error) = kept {
            tracing::warn!(?error, ?hint, "dreamer session hint not kept");
        }
    }

    /// A turn landed: a due turn queues the running Dreamer's Micro wake
    /// (ARCH-0026 RD-26), off the request path. A no-op without a running
    /// Dreamer, so a model-free vault queues nothing that never runs.
    pub fn turn_landed(&self, vault: &Arc<Vault>, subject: WakeTurnSubject) {
        self.inbound.fetch_max(unix_now(), Ordering::AcqRel);
        drop(self.wake_on_turn(vault, subject));
    }

    /// [`Self::turn_landed`]'s wake and the task it runs on, for a caller
    /// that waits for it. `None` without a running Dreamer.
    pub(super) fn wake_on_turn(
        &self,
        vault: &Arc<Vault>,
        subject: WakeTurnSubject,
    ) -> Option<tokio::task::JoinHandle<()>> {
        self.hints.as_ref()?;
        let (vault, handle) = (Arc::clone(vault), self.clone());
        Some(tokio::task::spawn_blocking(move || {
            // An agent waking under a dial its owner moved notes the move in
            // its own diary before it acts again (OF-533).
            if let WakeTurnSubject::Agent { id, .. } = subject
                && let Err(error) = vault.note_refusal_dial_change(id)
            {
                tracing::warn!(%error, agent = %id.to_hex(), "refusal dial note not written");
            }
            // Queued or not, the turn is news to the wake policy: the pass
            // the hint takes re-reads its rows and re-arms its quiet timer.
            match vault.wake_dreamer_on_turn(subject, vault.now_recorded_at()) {
                Ok(_) => handle.attempt_queued(),
                Err(error) => tracing::warn!(%error, ?subject, "turn wake not queued"),
            }
            // DOOR-141: a program this turn woke is admitted from the wake
            // its commit recorded; at boot, every wake a stop or crash left.
            turn_program::drain_turn_programs(&vault);
        }))
    }

    /// The sieve reads a bounded batch with each turn wake; history it has
    /// not read yet (a vault the Dreamer starts on for the first time) is
    /// read here, a pass at a time, off the request path, until it is read
    /// or shutdown raises the drain's stop. A pass in flight then commits
    /// its own transaction, and the drain stops before the next. `None`
    /// without a running Dreamer.
    pub(super) fn drain_sieve(&self, vault: &Arc<Vault>) -> Option<SieveDrain> {
        self.hints.as_ref()?;
        let vault = Arc::clone(vault);
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let task = tokio::task::spawn_blocking(move || {
            while !stopped.load(Ordering::Acquire) {
                match vault.sieve_pass(vault.now_recorded_at()) {
                    Ok(pass) if pass.more => {}
                    Ok(_) => break,
                    Err(error) => {
                        tracing::warn!(kind = ?error.kind(), "sieve backlog pass failed");
                        break;
                    }
                }
            }
        });
        Some(SieveDrain { stop, task })
    }

    /// A Dreamer attempt was queued outside the driver: the running Dreamer
    /// takes a pass for it now instead of at its next deadline.
    pub fn attempt_queued(&self) {
        let Some(hints) = &self.hints else {
            return;
        };
        if let Err(error) = hints.push_hint() {
            tracing::warn!(?error, "dreamer pass hint dropped");
        }
    }

    /// [`Self::turn_landed`] for a turn `actor` wrote: an agent with a stored
    /// definition counts it on its own cadence dial, anyone else on the
    /// vault's grain.
    pub fn turn_landed_by(&self, vault: &Arc<Vault>, actor: EntityId, class: EdgeActorClass) {
        let agent = class == EdgeActorClass::Agent
            && vault
                .get_agent_definition(&actor)
                .is_ok_and(|found| found.is_some());
        self.turn_landed(
            vault,
            if agent {
                WakeTurnSubject::Agent {
                    id: actor,
                    signals: AgentWakeSignals::default(),
                }
            } else {
                WakeTurnSubject::Vault
            },
        );
    }
}

impl AiHandle {
    /// The model seats this host built: inert ones when `[models]` is unset.
    pub(crate) fn models(&self) -> &Arc<ModelRuntime> {
        &self.runtime
    }

    /// The router the raw `/v1/llm` routes call, with its own meter.
    pub(crate) fn decision_read(&self) -> Option<crate::models::DecisionReadDoor> {
        self.runtime.decision_read().cloned()
    }

    /// The raw routes' inference: the runtime's raw router on its own meter.
    /// With no configured model the router holds only the models the
    /// owner's other nodes offer (FIX 3229).
    pub(crate) fn raw_inference(&self) -> RawInference {
        RawInference::configured(
            self.runtime.raw_router(),
            oneiron::BudgetGuard::new(
                "raw-inference",
                self.raw_budget_units,
                oneiron::BudgetExhaustionPolicy::Suspend,
            ),
            self.runtime.host_account(),
        )
    }
}
