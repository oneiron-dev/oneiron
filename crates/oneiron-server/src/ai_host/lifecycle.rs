//! The running host's lifecycle (`AiHost`): attach and start, the binds a
//! server makes once it exists, shutdown and drop, and the boot and
//! recovery requeues of attempts a stopped process or an outage parked.

use super::*;

impl AiHost {
    /// Builds every seat from `models`, starts the workers those seats can
    /// serve, and hands the server its handle (and the raw `/v1/llm` routes
    /// their router, and MCP `execute_code` its executor).
    pub async fn attach(server: SyncServer, models: Option<&ModelsConfig>) -> (SyncServer, Self) {
        Self::attach_device(server, models, false).await
    }

    /// [`Self::attach`] on a host that syncs as a device of another home
    /// (`[device_sync]`, `device`): its Dreamer never claims the MACRO home,
    /// so device sync's standing reads the home the section names.
    pub async fn attach_device(
        server: SyncServer,
        models: Option<&ModelsConfig>,
        device: bool,
    ) -> (SyncServer, Self) {
        Self::attach_controlled(server, models, device, None).await
    }

    /// [`Self::attach_device`] with the Dreamer under `control` when set:
    /// managed serve's reap freeze (FIX 6909), installed before the Dreamer
    /// starts, so its first pass is admitted and paused through it.
    pub(crate) async fn attach_controlled(
        server: SyncServer,
        models: Option<&ModelsConfig>,
        device: bool,
        control: Option<DreamerControl>,
    ) -> (SyncServer, Self) {
        let mut host = Self::start_with(
            Arc::clone(server.vault()),
            models,
            server.host_root_provisioned(),
            server.run_receipts(),
            Some(server.host_account()),
            Some(Attached { device, control }),
            server.broker_context(),
        )
        .await;
        if host.handle.hints.is_some() {
            host.sync_wake = Some(sync_wake::SyncWake::spawn(
                host.handle.clone(),
                Arc::clone(server.vault()),
                &server.reassert_manager,
            ));
        }
        let server = server
            .with_ai(host.handle.clone())
            .with_decision_config(models);
        // The Dreamer and the workflow pump started before the server
        // staffed its ladder; the Dreamer's next pass and the pump's next
        // wave cut ask through it.
        let _ = host.handle.decisions.set(server.decision_host().clone());
        // From the pump's next leaf on, a leaf that ran is judged on its
        // execution context through the same ladder (OF-540).
        if let Some(pump) = &host.workflows {
            pump.with_attribution_ladder(server.decision_host().ladder().clone());
            // And each queued project question runs on it from the next pass
            // (OF-501), up to the big rung: the card it drafts is the
            // person's ask, so the ladder queues none of its own.
            let decisions = server.decision_host();
            pump.with_project_detection(oneiron::agent_dispatch::ProjectDetection {
                ladder: decisions.ladder().clone(),
                dial: decisions.dial(oneiron::llm::decision::DecisionRung::Big),
                bands: decisions.bands(),
                wording: PROJECT_DETECTION_WORDING.to_owned(),
                budget: PROJECT_DETECTION_BUDGET,
            });
        }
        // The writer factory chat and code mode share (FIX 4465 D, Engine
        // D4), settled whether or not the code sandbox binds.
        let shared =
            compaction::CodeModeCompaction::bind_shared(&server, &host.handle.runtime, models);
        if let Some((compaction, _)) = &shared {
            let _ = host.handle.writer_compaction.set(compaction.clone());
        }
        #[cfg(feature = "code-sandbox-wasmtime")]
        let server = code_mode::bind(
            server,
            &host.handle.runtime,
            models,
            &host.handle.status,
            shared,
        )
        .await;
        (server, host)
    }

    /// Binds the standing-question pump to the running Dreamer's timer
    /// (OF-506): its Deadline passes run the pump on the home node. `false`
    /// when no Dreamer runs, so the caller starts the pump's own sleeper and
    /// exactly one runner serves the questions. Should the bound Dreamer end
    /// before shutdown, already or later, the questions and due digests go
    /// to their own sleepers on `server` once (FIX 1149), so one runner
    /// still serves them. First, with a Dreamer or without, the workflow
    /// pump's steps bind their `self.use` to `server`'s door (FIX 7016).
    pub(crate) fn bind_question_timer(&self, server: &Arc<SyncServer>) -> bool {
        // A workflow step's `self.use` calls this server's door from now on,
        // whether or not a Dreamer runs (FIX 7016); a second bind keeps the
        // first.
        let _ = self.step_host.set(Arc::downgrade(server));
        let Some(dreamer) = &self.dreamer else {
            return false;
        };
        // A second bind finds the first; the timer still drives the pump,
        // and the first bind's watch stands.
        let _ = self.question_timer.set(Arc::downgrade(server));
        // The Dreamer's program runtime binds through the bound server from
        // now on: a program held for want of it resumes (FIX 5874), now and
        // on each recheck after (FIX 6059).
        if let Some(bound) = self.question_timer.get().and_then(std::sync::Weak::upgrade) {
            let _ = self
                .program_monitor
                .get_or_init(|| turn_program_host::monitor_held_for_host(&bound));
        }
        let _ = self.dreamer_fallback.get_or_init(|| {
            question_timer::DreamerFallback::spawn(
                server,
                dreamer.ended(),
                self.pass_admission.clone(),
            )
        });
        true
    }

    /// Starts the turn-action worker of a host attached to `server`, now
    /// that `server` exists (FIX 6920): each queued Continue and Retry reads
    /// a fresh context board through it, held weakly. Until this bind an
    /// attached host's queued actions wait; a second bind, or one on a host
    /// started on its own, starts nothing, so one worker drains the queue.
    pub(crate) fn bind_turn_actions(&self, server: &Arc<SyncServer>) {
        if self.turn_actions.set(()).is_ok() {
            turn_actions::spawn_hosted(server.vault(), &self.handle, Arc::downgrade(server));
        }
    }

    /// The running Dreamer's next wake: the earliest instant (unix
    /// milliseconds) its queue, wake-policy and session-expiry lanes are
    /// armed for, `None` while none is, updated as they re-arm. `None` when
    /// no Dreamer runs. A host that may suspend the process arms its own
    /// timer for it and wakes the Dreamer through
    /// [`AiHandle::attempt_queued`].
    pub(crate) fn next_wake(&self) -> Option<tokio::sync::watch::Receiver<Option<u64>>> {
        self.handle.hints.as_ref().map(|hints| hints.next_wake())
    }

    /// Builds every seat from `models` and starts the workers those seats can
    /// serve. Every model call they make is admitted as a run whose receipts
    /// are written to the log. With no credential-broker context, a
    /// `key_secret` provider is unavailable.
    pub async fn start(vault: Arc<Vault>, models: Option<&ModelsConfig>, host_root: bool) -> Self {
        Self::start_receipted(vault, models, host_root, Arc::new(LoggedReceipts), None).await
    }

    /// `start`, with the run receipts going to `receipts`.
    pub(crate) async fn start_receipted(
        vault: Arc<Vault>,
        models: Option<&ModelsConfig>,
        host_root: bool,
        receipts: Arc<dyn RunReceiptSink>,
        account: Option<Arc<oneiron::llm::run_admission::HostAccount>>,
    ) -> Self {
        Self::start_with(vault, models, host_root, receipts, account, None, None).await
    }

    /// `start_receipted`, `attached` to a server when `Some`, on a device
    /// host and under a Dreamer control as that says, its `key_secret`
    /// providers sending through `broker`, the vault's one credential-broker
    /// context. An attached host's turn-action worker waits for
    /// [`Self::bind_turn_actions`].
    async fn start_with(
        vault: Arc<Vault>,
        models: Option<&ModelsConfig>,
        host_root: bool,
        receipts: Arc<dyn RunReceiptSink>,
        account: Option<Arc<oneiron::llm::run_admission::HostAccount>>,
        attached: Option<Attached>,
        broker: Option<&BrokerContext>,
    ) -> Self {
        let device = attached.as_ref().is_some_and(|attached| attached.device);
        recover_dead_leases(&vault);
        let rests = OfferCooldowns::in_vault(Arc::clone(&vault));
        let mut runtime = ModelRuntime::build_hosted(models, broker, rests)
            .with_receipts(receipts)
            .with_media_vault(Arc::clone(&vault));
        if let Some(account) = account {
            runtime = runtime.with_host_account(account);
        }
        runtime.take_up_kept_media_jobs();
        let runtime = Arc::new(runtime);
        // Launch statements price in dollars at the generative seat's model;
        // a unit other than tokens reads the runtime's offers, held weakly.
        if let Some(seat) = runtime.seat(CHAT_ROLE) {
            vault.install_launch_usd_prices(Arc::new(
                crate::models::launch_price::LaunchUsdQuote::new(
                    seat.model.clone(),
                    Arc::downgrade(&runtime),
                ),
            ));
        }
        let mut handle = AiHandle::unstarted(Arc::clone(&runtime), models);
        handle.device = device;
        let mut host = Self {
            handle: handle.clone(),
            dreamer: None,
            workflows: None,
            sieve: None,
            sync_wake: None,
            question_timer: dreamer::QuestionTimer::default(),
            step_host: step::StepHost::default(),
            pass_admission: attached
                .as_ref()
                .and_then(|attached| attached.control.clone()),
            dreamer_fallback: OnceLock::new(),
            program_monitor: OnceLock::new(),
            turn_actions: if attached.is_some() {
                OnceLock::new()
            } else {
                OnceLock::from(())
            },
        };
        let Some(models) = models else {
            served_without_dreamer(&vault, device);
            return host;
        };
        let status = Arc::clone(&handle.status);
        let idle = handle.idle_sample();
        let timer = Arc::clone(&host.question_timer);
        let admission = host.pass_admission.clone();
        let decisions = Arc::clone(&handle.decisions);
        match start_dreamer(
            &vault, &runtime, models, host_root, device, &status, idle, decisions, timer, admission,
        )
        .await
        {
            Ok(dreamer) => {
                handle.hints = Some(dreamer.hints());
                handle.summaries = models.dreamer.summary_instruction.is_some();
                host.dreamer = Some(dreamer);
            }
            Err(reason) => {
                status.update(|status| status.dreamer = WorkStatus::idle(reason));
                served_without_dreamer(&vault, device);
            }
        }
        match start_workflows(
            &vault,
            &runtime,
            models,
            &status,
            Arc::clone(&handle.decisions),
            Arc::clone(&host.step_host),
        ) {
            Ok(pump) => host.workflows = Some(pump),
            Err(reason) => status.update(|status| status.workflows = WorkStatus::idle(reason)),
        }
        host.handle = handle;
        // An attached host's worker starts once its server is bound
        // (FIX 6920), so it alone takes up the queue.
        if attached.is_none() {
            turn_actions::spawn(&vault, &host.handle);
        }
        // A provider's recovery resumes the Dreamer's outage parks and the
        // agent runs' (FIX 3194), so it runs whether or not a Dreamer does.
        resume_on_recovery(&vault, &runtime);
        // Turns that landed while no Dreamer ran, or just before a crash,
        // get their due wake now rather than waiting for the next turn. It
        // settles before start returns, so it reads only those turns: one
        // that lands later is woken by its own door, never by this one.
        if let Some(wake) = host.handle.wake_on_turn(&vault, WakeTurnSubject::Vault)
            && let Err(error) = wake.await
        {
            tracing::warn!(panicked = error.is_panic(), "boot turn wake did not finish");
        }
        host.sieve = host.handle.drain_sieve(&vault);
        host
    }

    #[must_use]
    pub fn handle(&self) -> AiHandle {
        self.handle.clone()
    }

    /// Lets running chat turns end, then stops both workers and the sieve's
    /// backlog drain cooperatively and waits for them.
    pub async fn shutdown(mut self) {
        // A planned stop hands nothing over: the watch stops before the
        // Dreamer does, and any sleepers it started stop with it.
        if let Some(fallback) = self.dreamer_fallback.take() {
            fallback.stop();
        }
        drop(self.program_monitor.take());
        if let Some(wake) = self.sync_wake.take() {
            wake.stop();
        }
        let sieve = self.sieve.take();
        if let Some(drain) = &sieve {
            drain.stop.store(true, Ordering::Release);
        }
        self.handle.turns.shutdown(TURN_GRACE).await;
        if let Some(pump) = self.workflows.take() {
            pump.stop().await;
        }
        if let Some(dreamer) = self.dreamer.take() {
            dreamer.stop().await;
        }
        if let Some(drain) = sieve
            && let Err(error) = drain.task.await
        {
            tracing::warn!(
                panicked = error.is_panic(),
                "sieve backlog drain did not stop cleanly"
            );
        }
        self.handle.status.update(|status| {
            for work in [&mut status.dreamer, &mut status.workflows] {
                if work.state != WorkState::Idle {
                    work.state = WorkState::Idle;
                    work.reason = Some(IdleReason::Stopped);
                }
            }
        });
    }
}

/// A host dropped without [`AiHost::shutdown`] (an embedding process whose
/// startup failed after attach, say) still tells every worker to stop; it
/// cannot wait for them here.
impl Drop for AiHost {
    fn drop(&mut self) {
        if let Some(fallback) = self.dreamer_fallback.get() {
            fallback.stop();
        }
        self.handle.turns.stop_now();
        if let Some(wake) = &self.sync_wake {
            wake.stop();
        }
        if let Some(pump) = &self.workflows {
            pump.signal_stop();
        }
        if let Some(dreamer) = &self.dreamer {
            dreamer.signal_stop();
        }
        if let Some(drain) = &self.sieve {
            drain.stop.store(true, Ordering::Release);
        }
    }
}

/// This process owns the vault exclusively, so every attempt lease at boot
/// was held by a process that is gone. Requeue them: an interrupted pass or
/// step runs again exactly once, from its durable checkpoints.
///
/// A parked attempt is requeued only when this server's Dreamer parked it
/// itself (a pass cut at its deadline, an executor error): that park is its
/// own checkpoint, cleared here; so is an agent run's park on a provider
/// outage (FIX 3194), whose run goes on from its next step, and any other
/// owner's checkpoint park, whose owner died with the process that held it.
/// One parked on a signal (a budget or consent trap, a wait) stays leased: a
/// restart is not its resume signal (runtime.md), and it resumes only when
/// its signal is consumed. Expiry is by age, so "now"
/// is the later of the wall clock and one second past the youngest lease:
/// every dead lease expires, even after the clock stepped back, and none
/// waits.
fn recover_dead_leases(vault: &Vault) {
    let queue = AttemptQueue::new(vault);
    let rows = match queue.list() {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(%error, "boot lease recovery could not list attempts");
            return;
        }
    };
    let runner = DreamerRunnerStore::new(vault);
    let mut held = HashSet::new();
    let mut youngest = None;
    for row in rows
        .iter()
        .filter(|row| matches!(row.state, AttemptState::Leased | AttemptState::Landing))
    {
        let parked = match runner.parked_attempt(row.id) {
            Ok(parked) => parked,
            Err(error) => {
                tracing::warn!(%error, attempt = ?row.id, "a parked attempt could not be read; its lease is kept");
                held.insert(row.id);
                continue;
            }
        };
        match parked {
            Some(park)
                if park.park_owner == dreamer::LEASE_OWNER
                    || park.cause == oneiron::DreamerParkCause::Checkpoint
                    || run_outage_park(&park.park_owner, park.cause) =>
            {
                if let Err(error) = runner.resume_parked(row.id, &park.park_owner, unix_now()) {
                    tracing::warn!(%error, attempt = ?row.id, "a checkpoint park was not cleared; its lease is kept");
                    held.insert(row.id);
                    continue;
                }
            }
            Some(_) => {
                held.insert(row.id);
                continue;
            }
            None => {}
        }
        youngest = youngest.max(Some(row.updated_at));
    }
    if !held.is_empty() {
        tracing::info!(
            attempts = held.len(),
            "attempts parked on a signal keep their leases"
        );
    }
    let Some(youngest) = youngest else {
        return;
    };
    match queue.cleanup_leases_except(
        CleanupAttemptLeases {
            now: unix_now().max(youngest.saturating_add(1)),
            lease_timeout_secs: 1,
        },
        &held,
    ) {
        Ok(report) => tracing::info!(?report, "requeued attempt leases a stopped process held"),
        Err(error) => tracing::warn!(%error, "boot lease recovery failed"),
    }
}

/// After each stable recovery of a provider that was down (OF-305), the
/// attempts this server's Dreamer parked because a provider was unavailable,
/// and the agent runs the pump parked on one (FIX 3194), are requeued, as a
/// restart requeues them: the outage that failed their step is over. One
/// parked on a signal (a budget or consent trap, a wait), by a hard cut or
/// on any other error is not this resume's. The task holds the vault weakly
/// and ends with the runtime.
fn resume_on_recovery(vault: &Arc<Vault>, runtime: &ModelRuntime) {
    let vault = Arc::downgrade(vault);
    let mut recoveries = runtime.recoveries();
    tokio::spawn(async move {
        while recoveries.changed().await.is_ok() {
            let Some(vault) = vault.upgrade() else {
                return;
            };
            let resumed = tokio::task::spawn_blocking(move || resume_outage_parks(&vault)).await;
            if let Err(error) = resumed {
                tracing::warn!(
                    panicked = error.is_panic(),
                    "recovery resume did not finish"
                );
            }
        }
    });
}

/// Requeues every attempt this server's Dreamer or its agent run pump parked
/// on an unavailable provider.
fn resume_outage_parks(vault: &Vault) {
    let rows = match AttemptQueue::new(vault).list() {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(%error, "recovery resume could not list attempts");
            return;
        }
    };
    let runner = DreamerRunnerStore::new(vault);
    let mut resumed = 0usize;
    for row in rows
        .iter()
        .filter(|row| matches!(row.state, AttemptState::Leased))
    {
        let Ok(Some(park)) = runner.parked_attempt(row.id) else {
            continue;
        };
        let dreamer_outage = park.park_owner == dreamer::LEASE_OWNER
            && park.cause == oneiron::DreamerParkCause::ProviderUnavailable;
        if !dreamer_outage && !run_outage_park(&park.park_owner, park.cause) {
            continue;
        }
        match runner.resume_parked(row.id, &park.park_owner, unix_now()) {
            Ok(Some(_)) => resumed += 1,
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%error, attempt = ?row.id, "an outage park was not resumed");
            }
        }
    }
    if resumed > 0 {
        tracing::info!(
            resumed,
            "a provider recovered; attempts its outage parked resume"
        );
    }
}

/// Whether a park is an agent run's on a provider outage (FIX 3194): the
/// pump's own, under its lease owner.
fn run_outage_park(park_owner: &str, cause: oneiron::DreamerParkCause) -> bool {
    park_owner == crate::server::RUN_LEASE_OWNER
        && cause == oneiron::DreamerParkCause::ProviderUnavailable
}
