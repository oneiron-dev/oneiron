//! Startup and ordered shutdown of unmanaged and embedded serve workers.
//! The worker handles travel together with their existing owner and drop scopes.
//! Listener setup, transport shutdown, and vault construction stay in the parent.

#[cfg(feature = "code-sandbox-wasmtime")]
use super::spawn_fact_hooks;
use super::{Arc, ServeConfig, SyncServer, build_artifact_app};

/// What [`start_desktop_workers`] hands the transport half of a serve path.
pub(crate) struct StartedWorkers {
    /// The server every worker runs on.
    pub(crate) server: Arc<SyncServer>,
    /// The artifact-only router, for an origin of its own.
    pub(crate) artifact_app: axum::Router,
    /// What a connection pool asks when a limit is met.
    pub(crate) questions: Arc<crate::wire_telemetry::LimitQuestions>,
    /// The vault's id, for the local runtime file.
    #[cfg(unix)]
    pub(crate) vault_id: Option<String>,
    /// Turns `true` when serving stops; the fact hooks stop on it too.
    pub(crate) stopping: tokio::sync::watch::Sender<bool>,
    pub(crate) stopped: tokio::sync::watch::Receiver<bool>,
    /// The workers themselves, until [`DesktopWorkers::shutdown`].
    pub(crate) workers: DesktopWorkers,
}

/// The workers [`start_desktop_workers`] started, stopped together by
/// [`Self::shutdown`].
pub(crate) struct DesktopWorkers {
    #[cfg(unix)]
    voice: Option<crate::voice_host::VoiceBoot>,
    ai: crate::ai_host::AiHost,
    oversight: crate::server::HealerOversight,
    lifecycle: crate::server::LifecycleScheduler,
    linear_handle: Option<tokio::task::JoinHandle<()>>,
    /// Plain serve's tagging worker and the sender of the stop it watches,
    /// joined rather than aborted.
    tagging: Option<(
        tokio::task::JoinHandle<()>,
        tokio::sync::watch::Sender<bool>,
    )>,
    workers: Vec<tokio::task::JoinHandle<()>>,
    /// Plain serve's owner host, whose scheduled backup pass in flight ends
    /// before the stop returns (FIX 6732). Embedded serve keeps none: its
    /// vault and runtime stay up, so a pass in flight finishes there.
    owner_host: Option<Arc<crate::owner::schedule::OwnerHost>>,
    /// The tagger slot's close, run once every worker has ended (FIX 7383).
    tagger: Option<crate::oneironer::SlotClose>,
}

/// Starts every worker the unmanaged serve path runs on `sync_server`, in
/// serve's order, once the host's listeners are bound. `gpu_poller` is the
/// GPU pool's health poller, already running. `lifecycle_admission` is
/// called where the lifecycle scheduler starts, after the Linear mirror,
/// and gates each housekeeping pass. Embedded serve starts the same workers
/// through here. With `drain_tagging`, plain serve's, the tagging worker
/// claims nothing once serving stops, and [`DesktopWorkers::shutdown`] waits
/// until every call it made has settled (FIX 7303). Without it, embedded
/// serve's, tagging is aborted with the other workers: the app never waits
/// on a model call to stop, and a marker it left leased is tagged again at
/// the next start. On plain serve the background passes stop at the vault's
/// deletion (FIX 11979, FIX 12008); embedded serve admits every pass as today.
pub(crate) async fn start_desktop_workers(
    sync_server: SyncServer,
    config: &ServeConfig,
    gpu_poller: Option<tokio::task::JoinHandle<()>>,
    lifecycle_admission: impl FnOnce() -> crate::server::HousekeepingAdmission,
    drain_tagging: bool,
) -> anyhow::Result<StartedWorkers> {
    // Read before any worker starts, so a candidate file that does not read
    // stops the start with nothing running (FIX 7386).
    let publisher_candidates = config.failure_signals.publisher_candidates()?;
    #[cfg(unix)]
    let import_queue = super::history_import::queue::ImportQueue::from_config(config);
    // Model seats, the Dreamer and the workflow pump, from `[models]`. With
    // no section every seat stays empty and the model-free server is whole.
    // A machine that dials a home, by its section or its enrolment, is a
    // device of that home. A startup error below drops `ai`, which tells its
    // workers to stop.
    let device = crate::device_sync::dials_home(config, sync_server.vault());
    // Plain and embedded serve launch `[models.workers]`' managed workers; a
    // managed per-vault process never reaches here (FIX 8315).
    crate::models::permit_worker_launch();
    // `--no-hooks` turns verb hooks off before any worker starts, so a queued
    // Continue or Retry taken up below runs none (FIX 9480).
    if !config.hooks {
        sync_server.vault().suppress_verb_hooks();
    }
    // The vault's deletion gate over plain serve's background passes (FIX
    // 11979, FIX 12008): once the marker is present each gated pass is refused,
    // logged once, while the backup schedule and custody publication run
    // on; embedded serve keeps every pass admitted as today.
    let deletion = Arc::new(crate::server::DeletionMarker::default());
    let deletion_vault = Arc::clone(sync_server.vault());
    let plain_serve = drain_tagging;
    let admitted = || -> crate::server::HousekeepingAdmission {
        if !plain_serve {
            return crate::server::admit_every_pass();
        }
        deletion.gate(&deletion_vault, crate::server::admit_every_pass())
    };
    // The owner's own Dreamer pause works on a plain host too, held in
    // memory (FIX 11573); managed serve installs its reap freeze instead.
    // On plain serve the Dreamer's passes stop at the vault's deletion.
    let mut dreamer_control = crate::ai_host::DreamerControl::local();
    if plain_serve {
        dreamer_control.admission =
            deletion.gate(&deletion_vault, dreamer_control.admission.clone());
    }
    let (sync_server, ai) = crate::ai_host::AiHost::attach_controlled(
        sync_server,
        config.models.as_ref(),
        device,
        Some(dreamer_control),
    )
    .await;
    let sync_server = Arc::new(sync_server);
    // A managed vault's attested owner's queued work is judged by this
    // server's check, installed before any worker takes it up (FIX 11090).
    crate::managed_owner_check::ServerManagedOwnerCheck::install(&sync_server);
    // Queued Continue and Retry are taken up from here, on this server (FIX 6920).
    ai.bind_turn_actions(&sync_server);
    // The skill-edit gate's replay judge, on the ladder the server just built (OF-495).
    crate::replay_judge::register(&sync_server, config.skills.live_pulls_per_axis);
    // The vault's first oversight receipts, before the host's own workers
    // start: a vault that cannot sign them never reports ready.
    let oversight = sync_server
        .start_healer_oversight(crate::server::HEALER_OVERSIGHT_EVERY, || Some(()))
        .await?;
    // The `[linear]` mirror; its passes stop at the vault's deletion.
    let linear_handle = crate::linear_host::spawn_configured(
        sync_server.clone(),
        admitted(),
    )
    .await?;
    // The lifecycle's passes stop at the vault's deletion on plain serve;
    // the caller's admission, and its awake hold, is kept inside the gate.
    let lifecycle_admit = lifecycle_admission();
    let lifecycle_admit = if plain_serve {
        deletion.gate(&deletion_vault, lifecycle_admit)
    } else {
        lifecycle_admit
    };
    let lifecycle = sync_server.spawn_lifecycle_scheduler(lifecycle_admit);
    // An answered code consent wait's effect runs on this server, whatever
    // hooks or models it serves, before the connector settler starts
    // (DOOR-079 1a).
    crate::code_consent_host::ServerCodeConsentHost::install(&sync_server);
    // Open sockets may never close by themselves, so the drain is bounded.
    let (stopping, stopped) = tokio::sync::watch::channel(false);
    let (mut workers, tagging) = if drain_tagging {
        // The slot workers `spawn_slot_workers` starts, in its order, with
        // tagging's own handle kept apart: it stops on serve's stop.
        let embedding = sync_server.spawn_embedding_worker_admitted(admitted());
        let mut tagging_stopped = stopped.clone();
        let tagging = sync_server.spawn_tagging_worker_until(
            crate::server::PassControl::unpaused(admitted()),
            async move {
                let _ = tagging_stopped.wait_for(|stop| *stop).await;
            },
        );
        let slots = [
            embedding,
            sync_server.spawn_media_embedding_worker_admitted(admitted()),
            // Each pass stops at the vault's deletion; a run is the owner's
            // foreground work and stays admitted, as on a managed host.
            sync_server.spawn_resident_pump_admitted(
                admitted(),
                crate::server::admit_every_pass(),
            ),
            // The official CLIs' runs, on the person's own runtime (FIX 4552).
            sync_server.spawn_seat_host(),
            Some(sync_server.spawn_connector_settler_admitted(admitted())),
        ];
        let tagging = tagging.map(|handle| (handle, stopping.clone()));
        (slots.into_iter().flatten().collect::<Vec<_>>(), tagging)
    } else {
        (sync_server.spawn_slot_workers(), None)
    };
    workers.extend(gpu_poller);
    workers.push(sync_server.spawn_board_publisher());
    // Crossed thresholds ask the ladder whether everything is okay (OF-520).
    workers.push(crate::wire_health::spawn(&sync_server, admitted()));
    // Sensitive imported topics ask the owner who sees their later imports (OF-492).
    workers.push(crate::import_audience::spawn(&sync_server, admitted()));
    // Due standing questions are answered through the ladder (OF-506).
    if !ai.bind_question_timer(&sync_server) {
        workers.push(crate::decision_graph::spawn(&sync_server, admitted()));
        // Due digests, which a Dreamer's timer would otherwise serve (OF-499).
        workers.push(crate::ai_host::home_digests::spawn(&sync_server, admitted()));
    }
    // Saved queries are evaluated over the vault's people in bounded wakes (ARCH-0059).
    workers.push(crate::saved_query_sweep::spawn(&sync_server, admitted()));
    // Queued campaign enrollments land on the campaign's home node (ARCH-0059).
    workers.push(crate::campaign_enrollment::spawn(&sync_server, admitted()));
    // Uncertain identities are decided, or asked of the person (OF-123).
    workers.push(crate::ai_host::identity::spawn(&sync_server, admitted()));
    // Failure cases and blocked reports reach the Coach as proposed heals (OF-418).
    workers.push(crate::ai_host::coach_heal::spawn(
        &sync_server,
        publisher_candidates,
        admitted(),
    ));
    // The nightly Coach jobs that need the host's model or rules (OF-420).
    workers.push(crate::ai_host::coach_host::spawn(&sync_server, admitted()));
    // Queued browser program admissions run as their source caller (CUA E8b).
    workers.push(crate::ai_host::browser_program_admission::spawn(&sync_server, admitted()));
    // An accepted Coach person-threshold row goes live on the ladder (Q3).
    workers.extend(crate::decision_host::spawn_person_threshold_admitted(
        &sync_server,
        admitted(),
    ));
    // Failure signals reach the deployment's publisher (OF-380). The
    // private endpoint's bearer (FIX 5013): a named vault secret wins, and
    // reads as none when it does not resolve; without one the env token,
    // as today. Its passes stop at the vault's deletion.
    let failure_signals_bearer = if config.failure_signals.key_secret.is_some() {
        config.failure_signals.bearer_from_secret(sync_server.vault())
    } else {
        std::env::var("ONEIRON_FAILURE_SIGNALS_TOKEN")
            .ok()
            .filter(|token| !token.is_empty())
            .map(zeroize::Zeroizing::new)
    };
    workers.push(crate::ai_host::failure_signals::spawn(
        &sync_server,
        crate::ai_host::failure_signals::FailureSignalHost::new(
            &config.failure_signals,
            config.privacy_posture == oneiron::HostingPrivacyPosture::Hosted,
            failure_signals_bearer,
        ),
        admitted(),
    ));
    // The owner's model-graded detectors read the retrieval telemetry (OF-418).
    workers.extend(crate::ai_host::self_heal_detectors::spawn(
        &sync_server,
        &config.self_heal,
        admitted(),
    ));
    workers.push(sync_server.spawn_connector_event_worker(admitted()));
    // Approved sends leave through the connector executor (OF-187).
    workers.push(sync_server.spawn_connector_send_worker(admitted()));
    // A Dreamer pass hands agent replies off; this worker runs them (FIX 2405).
    workers.push(sync_server.spawn_connector_reply_worker(admitted()));
    // Checked built-in channels and their provider webhooks (OF-519).
    workers.push(crate::builtin_host::spawn(&sync_server, admitted()));
    // Past the vault's deletion these two run on, to let its backups go at
    // their deadline (FIX 11979): every pass admitted, as today.
    workers.extend(sync_server.spawn_backup_schedule(crate::owner::schedule::SCHEDULE_TICK));
    // The custody head beside the backups, and its anchor (KS-4A1).
    workers.extend(sync_server.spawn_custody_publication());
    // Documents whose signing finished are sealed as a task (OF-415).
    #[cfg(unix)]
    workers.push(crate::api::spawn_esign_seal_worker_admitted(
        Arc::clone(&sync_server),
        admitted(),
        crate::api::EsignSealConfig::from_env(),
    ));
    workers.push(crate::api::spawn_esign_hold_worker_admitted(
        Arc::clone(&sync_server),
        admitted(),
    ));
    // Authorized e-sign mail goes to the host's sender through its outbox;
    // without `--esign-delivery-outbox-dir` none runs (OF-415).
    workers.extend(config.esign_delivery_outbox_dir.clone().map(|dir| {
        crate::api::spawn_esign_delivery_outbox(
            Arc::clone(&sync_server),
            admitted(),
            dir,
        )
    }));
    // The publisher training outbox, only with its flag (OF-420), and the
    // self-host shipper's descriptor fetch with it, only with its own (TL-6).
    workers.extend(crate::conversation_training::spawn_self_host_admitted(
        &sync_server,
        config,
        admitted(),
    ));
    #[cfg(unix)]
    workers.extend(import_queue.map(|queue| queue.spawn(Arc::clone(&sync_server))));
    // Attached folders rescan after the import queue starts (OF-554).
    #[cfg(unix)]
    workers.push(crate::files_intake::spawn_rescans(Arc::clone(&sync_server)));
    // Fact hooks (ARCH-0080) run unless `--no-hooks`; they stop with serve.
    #[cfg(feature = "code-sandbox-wasmtime")]
    if config.hooks {
        workers.extend(
            spawn_fact_hooks(&sync_server, admitted(), stopped.clone())
            .await,
        );
    }
    // The API's CORS stays the API's: the artifact origin is never granted.
    let artifact_app = build_artifact_app(sync_server.clone());
    let questions = Arc::clone(sync_server.wire_telemetry.limit_questions());
    #[cfg(unix)]
    let vault_id = super::local_servers::vault_id(sync_server.vault());
    // The server's own voice loop (OF-410): off unless `[models.voice]`
    // names its socket. A call is the owner's foreground work: one in flight
    // runs on, but no new call is admitted past the vault's deletion
    // (FIX 12039), as on a managed host.
    #[cfg(unix)]
    let voice = crate::voice_host::VoiceBoot::start(
        &sync_server,
        config.models.as_ref().map(|models| &models.voice),
        None,
        admitted(),
    );
    let tagger = sync_server
        .tagger
        .as_ref()
        .map(crate::oneironer::TaggerSlot::closer);
    let owner_host = sync_server.owner_host.clone().filter(|_| drain_tagging);
    Ok(StartedWorkers {
        server: sync_server,
        artifact_app,
        questions,
        #[cfg(unix)]
        vault_id,
        stopping,
        stopped,
        workers: DesktopWorkers {
            #[cfg(unix)]
            voice,
            ai,
            oversight,
            lifecycle,
            linear_handle,
            tagging,
            workers,
            owner_host,
            tagger,
        },
    })
}

impl DesktopWorkers {
    /// The AI workers, for a host that forwards its wakes to them.
    pub(crate) fn ai(&self) -> &crate::ai_host::AiHost {
        &self.ai
    }

    /// Stops every worker in serve's order, once serving has stopped.
    /// `on_stop` is the host's stop, made where serve has always made it:
    /// after oversight stops and before the lifecycle scheduler does. Its
    /// error ends the shutdown there.
    pub(crate) async fn shutdown(
        self,
        on_stop: impl FnOnce() -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        // A voice call in flight ends through its own teardown before the
        // models it speaks on stop.
        #[cfg(unix)]
        if let Some(voice) = self.voice {
            voice.stop().await;
        }
        // Plain serve's tagging claims nothing more, and every call it made
        // settles while the models it calls still serve (FIX 7303).
        if let Some((tagging, stopping)) = self.tagging {
            let _ = stopping.send_replace(true);
            let _ = tagging.await;
        }
        // A pass or step in flight reaches its own boundary before this returns.
        self.ai.shutdown().await;
        // A receipt write already admitted ends before the process does.
        self.oversight.stop().await;
        on_stop()?;
        // A housekeeping pass in flight stops at its next sweep or page.
        self.lifecycle.stop().await;
        if let Some(handle) = self.linear_handle {
            handle.abort();
            let _ = handle.await;
        }
        for handle in self.workers {
            handle.abort();
            let _ = handle.await;
        }
        if let Some(host) = self.owner_host {
            host.resident_stopped().await;
        }
        // Tagging has ended on both paths (joined above, or aborted and
        // awaited in the loop): each platform child is shut down and reaped.
        if let Some(tagger) = self.tagger {
            tagger.close().await;
        }
        Ok(())
    }
}
