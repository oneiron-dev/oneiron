//! Supervised vault startup, serving, and shutdown.
//! `serve_managed` keeps the existing boot and drain order in one coordinator.
//! State, admission, and shutdown definitions remain in the parent module.

mod ledger_report;
mod teardown;

use teardown::StartingHandles;

use super::{
    Arc, BoundServeListener, CONTRACT_VERSION, Host, ManagedArgs, ManagedCtl, ManagedShutdown,
    ManagedState, Path, ServeArgs, ServeListener, SyncServer, UnixTs, WakeLedger, WriteKind,
    admission, build_managed_app, build_managed_artifact_app, escrow_vault_key, managed_page_seal,
    open_managed_vault, provision_host_authority, spawn_sigterm_shutdown, spool_vault_key_escrow,
    watch,
};

/// Boots the engine as a supervised child process.
///
/// The startup order is the contract, not an implementation detail: the
/// delivered descriptor numbers are checked before any of them is consumed,
/// credentials are consumed before the data directory is opened, the open
/// gates run before anything is served, both sockets are bound before the
/// ready byte, and the ready byte is what tells the supervisor any of it
/// happened.
pub async fn serve_managed(args: &ServeArgs, managed: ManagedArgs) -> anyhow::Result<()> {
    let mut handles = StartingHandles::default();
    let outcome = serve_with_handles(args, managed, &mut handles).await;
    let (stopped, telemetry_drained) = teardown::stop(handles).await;
    match outcome {
        Err(error) => {
            if let Err(cleanup) = stopped {
                tracing::warn!(%cleanup, "managed failed-start stop notification failed");
            }
            if let Err(cleanup) = telemetry_drained {
                tracing::warn!(%cleanup, "managed failed-start telemetry drain failed");
            }
            Err(error)
        }
        Ok(served) => {
            stopped?;
            served?;
            telemetry_drained?;
            Ok(())
        }
    }
}

async fn serve_with_handles(
    args: &ServeArgs,
    mut managed: ManagedArgs,
    handles: &mut StartingHandles,
) -> anyhow::Result<std::io::Result<()>> {
    // The supervisor names a personal vault's owner by the contract's copy of
    // the embedded owner's id; a copy that drifted stops the boot here.
    super::vault_gates::check_embedded_owner_holder()?;
    // Argv's configuration with the owner's settings file settled over it,
    // tracing started between the file's refusal and its settling.
    let (mut config, settled) = super::settings::configure(args, &managed)?;
    let cors = crate::commands::build_cors_layer(&config.sync_server_config())?;
    tracing::info!(
        vault = %managed.vault_name,
        data_dir = %managed.data_dir.display(),
        contract_version = CONTRACT_VERSION,
        "starting managed vault process"
    );

    // Resolution, not adoption, and it comes first on purpose. This is the
    // integer check over the three delivered descriptor numbers, and every
    // consequence of an alias is paid by whoever consumes one of them first:
    // an inherited listener that is also `--credentials-fd` gets `read_exact`
    // called on a listening socket and closed under the `File` that read it,
    // and one that is also `--ready-fd` is not refused until the credential
    // frame is spent and the vault — including its sealed DEK MAC — has been
    // opened. Refusing here costs nothing and consumes nothing; `bind` below
    // is still the only adoption.
    let shutdown = ManagedShutdown::new();
    let mut host = super::host::ManagedHost::new(&managed, managed.host_limits, shutdown.clone())?;
    let http = host.listener()?;
    let host_legal = crate::managed::host_legal::HostLegalListener::take(&mut managed)?;
    // A cold restore's plan, on its own pipe before the credential frame: no
    // socket below listens until the restore is verified and kept.
    let mut restore = super::restore::ManagedRestore::begin(&managed, &mut config)?;

    // The contract requires the credential frame to be read before the data
    // directory is opened, so a refused frame never touches storage.
    let credentials = oneiron_vault_contract::Credentials {
        dek: host.secret("dek")?.as_slice().try_into()?,
        token: host.secret("spawn_token")?.as_slice().try_into()?,
    };
    // So is the custody anchor door's credential, on its own pipe when the
    // supervisor hands one: never the environment (FIX 5788, FIX 6517).
    let anchor = host.custody_anchor_credentials(config.backup.custody_anchor_url.as_deref())?;
    let mut vault_config = config.base_vault_config();
    // The supervisor delivered this vault's data key at boot (FIX 4531).
    vault_config.privacy.data_key_custody = oneiron::VaultDataKeyCustody::SupervisorDelivered;
    // Our cloud hosts this vault. The owner's "Help improve Oneiron" and
    // training choices stand as the supervisor passed them; an unset export
    // takes the managed default, and unset training follows the export.
    vault_config.failure_signals.deployment =
        oneiron::config::failure_signals::DeploymentTier::Managed;
    let (vault, rehearsal_config) = match restore.as_mut() {
        // The restored vault, verified and kept, in place of the open.
        Some(restore) => {
            let anchor = anchor.clone();
            restore
                .land(&managed, &config, vault_config, &credentials.dek, anchor)
                .await?
        }
        None => {
            // Set before the open: LMDB takes the page key with the environment.
            vault_config.page_seal =
                managed_page_seal(&managed, config.maximum_tier, &credentials.dek)?;
            // The live seal opens the live vault and creates none: a rehearsal's
            // scratch takes a fresh incarnation of it (`owner::backup`).
            let mut rehearsal_config = vault_config.clone();
            rehearsal_config.page_seal = None;
            let vault = open_managed_vault(
                &managed.data_dir,
                vault_config,
                &managed.vault_name,
                &credentials,
                managed.derivation_owner,
            )?;
            (vault, rehearsal_config)
        }
    };
    let vault = Arc::new(vault);

    let mut server_config = config.sync_server_config();
    server_config.lease_vault_id = super::vault_gates::managed_lease_scope(&vault)?;
    // The supervisor authenticates ingress on the socket it owns, and this
    // process attests the owner on each route: a request with no credential
    // is anonymous. The Linear mirror checks this declaration, not a secret.
    server_config.ingress = crate::config::IngressAuth::Supervisor;
    server_config.hosted_private_origins = managed.hosted_private_origins.clone();
    // The host root signs with this vault's own independent issuer seed,
    // kept in this install's keystore slot under the supervisor's key
    // directory (FIX-LIST 3018): never the delivered DEK, which escrow
    // recipients hold, nor the per-spawn token or caller headers. A fresh
    // spawn of this install loads the same seed, so the same logged root.
    // Explicit hosted service requires that issuer before workers or ready;
    // non-hosted supervision retains its rootless warning behavior.
    let (issuer, readiness) = provision_host_authority(
        &vault,
        &config.keystore,
        settled.keystore_unbound,
        &managed.data_dir,
    )?;
    // This install's checkpoint signer, read once now that the keystore is
    // in: its first read may make the seed, so never on a `Ping` or under a
    // reap freeze. A signer that does not read leaves the vault serving.
    let backup_facts = super::backup_facts::observe(&vault);
    // The delivered DEK is the vault's data key (CROSS-ARCH-0022
    // #ov-custody): its sealed artifacts derive from it, and each escrow
    // recipient the node's operator installed keeps a copy of it.
    vault.admit_vault_key(&credentials.dek)?;
    escrow_vault_key(
        &vault,
        &managed,
        restore.as_ref().map(|restore| restore.checked_recipients()),
    )?;
    let spooled = spool_vault_key_escrow(&vault, &managed);
    // A sealed vault serves only once its mirror reopens it at the next start.
    vault.check_page_custody()?;
    // The owner's embedding spaces and kind slots, as plain serve applies them.
    if let Some(embedding) = &config.embedding {
        embedding.apply_to(&vault)?;
    }
    // The owner's backups and restore rehearsals, on the tenant's own disk
    // beside the data directory, as plain serve keeps them beside its vault.
    // A backup handoff policy that is not installed holds pruning and is
    // named missing in the readiness every `Ping` carries (FIX 6705).
    let (owner_host, backup_handoff) =
        super::owner_storage::owner_host(&config, rehearsal_config, &managed, anchor);
    let readiness = match backup_handoff {
        Some(notice) => readiness.and_missing(notice),
        None => readiness,
    };
    // A direct `[linear]` mirror's response custody, private beside them.
    super::owner_storage::linear_responses(&config);
    // Rehearsal scratch a stopped process left in `<data>.rehearsals` goes
    // before any worker starts or ready is said (FIX 5677).
    owner_host.sweep_rehearsals(&vault);
    // The one credential-broker context, built from the opened vault: the
    // `[models]` providers, the System One seat, the embedder and the GPU
    // pods read their `key_secret` keys at its custody door, call by call.
    // Its default broker is the same-user child beside this binary. Explicit
    // trusted bindings may name a separate-user socket or custom program/roots.
    // A missing broker or secret leaves those calls refused before they start,
    // as on any host.
    let broker = crate::models::BrokerContext::for_serve(&vault, &config);
    // The embedder slot and the pods' health poller, as plain serve builds
    // them; the worker that fills the slot starts under the write admission.
    let publisher_candidates = config.failure_signals.publisher_candidates()?;
    let host = handles.host.insert(host);
    let crate::commands::BuiltEmbedder {
        slot: embedder,
        gpu_pool,
        poller: gpu_poller,
    } = crate::commands::build_embedder(&vault, &config, broker.as_ref()).await?;
    handles.gpu_poller = gpu_poller;
    // The tagger slot `[oneironer]` names, as plain serve builds it; its
    // worker starts under the write admission too. Its engine rows sit in
    // the data directory: managed mode reads no HOME or XDG (FIX 6873).
    let rows = managed.data_dir.join("oneironer").join("engines.json");
    let tagger =
        crate::oneironer::build_slot_off_runtime(config.oneironer.clone(), Some(rows)).await?;
    handles.tagger_close = tagger.as_ref().map(crate::oneironer::TaggerSlot::closer);
    // The browser and desktop guests, as plain serve attaches them: each
    // section's own checks decide, and a run with no guest is refused.
    // Managed mode reads no environment: a private endpoint's bearer comes
    // from its vault secret alone (FIX 5013); our inbox takes none.
    let mut sync_server = SyncServer::new(Arc::clone(&vault), server_config)
        .map_err(|e| anyhow::anyhow!("sync server init failed: {e}"))?
        .with_embedder(embedder)
        .with_tagger(tagger)
        .with_model_setup_config(&config, &crate::config::ServeArgs::default())
        .with_gpu_pool(gpu_pool)
        .with_broker(broker)
        .with_owner_host(owner_host)
        .with_browser_guest(
            config
                .browser
                .as_ref()
                .and_then(crate::config::BrowserConfig::guest),
        )
        .with_desktop_guest(
            config
                .desktop
                .as_ref()
                .map(crate::config::DesktopConfig::guest),
        )
        .with_feedback(config.feedback.delivery().map(|delivery| {
            crate::feedback_delivery::FeedbackHost {
                config: delivery,
                bearer: config.feedback.bearer_from_secret(&vault),
            }
        }))
        .with_feedback_triage(config.feedback.triage.clone())
        // The settings file's `[policy]`, as plain serve applies it (FIX 5042).
        .with_owner_policy_config(config.policy.owner_policy_config());
    // Its browser readiness starts from the `[browser]` section, its runtime
    // binding and the runtime fact the supervisor observed for this vault's
    // UID (FIX 7670). No state of it stops this start.
    sync_server
        .browser_readiness()
        .seed(config.browser.as_ref(), managed.guest_runtime_fact);
    // The owner's `[models] extraction_egress` opt-in, as plain serve
    // installs it (FIX 6621): off, nonlocal extraction stays refused.
    if config
        .models
        .as_ref()
        .is_some_and(|models| models.extraction_egress)
    {
        sync_server = sync_server
            .with_extraction_egress(Arc::new(|_: &oneiron::LlmRequest| true))
            .with_tagger_egress(Arc::new(|_: &oneiron::llm::TaggerCall<'_>| true));
    }
    sync_server.managed_issuer = Some(crate::server::ManagedIssuer::new(issuer));
    if managed.artifact_socket.is_some() {
        sync_server = sync_server.with_artifact_socket();
    }
    // Pack organ builds, the seal's among them, land on the tenant's own
    // storage before any worker installs one, never in the shared temp
    // directory (FIX 3565).
    #[cfg(unix)]
    {
        sync_server = sync_server.with_organ_dir(super::owner_storage::organ_dir(&managed));
    }
    // Model seats, the Dreamer and the decision ladder from `[models]`, as
    // plain serve attaches them: a vault that dials a home, by the owner's
    // `[device_sync]` or its enrolment, is a device of that home and never
    // claims the MACRO home. The shared teardown stops and joins `ai` on a
    // startup error as on a normal stop.
    let device = crate::device_sync::dials_home_managed(&config, &vault);
    // The Dreamer's passes are admitted like a served write, and refused
    // until the managed state below exists. Its control is installed before
    // it starts, on the same reap freeze that state takes, so each pass also
    // reads the freeze as its pause (FIX 6909).
    let write_admission = Arc::new(admission::Admission::default());
    let reap_gate = Arc::new(std::sync::OnceLock::<Arc<ManagedState>>::new());
    let control = admission::dreamer_control(&write_admission, &reap_gate);
    // `--no-hooks` turns verb hooks off before any worker starts, so a queued
    // Continue or Retry taken up below runs none (FIX 9480).
    if !config.hooks {
        sync_server.vault().suppress_verb_hooks();
    }
    let (sync_server, ai) = crate::ai_host::AiHost::attach_controlled(
        sync_server,
        config.models.as_ref(),
        device,
        Some(control),
    )
    .await;
    let ai = handles.ai.insert(ai);
    let sync_server = Arc::new(sync_server);
    handles.server = Some(Arc::clone(&sync_server));
    // A managed vault's attested owner's queued work is judged by this
    // server's check, installed before any worker takes it up (FIX 11090).
    crate::managed_owner_check::ServerManagedOwnerCheck::install(&sync_server);
    // Served sends reach this host's provider APIs and mail server (FIX 4435).
    crate::builtin_host::install_served_transports(&sync_server, config.models.as_ref());
    // Queued Continue and Retry are taken up from here, on this server (FIX 6920).
    ai.bind_turn_actions(&sync_server);
    // An answered code consent wait's effect runs on this server, as plain
    // serve installs it, before the connector settler starts (DOOR-079 1a).
    crate::code_consent_host::ServerCodeConsentHost::install(&sync_server);
    // The skill-edit gate's replay judge, on the ladder just built (OF-495).
    crate::replay_judge::register(&sync_server, config.skills.live_pulls_per_axis);

    // Adoption stays here, after the gates: the listener was only resolved
    // above, and `bind` is what takes the descriptor over. A vault VM's cold
    // restore binds its vsock bridges here too, now its vault is kept.
    host.activate_service_bridges_after_keep()?;
    let http = http.bind().await?;
    handles.http_owned_path = http.owned_path().map(Path::to_path_buf);
    let ctl = ManagedCtl::bind(&managed.ctl_socket)?;
    handles.ctl_owned_path = Some(ctl.path().to_path_buf());
    // The artifact origin, on the socket the supervisor routes the vault's
    // artifact names to (OF-356); this process owns the path it binds.
    let artifacts = match &managed.artifact_socket {
        Some(path) => Some(ServeListener::UnixPath(path.clone()).bind().await?),
        None => None,
    };
    handles.artifacts_owned_path = artifacts
        .as_ref()
        .and_then(BoundServeListener::owned_path)
        .map(Path::to_path_buf);

    let ledger = handles.ledger.insert(WakeLedger::load(
        Arc::clone(&vault),
        managed.vault_name.clone(),
        managed.hypnos_socket.clone(),
        &credentials,
    )?);
    // The native preview socket has only exact held-lease origins. No flag
    // means no registration caller or listener, preserving standalone hosts.
    let previews = managed
        .preview_socket
        .as_deref()
        .map(crate::managed::preview::PreviewRouteListener::bind)
        .transpose()?;
    let preview_routes = if previews.is_some() {
        let routes = Arc::new(crate::managed::preview::PreviewRoutes::new(
            ledger.preview_route_client(),
        ));
        sync_server.configure_artifact_preview_routes(Arc::clone(&routes))?;
        Some(routes)
    } else {
        None
    };
    // The frame is spent. `Credentials` zeroizes on drop, so releasing it here
    // rather than at end of scope is what keeps the DEK out of memory for the
    // rest of the process lifetime.
    drop(credentials);
    host.clear_secrets();
    // A kept restore's receipt, sealed once its escrow reports are spooled.
    let restored = restore
        .as_mut()
        .map(|restore| restore.seal_receipt(spooled.as_ref()))
        .transpose()?;
    let state = Arc::new(
        ManagedState::new(
            managed.vault_name.clone(),
            Arc::clone(&sync_server),
            handles.ledger.take().expect("ledger loaded before state"),
        )
        .with_admission(write_admission)
        .with_readiness(readiness.clone())
        .with_backup_facts(backup_facts)
        .with_vm_outbox_revision(host.vm_outbox_revision())
        .with_restore(restored),
    );
    handles.state = Some(Arc::clone(&state));
    let _ = reap_gate.set(Arc::clone(&state));
    // A public live voice session (`ai.voice.start`) holds an admission like
    // a served write, as a voice loop call does: a session in flight keeps a
    // reap from finding the vault quiescent, and a frozen vault opens none.
    // One no call named for a minute releases it until the next call names
    // it; a deleted vault opens none either (FIX 12053). Bound before
    // anything serves.
    sync_server.live_voice.admit_with(state.voice_admission());

    spawn_sigterm_shutdown(shutdown.clone())?;
    // The receipts every vault signs (ARCH-0066 §8-§9), each admitted through
    // the reap freeze like a served write: a frozen vault signs nothing, and a
    // reap never reads quiescent over a set in flight. The first set comes
    // before ctl is served, so no reap can freeze the vault ahead of it.
    handles.oversight = Some(
        sync_server
            .start_healer_oversight(crate::server::HEALER_OVERSIGHT_EVERY, {
                let state = Arc::clone(&state);
                move || state.admit_background(WriteKind::BackgroundOther)
            })
            .await?,
    );
    // Fact hooks (ARCH-0080) and the settled verb-ask drain on their runner,
    // unless `--no-hooks`: each pass admitted like a served write. The sandbox
    // loads before ready, as plain serve loads it, so no verb waits on it.
    let (hooks_stop, hooks_stopped) = watch::channel(false);
    #[cfg(feature = "code-sandbox-wasmtime")]
    let fact_hooks = if config.hooks {
        crate::commands::spawn_fact_hooks(
            &sync_server,
            state.background_admission(WriteKind::BackgroundOther),
            hooks_stopped,
        )
        .await
    } else {
        None
    };
    #[cfg(not(feature = "code-sandbox-wasmtime"))]
    let fact_hooks: Option<tokio::task::JoinHandle<()>> = {
        drop(hooks_stopped);
        None
    };

    handles.hooks_stop = Some(hooks_stop);
    handles.fact_hooks = fact_hooks;

    // The owner's `[linear]` mirror and webhook mapping, as plain serve
    // starts them, each pass admitted like a served write and holding it
    // through its sends and settlement. Settings it cannot use stop the
    // start here, before ctl serves or the supervisor hears ready.
    handles.linear = crate::linear_host::spawn_configured(
        Arc::clone(&sync_server),
        state.background_admission(WriteKind::BackgroundOther),
    )
    .await?;
    // A cold restore's fresh recipients, for the carrier watch's first look
    // (FIX 11851): captured before `verified` spends the restore. `None`
    // without a restore, and the watch's first look is then unplanned as
    // today.
    #[cfg(target_os = "linux")]
    let restore_fresh = restore
        .as_ref()
        .map(|restore| restore.fresh_recipients().to_vec());
    // Every fallible step is done: a cold restore's receipt and `verified`
    // go out before ctl serves or ready is said.
    if let Some(restore) = restore {
        restore.verified(&vault)?;
    }

    // Dedicated environments open before ready and the opening wake push, so
    // the first supervisor schedule already includes their earliest deadlines.
    // The shared teardown stops them on every exit, a failed start included.
    let shared = crate::shared_envs::SharedEnvRegistry::open_all(
        config.shared_env.clone(),
        &config,
        config.lease_vault_id,
        state.background_admission(WriteKind::DeviceSync),
        Some(state.device_sync_freeze()),
    )
    .await;
    sync_server.install_shared_envs(shared);

    if let Some(listener) = host_legal {
        handles.host_legal = Some(listener.start(Arc::clone(&vault), shutdown.clone())?);
    }

    handles.ctl_task = Some(tokio::spawn({
        let state = Arc::clone(&state);
        let ctl_shutdown = shutdown.triggered();
        async move { ctl.serve(state, ctl_shutdown).await }
    }));
    // The serving task now owns removing the control socket.
    handles.ctl_owned_path = None;

    // Both sockets are bound, the credentials are consumed, and the open gates
    // have passed. Only now is this process something the supervisor may route
    // traffic to. A facility it serves without is named first, and the ready
    // signal is the same either way.
    super::vault_gates::warn_degraded(&readiness);
    host.ready()?;
    tracing::info!(vault = %managed.vault_name, "managed vault ready");
    #[cfg(target_os = "linux")]
    if let Some(link) = host.vm_link() {
        super::vm_guest::spawn_lifecycle(
            link,
            Arc::clone(&state),
            Arc::clone(&sync_server),
            shutdown.clone(),
            managed.vm_outbox_companion_admitted,
        );
        // Its carrier as it stands, and the recipients it delivers later.
        super::carrier_watch::spawn(
            Arc::clone(&state),
            Arc::clone(&vault),
            managed.clone(),
            shutdown.clone(),
            restore_fresh.clone(),
        );
    } else if managed.escrow_recipient.is_some() || managed.break_glass_recipient.is_some() {
        // A process host's argv escrow recipient files as they stand later: a
        // file replaced after the start seals at the next look (FIX 11852).
        super::carrier_watch::spawn_argv_watch(
            Arc::clone(&state),
            Arc::clone(&vault),
            managed.clone(),
            shutdown.clone(),
            restore_fresh,
        );
    }

    // Subscribed before the opening push reads the training setting, so a
    // change between the two still reaches the report task (FIX 5575).
    let training_changes = vault.subscribe_proactivity_changes();
    if let Err(_error) = state.ledger().push_if_changed(&sync_server).await {
        tracing::warn!(
            reason = "wake_ledger_export_failed",
            "initial wake ledger push failed"
        );
    }
    handles.ledger_report = Some(ledger_report::spawn(
        Arc::clone(&state),
        Arc::clone(&sync_server),
        training_changes,
        shutdown.triggered(),
    ));

    // Housekeeping passes are admitted like a served write: a vault frozen
    // for reap sweeps nothing, and a pass in flight keeps it from reading
    // quiescent. These and the workers below count as other background
    // passes, unless named (FIX 6902).
    let admitted = || state.background_admission(WriteKind::BackgroundOther);
    // Held here until stopped: on a start that fails below as on a clean
    // stop, its admitted passes end before the process does (FIX 9538).
    handles.background = Some(sync_server.spawn_serve_background(admitted()));
    // Surface events drain under the same admission (OF-218).
    handles.connector_events = Some(sync_server.spawn_connector_event_worker(admitted()));
    // Approved sends leave under the same admission (OF-187).
    handles.connector_sends = Some(sync_server.spawn_connector_send_worker(admitted()));
    // Checked built-in channels, under the same admission (OF-519).
    handles.builtin_host = Some(crate::builtin_host::spawn(&sync_server, admitted()));
    // Failure signals reach our collector under the same admission (OF-380).
    // Managed mode reads no environment: the send's bearer is its vault secret (FIX 5013).
    handles.failure_signals = Some(crate::ai_host::failure_signals::spawn(
        &sync_server,
        crate::ai_host::failure_signals::FailureSignalHost::new(
            &config.failure_signals,
            true,
            config.failure_signals.bearer_from_secret(&vault),
        ),
        admitted(),
    ));
    // The ladder's workers plain serve runs. Wire health and the standing
    // pump pass under the same admission.
    // The nightly Coach jobs that need the host's model or rules (OF-420).
    handles.coach_host = Some(crate::ai_host::coach_host::spawn(&sync_server, admitted()));
    // Crossed thresholds ask the ladder whether everything is okay (OF-520).
    handles
        .ladder_workers
        .push(crate::wire_health::spawn(&sync_server, admitted()));
    // Queued browser program admissions, each pass under the same admission (CUA E8b).
    handles
        .ladder_workers
        .push(crate::ai_host::browser_program_admission::spawn(
            &sync_server,
            admitted(),
        ));
    // The Linear mirror started before ready stops with the ladder.
    handles.ladder_workers.extend(handles.linear.take());
    // An accepted Coach person-threshold row goes live on the ladder (Q3).
    handles
        .ladder_workers
        .extend(crate::decision_host::spawn_person_threshold_admitted(
            &sync_server,
            admitted(),
        ));
    // Pending vectors are filled while the vault admits writes (FIX 777).
    handles
        .ladder_workers
        .extend(sync_server.spawn_embedding_worker_admitted(admitted()));
    // Witnessed turns' tagging markers, paused by the freeze, drain at shutdown, never aborted.
    let tagging = state.pass_control(WriteKind::BackgroundTagging);
    handles.tagging = sync_server.spawn_tagging_worker_until(tagging, shutdown.triggered());
    // Stored media is embedded under the same admission (OF-370).
    handles
        .ladder_workers
        .extend(sync_server.spawn_media_embedding_worker_admitted(admitted()));
    // Queued and resumed agent runs, each admitted with its permit (OF-533):
    // a run as the owner's foreground work, its discovery pass as background.
    let admit_run = state.background_admission(WriteKind::OwnerWrite);
    handles
        .ladder_workers
        .extend(sync_server.spawn_resident_pump_admitted(admitted(), admit_run));
    // Held and answered connector calls settle (ONE-2510).
    handles
        .ladder_workers
        .push(sync_server.spawn_connector_settler_admitted(admitted()));
    // The backup schedule, the owner's setting over `[backup]` (FIX 5621),
    // started while it is off too: each tick is admitted like a served write
    // and holds it through its policy read, its backup and its pruning. It
    // and the custody publication run on past the vault's deletion, so its
    // backups go at their deadline (FIX 11710).
    let tick = crate::owner::schedule::SCHEDULE_TICK;
    handles
        .ladder_workers
        .extend(sync_server.spawn_backup_schedule_admitted(tick, state.backup_admission()));
    handles
        .ladder_workers
        .extend(sync_server.spawn_custody_publication_admitted(state.backup_admission()));
    handles.ladder_workers.extend(handles.gpu_poller.take());
    // Sensitive imported topics ask the owner who sees their later imports (OF-492).
    handles
        .ladder_workers
        .push(crate::import_audience::spawn(&sync_server, admitted()));
    // Documents whose signing finished are sealed as a task (OF-415).
    #[cfg(unix)]
    handles
        .ladder_workers
        .push(crate::api::spawn_esign_seal_worker_admitted(
            Arc::clone(&sync_server),
            admitted(),
            managed.seal_config(),
        ));
    // Held automated sign acts are asked up their role chain (OF-415).
    handles
        .ladder_workers
        .push(crate::api::spawn_esign_hold_worker_admitted(
            Arc::clone(&sync_server),
            admitted(),
        ));
    // Authorized e-sign mail goes to the supervisor's sender through its
    // outbox, under the same admission; without the flag none runs (OF-415).
    handles
        .ladder_workers
        .extend(config.esign_delivery_outbox_dir.clone().map(|dir| {
            crate::api::spawn_esign_delivery_outbox(Arc::clone(&sync_server), admitted(), dir)
        }));
    // Training offers and withdrawals go to the supervisor's outbox, offers
    // under the same admission; without the flag none runs (OF-420).
    handles
        .ladder_workers
        .extend(config.publisher_training_outbox_dir.clone().map(|dir| {
            crate::conversation_training::spawn(
                Arc::clone(&sync_server),
                admitted(),
                dir,
                crate::conversation_training::Placement::Managed,
            )
        }));
    // Due standing questions are answered through the ladder (OF-506), each
    // pass starting no next unit once the reap freeze holds (FIX 7376).
    if !ai.bind_question_timer(&sync_server) {
        let epochs = Arc::clone(&state.admission);
        handles
            .ladder_workers
            .push(crate::decision_graph::spawn_with_pause(
                &sync_server,
                admitted(),
                move || Some(epochs.pass_pause()),
            ));
        // Due digests, which a Dreamer's timer would otherwise serve (OF-499).
        handles
            .ladder_workers
            .push(crate::ai_host::home_digests::spawn(
                &sync_server,
                admitted(),
            ));
    }
    // Saved queries are evaluated over the vault's people in bounded wakes (ARCH-0059).
    handles
        .ladder_workers
        .push(crate::saved_query_sweep::spawn(&sync_server, admitted()));
    // Queued campaign enrollments land on the campaign's home node (ARCH-0059).
    handles
        .ladder_workers
        .push(crate::campaign_enrollment::spawn(&sync_server, admitted()));
    // Uncertain identities are decided, or asked of the person (OF-123).
    handles
        .ladder_workers
        .push(crate::ai_host::identity::spawn(&sync_server, admitted()));
    // Failure cases and blocked reports reach the Coach as proposed heals (OF-418).
    handles
        .ladder_workers
        .push(crate::ai_host::coach_heal::spawn(
            &sync_server,
            publisher_candidates,
            admitted(),
        ));
    // The owner's model-graded detectors read the retrieval telemetry (OF-418).
    handles
        .ladder_workers
        .extend(crate::ai_host::self_heal_detectors::spawn(
            &sync_server,
            &config.self_heal,
            admitted(),
        ));
    // The server's own voice loop (FIX 2391), off unless `[models.voice]`
    // names its socket. A call opens on a hello the supervisor attests for
    // the vault's owner, or on the owner's own slip from a machine that
    // stands as his enrolled device (FIX 1949 = B), and is admitted like a
    // served write for its whole length: a call in flight keeps a reap from
    // finding the vault quiescent; a frozen vault takes no call, and a
    // deleted vault takes none either (FIX 12039).
    #[cfg(unix)]
    {
        handles.voice = crate::voice_host::VoiceBoot::start(
            &sync_server,
            config.models.as_ref().map(|models| &models.voice),
            Some({
                let state = Arc::clone(&state);
                Arc::new(
                    move |action: &oneiron_vault_contract::ManagedOwnerAction,
                          room: &str,
                          roster: &str,
                          issued_at: UnixTs,
                          nonce: &[u8; oneiron_vault_contract::MANAGED_VOICE_NONCE_BYTES]| {
                        state.verify_voice_owner(action, room, roster, issued_at, nonce)
                    },
                )
            }),
            state.voice_admission(),
        );
    }
    // The supervisor reaches the loop on the vault VM's voice port.
    #[cfg(unix)]
    if handles.voice.is_some()
        && let Some(socket) = config
            .models
            .as_ref()
            .and_then(|models| models.voice.socket.clone())
    {
        host.bridge_voice(socket)?;
    }
    // The managed surface, not the bare one: the reap freeze has to be
    // enforceable by the socket the supervisor routes traffic to, or
    // `quiescent: true` is a claim about a gate that nothing reaches. Each
    // socket upgraded on it or the mesh sees the shutdown, and is waited
    // for with the calls it admitted before any worker stops (FIX 4757).
    let (app, upgrades) = crate::embedded::upgrade_lifetime(
        build_managed_app(Arc::clone(&sync_server), Arc::clone(&state)).layer(cors),
        shutdown.0.subscribe(),
    );
    // The paired-machine mesh listener (OF-535), as `serve` starts it: off
    // unless the supervisor names its bind address on argv (WILL-PLAN L14
    // row 14); managed mode never reads `ONEIRON_MESH_*`.
    let mesh = crate::handler::mesh::start(
        Arc::clone(&sync_server),
        &crate::handler::mesh::MeshConfig::from_parts(
            managed.mesh_bind,
            managed.mesh_relays.clone(),
        ),
        &app,
        config.limits.connections(),
    )
    .await?;
    // A vault that is a device of another home dials it, on that mesh when
    // the home has a paired address there, as plain serve does (WILL-PLAN
    // L14 row 14): the owner's `[device_sync]` or `oneiron device enrol`
    // names the home. Each run between freezes holds an admission of its
    // own (FIX 5127): a freeze pauses it, a reap waits for the pause, and
    // after a thaw it runs again; a frozen vault starts none.
    let device_sync = crate::device_sync::DeviceSyncHost::start_admitted(
        &sync_server,
        &config,
        mesh.as_ref(),
        state.device_sync_freeze(),
    )
    .await;
    handles.artifact_task = artifacts.map(|listener| {
        let app = build_managed_artifact_app(Arc::clone(&sync_server), Arc::clone(&state));
        let stop = shutdown.triggered();
        tokio::spawn(async move { listener.serve_until(app, stop).await })
    });
    handles.preview_task = previews.zip(preview_routes).map(|(listener, routes)| {
        let stop = shutdown.clone();
        tokio::spawn(async move { listener.serve(routes, stop).await })
    });
    // Graceful shutdown couples "stop accepting" and "drain in-flight": the
    // listener closes the moment SIGTERM lands, and this resolves once the
    // requests already in the runtime have finished.
    let result = http.serve_until(app, shutdown.triggered()).await;
    // The mesh's sync streams end where they are, so an upgrade none
    // finished gives back its place; then every upgraded socket ends,
    // with no deadline, once the calls it admitted have.
    if let Some(mesh) = &mesh {
        mesh.end_streams().await;
    }
    upgrades.await;
    // This machine's send executor and agent run leases go to another
    // machine while the device-sync link can still carry the release
    // (FIX 4747).
    sync_server.release_send_executor_leases().await;
    sync_server.release_agent_run_leases().await;
    // Its channel detaches before the mesh it rides closes.
    if let Some(device_sync) = device_sync {
        device_sync.stop().await;
    }
    if let Some(mesh) = mesh {
        mesh.stop().await;
    }
    Ok(result)
}
