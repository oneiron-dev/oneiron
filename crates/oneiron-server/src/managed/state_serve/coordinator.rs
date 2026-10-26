//! Supervised vault startup, serving, and shutdown.
//! `serve_managed` keeps the existing boot and drain order in one coordinator.
//! State, admission, and shutdown definitions remain in the parent module.

use crate::managed::ledger::LEDGER_SCHEDULE_POLL;

use super::{
    Arc, BoundServeListener, CONTRACT_VERSION, ErrorKind, Host, HostLimits, ManagedArgs,
    ManagedCtl, ManagedShutdown, ManagedState, Path, ServeArgs, ServeListener, ShutdownSignal,
    SyncServer, UnixTs, WakeLedger, WriteKind, admission, build_managed_app,
    build_managed_artifact_app, escrow_vault_key, final_ledger_push, managed_page_seal,
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
    let mut host =
        super::host::ManagedHost::new(&managed, HostLimits::unbounded(), shutdown.clone())?;
    let http = host.listener()?;
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
    // Stable, domain-separated custody from the verified vault DEK, not the
    // per-spawn callback token or caller-controlled HTTP identity headers.
    // A fresh spawn with the same DEK must recover the same logged host root.
    let mut issuer_key = blake3::derive_key(
        "oneiron/managed-supervisor-host-authority/v2",
        &credentials.dek,
    );
    let issuer = oneiron::authority::HostSlipIssuer::from_secret(&issuer_key)?;
    issuer_key.fill(0);
    let readiness = provision_host_authority(
        &vault,
        &issuer,
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
    escrow_vault_key(&vault, &managed)?;
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
    // Its broker is the same-user child beside this binary; a missing broker
    // or secret leaves those calls refused before they start, as on any host.
    let broker = crate::models::BrokerContext::for_serve(&vault, &config);
    // The embedder slot and the pods' health poller, as plain serve builds
    // them; the worker that fills the slot starts under the write admission.
    let (embedder, gpu_poller) =
        crate::commands::build_embedder(&vault, &config, broker.as_ref()).await?;
    // The tagger slot `[oneironer]` names, as plain serve builds it; its
    // worker starts under the write admission too. Its engine rows sit in
    // the data directory: managed mode reads no HOME or XDG (FIX 6873).
    let rows = managed.data_dir.join("oneironer").join("engines.json");
    let tagger =
        crate::oneironer::build_slot_off_runtime(config.oneironer.clone(), Some(rows)).await?;
    // The browser and desktop guests, as plain serve attaches them: each
    // section's own checks decide, and a run with no guest is refused.
    // Managed mode reads no environment, so the feedback destination carries
    // no bearer: our inbox takes none.
    let mut sync_server = SyncServer::new(Arc::clone(&vault), server_config)
        .map_err(|e| anyhow::anyhow!("sync server init failed: {e}"))?
        .with_embedder(embedder)
        .with_tagger(tagger)
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
                bearer: None,
            }
        }))
        .with_feedback_triage(config.feedback.triage.clone());
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
        sync_server = sync_server.with_extraction_egress(Arc::new(|_: &oneiron::LlmRequest| true));
    }
    sync_server.managed_issuer = Some(issuer);
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
    // claims the MACRO home. A startup error below drops `ai`, which tells
    // its workers to stop.
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
    let sync_server = Arc::new(sync_server);
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
    let http_owned_path = http.owned_path().map(Path::to_path_buf);
    let ctl = ManagedCtl::bind(&managed.ctl_socket)?;
    // The artifact origin, on the socket the supervisor routes the vault's
    // artifact names to (OF-356); this process owns the path it binds.
    let artifacts = match &managed.artifact_socket {
        Some(path) => Some(ServeListener::UnixPath(path.clone()).bind().await?),
        None => None,
    };
    let artifacts_owned_path = artifacts
        .as_ref()
        .and_then(BoundServeListener::owned_path)
        .map(Path::to_path_buf);

    let ledger = WakeLedger::load(
        Arc::clone(&vault),
        managed.vault_name.clone(),
        managed.hypnos_socket.clone(),
        &credentials,
    )?;
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
        ManagedState::new(managed.vault_name.clone(), Arc::clone(&sync_server), ledger)
            .with_admission(write_admission)
            .with_readiness(readiness.clone())
            .with_backup_facts(backup_facts)
            .with_vm_outbox_revision(host.vm_outbox_revision())
            .with_restore(restored),
    );
    let _ = reap_gate.set(Arc::clone(&state));
    // A public live voice session (`ai.voice.start`) holds an admission like
    // a served write, as a voice loop call does: a session in flight keeps a
    // reap from finding the vault quiescent, and a frozen vault opens none.
    // One no call named for a minute releases it until the next call names
    // it. Bound before anything serves.
    sync_server
        .live_voice
        .admit_with(state.background_admission(WriteKind::OwnerWrite));

    spawn_sigterm_shutdown(shutdown.clone())?;
    // The receipts every vault signs (ARCH-0066 §8-§9), each admitted through
    // the reap freeze like a served write: a frozen vault signs nothing, and a
    // reap never reads quiescent over a set in flight. The first set comes
    // before ctl is served, so no reap can freeze the vault ahead of it.
    let oversight = sync_server
        .start_healer_oversight(crate::server::HEALER_OVERSIGHT_EVERY, {
            let state = Arc::clone(&state);
            move || state.admit_background(WriteKind::BackgroundOther)
        })
        .await?;
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

    // The owner's `[linear]` mirror and webhook mapping, as plain serve
    // starts them, each pass admitted like a served write and holding it
    // through its sends and settlement. Settings it cannot use stop the
    // start here, before ctl serves or the supervisor hears ready.
    let linear = crate::linear_host::spawn_configured(
        Arc::clone(&sync_server),
        state.background_admission(WriteKind::BackgroundOther),
    )
    .await?;
    // Every fallible step is done: a cold restore's receipt and `verified`
    // go out before ctl serves or ready is said.
    if let Some(restore) = restore {
        restore.verified(&vault)?;
    }

    let ctl_task = tokio::spawn({
        let state = Arc::clone(&state);
        let ctl_shutdown = shutdown.triggered();
        async move { ctl.serve(state, ctl_shutdown).await }
    });

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
        );
        // Its carrier as it stands, and the recipients it delivers later.
        super::carrier_watch::spawn(
            Arc::clone(&state),
            Arc::clone(&vault),
            managed.clone(),
            shutdown.clone(),
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
    let ledger_report = spawn_ledger_report(
        Arc::clone(&state),
        Arc::clone(&sync_server),
        training_changes,
        shutdown.triggered(),
    );

    // Housekeeping passes are admitted like a served write: a vault frozen
    // for reap sweeps nothing, and a pass in flight keeps it from reading
    // quiescent. These and the workers below count as other background
    // passes, unless named (FIX 6902).
    let admitted = || state.background_admission(WriteKind::BackgroundOther);
    // Held here until stopped: on a start that fails below as on a clean
    // stop, its admitted passes end before the process does (FIX 9538).
    let mut background = Some(sync_server.spawn_serve_background(admitted()));
    // Surface events drain under the same admission (OF-218).
    let connector_events = sync_server.spawn_connector_event_worker(admitted());
    // Approved sends leave under the same admission (OF-187).
    let connector_sends = sync_server.spawn_connector_send_worker(admitted());
    // Checked built-in channels, under the same admission (OF-519).
    let builtin_host = crate::builtin_host::spawn(&sync_server, admitted());
    // Failure signals reach our collector under the same admission (OF-380).
    // Managed mode reads no environment, so the send carries no bearer.
    let failure_signals = crate::ai_host::failure_signals::spawn(
        &sync_server,
        crate::ai_host::failure_signals::FailureSignalHost::new(
            &config.failure_signals,
            true,
            None,
        ),
        admitted(),
    );
    // The ladder's workers plain serve runs. Wire health and the standing
    // pump pass under the same admission.
    // The nightly Coach jobs that need the host's model or rules (OF-420).
    let coach_host = crate::ai_host::coach_host::spawn(&sync_server, admitted());
    // Crossed thresholds ask the ladder whether everything is okay (OF-520).
    let mut ladder_workers = vec![crate::wire_health::spawn(&sync_server, admitted())];
    // Queued browser program admissions, each pass under the same admission (CUA E8b).
    ladder_workers.push(crate::ai_host::browser_program_admission::spawn(
        &sync_server,
        admitted(),
    ));
    // The Linear mirror started before ready stops with the ladder.
    ladder_workers.extend(linear);
    // An accepted Coach person-threshold row goes live on the ladder (Q3).
    ladder_workers.extend(crate::decision_host::spawn_person_threshold_admitted(
        &sync_server,
        admitted(),
    ));
    // Pending vectors are filled while the vault admits writes (FIX 777).
    ladder_workers.extend(sync_server.spawn_embedding_worker_admitted(admitted()));
    // Witnessed turns' tagging markers, paused by the freeze, drain at shutdown, never aborted.
    let tagging = state.pass_control(WriteKind::BackgroundTagging);
    let tagging = sync_server.spawn_tagging_worker_until(tagging, shutdown.triggered());
    // Stored media is embedded under the same admission (OF-370).
    ladder_workers.extend(sync_server.spawn_media_embedding_worker_admitted(admitted()));
    // Queued and resumed agent runs, each admitted with its permit (OF-533):
    // a run as the owner's foreground work, its discovery pass as background.
    let admit_run = state.background_admission(WriteKind::OwnerWrite);
    ladder_workers.extend(sync_server.spawn_resident_pump_admitted(admitted(), admit_run));
    // Held and answered connector calls settle (ONE-2510).
    ladder_workers.push(sync_server.spawn_connector_settler_admitted(admitted()));
    // The backup schedule, the owner's setting over `[backup]` (FIX 5621),
    // started while it is off too: each tick is admitted like a served write
    // and holds it through its policy read, its backup and its pruning.
    let tick = crate::owner::schedule::SCHEDULE_TICK;
    ladder_workers.extend(sync_server.spawn_backup_schedule_admitted(tick, admitted()));
    ladder_workers.extend(sync_server.spawn_custody_publication_admitted(admitted()));
    ladder_workers.extend(gpu_poller);
    // Sensitive imported topics ask the owner who sees their later imports (OF-492).
    ladder_workers.push(crate::import_audience::spawn(&sync_server, admitted()));
    // Documents whose signing finished are sealed as a task (OF-415).
    #[cfg(unix)]
    ladder_workers.push(crate::api::spawn_esign_seal_worker_admitted(
        Arc::clone(&sync_server),
        admitted(),
        managed.seal_config(),
    ));
    // Held automated sign acts are asked up their role chain (OF-415).
    ladder_workers.push(crate::api::spawn_esign_hold_worker_admitted(
        Arc::clone(&sync_server),
        admitted(),
    ));
    // Authorized e-sign mail goes to the supervisor's sender through its
    // outbox, under the same admission; without the flag none runs (OF-415).
    ladder_workers.extend(config.esign_delivery_outbox_dir.clone().map(|dir| {
        crate::api::spawn_esign_delivery_outbox(Arc::clone(&sync_server), admitted(), dir)
    }));
    // Training offers and withdrawals go to the supervisor's outbox, offers
    // under the same admission; without the flag none runs (OF-420).
    ladder_workers.extend(config.publisher_training_outbox_dir.clone().map(|dir| {
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
        ladder_workers.push(crate::decision_graph::spawn_with_pause(
            &sync_server,
            admitted(),
            move || Some(epochs.pass_pause()),
        ));
        // Due digests, which a Dreamer's timer would otherwise serve (OF-499).
        ladder_workers.push(crate::ai_host::home_digests::spawn(
            &sync_server,
            admitted(),
        ));
    }
    // Saved queries are evaluated over the vault's people in bounded wakes (ARCH-0059).
    ladder_workers.push(crate::saved_query_sweep::spawn(&sync_server, admitted()));
    // Queued campaign enrollments land on the campaign's home node (ARCH-0059).
    ladder_workers.push(crate::campaign_enrollment::spawn(&sync_server, admitted()));
    // Uncertain identities are decided, or asked of the person (OF-123).
    ladder_workers.push(crate::ai_host::identity::spawn(&sync_server, admitted()));
    // Tagging stays outside this scope: an error in it returns only once
    // tagging has stopped and every call it made has settled (FIX 7304).
    let mut tagging = tagging;
    let outcome = async {
        // Failure cases and blocked reports reach the Coach as proposed heals (OF-418).
        ladder_workers.push(crate::ai_host::coach_heal::spawn(
            &sync_server,
            config.failure_signals.publisher_candidates()?,
            admitted(),
        ));
        // The owner's model-graded detectors read the retrieval telemetry (OF-418).
        ladder_workers.extend(crate::ai_host::self_heal_detectors::spawn(
            &sync_server,
            &config.self_heal,
            admitted(),
        ));
        // The server's own voice loop (FIX 2391), off unless `[models.voice]`
        // names its socket. A call opens on a hello the supervisor attests for
        // the vault's owner, or on the owner's own slip from a machine that
        // stands as his enrolled device (FIX 1949 = B), and is admitted like a
        // served write for its whole length: a call in flight keeps a reap from
        // finding the vault quiescent, and a frozen vault takes no call.
        #[cfg(unix)]
        let voice = crate::voice_host::VoiceBoot::start(
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
            state.background_admission(WriteKind::OwnerWrite),
        );
        // The supervisor reaches the loop on the vault VM's voice port.
        #[cfg(unix)]
        if voice.is_some()
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
        // names the home. The connection holds one admission for its whole run,
        // so a frozen vault starts none and a reap waits for it.
        let device_sync = crate::device_sync::DeviceSyncHost::start_admitted(
            &sync_server,
            &config,
            mesh.as_ref(),
            &state.background_admission(WriteKind::OwnerWrite),
        )
        .await;
        let artifact_task = artifacts.map(|listener| {
            let app = build_managed_artifact_app(Arc::clone(&sync_server), Arc::clone(&state));
            let stop = shutdown.triggered();
            tokio::spawn(async move { listener.serve_until(app, stop).await })
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
        // Its channel detaches before the mesh it rides closes.
        if let Some(device_sync) = device_sync {
            device_sync.stop().await;
        }
        if let Some(mesh) = mesh {
            mesh.stop().await;
        }
        host.on_stop()?;
        let _ = ctl_task.await;
        if let Some(task) = artifact_task {
            let _ = task.await;
        }
        // A call in flight ends through its usual teardown before the freeze.
        #[cfg(unix)]
        if let Some(voice) = voice {
            voice.stop().await;
        }
        // So does every public live voice session, its journal finished, and
        // none starts after (FIX 5324). A reap's freeze leaves them open; only
        // this stop ends them.
        sync_server.live_voice.stop_all().await;
        // Drain observation writes without thawing a previously quiescent process.
        let telemetry_drained = state.freeze();
        // No new durable background work from here on.
        if let Some(background) = background.take() {
            background.stop().await;
        }
        connector_events.abort();
        let _ = connector_events.await;
        connector_sends.abort();
        let _ = connector_sends.await;
        builtin_host.abort();
        let _ = builtin_host.await;
        coach_host.abort();
        let _ = coach_host.await;
        failure_signals.abort();
        let _ = failure_signals.await;
        let _ = futures_util::future::OptionFuture::from(tagging.take()).await;
        // Tagging has ended: each platform child is shut down and reaped (FIX 7383).
        if let Some(slot) = sync_server.tagger.as_ref() {
            slot.closer().close().await;
        }
        for worker in ladder_workers {
            worker.abort();
            let _ = worker.await;
        }
        // A backup before an idle reap ends before exit; none starts after.
        state.idle_backup.stopped().await;
        // A relay delete in flight finishes its unlink and sync; none starts after.
        state.relay_delete.stopped().await;
        // A hook pass in flight commits or fails whole before the runner stops.
        let _ = hooks_stop.send(true);
        if let Some(fact_hooks) = fact_hooks {
            let _ = fact_hooks.await;
        }
        // A pass or step in flight reaches its own boundary before this returns.
        ai.shutdown().await;
        // Frozen, so nothing new is admitted; an admitted write ends before exit.
        oversight.stop().await;

        if let Some(path) = http_owned_path {
            // Only ever the path this process created. An inherited socket's inode
            // belongs to the supervisor and has to survive us.
            if let Err(error) = std::fs::remove_file(&path)
                && error.kind() != ErrorKind::NotFound
            {
                tracing::warn!(%error, path = %path.display(), "http socket unlink failed");
            }
        }
        if let Some(path) = artifacts_owned_path
            && let Err(error) = std::fs::remove_file(&path)
            && error.kind() != ErrorKind::NotFound
        {
            tracing::warn!(%error, path = %path.display(), "artifact socket unlink failed");
        }

        // The report task stops before the final push, which reads the report
        // again itself.
        ledger_report.abort();
        let _ = ledger_report.await;
        final_ledger_push(&state, &sync_server).await;
        result?;
        telemetry_drained?;
        anyhow::Ok(())
    }
    .await;
    // Still running only when an error left the scope before its join.
    if let Some(background) = background {
        background.stop().await;
    }
    if let Some(tagging) = tagging {
        shutdown.trigger();
        let _ = tagging.await;
        // A failed start reaps its platform children too (FIX 7383).
        if let Some(slot) = sync_server.tagger.as_ref() {
            slot.closer().close().await;
        }
    }
    outcome
}

/// Reports the vault's training setting and its schedule to the supervisor
/// as they change (FIX 5575, FIX 7746), so a status read there never wakes
/// the vault and its next wake is the one the running vault would ask for.
///
/// Each notification on `changes` only says "re-read committed state", and
/// so does each [`LEDGER_SCHEDULE_POLL`] tick, since a lease, the sync queue
/// and a noted deadline move with no signal of their own: the report is read
/// again and pushed when the setting or the schedule moved from the last
/// report the supervisor took, or when it took none, so a refused push goes
/// out again on the next read. Notifications that land during a push are
/// read as one, since each report replaces the last whole. It takes no write
/// admission, so the reap freeze never holds it back, and it ends with
/// shutdown.
fn spawn_ledger_report(
    state: Arc<ManagedState>,
    server: Arc<SyncServer>,
    mut changes: watch::Receiver<u64>,
    mut stop: ShutdownSignal,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut poll = tokio::time::interval(LEDGER_SCHEDULE_POLL);
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The opening push has just read the report.
        poll.tick().await;
        loop {
            tokio::select! {
                () = &mut stop => return,
                changed = changes.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
                _ = poll.tick() => {}
            }
            if let Err(_error) = state.ledger().push_live_if_changed(&server).await {
                tracing::warn!(
                    reason = "wake_ledger_export_failed",
                    "wake ledger report failed"
                );
            }
        }
    })
}
