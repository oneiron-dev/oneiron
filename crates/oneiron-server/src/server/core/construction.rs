//! Construction of the core sync server from an opened vault.
//! `SyncServer::new` loads and reconciles the root before wiring host state.
//! The server definition, fields, and shared helpers stay in the parent module.

use super::{
    Arc, AtomicU32, BTreeMap, DreamerAttemptProgressProducer, EphemeralStore, HashSet, LoroDoc,
    Materializer, McpConnectorActorRegistry, McpCredentialHashKey, Mutex,
    NEXT_LIFECYCLE_SESSION_ID, Ordering, ROOT_LEASES_MAP, SERVER_USER_ID, SyncEngineContext,
    SyncServer, SyncServerConfig, UsageLedger, WindowManager, add_window_to_root, broadcast,
    host_root_secret, init_window_list, insert_root_schema_version, live_rows,
    mcp_registry_hash_key, read_window_list, server_state, spawn_local_change_producer,
};

impl SyncServer {
    /// Creates a SyncServer over the vault, reloading persisted CRDT state.
    ///
    /// Startup ordering per ARCH-0023b: (1) the root Doc loads from `d:root`
    /// plus pending `u:root:*`; (2) window Docs load on demand from
    /// `d:w:{key}` plus pending `u:w:{key}:*` in `Self::serve_window`.
    /// A fresh vault initializes and persists a new root Doc.
    ///
    /// Boot also reconciles `meta.windows` against the persisted `d:w:*`
    /// snapshots, so a crash between window-snapshot persistence and root
    /// persistence cannot permanently hide a window from clients.
    ///
    /// Errors (fail-closed) on corrupt persisted state: the server must not
    /// boot empty over an undecodable snapshot — that silently discards
    /// relayed updates, including tombstones.
    pub fn new(
        vault: Arc<oneiron::Vault>,
        config: SyncServerConfig,
    ) -> Result<Self, oneiron::Error> {
        config.validate()?;
        vault.recover_admission_intents()?;
        // Genuine host authority must exist before any scoped-read fail-closed
        // policy applies. Dev/no-secret and blind-relay modes mint nothing.
        // An empty configured secret mints nothing either, and every upgrade
        // bearing it (or nothing) still 401s at the auth door, so booting
        // rootless here is fail-closed, not open. The configured secret
        // admits rooting; the root signs with this install's own issuer seed
        // for the vault (FIX-LIST 3018), drawn only for a vault no root has
        // reached. An install holding no seed serves rootless, said once.
        let issuer = match host_root_secret(&vault, &config) {
            Some(_) => match vault.bootstrap_host_slip_issuer() {
                Ok(issuer) => {
                    vault.ensure_host_root_slip(&issuer)?;
                    // The engine's MACHINE writers sign with host-held keys (ONE-1634).
                    vault.provision_engine_machine_identities(&issuer)?;
                    Some(Arc::new(issuer))
                }
                Err(error) => {
                    tracing::warn!(
                        kind = ?error.kind(),
                        reason = %error,
                        "this install holds no host issuer seed for the vault, so it serves without \
                         signing as its root; reads and sync go on"
                    );
                    None
                }
            },
            None => None,
        };
        // This install's own machine profile, before any request is admitted,
        // so it carries the owner's acts from its first start (FIX 4648):
        // self-hosted and embedded serving alike. A start goes on without it.
        vault.ensure_serving_install_profile_at_start(issuer.as_deref(), "serve");

        let root_doc = match server_state::load_root_from_state(&vault)? {
            Some(doc) => doc,
            None => {
                let doc = LoroDoc::new();
                // Initialize root doc meta map
                let meta = doc.get_map("meta");
                // A native Loro I64, the shared schema's own encoding
                // (`schema::create_root_doc`).
                insert_root_schema_version(&meta).map_err(|e| {
                    oneiron::Error::sync_engine(SyncEngineContext::LoroMapInsert, e)
                })?;
                // `meta.windows` must use the shared schema-owned encoding so
                // fresh server docs, root-doc creation, and client decoding
                // cannot drift.
                init_window_list(&doc, &[]);
                // Historical receipt-key verification records. This map
                // grants no transport authority and has no live mint path.
                let _leases = doc.get_map(ROOT_LEASES_MAP);
                doc.commit();
                // Boot is pre-connection/single-threaded; no root-writer
                // mutex can race this initial persist.
                server_state::persist_root_snapshot(&vault, &doc)?;
                doc
            }
        };

        // Reconcile meta.windows with the persisted window snapshots.
        let known: HashSet<String> = read_window_list(&root_doc)
            .iter()
            .map(|k| k.as_str().to_string())
            .collect();
        let mut reconciled = false;
        for key in server_state::persisted_window_keys(&vault)?
            .into_iter()
            .chain(oneiron::sync::discover_local_window_keys(&vault)?)
        {
            if !known.contains(key.as_str()) {
                add_window_to_root(&root_doc, &key);
                reconciled = true;
            }
        }
        if reconciled {
            // Boot reconciliation is pre-connection/single-threaded; no
            // root-writer mutex can race this persist.
            server_state::persist_root_snapshot(&vault, &root_doc)?;
        }

        let (broadcast_tx, _) = broadcast::channel(256);
        let mcp_registry = Mutex::new(McpConnectorActorRegistry::new(
            McpCredentialHashKey::from_bytes(mcp_registry_hash_key(&config)),
        ));

        let reassert_manager = Arc::new(WindowManager::new(
            vault.clone(),
            Arc::new(Materializer::with_lease_vault_id(config.lease_vault_id)),
            SERVER_USER_ID,
        ));
        reassert_manager.attach_to_vault();
        let reactive_tee = super::windows::attach_local_read_tee(&reassert_manager, &broadcast_tx);
        // Detached on purpose: the relay ends by itself when the manager (and
        // with it the outbound sink holding the sender) drops with this server.
        spawn_local_change_producer(&reassert_manager, &broadcast_tx);

        let wire_telemetry = crate::wire_telemetry::WireTelemetry::new(vault.clone());
        live_rows(&vault, &config.limits, wire_telemetry.limit_questions());
        let retained = Arc::new(crate::byte_line::ByteLine::new(
            crate::wire_telemetry::LimitRow::RetainedMemoryBytes,
            usize::try_from(config.limits.retained_memory_bytes).unwrap_or(usize::MAX),
        ));
        let presence = Arc::new(super::presence::PresenceCharge::new(
            Arc::clone(&retained),
            Arc::clone(wire_telemetry.limit_questions()),
        ));
        let ephemeral_store = Arc::new(EphemeralStore::new(config.ephemeral_timeout_ms));
        let message_scopes = Arc::new(super::message_stream::MessageScopes::default());
        super::message_stream::spawn_message_stream_producer(
            &vault,
            &ephemeral_store,
            &presence,
            &message_scopes,
            &broadcast_tx,
            &config,
        );
        // The engine's `[limits]` rows on this vault ask where the server's do.
        let questions: Arc<crate::wire_telemetry::LimitQuestions> =
            Arc::clone(wire_telemetry.limit_questions());
        vault.set_limit_ask(questions);
        // Reader children wake this server's runner, which also keeps their
        // cutoff.
        let reader_runner = super::ReaderRunner::start(&vault, &config.limits);
        let runner: Arc<dyn oneiron::code_run::ReaderJobRunner> = reader_runner.clone();
        vault.set_reader_job_runner(runner);
        crate::models::outbound_wait::install(&vault);
        // V2-R3: a lock of this vault waits for this process's snapshot
        // release before its key drops; an erase drops its sessions.
        crate::models::install_snapshot_runtime(&vault);
        // Provider media replies are booked on their own line (FIX 8615),
        // this vault's, as its mesh bytes are (FIX 9321, FIX 9323).
        let model_budgets = crate::models::ModelHostBudgets::new(
            &config.limits,
            Arc::clone(wire_telemetry.limit_questions()),
        );
        // The cloud registration client reads its pins once, here; no
        // request is made until the owner asks.
        let cloud_registration = crate::cloud_registration::CloudRegistration::new(
            config.cloud_registration_pins.as_deref(),
        );
        let decision_reads = crate::admission::Admission::new(
            crate::wire_telemetry::LimitRow::DecisionReads,
            Arc::clone(wire_telemetry.limit_questions()),
            config.limits.decision_reads,
            config.limits.queue_wait(),
        );
        let renderer_turns = crate::admission::Admission::new(
            crate::wire_telemetry::LimitRow::RendererWork,
            Arc::clone(wire_telemetry.limit_questions()),
            config.limits.renderer_work,
            config.limits.queue_wait(),
        );
        // Task work waits in the vault's own line, which the embedded SDK, a
        // code run's own ask and wait and a pumped agent share with the
        // served doors; this server sets its `[limits]` row on it.
        vault.set_task_work(
            config.limits.task_work,
            config.limits.queue_wait(),
            Some(crate::admission::row_crossing(
                crate::wire_telemetry::LimitRow::TaskWork,
                Arc::clone(wire_telemetry.limit_questions()),
            )),
        );
        let decisions = crate::decision_host::DecisionHost::new(&vault);
        let run_receipts = Arc::new(crate::models::ServerReceipts::hooked(vault.clone()));
        let feedback_flood = crate::api::FloodCap::new(
            config.feedback_inbox.notes_per_sender,
            config.feedback_inbox.notes_per_hour,
            std::time::Instant::now(),
        );
        let lens_frames = Arc::new(crate::lens_frames::LensFrameStore::new(
            &retained,
            &wire_telemetry,
        ));
        // OF-181: a live run that ends closes the lens cards it created.
        let live_runs: Arc<super::LiveRuns> = Arc::default();
        live_runs.close_cards_with(Arc::clone(&lens_frames));
        // FIX 8143: a live run that ends closes its board sessions.
        let memories_cursors = Arc::new(Mutex::new(crate::api::MemoriesCursorStore::default()));
        live_runs.close_sessions_with(crate::api::run_session_closer(Arc::clone(
            &memories_cursors,
        )));
        // CUA-001: no run guest outlives a restart, so no takeover Ask can be answered.
        super::desktop_seats::clear_stale_asks(&vault);
        // FIX 8335: no run-bound record outlives a restart, so a host that
        // stopped mid-run leaves none behind. A failure is logged; the
        // records stay as they were.
        if let Err(error) = vault.erase_all_run_secrets() {
            tracing::warn!(%error, "run-bound secrets left by the last run of the host did not clear");
        }
        // FIX 3837: no connector's live exchange outlives a restart, so the
        // rounds of questions kept on its calls' rows stand with their
        // delivery uncertain.
        if let Err(error) = vault.mark_connector_inputs_uncertain() {
            tracing::warn!(%error, "connector call questions not marked uncertain");
        }
        // One machine memory line for the server's work and its organs'
        // own buffers alike (FIX 7649, FIX 7654).
        let memory = crate::machine::MachineMemory::new();
        // FIX 8569, 8574, 8596, 8598: office reads and edits reserve from
        // the same line, each reservation waiting the host's queue wait.
        // The first server of a process registers it.
        let _ = oneiron::office_body::register_document_memory(Arc::new(
            crate::document_memory::DocumentFloor {
                memory: memory.clone(),
                wait: config.limits.queue_wait(),
            },
        ));
        // Another vault of this process reads this one through this handle
        // (FIX 11157): the read-only door refuses a root held open here.
        vault.register_served();
        let hyde_queue_wait = config.limits.queue_wait();
        Ok(Self {
            note_editors: super::NoteEditors::default(),
            artifact_previews: super::ArtifactPreviews::default(),
            live_voice: Default::default(),
            asr_sessions: Default::default(),
            model_streams: Default::default(),
            export_transfers: Default::default(),
            lens_frames,
            retained,
            presence,
            removal_deliveries: crate::server::removal_delivery::RemovalDeliveries::start(&vault),
            usage_ledger: UsageLedger::new(vault.clone()),
            // Each resident's share of the allocation, kept in the vault (FIX 7767).
            host_account: oneiron::llm::run_admission::HostAccount::with_residents(
                oneiron::llm::VaultResidentLedger::new(vault.clone()),
            ),
            transfers: crate::api::Transfers::new(
                &config.limits,
                Arc::clone(wire_telemetry.limit_questions()),
                &vault,
            )?,
            memory: memory.clone(),
            renderer_turns,
            wire_telemetry,
            mesh_pressure: crate::wire_telemetry::PoolPressure::mesh(),
            vault,
            root_doc,
            ephemeral_store,
            message_scopes,
            broadcast_tx,
            next_conn_id: AtomicU32::new(1),
            lease_registrar: Mutex::new(()),
            reassert_manager,
            _reactive_tee: reactive_tee,
            lifecycle_session_id: NEXT_LIFECYCLE_SESSION_ID.fetch_add(1, Ordering::Relaxed),
            lifecycle_in_flight: Mutex::new(HashSet::new()),
            housekeeping_passes: Default::default(),
            standing_block_cache: Mutex::new(
                oneiron::persona_snapshot::standing::StandingBlockCache::default(),
            ),
            dreamer_progress: Mutex::new(DreamerAttemptProgressProducer::new()),
            query_checks: super::read_shape::QueryChecks::default(),
            config,
            managed_issuer: None,
            host_root_issuer: issuer,
            policy_doors: Default::default(),
            account_keys: None,
            mcp_registry,
            mcp_code_host: None,
            reader_runner,
            live_runs,
            secret_destinations: Default::default(),
            model_budgets,
            cloud_registration,
            connector_elicitations: Arc::default(),
            browser_guest: None,
            browser_readiness: Default::default(),
            desktop_guest: None,
            desktop_seats: Arc::default(),
            browser_seats: Arc::default(),
            web_fetcher: std::sync::OnceLock::new(),
            memories_cursors,
            self_brief_sessions: Mutex::new(BTreeMap::new()),
            deep_retrieval: None,
            embedder: None,
            tagger: None,
            llm: None,
            decision_read: None,
            decision_reads,
            decisions,
            hook_runtime: std::sync::OnceLock::new(),
            #[cfg(feature = "mesh")]
            mesh_transport: std::sync::OnceLock::new(),
            builtin_handles: Arc::default(),
            #[cfg(unix)]
            organs: Arc::new(oneiron_organ_host::OrganHost::with_floor(
                oneiron_organ_host::HostConfig::default(),
                Arc::new(crate::machine::OrganFloor(memory.clone())),
            )),
            #[cfg(unix)]
            organ_dir: None,
            run_receipts,
            ai: crate::ai_host::AiHandle::inert(),
            pattern_launch_runner: None,
            rerank_runtime: Default::default(),
            // Engine 00:59 for parked L14: the configured queue wait bounds
            // admission, not a new timeout of its own.
            hyde_host: Arc::new(crate::server::recall_hyde::HydeHost::new(hyde_queue_wait)),
            extraction_egress: None,
            owner_host: None,
            feedback: None,
            feedback_triage: crate::config::FeedbackTriageConfig::default(),
            feedback_flood,
            artifact_port: None,
            artifact_socket: false,
            #[cfg(test)]
            booking_test_now_secs: None,
            #[cfg(test)]
            booking_test_clock_from: None,
        })
    }
}
