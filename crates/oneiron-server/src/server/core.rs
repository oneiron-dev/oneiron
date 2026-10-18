//! Core server state: the `SyncServer` struct, construction, and shared helpers.
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use loro::LoroDoc;
use oneiron::DreamerAttemptProgressProducer;
use oneiron::SyncEngineContext;
use oneiron::sync::bridge::{LiveQueryTee, Materializer};
use oneiron::sync::lease::ROOT_LEASES_MAP;
use oneiron::sync::schema::{
    add_window_to_root, init_window_list, read_window_list, schema_version_bytes,
};
use oneiron::sync::server_state;
use oneiron::sync::{EphemeralStore, WindowManager};
use tokio::sync::{Mutex, broadcast};

use crate::api::DeepRetrievalHost;
use crate::config::SyncServerConfig;
use crate::embedder::EmbedderSlot;
use crate::mcp::{McpConnectorActorRegistry, McpCredentialHashKey};
use crate::oneironer::TaggerSlot;
use crate::usage::UsageLedger;

use super::lifecycle::{LifecycleJobKey, NEXT_LIFECYCLE_SESSION_ID};
use super::windows::{SERVER_USER_ID, spawn_local_change_producer};

/// Internal fan-out. Recovery notices never become wire frames.
#[derive(Debug, Clone)]
pub(crate) enum BroadcastPayload {
    /// Sender zero denotes a local write; other senders use echo suppression.
    Frame(u32, Vec<u8>),
    /// Committed entity changes from Observer B, for local reads only.
    LocalDocs(Vec<oneiron::EntityId>),
    /// A producer lost notifications before they reached this channel.
    Resync { missed: u64 },
}

/// One host-resolved agent run and the prefix this session actually emitted.
/// The host advances the epoch only after a real fold; an HTTP request cannot.
pub(crate) struct HostSelfBriefSession {
    pub(crate) state: oneiron::context_board::SelfBriefState,
    pub(crate) render: oneiron::context_board::SelfBriefSession,
    pub(crate) epoch: u64,
    pub(crate) emitted_epoch: Option<u64>,
}

/// One piece of task work's turn on a vault ([`SyncServer::admit_task_work`]).
pub use oneiron::work_line::TaskWorkTurn;

/// Core sync server state shared across all connections.
pub struct SyncServer {
    pub(crate) vault: Arc<oneiron::Vault>,
    /// Root LoroDoc (server-authoritative, contains meta.windows).
    pub(crate) root_doc: LoroDoc,
    /// Hub-held Loro ephemeral state for late join/reconnect snapshots.
    pub(crate) ephemeral_store: Arc<EphemeralStore>,
    /// Producer state for Dreamer live attempt-progress rows on the ephemeral lane.
    pub(crate) dreamer_progress: Mutex<DreamerAttemptProgressProducer>,
    /// Node-local compiled standing blocks; rebuilt from claims, never synced.
    pub(crate) standing_block_cache: Mutex<oneiron::persona_snapshot::standing::StandingBlockCache>,
    /// Broadcast channel for fan-out to all connected clients.
    pub(crate) broadcast_tx: broadcast::Sender<BroadcastPayload>,
    /// Monotonic connection ID counter. 0 = reserved for bridge/local writes.
    pub(crate) next_conn_id: AtomicU32,
    /// Serializes lease-registry mutations (ONE-1140, OD-3): two concurrent
    /// connects racing the same client id must observe first-binding-wins,
    /// never a read-modify-write interleave.
    pub(crate) lease_registrar: Mutex<()>,
    /// Window manager used by server-side safe-point maintenance jobs.
    pub(crate) reassert_manager: Arc<WindowManager>,
    /// Keep the weakly attached Observer B local-read tee alive for this server.
    _reactive_tee: Arc<dyn LiveQueryTee>,
    /// Process-local session component for lifecycle job debounce keys.
    pub(super) lifecycle_session_id: u64,
    /// In-flight lifecycle jobs keyed by `(kind, vault_id, session_id)`.
    pub(super) lifecycle_in_flight: Mutex<HashSet<LifecycleJobKey>>,
    /// Housekeeping passes in flight, scheduled or asked for by the owner.
    pub(crate) housekeeping_passes: super::housekeeping::HousekeepingPasses,
    /// Server configuration.
    pub(crate) config: SyncServerConfig,
    /// Permits for git and LFS transfers, sized by `config.limits`.
    pub(crate) transfers: crate::api::Transfers,
    /// OF-520 questions retrieval queries past `config.limits` raised.
    pub(crate) query_checks: super::read_shape::QueryChecks,
    /// Set only by managed boot after inherited-credential and DEK checks.
    /// The supervisor authenticates callers before routing its private socket.
    pub(crate) managed_issuer: Option<oneiron::authority::HostSlipIssuer>,
    /// Node-side account API key verifier (OF-448), installed by a host
    /// that supplies the control-plane checker. `None`: account keys are
    /// never admitted.
    pub(crate) account_keys: Option<Arc<crate::auth::account_key::AccountKeys>>,
    /// Per-vault usage ledger over the server vault.
    pub(crate) usage_ledger: UsageLedger,
    /// Stable across served runs and policy refreshes; empty until the host grants.
    host_account: Arc<oneiron::llm::run_admission::HostAccount>,
    pub(crate) wire_telemetry: crate::wire_telemetry::WireTelemetry,
    /// The line app-tier state kept between frames is charged to, sized by
    /// `limits.retained_memory_bytes` (rule 5: charged, never capped).
    pub(crate) retained: Arc<crate::byte_line::ByteLine>,
    /// The presence hub's charge on `retained`.
    pub(crate) presence: Arc<super::presence::PresenceCharge>,
    /// The lens frames held for the cards this server rendered (OF-181), charged to `retained`.
    pub(crate) lens_frames: Arc<crate::lens_frames::LensFrameStore>,
    /// Process-local connector actor registry for the MCP gateway.
    pub(crate) mcp_registry: Mutex<McpConnectorActorRegistry>,
    /// Vault-owned production code host. No request can replace it.
    pub(crate) mcp_code_host: Option<Arc<dyn crate::mcp::McpCodeExecutionHost>>,
    /// Runs the reader children code runs spawn, on the code host once one
    /// is bound, and keeps their clock (ARCH-0079 #reader-forks).
    pub(crate) reader_runner: Arc<super::ReaderRunner>,
    /// The live agent runs a harness may act for over HTTP (OF-181): each
    /// runner's lease proof, its attached credential and its guard.
    pub(crate) live_runs: Arc<super::LiveRuns>,
    /// The `[browser]` guest each code run starts for its own browser verbs.
    /// `None` answers every browser call `browser_unbound`.
    pub(crate) browser_guest: Option<oneiron_browser::BrowserGuest>,
    /// The `[desktop]` guest each code run starts for its own desktop verbs.
    /// `None` answers every desktop call `browser_unbound`.
    pub(crate) desktop_guest: Option<oneiron_browser::DesktopGuest>,
    /// The run desktops bound now, for the owner's takeover (CUA-001).
    pub(crate) desktop_seats: Arc<super::DesktopSeats>,
    /// Actor/session read observations share the server lifetime, never a process global.
    pub(crate) memories_cursors: Mutex<crate::api::MemoriesCursorStore>,
    /// Host-resolved run briefs, keyed by authenticated actor and session.
    pub(crate) self_brief_sessions:
        Mutex<BTreeMap<(oneiron::EntityId, String), HostSelfBriefSession>>,
    /// ONE-207: the optional deep-retrieval host.
    ///
    /// `None` on every server [`SyncServer::new`] builds, and that is the
    /// shipped posture: this crate injects no backend, pins no model and mints
    /// no deep budget, exactly as the MCP endpoints bind no `execute_code`
    /// host. A `depth=deep` request against a `None` here is refused with
    /// `DEEP_RETRIEVAL_UNAVAILABLE` rather than quietly served at standard
    /// effort, so "deep" never names a read that was not deep.
    pub(crate) deep_retrieval: Option<Arc<DeepRetrievalHost>>,
    /// ONE-1979: the embedder slot, `None` at rung 0.
    ///
    /// Holds the resolved `[embedder]` section and, once the provider is
    /// serving, the provider itself. A slot is attached by the serve path after
    /// construction, the same way the deep-retrieval host is: `Self::new` pins
    /// no model and downloads nothing.
    pub(crate) embedder: Option<EmbedderSlot>,
    /// The `[oneironer]` tagger slot, `None` when no tagger is configured.
    /// Attached by the serve path after construction, like the embedder.
    pub(crate) tagger: Option<TaggerSlot>,
    /// The raw `/v1/llm` routes' models and meter; `None` turns them off.
    pub(crate) llm: Option<crate::models::RawInference>,
    /// The house model's decision read the owner probes at
    /// `/v1/llm/decision_read`, and the meter its reads are admitted on;
    /// `None` turns the route off.
    pub(crate) decision_read: Option<(crate::models::DecisionReadDoor, oneiron::BudgetGuard)>,
    /// Reads that route holds at once (`limits.decision_reads`).
    pub(crate) decision_reads: crate::admission::Admission<()>,
    /// The host's decision ladder: the rule table and the owner's ask queue
    /// on every server, with the rungs `[models]` binds once the AI host
    /// attaches.
    pub(crate) decisions: crate::decision_host::DecisionHost,
    /// The hook sandbox the fact-hook runner runs bodies on, set by `serve`
    /// once it loads; `vault.hooks.replay` replays on the same one. Empty
    /// under `--no-hooks`, or when the sandbox did not load.
    pub(crate) hook_runtime: std::sync::OnceLock<Arc<dyn oneiron::runtime_hooks::HookBodyRuntime>>,
    /// The checked built-in channels this host serves (OF-519), kept by
    /// `builtin_host::spawn` and read by their provider webhooks.
    pub(crate) builtin_handles: Arc<crate::builtin_host::BuiltinHandles>,
    /// This server's one organ host: the seal worker and the mesh
    /// listener's `oneiron/organ/1` share its budget and warm processes.
    #[cfg(unix)]
    pub(crate) organs: Arc<oneiron_organ_host::OrganHost>,
    /// Where the run admission of every model call writes its receipts.
    pub(crate) run_receipts: Arc<crate::models::ServerReceipts>,
    /// Model seats, background AI status and the Dreamer's session hints.
    /// Inert unless the serve path attaches a configured host.
    pub(crate) ai: crate::ai_host::AiHandle,
    /// Where rerank calls run when their door cannot drive them on its
    /// caller's runtime.
    pub(crate) rerank_runtime: super::recall_rerank::CallRuntime,
    /// Host-injected, request-by-request egress decision for nonlocal extraction.
    pub(crate) extraction_egress: Option<Arc<dyn oneiron::llm::ExtractionEgressPredicate>>,
    /// The vault's path, backup plan and schedule, set by `serve`. `None`
    /// on a server built without a known vault path.
    pub(crate) owner_host: Option<Arc<crate::owner::schedule::OwnerHost>>,
    /// Where the owner's feedback goes; `None` until configured.
    pub(crate) feedback: Option<Arc<crate::feedback_delivery::FeedbackHost>>,
    /// The open feedback inbox's flood cap, counted while the inbox is on.
    pub(crate) feedback_flood: crate::api::FloodCap,
    /// The port of the artifact-only listener on the API's host, set by the
    /// serve path once it is bound. `None` where none serves.
    artifact_port: Option<u16>,
    /// Managed serve's artifact origin on a unix socket of its own
    /// (`--artifact-http-socket`), which has no port to advertise.
    artifact_socket: bool,
    /// Instance-local booking clock override; production always reads wall time.
    #[cfg(test)]
    pub(crate) booking_test_now_secs: Option<u64>,
    /// With the override set, the runtime instant it holds from: the booking
    /// clock then moves with the runtime's (paused) time.
    #[cfg(test)]
    pub(crate) booking_test_clock_from: Option<tokio::time::Instant>,
}

/// Sets the vault's live rows from `[limits]` and points their crossings at
/// this server's questions.
fn live_rows(
    vault: &oneiron::Vault,
    limits: &crate::config::LimitsConfig,
    questions: &Arc<crate::wire_telemetry::LimitQuestions>,
) {
    use crate::wire_telemetry::LimitRow;
    use oneiron::live_rows::{LiveRow, LiveRows};
    vault.set_live_rows(LiveRows {
        message_streams: limits.message_streams,
        live_documents: limits.live_documents,
        wait: limits.queue_wait(),
    });
    let questions = Arc::clone(questions);
    vault.set_live_row_crossing(Some(Arc::new(move |row, bound, observed| {
        let row = match row {
            LiveRow::MessageStreams => LimitRow::MessageStreams,
            LiveRow::LiveDocuments => LimitRow::LiveDocuments,
        };
        questions.ask(row, bound, observed);
    })));
}

impl SyncServer {
    // ─── Device-lease registry (ONE-1140, OD-3) ──────────────────────────

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
        // Genuine host authority must exist before any scoped-read fail-closed
        // policy applies. Dev/no-secret and blind-relay modes mint nothing.
        // An empty configured secret mints nothing either: it carries no key
        // material, and every upgrade bearing it (or nothing) still 401s at
        // the auth door, so booting rootless here is fail-closed, not open.
        if let Some(secret) = host_root_secret(&vault, &config) {
            let issuer = oneiron::authority::HostSlipIssuer::from_secret(secret.as_bytes())?;
            vault.ensure_host_root_slip(&issuer)?;
            // The engine's MACHINE writers sign with host-held keys (ONE-1634).
            vault.provision_engine_machine_identities(&issuer)?;
        }

        let root_doc = match server_state::load_root_from_state(&vault)? {
            Some(doc) => doc,
            None => {
                let doc = LoroDoc::new();
                // Initialize root doc meta map
                let meta = doc.get_map("meta");
                // i64-LE BYTES (Loro Binary), conforming to the shared schema
                // (`schema::create_root_doc`) — NOT a Loro i64, which the
                // byte-only schema readers would not decode.
                meta.insert("schema_version", schema_version_bytes().as_slice())
                    .map_err(|e| {
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
        super::message_stream::spawn_message_stream_producer(
            &vault,
            &ephemeral_store,
            &presence,
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
        let decision_reads = crate::admission::Admission::new(
            crate::wire_telemetry::LimitRow::DecisionReads,
            Arc::clone(wire_telemetry.limit_questions()),
            config.limits.decision_reads,
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
        Ok(Self {
            lens_frames,
            retained,
            presence,
            usage_ledger: UsageLedger::new(vault.clone()),
            host_account: oneiron::llm::run_admission::HostAccount::new(),
            transfers: crate::api::Transfers::new(
                &config.limits,
                Arc::clone(wire_telemetry.limit_questions()),
                &vault,
            )?,
            wire_telemetry,
            vault,
            root_doc,
            ephemeral_store,
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
            account_keys: None,
            mcp_registry,
            mcp_code_host: None,
            reader_runner,
            live_runs,
            browser_guest: None,
            desktop_guest: None,
            desktop_seats: Arc::default(),
            memories_cursors: Mutex::new(crate::api::MemoriesCursorStore::default()),
            self_brief_sessions: Mutex::new(BTreeMap::new()),
            deep_retrieval: None,
            embedder: None,
            tagger: None,
            llm: None,
            decision_read: None,
            decision_reads,
            decisions,
            hook_runtime: std::sync::OnceLock::new(),
            builtin_handles: Arc::default(),
            #[cfg(unix)]
            organs: Arc::new(oneiron_organ_host::OrganHost::new(
                oneiron_organ_host::HostConfig::default(),
            )),
            run_receipts,
            ai: crate::ai_host::AiHandle::inert(),
            rerank_runtime: Default::default(),
            extraction_egress: None,
            owner_host: None,
            feedback: None,
            feedback_flood,
            artifact_port: None,
            artifact_socket: false,
            #[cfg(test)]
            booking_test_now_secs: None,
            #[cfg(test)]
            booking_test_clock_from: None,
        })
    }

    /// Install an already resolved run snapshot from the trusted host. The
    /// HTTP request never supplies scope, class verdicts, or budget. Advancing
    /// `epoch` happens only when the host has completed a real fold.
    pub async fn install_self_brief_session(
        &self,
        actor: oneiron::EntityId,
        session_id: String,
        epoch: u64,
        state: oneiron::context_board::SelfBriefState,
    ) -> oneiron::Result<()> {
        if state.self_ref != actor || session_id.is_empty() || session_id.len() > 256 {
            return Err(oneiron::Error::InvariantViolation(
                "self brief actor or session mismatch",
            ));
        }
        let mut runs = self.self_brief_sessions.lock().await;
        let entry = runs
            .entry((actor, session_id))
            .or_insert_with(|| HostSelfBriefSession {
                state: state.clone(),
                render: oneiron::context_board::SelfBriefSession::default(),
                epoch,
                emitted_epoch: None,
            });
        if epoch < entry.epoch {
            return Err(oneiron::Error::InvariantViolation("stale self brief epoch"));
        }
        entry.state = state;
        entry.epoch = epoch;
        Ok(())
    }

    /// Bind a readiness-verified QuickJS provider before exposing this vault's
    /// routes, running at most `runs` at once. Missing components or providers
    /// keep execute_code unadvertised.
    #[cfg(feature = "code-sandbox-wasmtime")]
    #[must_use]
    pub fn with_mcp_quickjs_provider(
        mut self,
        provider: crate::mcp::McpQuickJsProvider,
        runs: crate::mcp::CodeRunLimits,
    ) -> Self {
        let provider = provider.with_run_receipts(self.run_receipts());
        let host: Arc<dyn crate::mcp::McpCodeExecutionHost> = Arc::new(
            crate::mcp::McpEngineNativeCodeHost::new(
                Arc::new(provider),
                runs,
                Arc::clone(self.wire_telemetry.limit_questions()),
            )
            .with_reader_seats(self.reader_runner.seats()),
        );
        // Reader children run on the same provider and pool.
        self.reader_runner.bind_host(Arc::clone(&host));
        self.mcp_code_host = Some(host);
        self
    }

    /// Installs the node-side account API key verifier a host built
    /// around its control-plane checker (OF-448). Without one, no account
    /// key is ever admitted.
    #[must_use]
    pub fn with_account_keys(
        mut self,
        keys: Option<Arc<crate::managed::key_sync::AccountKeys>>,
    ) -> Self {
        self.account_keys = keys;
        self
    }

    /// Gives code runs a browser guest, from the `[browser]` section.
    #[must_use]
    pub fn with_browser_guest(mut self, guest: Option<oneiron_browser::BrowserGuest>) -> Self {
        self.browser_guest = guest;
        self
    }

    pub(crate) fn browser_guest(&self) -> Option<&oneiron_browser::BrowserGuest> {
        self.browser_guest.as_ref()
    }

    /// Gives code runs a desktop guest, from the `[desktop]` section.
    #[must_use]
    pub fn with_desktop_guest(mut self, guest: Option<oneiron_browser::DesktopGuest>) -> Self {
        self.desktop_guest = guest;
        self
    }

    pub(crate) fn desktop_guest(&self) -> Option<&oneiron_browser::DesktopGuest> {
        self.desktop_guest.as_ref()
    }

    pub(crate) fn code_execution_host(&self) -> Option<&Arc<dyn crate::mcp::McpCodeExecutionHost>> {
        self.mcp_code_host
            .as_ref()
            .filter(|host| host.production_runtime_available())
    }

    pub(crate) fn mcp_surface(
        &self,
        mode: crate::mcp::McpSurfaceMode,
    ) -> crate::mcp::McpRegisteredSurface {
        crate::mcp::McpRegisteredSurface::register_with_execution(
            mode,
            self.code_execution_host().is_some(),
        )
        .expect("every exported verb projects onto an executable tool")
    }

    /// Attaches the ONE-207 deep-retrieval host.
    ///
    /// Crate-visible on purpose: the host carries a `BudgetGuard`, so wiring
    /// one is a spend decision, and this release exposes no public seam for
    /// making it. Tests take this door; production servers keep the `None`
    /// [`Self::new`] builds until a hosted binding lands with its own ticket.
    #[allow(dead_code)] // No in-tree production host yet; the tests are its only caller.
    pub(crate) fn with_deep_retrieval_host(mut self, host: Arc<DeepRetrievalHost>) -> Self {
        self.deep_retrieval = Some(host);
        self
    }

    /// Enables owner-authenticated raw inference with a host-owned backend and budget.
    /// Remote lease IDs are correlation only; each call needs local admission.
    ///
    /// Each call is admitted as a run on `budget` and sent through the run's
    /// gate, which wraps only a backend that sends one request per call, so
    /// `backend` is a [`oneiron::llm::SingleRouteBackend`]: a ladder or a
    /// retrying backend cannot be injected below the gate.
    pub fn with_llm_backend(
        mut self,
        backend: Arc<dyn oneiron::llm::SingleRouteBackend>,
        budget: oneiron::BudgetGuard,
    ) -> Self {
        self.llm = Some(crate::models::RawInference::injected(backend, budget));
        self
    }

    /// Serves `door` at `/v1/llm/decision_read`, each read admitted as a run
    /// on `meter`.
    #[must_use]
    pub fn with_decision_read(
        mut self,
        door: crate::models::DecisionReadDoor,
        meter: oneiron::BudgetGuard,
    ) -> Self {
        self.decision_read = Some((door, meter));
        self.decisions = self
            .decisions
            .clone()
            .with_house_read(self.decision_read.as_ref(), self.house_read_admission());
        self
    }

    /// What admits the ladder's house reads: this server's decision-read
    /// pool, host account and run receipts.
    fn house_read_admission(&self) -> crate::decision_host::ReadAdmission {
        crate::decision_host::ReadAdmission {
            turns: self.decision_reads.clone(),
            host: self.host_account(),
            receipts: self.run_receipts(),
        }
    }

    /// The live allocation shared by all this vault's served runs. The
    /// trusted host grants newer generations and updates holds on this same
    /// account; admitted work keeps the allocation it already reserved.
    #[must_use]
    pub fn host_account(&self) -> Arc<oneiron::llm::run_admission::HostAccount> {
        Arc::clone(&self.host_account)
    }

    /// Enables durable usage facts for the owner the trusted host resolved.
    /// The vault id comes from the authority log, never an HTTP payload.
    /// Bind before starting work so every admission has attribution.
    pub fn with_usage_metering(
        self,
        owner: impl Into<String>,
    ) -> Result<Self, crate::usage::UsageError> {
        let vault_id = self.vault.authority_fold()?.vault_id.ok_or(
            crate::usage::UsageError::InvalidField {
                field: "vaultId",
                message: "usage metering requires an authority-log genesis",
            },
        )?;
        let vault_id = vault_id.iter().map(|byte| format!("{byte:02x}")).collect();
        let usage =
            crate::runtime::VaultUsage::new(self.usage_ledger.clone(), owner.into(), vault_id)?;
        self.run_receipts.meter(usage);
        Ok(self)
    }

    #[must_use]
    pub fn vault_usage(&self) -> Option<Arc<crate::runtime::VaultUsage>> {
        self.run_receipts.usage()
    }

    /// Writes every model call's run receipts to `receipts` instead of the
    /// log, including the calls of models and providers attached before.
    #[must_use]
    pub fn with_run_receipts(
        self,
        receipts: Arc<dyn oneiron::llm::run_admission::RunReceiptSink>,
    ) -> Self {
        self.run_receipts.choose(receipts);
        self
    }

    pub(crate) fn run_receipts(&self) -> Arc<dyn oneiron::llm::run_admission::RunReceiptSink> {
        self.run_receipts.clone()
    }

    /// Attaches the AI host's handle. When `[models]` configured any model,
    /// the raw `/v1/llm` routes get its router and their own meter: the
    /// config is the host injection `with_llm_backend` names.
    #[must_use]
    pub fn with_ai(mut self, ai: crate::ai_host::AiHandle) -> Self {
        if let Some(raw) = ai.raw_inference() {
            self.llm = Some(raw);
        }
        // Its reads go on the raw routes' meter.
        if let (Some(door), Some(raw)) = (ai.decision_read(), &self.llm) {
            self.decision_read = Some((door, raw.meter().clone()));
        }
        // The house read fills the ladder's escalation rung.
        self.decisions = self
            .decisions
            .clone()
            .with_house_read(self.decision_read.as_ref(), self.house_read_admission());
        self.ai = ai;
        self
    }

    /// Whether boot rooted this vault and provisioned the engine's machine
    /// writers (the Dreamer among them).
    pub(crate) fn host_root_provisioned(&self) -> bool {
        host_root_secret(&self.vault, &self.config).is_some()
    }

    /// Install the host's extraction egress predicate. An absent predicate
    /// refuses nonlocal extraction rather than trusting an editable default.
    pub fn with_extraction_egress(
        mut self,
        predicate: Arc<dyn oneiron::llm::ExtractionEgressPredicate>,
    ) -> Self {
        self.extraction_egress = Some(predicate);
        self
    }

    /// Attaches the embedder slot resolved from configuration.
    ///
    /// Separate from [`Self::new`] because an embedder is a model decision and
    /// a possible download: a server built without one runs at rung 0 forever,
    /// which is what every deployment did before this ticket.
    pub(crate) fn with_embedder(mut self, embedder: Option<EmbedderSlot>) -> Self {
        self.embedder = embedder;
        self
    }

    /// Attaches the tagger slot resolved from configuration. Its worker
    /// drains the tagging markers every witnessed turn commits.
    pub(crate) fn with_tagger(mut self, tagger: Option<TaggerSlot>) -> Self {
        self.tagger = tagger;
        self
    }

    pub(crate) fn with_owner_host(mut self, host: crate::owner::schedule::OwnerHost) -> Self {
        self.owner_host = Some(Arc::new(host));
        self
    }

    pub(crate) fn with_feedback(
        mut self,
        host: Option<crate::feedback_delivery::FeedbackHost>,
    ) -> Self {
        self.feedback = host.map(Arc::new);
        self
    }

    /// Records that the artifact-only router ([`crate::build_artifact_app`])
    /// serves this server's `/a/` on `port` of the API's host. Health then
    /// advertises the port, and the API's own `/a/` sandboxes code bundles,
    /// whose scripts would otherwise run on the API's origin.
    #[must_use]
    pub fn with_artifact_listener(mut self, port: u16) -> Self {
        self.artifact_port = Some(port);
        self
    }

    pub(crate) fn artifact_port(&self) -> Option<u16> {
        self.artifact_port
    }

    /// Records that the artifact-only router serves this server's `/a/` on a
    /// unix socket of its own (managed serve, OF-356). As with a port, the
    /// API's own `/a/` then sandboxes code bundles.
    #[must_use]
    pub fn with_artifact_socket(mut self) -> Self {
        self.artifact_socket = true;
        self
    }

    /// Whether an artifact-only listener serves this server's `/a/` on an
    /// origin apart from the API's.
    pub(crate) fn has_artifact_origin(&self) -> bool {
        self.artifact_port.is_some() || self.artifact_socket
    }

    /// Returns the vault backing this server (used by integration tests to
    /// assert sync_state durability).
    pub fn vault(&self) -> &Arc<oneiron::Vault> {
        &self.vault
    }

    /// `caller`'s turn to run one piece of task work on this vault (`can`,
    /// `ask`, `wait`, `tasks.answer`; Rule 5), in the vault's own line
    /// ([`oneiron::Vault::admit_task_work`]): at once while fewer than
    /// `limits.task_work` run, else in a fair line, one caller's work after
    /// another's, each caller's oldest first. Crossing the bound asks its
    /// OF-520 question. Work is never refused: past `queue_wait_timeout_ms`
    /// it runs without a turn. Hold the turn until the work ends; take it
    /// before the engine opens a transaction.
    pub async fn admit_task_work(&self, caller: oneiron::EntityId) -> TaskWorkTurn {
        self.vault.admit_task_work(caller).await
    }

    /// Allocates a new unique nonzero connection ID.
    ///
    /// `conn_id = 0` is reserved as the bridge/local-broadcast sender
    /// sentinel; a real connection returning 0 would silently bypass echo
    /// suppression. `fetch_update` skips 0 on wraparound.
    pub(crate) fn alloc_conn_id(&self) -> u32 {
        self.next_conn_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                let next = current.wrapping_add(1);
                Some(if next == 0 { 1 } else { next })
            })
            .expect("fetch_update closure always returns Some")
    }
}

/// Genuine host authority exists only off the relay posture and with a
/// non-empty configured secret. Dev/no-secret and blind-relay modes mint
/// nothing.
fn host_root_secret<'c>(vault: &oneiron::Vault, config: &'c SyncServerConfig) -> Option<&'c str> {
    if vault.privacy_posture() == oneiron::HostingPrivacyPosture::Relay {
        return None;
    }
    config
        .auth_secret
        .as_deref()
        .filter(|secret| !secret.is_empty())
}

fn mcp_registry_hash_key(config: &SyncServerConfig) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron-server:mcp-connector-registry:v1");
    if let Some(secret) = config.auth_secret.as_deref() {
        hasher.update(secret.as_bytes());
    } else if config.allow_unauthenticated {
        hasher.update(b"unauthenticated-dev");
    } else {
        hasher.update(b"no-auth-secret-configured");
    }
    *hasher.finalize().as_bytes()
}

/// Wall-clock Unix seconds, saturating to 0 pre-epoch (matches the
/// client-side SystemTime uses).
pub(super) fn unix_seconds_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
