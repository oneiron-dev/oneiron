//! Managed runtime state, the reap freeze gate, and the supervised serve loop.

use std::future::Future;
use std::io::ErrorKind;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use axum::Json;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode, header::UPGRADE};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use oneiron_vault_contract::ManagedWidenAction;
use oneiron_vault_contract::{
    CONTRACT_VERSION, CtlRequest, CtlResponse, UnixTs, now_ts, validate_wake_entries,
};
use tokio::sync::{Mutex, watch};

use crate::build_app;
use crate::config::ServeArgs;
use crate::server::SyncServer;

use super::args::{ManagedArgs, ManagedError};
use super::ledger::{SYNC_UPGRADE_SETTLE_SECS, WakeLedger};
use super::listener::{BoundServeListener, ManagedCtl, ServeListener, init_managed_tracing};
use super::vault_gates::{open_managed_vault, provision_host_authority};
use oneiron_vault_contract::host::{Host, HostLimits};

/// Machine-readable tag on the refusals a frozen engine serves, so a client can
/// match on it rather than parse prose.
///
/// [`ManagedError::WritesFrozen`] is the only thing that emits it. That is what
/// keeps "the reap freeze refused this" distinguishable from every other way
/// this surface can be briefly unavailable — a 503 without the tag is a
/// different outage and means a different response from the caller.
pub const WRITES_FROZEN_TAG: &str = "writes_frozen";

/// An alarm the supervisor pushed, as the reconciler hook saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedAlarm {
    pub id: String,
    pub reason_tag: String,
    pub at: UnixTs,
}

/// A future that resolves when managed shutdown has been tripped.
pub type ShutdownSignal = std::pin::Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Cooperative shutdown for managed mode.
///
/// A `watch` rather than a broadcast on purpose: a task that subscribes after
/// the trigger still observes it, so a late-spawned listener cannot miss the
/// edge and keep serving past SIGTERM.
#[derive(Debug, Clone)]
pub struct ManagedShutdown(watch::Sender<bool>);

impl ManagedShutdown {
    pub fn new() -> Self {
        Self(watch::channel(false).0)
    }

    /// Trips shutdown. Idempotent — a second SIGTERM changes nothing.
    ///
    /// `send_replace` rather than `send`: `send` refuses once every receiver
    /// has been dropped and leaves the value untouched, which would silently
    /// lose a trigger that arrived before anything subscribed.
    pub fn trigger(&self) {
        let _ = self.0.send_replace(true);
    }

    pub fn is_triggered(&self) -> bool {
        *self.0.borrow()
    }

    /// Resolves once shutdown has been tripped, including when it was tripped
    /// before this future was created.
    ///
    /// Boxed so it is plainly `'static` and detached from the handle it came
    /// from: callers hand it to `axum`'s graceful shutdown and to spawned
    /// tasks, both of which outlive the borrow.
    pub fn triggered(&self) -> ShutdownSignal {
        let mut rx = self.0.subscribe();
        Box::pin(async move {
            loop {
                if *rx.borrow_and_update() {
                    return;
                }
                if rx.changed().await.is_err() {
                    // Every sender is gone, which can only mean the process is
                    // on its way out. Treat it as tripped rather than parking
                    // forever.
                    return;
                }
            }
        })
    }
}

impl Default for ManagedShutdown {
    fn default() -> Self {
        Self::new()
    }
}

/// Installs the managed-mode SIGTERM handler.
///
/// Only ever called in managed mode: an unmanaged serve keeps the default
/// disposition, so its SIGTERM behaviour is untouched.
pub fn spawn_sigterm_shutdown(shutdown: ManagedShutdown) -> Result<(), ManagedError> {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::spawn(async move {
        if sigterm.recv().await.is_some() {
            tracing::info!("SIGTERM received; starting managed quiesce");
            shutdown.trigger();
        }
    });
    Ok(())
}

/// Everything a ctl verb can reach: the reap freeze, the alarm reconciler
/// hook, and the wake ledger.
pub struct ManagedState {
    vault_name: String,
    server: Arc<SyncServer>,
    frozen: AtomicBool,
    http_mutating_in_flight: AtomicU64,
    /// Unix seconds of the most recent sync upgrade the freeze gate admitted,
    /// or 0 if none. The handshake is the last thing that gate ever sees of a
    /// sync session, so this stamp is the only record that one exists.
    last_sync_upgrade: AtomicU64,
    alarms: Mutex<Vec<ObservedAlarm>>,
    ledger: WakeLedger,
}

/// A supervisor-signed account action, not the child process's host-root slip.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ManagedWidenHolder(pub(crate) oneiron::EntityId);

struct HttpMutation(Arc<ManagedState>);

impl Drop for HttpMutation {
    fn drop(&mut self) {
        self.0
            .http_mutating_in_flight
            .fetch_sub(1, Ordering::SeqCst);
    }
}

impl std::fmt::Debug for ManagedState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedState")
            .field("vault_name", &self.vault_name)
            .field("frozen", &self.is_frozen())
            .field("ledger", &self.ledger)
            .finish_non_exhaustive()
    }
}

impl ManagedState {
    pub fn new(vault_name: String, server: Arc<SyncServer>, ledger: WakeLedger) -> Self {
        Self {
            vault_name,
            server,
            frozen: AtomicBool::new(false),
            http_mutating_in_flight: AtomicU64::new(0),
            last_sync_upgrade: AtomicU64::new(0),
            alarms: Mutex::new(Vec::new()),
            ledger,
        }
    }

    fn admit_http_mutation(self: &Arc<Self>) -> Result<HttpMutation, ManagedError> {
        // Increment BEFORE checking freeze. A concurrent freeze must either see
        // this writer or make this admission fail; check-then-increment races.
        self.http_mutating_in_flight.fetch_add(1, Ordering::SeqCst);
        let admission = HttpMutation(Arc::clone(self));
        self.guard_write()?;
        Ok(admission)
    }

    pub fn vault_name(&self) -> &str {
        &self.vault_name
    }

    pub fn ledger(&self) -> &WakeLedger {
        &self.ledger
    }

    pub fn is_frozen(&self) -> bool {
        self.frozen.load(Ordering::SeqCst)
    }

    pub fn freeze(&self) -> Result<(), ManagedError> {
        self.frozen.store(true, Ordering::SeqCst);
        self.server
            .wire_telemetry
            .freeze_and_flush()
            .map_err(|error| ManagedError::VaultMeta(error.to_string()))
    }

    /// Lifts the process-local freeze on `reap_abort`. A new process starts
    /// unfrozen; shutdown must not reactivate observation writes.
    pub fn unfreeze(&self) -> Result<(), ManagedError> {
        self.server
            .wire_telemetry
            .unfreeze()
            .map_err(|error| ManagedError::VaultMeta(error.to_string()))?;
        self.frozen.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// The write gate a frozen vault refuses at. Typed, so a caller can tell
    /// "frozen for reap" from a storage failure and retry rather than
    /// surface an error to a user.
    pub fn guard_write(&self) -> Result<(), ManagedError> {
        if self.is_frozen() {
            return Err(ManagedError::WritesFrozen);
        }
        Ok(())
    }

    /// Records a sync upgrade the freeze gate let through.
    ///
    /// Called on the handshake and nowhere else, because the handshake is the
    /// last moment a per-request gate can see this session at all: what
    /// follows is frames on a socket, and no middleware runs over those.
    pub fn admit_sync_upgrade(&self) {
        self.last_sync_upgrade.store(now_ts(), Ordering::SeqCst);
    }

    /// Whether a sync session that upgraded before the freeze could still
    /// commit a durable write.
    ///
    /// Two ways one can be live, and quiescence has to answer for both. A
    /// session past its protocol hello holds a broadcast receiver for as long
    /// as it runs, and it subscribes before it can import a single update, so
    /// the receiver count covers every session that is able to write. A
    /// session that upgraded and has not spoken yet holds nothing to count, so
    /// a 15-second settle window (the protocol hello deadline plus margin)
    /// covers that blind window instead.
    ///
    /// Fail-closed on both halves: an upgrade that was refused after this gate
    /// (401, no such route) still counts for the settle window, and a clock
    /// that steps backwards reads as live rather than as settled.
    pub fn live_sync_writer(&self) -> bool {
        // Crate-internal on purpose: the receiver count is the only liveness
        // signal a session leaves outside its own task, and adding a second
        // registry to `SyncServer` would put the same fact in two places.
        if self.server.broadcast_tx.receiver_count() > 0 {
            return true;
        }
        let admitted = self.last_sync_upgrade.load(Ordering::SeqCst);
        admitted != 0 && now_ts().saturating_sub(admitted) < SYNC_UPGRADE_SETTLE_SECS
    }

    /// The reconciler hook `alarm_due` reaches.
    pub async fn record_alarm(&self, id: String, reason_tag: String) {
        self.alarms.lock().await.push(ObservedAlarm {
            id,
            reason_tag,
            at: now_ts(),
        });
    }

    pub async fn observed_alarms(&self) -> Vec<ObservedAlarm> {
        self.alarms.lock().await.clone()
    }

    /// Dispatches one parsed ctl request.
    ///
    /// [`CtlRequest::validate`] runs first on every request: deserialization
    /// alone does not enforce the wire limits, so an `alarm_due` carrying an
    /// out-of-bounds id or reason tag is refused here rather than reaching the
    /// reconciler.
    pub async fn handle_request(&self, request: CtlRequest) -> Result<CtlResponse, ManagedError> {
        request
            .validate()
            .map_err(|error| ManagedError::CtlRequestRefused {
                reason: error.to_string(),
            })?;
        match request {
            CtlRequest::Ping => Ok(CtlResponse::Ping {
                ok: true,
                vault: self.vault_name.clone(),
                pid: std::process::id(),
                contract_version: CONTRACT_VERSION,
            }),
            CtlRequest::Shed { cause, waited_secs } => {
                self.guard_write()?;
                super::shed::shed(self.server.vault(), cause, waited_secs)
            }
            CtlRequest::PrepareReap => self.prepare_reap().await,
            CtlRequest::ReapAbort => {
                self.unfreeze()?;
                Ok(CtlResponse::Ok { ok: true })
            }
            CtlRequest::AlarmDue { id, reason_tag } => {
                self.record_alarm(id, reason_tag).await;
                Ok(CtlResponse::Ok { ok: true })
            }
        }
    }

    /// Freeze, drain, export — in that order.
    ///
    /// The freeze goes first so nothing new enters the lease table while it is
    /// being drained, and the export runs last so the entries the supervisor
    /// gets describe the quiesced state rather than the one before it.
    ///
    /// `quiescent` needs a third answer beyond "frozen" and "drained": the
    /// freeze refuses new requests and new upgrades, but a sync session
    /// upgraded before it rides past every per-request gate and can still
    /// commit. `PrepareReap` is not shutdown and closes nothing, so while one
    /// of those may be live this reports `false` and the supervisor reaps
    /// later rather than over a live writer.
    async fn prepare_reap(&self) -> Result<CtlResponse, ManagedError> {
        self.freeze()?;
        // Check BEFORE drain/export. A writer finishing after export must not
        // turn a stale exported ledger into a quiescent reply.
        let http_drained = self.http_mutating_in_flight.load(Ordering::SeqCst) == 0;
        let drained = self.drain_lease_table().await;
        let (ledger_rev, next_wake) = self.ledger.export_at_freeze(&self.server).await?;
        // The reply carries the entries, so they are bounds-checked before
        // they are serialized rather than after a supervisor has trusted them.
        validate_wake_entries(&next_wake).map_err(|error| ManagedError::LedgerRefused {
            reason: error.to_string(),
        })?;
        Ok(CtlResponse::PrepareReap {
            quiescent: http_drained && drained && self.is_frozen() && !self.live_sync_writer(),
            ledger_rev,
            next_wake,
        })
    }

    /// Runs the lease table to completion once. A skipped run means a previous
    /// sweep is still in flight, which is exactly "not yet quiescent".
    async fn drain_lease_table(&self) -> bool {
        match self.server.expire_leases_once().await {
            Ok(report) => !report.skipped,
            Err(error) => {
                tracing::error!(kind = ?error.kind(), "lease table drain failed during prepare_reap");
                false
            }
        }
    }
}

/// Builds the surface managed mode serves: the ordinary app, behind the reap
/// freeze.
///
/// The gate is a layer over the whole router rather than a call inside each
/// write handler, and that placement is the fail-closed half of it. It sits
/// ahead of routing, so a write route added next year, a method this build does
/// not recognise, and a request that matches no route at all are all refused
/// while frozen without anyone having to remember this module exists. Nothing
/// can be let through by forgetting to call [`ManagedState::guard_write`],
/// because no handler is where the calling happens.
///
/// Only managed mode builds this. [`crate::build_app`] is untouched, so an
/// unmanaged serve carries no extra layer and behaves exactly as it did.
pub fn build_managed_app(server: Arc<SyncServer>, state: Arc<ManagedState>) -> Router {
    let freeze = middleware::from_fn_with_state(state, refuse_frozen_writes);
    build_app(server).layer(freeze)
}

/// The managed artifact origin: this vault's `/a/`, and its names under the
/// artifact domains (`oneiron_vault_contract::artifact_origin`), behind the
/// same freeze gate as the API socket.
pub(super) fn build_managed_artifact_app(
    server: Arc<SyncServer>,
    state: Arc<ManagedState>,
) -> Router {
    let freeze = middleware::from_fn_with_state(state, refuse_frozen_writes);
    crate::build_artifact_app(server).layer(freeze)
}

/// The freeze gate on the served path.
///
/// Consulted per request, before the handler runs: once `prepare_reap` has
/// flipped the flag, anything that could mutate the vault is answered with the
/// typed refusal instead of reaching storage. That is what turns
/// `quiescent: true` from an advisory into something a supervisor can reap
/// against — without it the engine keeps committing durable writes after
/// reporting that it stopped.
///
/// Admitted mutations keep a guard through extraction and handler completion.
/// Upgrades also leave a sync-session stamp: their subsequent frames do not
/// pass through HTTP middleware.
async fn refuse_frozen_writes(
    State(state): State<Arc<ManagedState>>,
    mut request: Request,
    next: Next,
) -> Response {
    if state.server.managed_issuer.is_some() {
        // This one route needs the SUPERVISOR'S holder action, not the host
        // root. Verify the account-authenticated assertion against the
        // per-spawn secret and the exact request body before removing every
        // forwarded credential. Unverified headers never become extensions.
        if request.method() == Method::POST
            && request.uri().path() == "/v1/core/consent/widen/accept"
        {
            let assertion = request
                .headers()
                .get("x-oneiron-managed-widen-action")
                .and_then(|value| value.to_str().ok())
                .and_then(|text| serde_json::from_str::<ManagedWidenAction>(text).ok());
            if let Some(assertion) = assertion {
                let (parts, body) = request.into_parts();
                let Ok(bytes) = to_bytes(body, 2 * 1024 * 1024).await else {
                    return StatusCode::PAYLOAD_TOO_LARGE.into_response();
                };
                request = Request::from_parts(parts, Body::from(bytes.clone()));
                if state.ledger.verify_widen_action(&assertion, &bytes)
                    && let Ok(holder) = oneiron::EntityId::from_hex(&assertion.holder_ref)
                {
                    request.extensions_mut().insert(ManagedWidenHolder(holder));
                }
            }
        }
        request
            .headers_mut()
            .remove("x-oneiron-managed-widen-action");
        // Bearer authentication terminated at the supervisor. Do not let a
        // forwarded legacy/dev claim select a principal on secondary routes.
        for header in [
            "authorization",
            "x-oneiron-binding",
            "x-oneiron-mcp-credential",
        ] {
            request.headers_mut().remove(header);
        }
    }
    if is_read_only(&request) {
        return run_admitted_request(state, request, next).await;
    }
    let admission = match state.admit_http_mutation() {
        Ok(admission) => admission,
        Err(error) => return writes_frozen_response(&error),
    };
    // A dropped response waiter must not release admission while a handler's
    // spawn_blocking write is still running. The owned task finishes the handler.
    tokio::spawn(async move {
        let _admission = admission;
        run_admitted_request(state, request, next).await
    })
    .await
    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn run_admitted_request(state: Arc<ManagedState>, request: Request, next: Next) -> Response {
    if request.headers().contains_key(UPGRADE) {
        // Admitted, and out of sight from here on. A freeze with one of these
        // behind it is not quiescent, and `prepare_reap` is where that is
        // answered for — this gate cannot refuse a frame it never sees.
        state.admit_sync_upgrade();
    }
    if let Err(error) = state.server.vault().resume_from_slim_on_inbound() {
        return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
    }
    next.run(request).await
}

/// Whether a frozen vault may still answer this request.
///
/// A whitelist, so the failure direction is refusal: a method this build does
/// not recognise reads as a write rather than getting waved through. The
/// upgrade check is the other half — a WebSocket handshake is a `GET`, but what
/// it opens is a bidirectional sync session whose updates ride past every
/// per-request gate, so a frozen engine refuses the handshake rather than
/// frames it has no way to inspect.
///
/// The method is deliberately the whole test. Several reads on this surface are
/// `POST` (query, hydrate, context-pack) and a frozen engine refuses those too;
/// a path list that spared them would be one rename away from sparing a write,
/// and this window is the few seconds before a reap.
fn is_read_only(request: &Request) -> bool {
    if request.headers().contains_key(UPGRADE) {
        return false;
    }
    let method = request.method();
    *method == Method::GET || *method == Method::HEAD || *method == Method::OPTIONS
}

/// Renders the typed refusal for the wire.
///
/// The message is the error's own `Display`, so the served refusal and the
/// object-level one cannot drift apart. 503 because the refusal is temporary by
/// construction: `reap_abort` lifts it and the same request succeeds.
fn writes_frozen_response(error: &ManagedError) -> Response {
    let body = serde_json::json!({
        "error": WRITES_FROZEN_TAG,
        "message": error.to_string(),
    });
    (StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response()
}

/// Seals the vault's held data key to the node's managed escrow recipient
/// and the owner's break-glass recipient, each named by the supervisor.
/// A wrap is labelled by its recipient's fingerprint, so a restart adds
/// nothing, and a recipient of a new epoch gets a wrap of its own.
fn escrow_vault_key(vault: &oneiron::Vault, managed: &ManagedArgs) -> anyhow::Result<()> {
    let present = vault.vault_key_wraps()?;
    for (role, path) in [
        ("managed", &managed.escrow_recipient),
        ("break-glass", &managed.break_glass_recipient),
    ] {
        let Some(path) = path else {
            continue;
        };
        let bytes = std::fs::read(path)
            .map_err(|error| anyhow::anyhow!("{role} escrow recipient unreadable: {error}"))?;
        let recipient = oneiron::world_keys::HybridPublicKey::from_bytes(&bytes)
            .map_err(|_| anyhow::anyhow!("{role} escrow recipient is not a hybrid public key"))?;
        let fingerprint = blake3::hash(&bytes);
        let label = format!("{role}.{}", &fingerprint.to_hex()[..16]);
        let sealed = present.iter().any(|wrap| {
            matches!(&wrap.kind, oneiron::world_keys::VaultKeyWrapKind::Escrow { label: held } if *held == label)
        });
        if !sealed {
            vault.add_vault_key_escrow(&label, &recipient)?;
        }
    }
    Ok(())
}

/// The page seal a managed vault opens with (OF-570 maximum tier), from the
/// data key its supervisor delivered: a sealed vault's, reopened from the
/// mirror beside it; a new one where no vault is yet and `--maximum-tier`
/// opted in; none for a plain vault, which stays plain (no converter).
fn managed_page_seal(
    managed: &ManagedArgs,
    dek: &[u8; 32],
) -> anyhow::Result<Option<oneiron::VaultPageSeal>> {
    let path = &managed.data_dir;
    if oneiron::world_keys::vault_is_sealed(path)? {
        return Ok(Some(oneiron::world_keys::reopen_delivered_page_seal(
            path, dek,
        )?));
    }
    if !managed.maximum_tier {
        return Ok(None);
    }
    if path.join("data.mdb").exists() {
        tracing::warn!(
            "--maximum-tier is chosen when a vault is created; this plain vault opens plain"
        );
        return Ok(None);
    }
    Ok(Some(oneiron::world_keys::new_delivered_page_seal(
        path, dek,
    )?))
}

/// Hands each escrow capsule the outbox does not hold yet to the outbox the
/// supervisor named (CROSS-ARCH-0022 #ov-custody, invariant 03): the report
/// is written durably first and marked in the vault after, so a crash
/// between the two writes the same report again. The node ships it and
/// removes it only after the registry's durable acknowledgement. A capsule
/// that cannot be spooled waits for the next start; the vault still serves,
/// since the node holds the key it runs on.
fn spool_vault_key_escrow(vault: &oneiron::Vault, managed: &ManagedArgs) {
    let Some(outbox) = &managed.escrow_outbox else {
        return;
    };
    let spool = || -> anyhow::Result<()> {
        for capsule in vault.vault_key_escrow_capsules()? {
            let Some((role @ ("managed" | "break-glass"), _)) = capsule.label.split_once('.')
            else {
                continue;
            };
            if capsule.spooled {
                continue;
            }
            let report = oneiron_vault_contract::escrow::EscrowCapsuleReport {
                schema_version: oneiron_vault_contract::escrow::ESCROW_REPORT_SCHEMA_VERSION,
                report_type: oneiron_vault_contract::escrow::ESCROW_REPORT_TYPE.to_owned(),
                report_id: blake3::hash(&capsule.capsule).to_hex().to_string(),
                vault_name: managed.vault_name.clone(),
                vault_id: oneiron_vault_contract::hex(&capsule.vault_id),
                role: role.to_owned(),
                label: capsule.label.clone(),
                wrap_id: capsule.wrap_id.clone(),
                key_commitment: oneiron_vault_contract::hex(&capsule.commitment),
                capsule: oneiron_vault_contract::hex(&capsule.capsule),
                sealed_at: capsule.created_at,
            };
            oneiron_vault_contract::escrow::spool_escrow_report(outbox, &report)?;
            vault.mark_vault_key_escrow_spooled(&capsule.wrap_id, &capsule.capsule)?;
        }
        Ok(())
    };
    if let Err(error) = spool() {
        tracing::warn!(%error, "an escrow capsule was not spooled; the next start spools it");
    }
}

/// Boots the engine as a supervised child process.
///
/// The startup order is the contract, not an implementation detail: the
/// delivered descriptor numbers are checked before any of them is consumed,
/// credentials are consumed before the data directory is opened, the open
/// gates run before anything is served, both sockets are bound before the
/// ready byte, and the ready byte is what tells the supervisor any of it
/// happened.
pub async fn serve_managed(args: &ServeArgs, managed: ManagedArgs) -> anyhow::Result<()> {
    let mut config = managed.serve_config(args);
    // The supervisor's models table, read and checked before anything opens.
    config.models = managed.models()?;
    let cors = crate::commands::build_cors_layer(&config.sync_server_config())?;
    init_managed_tracing(&config.log_level);
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

    // The contract requires the credential frame to be read before the data
    // directory is opened, so a refused frame never touches storage.
    let credentials = oneiron_vault_contract::Credentials {
        dek: host.secret("dek")?.as_slice().try_into()?,
        token: host.secret("spawn_token")?.as_slice().try_into()?,
    };
    let mut vault_config = config.vault_config();
    vault_config.failure_signals.deployment =
        oneiron::config::failure_signals::DeploymentTier::Managed;
    vault_config.failure_signals.training_opt_in = args.failure_signal_training.unwrap_or(false);
    // Set before the open: LMDB takes the page key with the environment.
    vault_config.page_seal = managed_page_seal(&managed, &credentials.dek)?;
    let vault = Arc::new(open_managed_vault(
        &managed.data_dir,
        vault_config,
        &managed.vault_name,
        &credentials,
        managed.derivation_owner,
    )?);

    let mut server_config = config.sync_server_config();
    server_config.lease_vault_id = super::vault_gates::managed_lease_scope(&vault)?;
    // Stable, domain-separated custody from the verified vault DEK, not the
    // per-spawn callback token or caller-controlled HTTP identity headers.
    // A fresh spawn with the same DEK must recover the same logged host root.
    let mut issuer_key = blake3::derive_key(
        "oneiron/managed-supervisor-host-authority/v2",
        &credentials.dek,
    );
    let issuer = oneiron::authority::HostSlipIssuer::from_secret(&issuer_key)?;
    issuer_key.fill(0);
    provision_host_authority(&vault, &issuer, &config.keystore, &managed.data_dir)?;
    // The delivered DEK is the vault's data key (CROSS-ARCH-0022
    // #ov-custody): its sealed artifacts derive from it, and each escrow
    // recipient the node's operator installed keeps a copy of it.
    vault.admit_vault_key(&credentials.dek)?;
    escrow_vault_key(&vault, &managed)?;
    spool_vault_key_escrow(&vault, &managed);
    // A sealed vault serves only once its mirror reopens it at the next start.
    vault.check_page_custody()?;
    // Managed mode reads no environment, so the destination carries no
    // bearer: our inbox takes none.
    let mut sync_server = SyncServer::new(Arc::clone(&vault), server_config)
        .map_err(|e| anyhow::anyhow!("sync server init failed: {e}"))?
        .with_feedback(config.feedback.delivery().map(|delivery| {
            crate::feedback_delivery::FeedbackHost {
                config: delivery,
                bearer: None,
            }
        }));
    sync_server.managed_issuer = Some(issuer);
    if managed.artifact_socket.is_some() {
        sync_server = sync_server.with_artifact_socket();
    }
    // Model seats, the Dreamer and the decision ladder from `[models]`, as
    // plain serve attaches them. A startup error below drops `ai`, which
    // tells its workers to stop.
    let (sync_server, ai) =
        crate::ai_host::AiHost::attach(sync_server, config.models.as_ref()).await;
    // The Dreamer's passes are admitted like a served write, and refused
    // until the managed state below exists.
    let reap_gate = Arc::new(std::sync::OnceLock::<Arc<ManagedState>>::new());
    ai.bind_pass_admission({
        let gate = Arc::clone(&reap_gate);
        Arc::new(move || {
            gate.get()?
                .admit_http_mutation()
                .ok()
                .map(|admission| Box::new(admission) as Box<dyn Send>)
        })
    });
    let sync_server = Arc::new(sync_server);
    // The skill-edit gate's replay judge, on the ladder just built (OF-495).
    crate::replay_judge::register(&sync_server, config.skills.live_pulls_per_axis);

    // Adoption stays here, after the gates: the listener was only resolved
    // above, and `bind` is what takes the descriptor over.
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
    let state = Arc::new(ManagedState::new(
        managed.vault_name.clone(),
        Arc::clone(&sync_server),
        ledger,
    ));
    let _ = reap_gate.set(Arc::clone(&state));

    spawn_sigterm_shutdown(shutdown.clone())?;
    // The receipts every vault signs (ARCH-0066 §8-§9), each admitted through
    // the reap freeze like a served write: a frozen vault signs nothing, and a
    // reap never reads quiescent over a set in flight. The first set comes
    // before ctl is served, so no reap can freeze the vault ahead of it.
    let oversight = sync_server
        .start_healer_oversight(crate::server::HEALER_OVERSIGHT_EVERY, {
            let state = Arc::clone(&state);
            move || state.admit_http_mutation().ok()
        })
        .await?;
    // Fact hooks (ARCH-0080) and the settled verb-ask drain on their runner,
    // unless `--no-hooks`: each pass admitted like a served write. The sandbox
    // loads before ready, as plain serve loads it, so no verb waits on it.
    let (hooks_stop, hooks_stopped) = watch::channel(false);
    #[cfg(feature = "code-sandbox-wasmtime")]
    let fact_hooks = if config.hooks {
        let state = Arc::clone(&state);
        crate::commands::spawn_fact_hooks(
            &sync_server,
            Arc::new(move || {
                state
                    .admit_http_mutation()
                    .ok()
                    .map(|admission| Box::new(admission) as Box<dyn Send>)
            }),
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
    if !config.hooks {
        sync_server.vault().suppress_verb_hooks();
    }

    let ctl_task = tokio::spawn({
        let state = Arc::clone(&state);
        let ctl_shutdown = shutdown.triggered();
        async move { ctl.serve(state, ctl_shutdown).await }
    });

    // Both sockets are bound, the credentials are consumed, and the open gates
    // have passed. Only now is this process something the supervisor may route
    // traffic to.
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
    }

    if let Err(_error) = state.ledger().push_if_changed(&sync_server).await {
        tracing::warn!(
            reason = "wake_ledger_export_failed",
            "initial wake ledger push failed"
        );
    }

    // Housekeeping passes are admitted like a served write: a vault frozen
    // for reap sweeps nothing, and a pass in flight keeps it from reading
    // quiescent.
    let background = sync_server.spawn_serve_background({
        let state = Arc::clone(&state);
        Arc::new(move || {
            state
                .admit_http_mutation()
                .ok()
                .map(|admission| Box::new(admission) as Box<dyn Send>)
        })
    });
    // Surface events drain under the same admission (OF-218).
    let connector_events = sync_server.spawn_connector_event_worker({
        let state = Arc::clone(&state);
        Arc::new(move || {
            state
                .admit_http_mutation()
                .ok()
                .map(|admission| Box::new(admission) as Box<dyn Send>)
        })
    });
    // Approved sends leave under the same admission (OF-187).
    let connector_sends = sync_server.spawn_connector_send_worker({
        let state = Arc::clone(&state);
        Arc::new(move || {
            state
                .admit_http_mutation()
                .ok()
                .map(|admission| Box::new(admission) as Box<dyn Send>)
        })
    });
    // Checked built-in channels, under the same admission (OF-519).
    let builtin_host = crate::builtin_host::spawn(&sync_server, {
        let state = Arc::clone(&state);
        Arc::new(move || {
            state
                .admit_http_mutation()
                .ok()
                .map(|admission| Box::new(admission) as Box<dyn Send>)
        })
    });
    // Failure signals reach our collector under the same admission (OF-380).
    // Managed mode reads no environment, so the send carries no bearer.
    let failure_signals = crate::ai_host::failure_signals::spawn(
        &sync_server,
        crate::ai_host::failure_signals::FailureSignalHost::new(
            &config.failure_signals,
            true,
            None,
        ),
        {
            let state = Arc::clone(&state);
            Arc::new(move || {
                state
                    .admit_http_mutation()
                    .ok()
                    .map(|admission| Box::new(admission) as Box<dyn Send>)
            })
        },
    );
    // The ladder's workers plain serve runs. Wire health and the standing
    // pump pass under the same admission.
    let admitted = || -> crate::server::HousekeepingAdmission {
        let state = Arc::clone(&state);
        Arc::new(move || {
            state
                .admit_http_mutation()
                .ok()
                .map(|admission| Box::new(admission) as Box<dyn Send>)
        })
    };
    // The nightly Coach jobs that need the host's model or rules (OF-420).
    let coach_host = crate::ai_host::coach_host::spawn(&sync_server, admitted());
    // Crossed thresholds ask the ladder whether everything is okay (OF-520).
    let mut ladder_workers = vec![crate::wire_health::spawn(&sync_server, admitted())];
    // Documents whose signing finished are sealed as a task (OF-415).
    #[cfg(unix)]
    ladder_workers.push(crate::api::spawn_esign_seal_worker_admitted(
        Arc::clone(&sync_server),
        admitted(),
    ));
    // Due standing questions are answered through the ladder (OF-506).
    if !ai.bind_question_timer(&sync_server) {
        ladder_workers.push(crate::decision_graph::spawn(&sync_server, admitted()));
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
    // The managed surface, not the bare one: the reap freeze has to be
    // enforceable by the socket the supervisor routes traffic to, or
    // `quiescent: true` is a claim about a gate that nothing reaches.
    let app = build_managed_app(Arc::clone(&sync_server), Arc::clone(&state)).layer(cors);
    // The paired-machine mesh listener (OF-535), as `serve` starts it: off
    // unless the host names its bind address.
    let mesh = crate::handler::mesh::start(
        Arc::clone(&sync_server),
        &crate::handler::mesh::MeshConfig::from_env()?,
        &app,
        config.limits.connections(),
    )
    .await?;
    let artifact_task = artifacts.map(|listener| {
        let app = build_managed_artifact_app(Arc::clone(&sync_server), Arc::clone(&state));
        let stop = shutdown.triggered();
        tokio::spawn(async move { listener.serve_until(app, stop).await })
    });
    // Graceful shutdown couples "stop accepting" and "drain in-flight": the
    // listener closes the moment SIGTERM lands, and this resolves once the
    // requests already in the runtime have finished.
    let result = http.serve_until(app, shutdown.triggered()).await;
    if let Some(mesh) = mesh {
        mesh.stop().await;
    }
    host.on_stop()?;
    let _ = ctl_task.await;
    if let Some(task) = artifact_task {
        let _ = task.await;
    }
    // Drain observation writes without thawing a previously quiescent process.
    let telemetry_drained = state.freeze();
    // No new durable background work from here on.
    background.stop().await;
    connector_events.abort();
    let _ = connector_events.await;
    connector_sends.abort();
    let _ = connector_sends.await;
    builtin_host.abort();
    let _ = builtin_host.await;
    coach_host.abort();
    let _ = coach_host.await;
    if let Some(failure_signals) = failure_signals {
        failure_signals.abort();
        let _ = failure_signals.await;
    }
    for worker in ladder_workers {
        worker.abort();
        let _ = worker.await;
    }
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

    final_ledger_push(&state, &sync_server).await;
    result?;
    telemetry_drained?;
    Ok(())
}

/// The last thing the supervisor hears from this process.
///
/// Rev-ordered, through the same push-on-change path a running engine uses,
/// and that is the whole point of not hand-rolling it here. [`LedgerUpdate`](oneiron_vault_contract::LedgerUpdate)
/// is a full replacement ordered by `rev`: a shutdown snapshot carrying
/// entries that moved since the last accepted push — a job that became ready,
/// a lease that changed — has to advance the revision, or a supervisor that
/// drops `rev <= last_acked` drops precisely the snapshot this exit exists to
/// deliver. Unchanged entries send nothing, because the supervisor already
/// holds that snapshot at that revision.
///
/// Failure is logged and stepped over. A supervisor that has already died must
/// not be able to hold this exit open.
pub async fn final_ledger_push(state: &ManagedState, server: &SyncServer) {
    let ledger = state.ledger();
    match ledger.push_if_changed(server).await {
        Ok(accepted) => {
            tracing::info!(
                rev = ledger.rev(),
                accepted,
                "final wake ledger push complete"
            );
        }
        Err(_) => tracing::warn!(
            reason = "wake_ledger_export_failed",
            "final wake ledger export failed"
        ),
    }
}

#[cfg(test)]
mod shed_tests {
    use super::*;
    use oneiron_vault_contract::{Credentials, DEK_LEN};
    use oneiron_vault_contract::{ShedCause, TOKEN_LEN, supports_slim};
    use tower::ServiceExt;

    #[tokio::test]
    async fn ctl_shed_refusal_preserves_other_verbs() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let vault = Arc::new(oneiron::Vault::open(
            dir.path(),
            oneiron::VaultConfig::server(),
        )?);
        let server = Arc::new(SyncServer::new(
            Arc::clone(&vault),
            crate::config::SyncServerConfig::default(),
        )?);
        let credentials = Credentials {
            dek: [0x11; DEK_LEN],
            token: [0x22; TOKEN_LEN],
        };
        let ledger = WakeLedger::load(
            Arc::clone(&vault),
            "ctl-test".to_owned(),
            dir.path().join("supervisor.sock"),
            &credentials,
        )?;
        let state = Arc::new(ManagedState::new(
            "ctl-test".to_owned(),
            server.clone(),
            ledger,
        ));
        let router = build_managed_app(server.clone(), state.clone());
        let counter = &server.wire_telemetry;
        counter.set_thresholds(&crate::wire_telemetry::WireThresholds {
            window_secs: 60,
            per_verb: 1,
            per_actor: 1,
        })?;
        counter.record("rpc:test", "reader", 121)?;
        let before_reap = counter.snapshot()?.unwrap();
        let revision = state.ledger().rev();
        for cause in [ShedCause::LongOutboundWait, ShedCause::MemoryPressure] {
            for waited_secs in [0, 1] {
                let response = state
                    .handle_request(CtlRequest::Shed { cause, waited_secs })
                    .await;
                if waited_secs == 0 {
                    assert!(matches!(
                        response,
                        Err(ManagedError::CtlRequestRefused { .. })
                    ));
                } else {
                    let response = response?;
                    response.validate()?;
                    assert!(
                        matches!(response, CtlResponse::Slim { slim: false, status: oneiron_vault_contract::ShedStatus::Refused, blocker: Some(blocker), .. } if blocker.kind == "no_pending_outbound_step")
                    );
                }
                assert!(!state.is_frozen());
                assert!(state.observed_alarms().await.is_empty());
                assert_eq!(state.ledger().rev(), revision);
                assert_eq!(vault.residency(), oneiron::VaultResidency::Full);
            }
        }
        assert!(matches!(
            state.handle_request(CtlRequest::Ping).await?,
            CtlResponse::Ping {
                ok: true,
                vault,
                pid,
                contract_version,
            } if vault == "ctl-test"
                && pid == std::process::id()
                && contract_version == CONTRACT_VERSION
                && supports_slim(contract_version)
        ));
        assert!(matches!(
            state.handle_request(CtlRequest::PrepareReap).await?,
            CtlResponse::PrepareReap {
                quiescent: true,
                ..
            }
        ));
        assert!(state.is_frozen());
        assert_eq!(counter.receipt(120, 180)?, Some(before_reap.clone()));
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .body(axum::body::Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        counter.record("rpc:test", "reader", 122)?;
        counter.flush_if_expired(200)?;
        counter.flush()?;
        assert_eq!(counter.snapshot()?, Some(before_reap.clone()));
        assert_eq!(counter.receipt(120, 180)?, Some(before_reap));
        assert!(counter.question(120, 180)?.is_none());
        assert!(matches!(
            counter.set_thresholds(&Default::default()),
            Err(oneiron::Error::InvalidConfig(_))
        ));
        assert!(matches!(
            state.handle_request(CtlRequest::ReapAbort).await?,
            CtlResponse::Ok { ok: true }
        ));
        assert!(!state.is_frozen());
        counter.record("rpc:test", "reader", 123)?;
        counter.flush()?;
        assert_eq!(counter.receipt(120, 180)?.unwrap().by_verb["rpc:test"], 2);
        assert!(counter.question(120, 180)?.is_some());
        assert!(matches!(
            state
                .handle_request(CtlRequest::AlarmDue {
                    id: "nightly".to_owned(),
                    reason_tag: "cron".to_owned(),
                })
                .await?,
            CtlResponse::Ok { ok: true }
        ));
        let alarms = state.observed_alarms().await;
        assert_eq!(alarms.len(), 1);
        assert_eq!(alarms[0].id, "nightly");
        assert_eq!(alarms[0].reason_tag, "cron");
        Ok(())
    }
}
