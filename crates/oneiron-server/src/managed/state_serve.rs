//! Managed runtime state, the reap freeze gate, and the supervised serve loop.

use std::future::Future;
use std::io::ErrorKind;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use axum::Json;
use axum::Router;
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode, header::UPGRADE};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use oneiron_vault_contract::{
    CONTRACT_VERSION, CtlRequest, CtlResponse, UnixTs, now_ts, validate_wake_entries,
};
use tokio::sync::{Mutex, watch};

use crate::build_app;
use crate::config::ServeArgs;
use crate::server::SyncServer;

use super::args::{ManagedArgs, ManagedError};
use super::ledger::{SYNC_UPGRADE_SETTLE_SECS, WakeLedger};
use super::listener::{ManagedCtl, ServeListener, init_managed_tracing, signal_ready};
use super::vault_gates::{open_managed_vault, read_managed_credentials};

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
    /// Unix seconds of the most recent sync upgrade the freeze gate admitted,
    /// or 0 if none. The handshake is the last thing that gate ever sees of a
    /// sync session, so this stamp is the only record that one exists.
    last_sync_upgrade: AtomicU64,
    alarms: Mutex<Vec<ObservedAlarm>>,
    ledger: WakeLedger,
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
            last_sync_upgrade: AtomicU64::new(0),
            alarms: Mutex::new(Vec::new()),
            ledger,
        }
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

    pub fn freeze(&self) {
        self.frozen.store(true, Ordering::SeqCst);
    }

    /// Lifts the freeze. Called by `reap_abort` and again on the shutdown
    /// path, so a process that dies mid-reap never leaves a frozen vault
    /// behind for the next boot to inherit.
    pub fn unfreeze(&self) {
        self.frozen.store(false, Ordering::SeqCst);
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
            CtlRequest::Shed { .. } => Err(ManagedError::CtlRequestRefused {
                reason: "shed integration is deferred; managed ctl does not invoke engine shedding"
                    .to_owned(),
            }),
            CtlRequest::PrepareReap => self.prepare_reap().await,
            CtlRequest::ReapAbort => {
                self.unfreeze();
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
        self.freeze();
        let drained = self.drain_lease_table().await;
        let (ledger_rev, next_wake) = self.ledger.export_at_freeze(&self.server).await?;
        // The reply carries the entries, so they are bounds-checked before
        // they are serialized rather than after a supervisor has trusted them.
        validate_wake_entries(&next_wake).map_err(|error| ManagedError::LedgerRefused {
            reason: error.to_string(),
        })?;
        Ok(CtlResponse::PrepareReap {
            quiescent: drained && self.is_frozen() && !self.live_sync_writer(),
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
                tracing::error!(%error, "lease table drain failed during prepare_reap");
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

/// The freeze gate on the served path.
///
/// Consulted per request, before the handler runs: once `prepare_reap` has
/// flipped the flag, anything that could mutate the vault is answered with the
/// typed refusal instead of reaching storage. That is what turns
/// `quiescent: true` from an advisory into something a supervisor can reap
/// against — without it the engine keeps committing durable writes after
/// reporting that it stopped.
///
/// What it cannot see from here is a request that was already past this point
/// when the flag flipped, and a sync session upgraded before it. The first is
/// what graceful shutdown drains; the second is why an upgrade is itself
/// treated as a write below, and why an upgrade this gate *admits* is recorded
/// on the way through: refusing new sessions says nothing about the one that
/// was already open, whose frames no middleware will ever see.
async fn refuse_frozen_writes(
    State(state): State<Arc<ManagedState>>,
    request: Request,
    next: Next,
) -> Response {
    if !is_read_only(&request)
        && let Err(error) = state.guard_write()
    {
        return writes_frozen_response(&error);
    }
    if request.headers().contains_key(UPGRADE) {
        // Admitted, and out of sight from here on. A freeze with one of these
        // behind it is not quiescent, and `prepare_reap` is where that is
        // answered for — this gate cannot refuse a frame it never sees.
        state.admit_sync_upgrade();
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

/// Boots the engine as a supervised child process.
///
/// The startup order is the contract, not an implementation detail: the
/// delivered descriptor numbers are checked before any of them is consumed,
/// credentials are consumed before the data directory is opened, the open
/// gates run before anything is served, both sockets are bound before the
/// ready byte, and the ready byte is what tells the supervisor any of it
/// happened.
pub async fn serve_managed(args: &ServeArgs, managed: ManagedArgs) -> anyhow::Result<()> {
    let config = managed.serve_config(args);
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
    let http = ServeListener::for_managed(&managed)?;

    // The contract requires the credential frame to be read before the data
    // directory is opened, so a refused frame never touches storage.
    let credentials = read_managed_credentials(managed.credentials_fd)?;
    let vault = Arc::new(open_managed_vault(
        &managed.data_dir,
        config.vault_config(),
        &managed.vault_name,
        &credentials,
    )?);

    let sync_server = Arc::new(
        SyncServer::new(Arc::clone(&vault), config.sync_server_config())
            .map_err(|e| anyhow::anyhow!("sync server init failed: {e}"))?,
    );

    // Adoption stays here, after the gates: the listener was only resolved
    // above, and `bind` is what takes the descriptor over.
    let http = http.bind().await?;
    let http_owned_path = http.owned_path().map(Path::to_path_buf);
    let ctl = ManagedCtl::bind(&managed.ctl_socket)?;

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
    let state = Arc::new(ManagedState::new(
        managed.vault_name.clone(),
        Arc::clone(&sync_server),
        ledger,
    ));

    let shutdown = ManagedShutdown::new();
    spawn_sigterm_shutdown(shutdown.clone())?;
    let ctl_task = tokio::spawn({
        let state = Arc::clone(&state);
        let ctl_shutdown = shutdown.triggered();
        async move { ctl.serve(state, ctl_shutdown).await }
    });

    // Both sockets are bound, the credentials are consumed, and the open gates
    // have passed. Only now is this process something the supervisor may route
    // traffic to.
    signal_ready(managed.ready_fd)?;
    tracing::info!(vault = %managed.vault_name, "managed vault ready");

    if let Err(error) = state.ledger().push_if_changed(&sync_server).await {
        tracing::warn!(%error, "initial wake ledger push failed");
    }

    let lifecycle_handle = sync_server.spawn_lifecycle_scheduler();
    // The managed surface, not the bare one: the reap freeze has to be
    // enforceable by the socket the supervisor routes traffic to, or
    // `quiescent: true` is a claim about a gate that nothing reaches.
    let app = build_managed_app(Arc::clone(&sync_server), Arc::clone(&state));
    // Graceful shutdown couples "stop accepting" and "drain in-flight": the
    // listener closes the moment SIGTERM lands, and this resolves once the
    // requests already in the runtime have finished.
    let result = http.serve_until(app, shutdown.triggered()).await;

    let _ = ctl_task.await;
    // An interrupted reap must not outlive the process that started it.
    state.unfreeze();
    // No new durable background work from here on.
    lifecycle_handle.abort();
    let _ = lifecycle_handle.await;

    if let Some(path) = http_owned_path {
        // Only ever the path this process created. An inherited socket's inode
        // belongs to the supervisor and has to survive us.
        if let Err(error) = std::fs::remove_file(&path)
            && error.kind() != ErrorKind::NotFound
        {
            tracing::warn!(%error, path = %path.display(), "http socket unlink failed");
        }
    }

    final_ledger_push(&state, &sync_server).await;
    result?;
    Ok(())
}

/// The last thing the supervisor hears from this process.
///
/// Rev-ordered, through the same push-on-change path a running engine uses,
/// and that is the whole point of not hand-rolling it here. [`LedgerUpdate`]
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
        Err(error) => tracing::warn!(%error, "final wake ledger export failed"),
    }
}

#[cfg(test)]
mod shed_tests {
    use super::*;
    use oneiron_vault_contract::{Credentials, DEK_LEN};
    use oneiron_vault_contract::{ShedCause, TOKEN_LEN, supports_slim};

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
        let state = ManagedState::new("ctl-test".to_owned(), server, ledger);
        let revision = state.ledger().rev();
        for cause in [ShedCause::LongOutboundWait, ShedCause::MemoryPressure] {
            for waited_secs in [0, 1] {
                let error = state
                    .handle_request(CtlRequest::Shed { cause, waited_secs })
                    .await
                    .unwrap_err();
                let ManagedError::CtlRequestRefused { reason } = error else {
                    panic!("expected typed ctl refusal, got {error:?}");
                };
                if waited_secs == 0 {
                    assert_eq!(reason, "shed requires a positive waited_secs");
                } else {
                    assert!(reason.contains("shed integration is deferred"));
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
        assert!(matches!(
            state.handle_request(CtlRequest::ReapAbort).await?,
            CtlResponse::Ok { ok: true }
        ));
        assert!(!state.is_frozen());
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
