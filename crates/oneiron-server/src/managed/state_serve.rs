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
    CONTRACT_VERSION, CtlRequest, CtlResponse, REAP_PAUSE_REFUSAL, UnixTs, now_ts,
    validate_wake_entries,
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
/// different outage and means a different response from the caller. It is
/// the wire spelling of [`REAP_PAUSE_REFUSAL`]'s kind, which a ctl refusal
/// carries too.
pub const WRITES_FROZEN_TAG: &str = REAP_PAUSE_REFUSAL.error.as_str();

/// What a vault frozen for reap says (K18), served and logged: a temporary
/// pause under the service's vault lifecycle allocation, what it holds back,
/// how it lifts, and that a self-hosted vault has no such limit. It names no
/// duration: this process knows none.
pub(super) const WRITES_FROZEN_MESSAGE: &str = "This hosted vault is paused while the service prepares to reap it under its vault lifecycle allocation. New effects, requests other than GET, HEAD and OPTIONS (POST reads included) and connection upgrades are refused, and background passes wait, until the reap is aborted or the vault wakes again; the same request then succeeds. The same action works on a self-hosted vault, which has no such service reap limit; its storage and authorization checks still apply.";

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
    /// Whether a background pass the freeze refused has logged why since
    /// the last unfreeze: the pending reason is logged once per freeze.
    background_waiting: AtomicBool,
    /// The voice hello attestations already taken, each kept until its
    /// `issued_at` leaves the skew window (FIX 2391).
    voice_actions: std::sync::Mutex<std::collections::HashMap<String, UnixTs>>,
}

/// A supervisor-signed account action, not the child process's host-root slip.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ManagedWidenHolder(pub(crate) oneiron::EntityId);

/// The vault owner a supervisor-signed `ManagedOwnerAction` names for one
/// request, verified at ingress; never the host root.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ManagedOwnerHolder(pub(crate) oneiron::EntityId);

/// Managed ingress's mark on every request it hands the app (FIX 5125): the
/// supervisor forwarded it on its caller's behalf, so the caller sits off this
/// device whatever socket it arrived on, and the machine its own proof shows
/// is still the one it proved.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ManagedIngress;

/// The reap admission a held MCP socket's work takes (FIX 5128): managed
/// ingress hands it to every upgrade it admits, as lifecycle context, never
/// as anyone's authority. The upgrade's own admission ends with its
/// handshake, so the socket holds none while it idles. Each call it carries
/// is admitted as the served request it becomes ([`Self::admit_requests`]),
/// and each receipt it writes outside a call alone
/// ([`Self::admit_receipt`]), on the one count of served writes in flight a
/// reap waits for.
#[derive(Clone)]
pub(crate) struct ManagedCarrierContext(Arc<ManagedState>);

impl ManagedCarrierContext {
    /// `routes` behind managed ingress and the reap freeze, as the served
    /// app is ([`with_managed_requests`]): each request through them is
    /// admitted on its own, and its handler finishes in a task that owns
    /// that admission.
    pub(crate) fn admit_requests(&self, routes: Router) -> Router {
        with_managed_requests(routes, Arc::clone(&self.0))
    }

    /// Runs `action`, one write the socket makes outside any request (a
    /// receipt), under a served write's admission, released as it returns;
    /// `action` does not await. While the vault is frozen for reap nothing
    /// runs, and the pause a served write gets is returned instead.
    pub(crate) fn admit_receipt<T>(&self, action: impl FnOnce() -> T) -> Result<T, CarrierPaused> {
        let _admission = self.0.admit_http_mutation().map_err(CarrierPaused)?;
        Ok(action())
    }

    /// Marks `request` as a call the socket carries, so the task its
    /// admission finishes in runs as the socket's connection (FIX 811),
    /// not as a fresh one.
    pub(crate) fn carry<B>(&self, request: &mut axum::http::Request<B>) {
        request
            .extensions_mut()
            .insert(CarriedConnection(crate::api::call_receipt::connection_id()));
    }
}

/// The connection a held socket's call arrived on, as
/// [`ManagedCarrierContext::carry`] marked it.
#[derive(Clone, Copy)]
struct CarriedConnection(u128);

/// The reap freeze's refusal of a held socket's write
/// ([`ManagedCarrierContext::admit_receipt`]): the pause a served write gets
/// ([`writes_frozen_response`]), as the status and body the socket answers
/// with.
pub(crate) struct CarrierPaused(ManagedError);

impl CarrierPaused {
    pub(crate) fn status(&self) -> StatusCode {
        StatusCode::SERVICE_UNAVAILABLE
    }

    pub(crate) fn body(&self) -> serde_json::Value {
        writes_frozen_body(&self.0)
    }
}

/// The vault owner a held MCP socket serves (FIX 5128): the person his
/// supervisor attested on the socket's upgrade, whom the vault recorded as
/// its live owner then. Not [`ManagedOwnerHolder`], which attests one
/// request and its exact body: this attests no later body. It names whose
/// socket a call came on, and every call judges him again on the vault's
/// live owner record.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ManagedOwnerSession(oneiron::EntityId);

impl ManagedOwnerSession {
    /// The session an upgrade's caller `auth` opens: a managed vault's
    /// attested owner's, built for him alone
    /// ([`CoreAuth::for_attested_owner`](crate::auth::CoreAuth::for_attested_owner)),
    /// never a slip's or the host's.
    pub(crate) fn opened_by(auth: &crate::auth::CoreAuth) -> Option<Self> {
        auth.managed_owner().map(Self)
    }

    /// The owner whose socket this is.
    pub(crate) fn holder(&self) -> oneiron::EntityId {
        self.0
    }
}

/// The listener a request reached: the API's, or the artifact origin's,
/// which serves artifact reads alone.
#[derive(Clone, Copy)]
enum Surface {
    Api,
    Artifact,
}

/// The facade's nest: its `POST`s are the requests a `ManagedOwnerAction`
/// may name the owner for, with every request under [`OWNER_PREFIX`].
const FACADE_PREFIX: &str = "/v1/core/facade/";

/// The owner's own nest (`/v1/owner`), any method.
const OWNER_PREFIX: &str = "/v1/owner/";

/// The app's action transport: `POST /v1/core/actions/{verb}`.
const ACTIONS_PREFIX: &str = "/v1/core/actions/";

/// A held lens card's transports: `POST /v1/core/lens-frames/{card_id}/events`
/// and `DELETE /v1/core/lens-frames/{card_id}`.
const LENS_FRAMES_PREFIX: &str = "/v1/core/lens-frames/";

/// Whether a `ManagedOwnerAction` may name the owner for this request on
/// the buffered path: the facade's and the owner's nests, the action and
/// frame transports, the console's own routes, and every other route
/// [`super::attested_routes`] lists for the listener it reached. Its staged
/// routes are [`super::attested_routes::staged_route`]'s.
fn owner_attestable(surface: Surface, method: &Method, path: &str) -> bool {
    match surface {
        Surface::Api => {
            (*method == Method::POST && path.starts_with(FACADE_PREFIX))
                || path.starts_with(OWNER_PREFIX)
                || action_or_frame_attestable(method, path)
                || console_attestable(method, path)
                || super::attested_routes::owner_route(method, path)
        }
        Surface::Artifact => super::attested_routes::artifact_route(method, path),
    }
}

/// The console's own reads and acts outside those nests, each matched
/// exactly by method and path, every `{..}` one non-empty path segment
/// (WILL-PLAN L14 row 01): `GET /api/search/vector`, `/api/search/text`,
/// `/api/entity/{id}`, `/api/edges/{id}`, `/api/core/discover`,
/// `/api/booking/{page_token}/agent-instructions`, `/v1/llm/defaults`,
/// `/v1/ai/waves/{attempt}` and `/v1/ai/video/{job}`; `POST
/// /v1/core/pairing/links`, `/v1/core/slips/revoke`,
/// `/v1/core/org-admin/{org}/policy`, the four
/// `/api/booking/{page_token}/{availability|book|reschedule|cancel}` and
/// `/mcp`. The rest of the attested routes, root-admin doors among them, are
/// [`super::attested_routes`]'s.
fn console_attestable(method: &Method, path: &str) -> bool {
    let between = |prefix: &str, suffix: &str| {
        path.strip_prefix(prefix)
            .and_then(|rest| rest.strip_suffix(suffix))
            .is_some_and(|rest| !rest.is_empty() && !rest.contains('/'))
    };
    if *method == Method::GET {
        matches!(
            path,
            "/api/search/vector" | "/api/search/text" | "/api/core/discover" | "/v1/llm/defaults"
        ) || between("/api/entity/", "")
            || between("/api/edges/", "")
            || between("/api/booking/", "/agent-instructions")
            || between("/v1/ai/waves/", "")
            || between("/v1/ai/video/", "")
    } else if *method == Method::POST {
        matches!(
            path,
            "/v1/core/pairing/links" | "/v1/core/slips/revoke" | "/mcp"
        ) || between("/v1/core/org-admin/", "/policy")
            || ["/availability", "/book", "/reschedule", "/cancel"]
                .into_iter()
                .any(|operation| between("/api/booking/", operation))
    } else {
        false
    }
}

/// The owner's action and frame transports, each matched exactly (WILL-PLAN
/// L13 row 01): `POST /v1/core/actions/{verb}`, `POST
/// /v1/core/lens-frames/{card_id}/events` and `DELETE
/// /v1/core/lens-frames/{card_id}`, each `{..}` one non-empty path segment.
/// The other `/v1/core/*` routes are [`console_attestable`]'s and
/// [`super::attested_routes`]'s. The assertion is verified over the method,
/// path, raw query, placing headers and exact body as for the facade.
fn action_or_frame_attestable(method: &Method, path: &str) -> bool {
    let segment = |rest: &str| !rest.is_empty() && !rest.contains('/');
    if *method == Method::POST {
        path.strip_prefix(ACTIONS_PREFIX).is_some_and(segment)
            || path
                .strip_prefix(LENS_FRAMES_PREFIX)
                .and_then(|rest| rest.strip_suffix("/events"))
                .is_some_and(segment)
    } else if *method == Method::DELETE {
        path.strip_prefix(LENS_FRAMES_PREFIX).is_some_and(segment)
    } else {
        false
    }
}

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
            background_waiting: AtomicBool::new(false),
            voice_actions: std::sync::Mutex::default(),
        }
    }

    /// The owner a managed voice hello's supervisor attestation names
    /// (FIX 2391): signed for this vault over the room and roster the hello
    /// names, its `issued_at` and its fresh nonce, issued within
    /// [`MANAGED_VOICE_MAX_SKEW_SECS`](oneiron_vault_contract::MANAGED_VOICE_MAX_SKEW_SECS)
    /// of now, and not taken before, so a captured hello opens no second
    /// call while two hellos in the same second each open one. The person
    /// is the call's owner only while the owner door says so; this proves
    /// only the supervisor's word.
    pub(crate) fn verify_voice_owner(
        &self,
        action: &oneiron_vault_contract::ManagedOwnerAction,
        room: &str,
        roster: &str,
        issued_at: UnixTs,
        nonce: &[u8; oneiron_vault_contract::MANAGED_VOICE_NONCE_BYTES],
    ) -> Option<oneiron::EntityId> {
        let skew = oneiron_vault_contract::MANAGED_VOICE_MAX_SKEW_SECS;
        let now = now_ts();
        if now.abs_diff(issued_at) > skew {
            return None;
        }
        let body = oneiron_vault_contract::managed_voice_body(issued_at, nonce);
        let request = oneiron_vault_contract::ManagedOwnerRequest::voice(room, roster, &body);
        if !self.ledger.verify_owner_action(action, &request) {
            return None;
        }
        let holder = oneiron::EntityId::from_hex(&action.holder_ref).ok()?;
        let mut taken = self
            .voice_actions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        taken.retain(|_, until| *until >= now);
        taken
            .insert(action.mac.clone(), issued_at.saturating_add(skew))
            .is_none()
            .then_some(holder)
    }

    fn admit_http_mutation(self: &Arc<Self>) -> Result<HttpMutation, ManagedError> {
        // Increment BEFORE checking freeze. A concurrent freeze must either see
        // this writer or make this admission fail; check-then-increment races.
        self.http_mutating_in_flight.fetch_add(1, Ordering::SeqCst);
        let admission = HttpMutation(Arc::clone(self));
        self.guard_write()?;
        Ok(admission)
    }

    /// A background pass's admission, taken as a served write's and held on
    /// the pass's own thread until its last write. A refused pass logs the
    /// pause's typed reason, once per freeze, and asks again later.
    fn admit_background(self: &Arc<Self>) -> Option<Box<dyn Send>> {
        match self.admit_http_mutation() {
            Ok(admission) => Some(Box::new(admission)),
            Err(_) => {
                if !self.background_waiting.swap(true, Ordering::SeqCst) {
                    tracing::info!(
                        reason = WRITES_FROZEN_TAG,
                        bound_kind = REAP_PAUSE_REFUSAL.bound.kind.as_str(),
                        bound_resource = REAP_PAUSE_REFUSAL.bound.resource.as_str(),
                        bound_phase = REAP_PAUSE_REFUSAL.bound.phase.as_str(),
                        "background passes wait: the vault is paused for reap preparation until the reap is aborted or the vault wakes again"
                    );
                }
                None
            }
        }
    }

    /// [`Self::admit_background`] as the admission a background worker takes.
    fn background_admission(self: &Arc<Self>) -> crate::server::HousekeepingAdmission {
        let state = Arc::clone(self);
        Arc::new(move || state.admit_background())
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
        if self.background_waiting.swap(false, Ordering::SeqCst) {
            tracing::info!("the reap pause lifted; background passes run again");
        }
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
    with_managed_requests(build_app(server), state)
}

/// `router` behind managed ingress and the reap freeze: the served app
/// ([`build_managed_app`]), and the routes a held MCP socket runs each of
/// its calls through (FIX 5128).
fn with_managed_requests(router: Router, state: Arc<ManagedState>) -> Router {
    let freeze = middleware::from_fn_with_state(state, refuse_frozen_writes);
    router.layer(freeze)
}

/// The managed artifact origin: this vault's `/a/`, and its names under the
/// artifact domains (`oneiron_vault_contract::artifact_origin`), behind the
/// same freeze gate as the API socket.
pub(super) fn build_managed_artifact_app(
    server: Arc<SyncServer>,
    state: Arc<ManagedState>,
) -> Router {
    let freeze = middleware::from_fn_with_state(state, refuse_frozen_artifact_writes);
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
    request: Request,
    next: Next,
) -> Response {
    freeze_gate(state, Surface::Api, request, next).await
}

/// [`refuse_frozen_writes`] on the artifact listener.
async fn refuse_frozen_artifact_writes(
    State(state): State<Arc<ManagedState>>,
    request: Request,
    next: Next,
) -> Response {
    freeze_gate(state, Surface::Artifact, request, next).await
}

/// The freeze gate, and managed ingress before it, for a request that reached
/// `surface`.
async fn freeze_gate(
    state: Arc<ManagedState>,
    surface: Surface,
    mut request: Request,
    next: Next,
) -> Response {
    if state.server.managed_issuer.is_some() {
        request.extensions_mut().insert(ManagedIngress);
        // The widen answer routes need the SUPERVISOR'S holder action, not
        // the host root. Verify the account-authenticated assertion against
        // the per-spawn secret and the exact request body before removing
        // it. Unverified headers never become extensions.
        if request.method() == Method::POST
            && matches!(
                request.uri().path(),
                "/v1/core/consent/widen/accept" | "/v1/core/consent/widen/reject"
            )
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
        // A request the supervisor attests is the vault owner's own
        // (`ManagedOwnerAction`), on every route whose body the buffer holds,
        // and on every route whose body streams once that body is staged on
        // the vault's disk (`owner_stage`): verified the same way, over the
        // method, path, raw query, placing headers and exact body, before
        // any handler runs. A verified one names the owner, as a request
        // extension the credential reads; one that does not verify is
        // refused, never served as the host's root.
        let staged = match surface {
            Surface::Api => {
                super::attested_routes::staged_route(request.method(), request.uri().path())
            }
            Surface::Artifact => None,
        };
        if staged.is_some() || owner_attestable(surface, request.method(), request.uri().path()) {
            let assertion = request
                .headers()
                .get(oneiron_vault_contract::MANAGED_OWNER_ACTION_HEADER)
                .and_then(|value| value.to_str().ok())
                .and_then(|text| {
                    serde_json::from_str::<oneiron_vault_contract::ManagedOwnerAction>(text).ok()
                });
            if let Some(assertion) = &assertion
                && let Some(staged) = staged
            {
                let ceiling = staged.ceiling();
                request = match super::owner_stage::verify_staged(
                    &state.server,
                    &state.ledger,
                    assertion,
                    request,
                    ceiling,
                )
                .await
                {
                    Ok(request) => request,
                    Err(refusal) => return refusal,
                };
            } else if let Some(assertion) = assertion {
                let (parts, body) = request.into_parts();
                let Ok(bytes) =
                    to_bytes(body, oneiron::memory::caps::MAX_REMOTE_REQUEST_BYTES).await
                else {
                    return StatusCode::PAYLOAD_TOO_LARGE.into_response();
                };
                let header = |name: &'static str| {
                    parts
                        .headers
                        .get(name)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("")
                };
                let [room_turn, invocation, session] =
                    oneiron_vault_contract::MANAGED_OWNER_BOUND_HEADERS.map(header);
                let verified = state.ledger.verify_owner_action(
                    &assertion,
                    &oneiron_vault_contract::ManagedOwnerRequest {
                        method: parts.method.as_str(),
                        path: parts.uri.path(),
                        query: parts.uri.query().unwrap_or(""),
                        headers: [room_turn, invocation, session],
                        body: &bytes,
                    },
                );
                let holder = oneiron::EntityId::from_hex(&assertion.holder_ref)
                    .ok()
                    .filter(|_| verified);
                let Some(holder) = holder else {
                    return owner_attestation_refused(parts.uri.path());
                };
                request = Request::from_parts(parts, Body::from(bytes));
                request.extensions_mut().insert(ManagedOwnerHolder(holder));
            } else if request
                .headers()
                .contains_key(oneiron_vault_contract::MANAGED_OWNER_ACTION_HEADER)
            {
                return owner_attestation_refused(request.uri().path());
            }
        }
        request
            .headers_mut()
            .remove("x-oneiron-managed-widen-action");
        request
            .headers_mut()
            .remove(oneiron_vault_contract::MANAGED_OWNER_ACTION_HEADER);
        // A caller's own slip, its holder proof and its machine claim go on
        // unchanged: the child verifies them, spends the proof once, and the
        // caller stays itself (WILL-PLAN L14 row 01). Any other bearer
        // terminated at the supervisor; a legacy or dev claim never selects a
        // principal, so a request with neither a slip nor an attestation is
        // anonymous: only the public doors serve it, never as the host's root
        // (FIX 2222).
        crate::auth::forward_caller_credentials(request.headers_mut());
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
    // A call a held socket carries finishes there as that socket's connection.
    let carried = request
        .extensions()
        .get::<CarriedConnection>()
        .map(|carried| carried.0);
    tokio::spawn(async move {
        let _admission = admission;
        let run = run_admitted_request(state, request, next);
        match carried {
            Some(connection) => crate::api::call_receipt::on_connection(connection, run).await,
            None => run.await,
        }
    })
    .await
    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// The answer to an owner attestation managed ingress could not verify on
/// `path`: refused, named, with nothing served in the owner's place.
pub(super) fn owner_attestation_refused(path: &str) -> Response {
    let error = crate::auth::owner_attestation_refused();
    if path.starts_with("/v1/") {
        crate::error::EnvelopedApiError::from(error).into_response()
    } else {
        error.into_response()
    }
}

async fn run_admitted_request(
    state: Arc<ManagedState>,
    mut request: Request,
    next: Next,
) -> Response {
    if request.headers().contains_key(UPGRADE) {
        // Admitted, and out of sight from here on. A freeze with one of these
        // behind it is not quiescent, and `prepare_reap` is where that is
        // answered for — this gate cannot refuse a frame it never sees.
        state.admit_sync_upgrade();
        // A held MCP socket admits each call it carries here again, and each
        // receipt it writes outside one (FIX 5128).
        request
            .extensions_mut()
            .insert(ManagedCarrierContext(Arc::clone(&state)));
    }
    // Observation does not wake the vault. Explicit lifecycle calls own their
    // transition so their completion receipt reports what they actually did.
    let lifecycle_observation = match (request.method().as_str(), request.uri().path()) {
        ("GET", "/api/health") => true,
        ("POST", path) => matches!(
            path,
            "/v1/core/facade/vault.slim.policy"
                | "/v1/core/facade/vault.slim.state"
                | "/v1/core/facade/vault.slim.resume_step"
                | "/v1/core/facade/vault.slim.drop_heavy"
                | "/v1/core/facade/vault.slim.resume"
        ),
        _ => false,
    };
    if !lifecycle_observation && let Err(error) = state.server.vault().resume_from_slim_on_inbound()
    {
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
/// construction: `reap_abort` lifts it and the same request succeeds. The
/// fields beside it name the bound (K18): the service's vault lifecycle
/// allocation while it prepares a reap, what waits, what lifts it, and that a
/// self-hosted vault has no such limit. Each comes from the same
/// [`REAP_PAUSE_REFUSAL`] a ctl refusal carries, so the two cannot drift.
fn writes_frozen_response(error: &ManagedError) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(writes_frozen_body(error)),
    )
        .into_response()
}

/// [`writes_frozen_response`]'s body.
fn writes_frozen_body(error: &ManagedError) -> serde_json::Value {
    let refusal = REAP_PAUSE_REFUSAL;
    serde_json::json!({
        "error": refusal.error,
        "message": error.to_string(),
        "bound": refusal.bound,
        "temporary": refusal.temporary,
        "affected": ["effects", "non_safe_method_requests", "upgrades", "background_passes"],
        "resumes_on": refusal.resumes_on,
        "self_hosted": {
            "supported": refusal.self_hosted_supported,
            "condition": "no_service_reap_limit",
        },
    })
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
/// mirror beside it; a new one where no vault is yet and `maximum_tier`
/// (`--maximum-tier`, else the settings file's) opted in; none for a plain
/// vault, which stays plain (no converter).
fn managed_page_seal(
    managed: &ManagedArgs,
    maximum_tier: bool,
    dek: &[u8; 32],
) -> anyhow::Result<Option<oneiron::VaultPageSeal>> {
    let path = &managed.data_dir;
    if oneiron::world_keys::vault_is_sealed(path)? {
        return Ok(Some(oneiron::world_keys::reopen_delivered_page_seal(
            path, dek,
        )?));
    }
    if !maximum_tier {
        return Ok(None);
    }
    if path.join("data.mdb").exists() {
        tracing::warn!(
            "the maximum tier is chosen when a vault is created; this plain vault opens plain"
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
    // The supervisor names a personal vault's owner by the contract's copy of
    // the embedded owner's id; a copy that drifted stops the boot here.
    super::vault_gates::check_embedded_owner_holder()?;
    let mut config = managed.serve_config(args);
    // The owner's settings file, refused leaf by leaf and settled once,
    // before anything reads the configuration: its `[oneironer]` arms the
    // write-time marker in `vault_config` below. Tracing starts between its
    // refusal and its settling, at the level the settled configuration runs
    // at (argv over the file), so what settling decides is logged.
    let settings = super::settings::prepare(&managed, args, &mut config)?;
    init_managed_tracing(super::settings::log_level(settings.as_ref(), &config));
    super::settings::settle(settings, &mut config)?;
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

    // The contract requires the credential frame to be read before the data
    // directory is opened, so a refused frame never touches storage.
    let credentials = oneiron_vault_contract::Credentials {
        dek: host.secret("dek")?.as_slice().try_into()?,
        token: host.secret("spawn_token")?.as_slice().try_into()?,
    };
    let mut vault_config = config.vault_config();
    // Our cloud hosts this vault. The owner's "Help improve Oneiron" and
    // training choices stand as the supervisor passed them; an unset export
    // takes the managed default, and unset training follows the export.
    vault_config.failure_signals.deployment =
        oneiron::config::failure_signals::DeploymentTier::Managed;
    // Set before the open: LMDB takes the page key with the environment.
    vault_config.page_seal = managed_page_seal(&managed, config.maximum_tier, &credentials.dek)?;
    // The live seal opens the live vault and creates none: a rehearsal's
    // scratch takes a fresh incarnation of it (`owner::backup`).
    let mut rehearsal_config = vault_config.clone();
    rehearsal_config.page_seal = None;
    let vault = Arc::new(open_managed_vault(
        &managed.data_dir,
        vault_config,
        &managed.vault_name,
        &credentials,
        managed.derivation_owner,
    )?);

    let mut server_config = config.sync_server_config();
    server_config.lease_vault_id = super::vault_gates::managed_lease_scope(&vault)?;
    // The supervisor authenticates ingress on the socket it owns, and this
    // process attests the owner on each route: a request with no credential
    // is anonymous. The Linear mirror checks this declaration, not a secret.
    server_config.ingress = crate::config::IngressAuth::Supervisor;
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
    // The owner's embedding spaces and kind slots, as plain serve applies them.
    if let Some(embedding) = &config.embedding {
        embedding.apply_to(&vault)?;
    }
    // The owner's backups and restore rehearsals, on the tenant's own disk
    // beside the data directory, as plain serve keeps them beside its vault.
    let owner_host = super::owner_storage::owner_host(&config, rehearsal_config);
    // A direct `[linear]` mirror's response custody, private beside them.
    super::owner_storage::linear_responses(&config);
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
    // worker starts under the write admission too.
    let tagger = crate::oneironer::build_slot_off_runtime(config.oneironer.clone()).await?;
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
                .map(crate::config::BrowserConfig::guest),
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
        }));
    sync_server.managed_issuer = Some(issuer);
    if managed.artifact_socket.is_some() {
        sync_server = sync_server.with_artifact_socket();
    }
    // Model seats, the Dreamer and the decision ladder from `[models]`, as
    // plain serve attaches them: a vault the owner's `[device_sync]` makes a
    // device of another home never claims the MACRO home. A startup error
    // below drops `ai`, which tells its workers to stop.
    let (sync_server, ai) = crate::ai_host::AiHost::attach_device(
        sync_server,
        config.models.as_ref(),
        config.device_sync.is_some(),
    )
    .await;
    // The Dreamer's passes are admitted like a served write, and refused
    // until the managed state below exists.
    let reap_gate = Arc::new(std::sync::OnceLock::<Arc<ManagedState>>::new());
    ai.bind_pass_admission({
        let gate = Arc::clone(&reap_gate);
        Arc::new(move || gate.get()?.admit_background())
    });
    let sync_server = Arc::new(sync_server);
    // An answered code consent wait's effect runs on this server, as plain
    // serve installs it, before the connector settler starts (DOOR-079 1a).
    crate::code_consent_host::ServerCodeConsentHost::install(&sync_server);
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
    // A public live voice session (`ai.voice.start`) holds an admission like
    // a served write, as a voice loop call does: a session in flight keeps a
    // reap from finding the vault quiescent, and a frozen vault opens none.
    // One no call named for a minute releases it until the next call names
    // it. Bound before anything serves.
    sync_server
        .live_voice
        .admit_with(state.background_admission());

    spawn_sigterm_shutdown(shutdown.clone())?;
    // The receipts every vault signs (ARCH-0066 §8-§9), each admitted through
    // the reap freeze like a served write: a frozen vault signs nothing, and a
    // reap never reads quiescent over a set in flight. The first set comes
    // before ctl is served, so no reap can freeze the vault ahead of it.
    let oversight = sync_server
        .start_healer_oversight(crate::server::HEALER_OVERSIGHT_EVERY, {
            let state = Arc::clone(&state);
            move || state.admit_background()
        })
        .await?;
    // Fact hooks (ARCH-0080) and the settled verb-ask drain on their runner,
    // unless `--no-hooks`: each pass admitted like a served write. The sandbox
    // loads before ready, as plain serve loads it, so no verb waits on it.
    let (hooks_stop, hooks_stopped) = watch::channel(false);
    #[cfg(feature = "code-sandbox-wasmtime")]
    let fact_hooks = if config.hooks {
        crate::commands::spawn_fact_hooks(&sync_server, state.background_admission(), hooks_stopped)
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

    // The owner's `[linear]` mirror and webhook mapping, as plain serve
    // starts them, each pass admitted like a served write and holding it
    // through its sends and settlement. Settings it cannot use stop the
    // start here, before ctl serves or the supervisor hears ready.
    let linear = crate::linear_host::spawn_configured(
        Arc::clone(&sync_server),
        state.background_admission(),
    )
    .await?;

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
    let background = sync_server.spawn_serve_background(state.background_admission());
    // Surface events drain under the same admission (OF-218).
    let connector_events = sync_server.spawn_connector_event_worker(state.background_admission());
    // Approved sends leave under the same admission (OF-187).
    let connector_sends = sync_server.spawn_connector_send_worker(state.background_admission());
    // Checked built-in channels, under the same admission (OF-519).
    let builtin_host = crate::builtin_host::spawn(&sync_server, state.background_admission());
    // Failure signals reach our collector under the same admission (OF-380).
    // Managed mode reads no environment, so the send carries no bearer.
    let failure_signals = crate::ai_host::failure_signals::spawn(
        &sync_server,
        crate::ai_host::failure_signals::FailureSignalHost::new(
            &config.failure_signals,
            true,
            None,
        ),
        state.background_admission(),
    );
    // The ladder's workers plain serve runs. Wire health and the standing
    // pump pass under the same admission.
    let admitted = || state.background_admission();
    // The nightly Coach jobs that need the host's model or rules (OF-420).
    let coach_host = crate::ai_host::coach_host::spawn(&sync_server, admitted());
    // Crossed thresholds ask the ladder whether everything is okay (OF-520).
    let mut ladder_workers = vec![crate::wire_health::spawn(&sync_server, admitted())];
    // The Linear mirror started before ready stops with the ladder.
    ladder_workers.extend(linear);
    // An accepted Coach person-threshold row goes live on the ladder (Q3).
    ladder_workers.extend(crate::decision_host::spawn_person_threshold_admitted(
        &sync_server,
        admitted(),
    ));
    // Pending vectors are filled while the vault admits writes (FIX 777).
    ladder_workers.extend(sync_server.spawn_embedding_worker_admitted(admitted()));
    // Witnessed turns' tagging markers drain under the same admission.
    ladder_workers.extend(sync_server.spawn_tagging_worker_admitted(admitted()));
    // Stored media is embedded under the same admission (OF-370).
    ladder_workers.extend(sync_server.spawn_media_embedding_worker_admitted(admitted()));
    // Queued and resumed agent runs, each admitted with its permit (OF-533).
    ladder_workers.extend(sync_server.spawn_resident_pump_admitted(admitted()));
    // Held and answered connector calls settle (ONE-2510).
    ladder_workers.push(sync_server.spawn_connector_settler_admitted(admitted()));
    // The owner's `[backup]` schedule: each tick is admitted like a served
    // write and holds it through its backup and pruning.
    ladder_workers.extend(
        sync_server
            .spawn_backup_schedule_admitted(crate::owner::schedule::SCHEDULE_TICK, admitted()),
    );
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
        admitted(),
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
    // A vault that is a device of another home dials it, on that mesh when
    // the home has a paired address there, as plain serve does (WILL-PLAN
    // L14 row 14): the owner's `[device_sync]` or `oneiron device enrol`
    // names the home. The connection holds one admission for its whole run,
    // so a frozen vault starts none and a reap waits for it.
    let device_sync = crate::device_sync::DeviceSyncHost::start_admitted(
        &sync_server,
        &config,
        mesh.as_ref(),
        &admitted(),
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
