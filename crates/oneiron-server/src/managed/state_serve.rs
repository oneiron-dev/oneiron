//! Managed runtime state, the reap freeze gate, and the supervised serve loop.

use std::future::Future;
use std::io::ErrorKind;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use axum::Json;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode, header::UPGRADE};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use oneiron_vault_contract::ManagedWidenAction;
use oneiron_vault_contract::{
    CONTRACT_VERSION, ManagedBackupFacts, ManagedReadiness, REAP_PAUSE_REFUSAL, UnixTs, now_ts,
};
// The test module below names the ctl request and response through `use
// super::*`; the dispatcher that names them lives in `control` and `reap`.
#[cfg(test)]
use oneiron_vault_contract::{CtlRequest, CtlResponse};
use tokio::sync::{Mutex, watch};

use crate::build_app;
use crate::config::ServeArgs;
use crate::server::SyncServer;

use super::args::{ManagedArgs, ManagedError};
use super::ledger::{SYNC_UPGRADE_SETTLE_SECS, WakeLedger};
use super::listener::{BoundServeListener, ManagedCtl, ServeListener};
use super::vault_gates::{open_managed_vault, provision_host_authority};
#[cfg(target_os = "linux")]
use super::vm_guest;
use super::{
    attested_routes, backup_facts, host, owner_stage, owner_storage, restore, settings, vault_gates,
};
use admission::WriteKind;
use boot_keys::{escrow_vault_key, managed_page_seal, spool_vault_key_escrow};
use oneiron_vault_contract::host::{Host, HostLimits};
use read_only::is_read_only;
use refusal::writes_frozen_body;

/// The reap freeze's write admission, held until a write's last write.
mod admission;
/// The vault data key's boot steps: its page seal, escrow wraps and spool.
mod boot_keys;
/// A vault VM's live look at its outbox companion and the escrow
/// recipients its carrier delivers (FIX 6683, FIX 6684).
#[cfg(target_os = "linux")]
mod carrier_watch;
/// The ctl dispatcher, [`ManagedState::handle_request`].
mod control;
/// Supervised boot, serve and shutdown: [`serve_managed`].
mod coordinator;
/// The backup before an idle reap (`prepare_idle_reap`).
mod idle_backup;
/// The managed routers and the reap freeze gate in front of them.
mod ingress;
/// Whether a frozen vault may still answer a request.
mod read_only;
/// The reap freeze and `prepare_reap`'s freeze, drain and export.
mod reap;
/// The body a frozen engine's refusal is served with.
mod refusal;
/// The relay delete ctl requests (FIX 6826).
mod relay_delete;

pub use self::coordinator::serve_managed;
pub use self::ingress::build_managed_app;
pub(super) use self::ingress::build_managed_artifact_app;
pub(super) use self::ingress::owner_attestation_refused;

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
    /// The reap freeze and the admitted writes in flight, by kind; a backup
    /// before an idle reap counts among them.
    admission: Arc<admission::Admission>,
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
    /// How the vault came up, as every `Ping` reports it (WILL-PLAN L14 row
    /// 17): set once at boot, before ctl serves.
    readiness: ManagedReadiness,
    /// What the vault reports of its backups on every `Ping` (Engine 10-20
    /// row (b)): set once at boot, before ctl serves. `None` until set, which
    /// a supervisor reads as unknown.
    backup_facts: Option<ManagedBackupFacts>,
    /// The vault VM outbox carrier's revision, as every `Ping` reports it
    /// (FIX 5235): set at boot, then as its companion answers each look
    /// (FIX 6683); 0 for none, on a node or while no companion answers.
    vm_outbox_revision: AtomicU32,
    /// The cold restore this process kept, which `restore_status` answers
    /// for: set once at boot, before ctl serves; `None` for an open.
    restore: Option<Arc<super::restore::RestoreOutcome>>,
    /// The backup before an idle reap, one attempt at a time.
    idle_backup: Arc<idle_backup::IdleBackup>,
    /// The relay locker deletes this engine executes (FIX 6826).
    relay_delete: Arc<super::relay_delete::RelayDeleteExecutor>,
}

/// A supervisor-signed account action, not the child process's host-root slip.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ManagedWidenHolder(pub(crate) oneiron::EntityId);

/// The vault owner a supervisor-signed `ManagedOwnerAction` names for one
/// request, verified at ingress; never the host root.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ManagedOwnerHolder(pub(crate) oneiron::EntityId);

/// The person a supervisor-signed `ManagedPersonAction` names for one
/// request at a member door (FIX 1302), verified at ingress; never the
/// owner and never the host root.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ManagedPersonHolder(pub(crate) oneiron::EntityId);

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

/// The connection a held socket's call arrived on, as
/// [`ManagedCarrierContext::carry`] marked it.
#[derive(Clone, Copy)]
struct CarriedConnection(u128);

/// The reap freeze's refusal of a held socket's write
/// ([`ManagedCarrierContext::admit_receipt`]): the pause a served write gets
/// ([`ingress::writes_frozen_response`]), as the status and body the socket answers
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
/// `/v1/llm/defaults/proposals`, `/v1/ai/waves/{attempt}` and
/// `/v1/ai/video/{job}`, each with its HEAD
/// (FIX 9496); `POST /v1/core/pairing/links`, `/v1/core/slips/revoke`,
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
    if super::attested_routes::registered_method_matches(method, Method::GET.as_str()) {
        matches!(
            path,
            "/api/search/vector"
                | "/api/search/text"
                | "/api/core/discover"
                | "/v1/llm/defaults"
                | "/v1/llm/defaults/proposals"
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
            admission: Arc::default(),
            last_sync_upgrade: AtomicU64::new(0),
            alarms: Mutex::new(Vec::new()),
            ledger,
            background_waiting: AtomicBool::new(false),
            voice_actions: std::sync::Mutex::default(),
            readiness: ManagedReadiness::Ready,
            backup_facts: None,
            vm_outbox_revision: AtomicU32::new(0),
            restore: None,
            idle_backup: Arc::default(),
            relay_delete: Arc::default(),
        }
    }

    /// This state with `readiness`, how the vault came up, for every `Ping`
    /// to report; `Ready` until set.
    #[must_use]
    pub fn with_readiness(mut self, readiness: ManagedReadiness) -> Self {
        self.readiness = readiness;
        self
    }

    /// This state with `facts`, what the vault reports of its backups, for
    /// every `Ping` to carry; none until set.
    #[must_use]
    pub fn with_backup_facts(mut self, facts: ManagedBackupFacts) -> Self {
        self.backup_facts = Some(facts);
        self
    }

    /// This state with `restore`, the cold restore this start kept, for
    /// `restore_status` to answer for.
    #[must_use]
    pub(super) fn with_restore(
        mut self,
        restore: Option<Arc<super::restore::RestoreOutcome>>,
    ) -> Self {
        self.restore = restore;
        self
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

    pub fn vault_name(&self) -> &str {
        &self.vault_name
    }

    pub fn ledger(&self) -> &WakeLedger {
        &self.ledger
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
}

/// The last thing the supervisor hears from this process.
///
/// Rev-ordered, through the same push-on-change path a running engine uses,
/// and that is the whole point of not hand-rolling it here. [`LedgerUpdate`](oneiron_vault_contract::LedgerUpdate)
/// is a full replacement ordered by `rev`: a shutdown snapshot carrying
/// entries that moved since the last accepted push — a job that became ready,
/// a lease that changed — has to advance the revision, or a supervisor that
/// drops `rev <= last_acked` drops precisely the snapshot this exit exists to
/// deliver. An unchanged report (entries and training setting) sends nothing,
/// because the supervisor already holds that snapshot at that revision.
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
