//! The host's dedicated shared-env registry (FIX 2051, FIX 11136): the
//! membership → env map a member device keeps its shared envs open through.
//!
//! Each entry holds one dedicated env strongly: its open [`Vault`] handle
//! plus, while the membership stands, its own sync lane. A confirmed leave
//! detaches the lane and keeps the handle, so post-leave removal-archive
//! reads and the owed orphan-body collect still have an open vault. Nothing
//! here is durable: restarts rebuild the registry from explicit host config,
//! left-ness is re-derived from each env's own receipt, and the owed collect
//! is the engine's own row. No second sync subsystem: leave checks and lane
//! runs both go through the engine's [`SyncConnection`], housekeeping runs
//! on the engine's pass.
//!
//! Each active lane runs: its own reconnecting `run_observed` loop under a
//! host admission, paused across reap freezes on managed vaults exactly as
//! device sync pauses. An ordinary run end — disconnect, stop, error — is
//! never a leave; only the leave check's confirmed receipt detaches.
//!
//! Integration (the lead wires these; this module only defines them):
//! open at each serve startup from the configured entries, run
//! [`SharedEnvRegistry::leave_check_round`] from the lifecycle tick and hold
//! its tasks in `HousekeepingPasses`, enumerate
//! [`SharedEnvRegistry::vault_handles`] in the housekeeping passes, fold
//! [`SharedEnvRegistry::housekeeping_wake_at`] into the managed wake
//! ledger's `housekeeping` entry, and [`SharedEnvRegistry::stop`] beside
//! `DeviceSyncHost::stop` at shutdown.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use oneiron::Vault;
use oneiron::sync::ConnectionConfig;
use oneiron::sync::SyncClientConfig;
use oneiron::sync::SyncConnection;
use oneiron::sync::WindowManager;
use oneiron::sync::bridge::Materializer;

/// How often one env's membership is re-checked: leave is rare, and each
/// check is one authenticated POST per membership.
const LEAVE_CHECK_EVERY_SECS: u64 = 3600;

/// How long one leave check may hold its round's task. `check_shared_leave`
/// builds a client with no timeout of its own; the bound lives here so a
/// hung home cannot stall the tick. Cancellation lands only at the check's
/// awaits; once the engine's confirm starts it is synchronous and runs to
/// completion, and its resume path is idempotent anyway.
const LEAVE_CHECK_TIMEOUT: Duration = Duration::from_secs(30);

/// The window-loader user id, the same label-only value the served vault's
/// construction passes (`server/windows.rs` `SERVER_USER_ID`, which is
/// `pub(super)` and not visible here). The loader does not key storage by
/// user, so this is a label only.
const SHARED_ENV_USER_ID: &str = "server";

/// One validated shared-env entry: [`crate::config::SharedEnvConfig`] past
/// [`SharedEnvSpec::from_config`], with the member normalized to the
/// lowercase hex the leave receipts name.
#[derive(Clone, Debug)]
pub(crate) struct SharedEnvSpec {
    pub(crate) path: PathBuf,
    pub(crate) vault_id: u64,
    pub(crate) member: String,
    pub(crate) home_url: String,
    pub(crate) credential_file: PathBuf,
}

// Staged: the lead's serve/managed/embedded integration calls this next.
#[allow(dead_code, reason = "staged for the lead's integration")]
impl SharedEnvSpec {
    /// Validates one configured entry. `Err` is a malformed entry: the
    /// caller logs and skips it, and serve runs on without that env.
    pub(crate) fn from_config(entry: &crate::config::SharedEnvConfig) -> anyhow::Result<Self> {
        entry.validate()?;
        let member = oneiron::EntityId::from_hex(entry.member.trim())
            .map(|member| member.to_hex())
            .map_err(|_| {
                anyhow::anyhow!("[shared_env] member is not a person id (32 hex characters)")
            })?;
        Ok(Self {
            path: entry.path.clone(),
            vault_id: entry.vault_id,
            member,
            home_url: entry.home_url.clone(),
            credential_file: entry.credential_file.clone(),
        })
    }
}

/// The membership a leave check names: the shared vault id and the member.
type SharedEnvKey = (u64, String);

/// One env's sync lane: the retained connection the leave checks run on,
/// the stop that ends its run, and the run task itself. The connection
/// holds the env's own manager (and through it the materializer) alive, so
/// dropping the lane frees all three. No renewal, no residence
/// registration: the run only syncs and ends.
struct ActiveLane {
    connection: Arc<SyncConnection>,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
    vault_id: u64,
}

struct SharedEnvEntry {
    /// The canonical env dir, for diagnostics.
    path: PathBuf,
    /// Strong: the host keeps the env open for archive reads and the owed
    /// orphan-body collect. The last handle drop closes the env.
    vault: Arc<Vault>,
    /// None once the env has left (or left before this process opened it).
    lane: Option<ActiveLane>,
    /// The last unix second a leave check ran clean (`None` answered).
    /// Failures leave the stamp alone, so they retry on the next round.
    last_leave_check: u64,
}

/// One opened env before its run starts: the vault, its leave state read,
/// and (while unleft) the constructed lane connection.
struct OpenedEnv {
    key: SharedEnvKey,
    path: PathBuf,
    vault: Arc<Vault>,
    lane: Option<Arc<SyncConnection>>,
}

#[derive(Default)]
struct SharedEnvInner {
    envs: Mutex<HashMap<SharedEnvKey, SharedEnvEntry>>,
}

/// The dedicated shared envs this host keeps open, keyed by membership.
/// A cloneable handle over one short-locked map: leave-check tasks hold a
/// clone so they can detach and re-throttle without borrowing the server.
#[derive(Clone, Default)]
pub(crate) struct SharedEnvRegistry {
    inner: Arc<SharedEnvInner>,
}

// Staged: the lead's serve/managed/embedded integration calls these next.
#[allow(dead_code, reason = "staged for the lead's integration")]
impl SharedEnvRegistry {
    /// An empty registry: no configured envs, or before [`Self::open_all`].
    pub(crate) fn empty() -> Self {
        Self::default()
    }

    /// Opens every configured env, runs each unleft lane, and returns the
    /// registry holding them. A malformed entry and a bad env (a missing
    /// dir, an unreadable leave state, an unreadable lane slip, an
    /// unbuildable lane, a refused first admission, a non-loopback `ws://`
    /// home) each log one line and are skipped; serve runs on without
    /// them. A repeated membership keeps its first entry.
    ///
    /// `vault_config` is the same engine config the served vault opened
    /// with (dimensions, map size, embedding space, seal); each env vault
    /// opens with a clone of it, existing roots only (a mistyped path
    /// refuses, it never mints a vault). `lease_vault_id` is the host's
    /// numeric lease scope, the same id the served vault's materializer
    /// carries. `admission` admits each env's first lane run, held through
    /// the whole run. `freeze` pauses lane runs for reap: `None` on
    /// plain/embedded (one run each), `Some` on managed (runs pause and
    /// resume with fresh admissions). Blocking opens run off the async
    /// worker.
    pub(crate) async fn open_all(
        entries: Vec<crate::config::SharedEnvConfig>,
        vault_config: &oneiron::VaultConfig,
        lease_vault_id: u64,
        admission: crate::server::HousekeepingAdmission,
        freeze: Option<crate::device_sync::ReapFreeze>,
    ) -> Self {
        let registry = Self::empty();
        for entry in entries {
            registry
                .insert(
                    &entry,
                    vault_config,
                    lease_vault_id,
                    admission.clone(),
                    freeze.clone(),
                )
                .await;
        }
        registry
    }

    /// Opens one configured entry, runs its lane unless it has left, and
    /// inserts it: the singular open behind [`Self::open_all`], and the seam
    /// the future join flow calls once it has enrolled a new membership. A
    /// malformed entry, failures, refused admissions, and repeated
    /// memberships log and leave the registry as it was.
    pub(crate) async fn insert(
        &self,
        entry: &crate::config::SharedEnvConfig,
        vault_config: &oneiron::VaultConfig,
        lease_vault_id: u64,
        admission: crate::server::HousekeepingAdmission,
        freeze: Option<crate::device_sync::ReapFreeze>,
    ) {
        let spec = match SharedEnvSpec::from_config(entry) {
            Ok(spec) => spec,
            Err(error) => {
                tracing::warn!("shared env skipped: {error:#}");
                return;
            }
        };
        let present = self
            .lock()
            .contains_key(&(spec.vault_id, spec.member.clone()));
        if present {
            tracing::warn!(
                vault_id = spec.vault_id,
                path = %spec.path.display(),
                "shared env skipped: its membership is already open"
            );
            return;
        }
        let Some(first) = admission() else {
            tracing::warn!(
                vault_id = spec.vault_id,
                "shared env skipped: its first run is not admitted"
            );
            return;
        };
        let vault_config = vault_config.clone();
        let opened =
            tokio::task::spawn_blocking(move || open_one(&spec, &vault_config, lease_vault_id))
                .await;
        match opened {
            Ok(Ok(env)) => {
                let lane = match env.lane {
                    Some(connection) => {
                        let (stop, stop_rx) = tokio::sync::oneshot::channel();
                        let task = tokio::spawn(run_lane(
                            Arc::clone(&connection),
                            stop_rx,
                            freeze,
                            first,
                            env.key.0,
                        ));
                        Some(ActiveLane {
                            connection,
                            stop,
                            task,
                            vault_id: env.key.0,
                        })
                    }
                    None => {
                        // Already left: no run to hold the admission.
                        drop(first);
                        None
                    }
                };
                self.lock().insert(
                    env.key,
                    SharedEnvEntry {
                        path: env.path,
                        vault: env.vault,
                        lane,
                        last_leave_check: 0,
                    },
                );
            }
            Ok(Err(reason)) => tracing::warn!("shared env skipped: {reason}"),
            Err(error) => tracing::warn!("shared env skipped: its open task failed: {error}"),
        }
    }

    /// One clone per open env, under a single short lock: the housekeeping
    /// tick runs its per-handle passes over these.
    pub(crate) fn vault_handles(&self) -> Vec<Arc<Vault>> {
        self.lock()
            .values()
            .map(|entry| Arc::clone(&entry.vault))
            .collect()
    }

    /// The earliest wake any open env owes, for the managed wake ledger's
    /// `housekeeping` entry (folded with the served vault's own wake by the
    /// caller). An env whose wake cannot be read warns and is skipped: one
    /// unreadable env must not silence the others' wakes.
    pub(crate) fn housekeeping_wake_at(&self) -> Option<u64> {
        let mut earliest: Option<u64> = None;
        for vault in self.vault_handles() {
            match vault.housekeeping_wake_at() {
                Ok(Some(at)) => earliest = Some(earliest.map_or(at, |seen| seen.min(at))),
                Ok(None) => {}
                Err(error) => tracing::warn!(
                    kind = ?error.kind(),
                    "shared env wake unreadable; its owed collections wait for the next pass"
                ),
            }
        }
        earliest
    }

    /// One leave-check round, called from the lifecycle tick: for each env
    /// that still has a lane, is due its hourly check, and has not left,
    /// one task runs `SyncConnection::check_shared_leave` under a bounded
    /// host-side timeout. The caller holds each handle (in
    /// `HousekeepingPasses`) so shutdown joins the checks. A confirmed
    /// leave detaches the lane and keeps the vault handle; a refusal or
    /// failure (a 401 included) warns and retries on the next round, and is
    /// never read as a leave.
    pub(crate) fn leave_check_round(&self, now: u64) -> Vec<tokio::task::JoinHandle<()>> {
        let due: Vec<(SharedEnvKey, Arc<Vault>, Arc<SyncConnection>)> = {
            let envs = self.lock();
            envs.iter()
                .filter_map(|(key, entry)| {
                    let lane = entry.lane.as_ref()?;
                    if now.saturating_sub(entry.last_leave_check) < LEAVE_CHECK_EVERY_SECS {
                        return None;
                    }
                    Some((
                        key.clone(),
                        Arc::clone(&entry.vault),
                        Arc::clone(&lane.connection),
                    ))
                })
                .collect()
        };
        let mut checks = Vec::with_capacity(due.len());
        for (key, vault, connection) in due {
            // Left-ness is re-derived, never stored: one cheap read per due env.
            match oneiron::sync::shared_leave::has_left(&vault) {
                Ok(true) => {
                    // The lane should already be gone (a confirmed check
                    // drops it); drop a drifted one now rather than
                    // checking again.
                    self.detach_lane(&key);
                }
                Ok(false) => checks.push(self.spawn_leave_check(key, connection, now)),
                Err(error) => tracing::warn!(
                    vault_id = key.0,
                    kind = ?error.kind(),
                    "shared env leave state unreadable; retry next round"
                ),
            }
        }
        checks
    }

    /// Stops the registry at shutdown: each lane's stop is sent, each run
    /// task awaited, and only then the vault handles dropped (the FIX 5772
    /// order: connections detach before the mesh closes and before any
    /// handle drops).
    pub(crate) async fn stop(&self) {
        let lanes: Vec<ActiveLane> = {
            let mut envs = self.lock();
            envs.values_mut()
                .filter_map(|entry| entry.lane.take())
                .collect()
        };
        for lane in &lanes {
            let _ = lane.stop.send(());
        }
        for lane in lanes {
            let vault_id = lane.vault_id;
            if let Err(error) = lane.task.await {
                tracing::warn!(vault_id = vault_id, %error, "shared env lane task");
            }
        }
        let envs = std::mem::take(&mut *self.lock());
        drop(envs);
    }

    /// One env's check: the POST, bounded; the outcome applied back to the
    /// registry from the task itself.
    fn spawn_leave_check(
        &self,
        key: SharedEnvKey,
        connection: Arc<SyncConnection>,
        now: u64,
    ) -> tokio::task::JoinHandle<()> {
        let this = self.clone();
        let (vault_id, member) = key.clone();
        tokio::spawn(async move {
            let check = connection.check_shared_leave(vault_id, &member);
            match tokio::time::timeout(LEAVE_CHECK_TIMEOUT, check).await {
                Ok(Ok(Some(receipt))) => {
                    this.detach_lane(&key);
                    tracing::info!(
                        vault_id = vault_id,
                        kind = ?receipt.kind,
                        "shared env left; its lane is detached and its vault stays open"
                    );
                }
                Ok(Ok(None)) => this.note_leave_check(&key, now),
                Ok(Err(error)) => tracing::warn!(
                    vault_id = vault_id,
                    reason = leave_check_refusal(&error),
                    "shared env leave check failed; retry next round"
                ),
                Err(_) => tracing::warn!(
                    vault_id = vault_id,
                    "shared env leave check timed out; retry next round"
                ),
            }
        })
    }

    /// Drops one env's lane and keeps its vault handle: the host-side
    /// detach a confirmed leave runs. The run task ends on its own once the
    /// loop sees the stop (the leave already quiesced it); its handle is
    /// dropped, not awaited. Left-ness from then on is the env's own
    /// durable receipt, read through `has_left`.
    fn detach_lane(&self, key: &SharedEnvKey) {
        let mut envs = self.lock();
        let Some(entry) = envs.get_mut(key) else {
            return;
        };
        if let Some(lane) = entry.lane.take() {
            let _ = lane.stop.send(());
            tracing::debug!(
                vault_id = key.0,
                path = %entry.path.display(),
                "shared env lane detached; vault stays open"
            );
        }
    }

    /// Notes a clean check round for one env: its next check is an hour
    /// out. Failures leave the stamp alone, so they retry next round.
    fn note_leave_check(&self, key: &SharedEnvKey, now: u64) {
        if let Some(entry) = self.lock().get_mut(key) {
            entry.last_leave_check = now;
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<SharedEnvKey, SharedEnvEntry>> {
        self.inner
            .envs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Drives one env's lane until `stop`: the connection's own reconnecting
/// run, paused across reap freezes like device sync's. `first` is admitted
/// before the first run and held until it ends; each run past a thaw takes
/// a fresh admission from the freeze, and a stop while paused ends the task
/// there. An ordinary end — disconnect, stop, error — is never a leave:
/// only the leave check's confirmed receipt detaches, and this task only
/// ends.
async fn run_lane(
    connection: Arc<SyncConnection>,
    mut stop: tokio::sync::oneshot::Receiver<()>,
    mut freeze: Option<crate::device_sync::ReapFreeze>,
    first: Box<dyn Send>,
    vault_id: u64,
) {
    // Dropped only once the run it admits has ended; none while paused.
    let mut _admitted: Option<Box<dyn Send>> = Some(first);
    // How one run ended short of its own end.
    enum End {
        Stop,
        Done(Result<(), String>),
        Pause,
    }
    loop {
        let (end, ended) = tokio::sync::oneshot::channel();
        let run = connection.run_observed(ended, lane_observer(vault_id));
        tokio::pin!(run);
        let end = match freeze.as_mut() {
            Some(freeze) => tokio::select! {
                biased;
                _ = &mut stop => End::Stop,
                ran = &mut run => End::Done(ran.map_err(|error| error.to_string())),
                () = freeze.frozen() => End::Pause,
            },
            None => tokio::select! {
                biased;
                _ = &mut stop => End::Stop,
                ran = &mut run => End::Done(ran.map_err(|error| error.to_string())),
            },
        };
        match end {
            End::Stop => {
                let _ = end.send(());
                match run.await {
                    Ok(()) => tracing::debug!(vault_id = vault_id, "shared env lane stopped"),
                    Err(error) => {
                        tracing::warn!(vault_id = vault_id, %error, "shared env lane stopped")
                    }
                }
                return;
            }
            End::Done(ran) => {
                match ran {
                    Ok(()) => tracing::debug!(vault_id = vault_id, "shared env lane run ended"),
                    Err(error) => {
                        tracing::warn!(vault_id = vault_id, %error, "shared env lane run ended")
                    }
                }
                return;
            }
            End::Pause => {
                let _ = end.send(());
                if let Err(error) = run.await {
                    tracing::warn!(
                        vault_id = vault_id,
                        %error,
                        "shared env lane run ended at the reap pause"
                    );
                }
                _admitted = None;
                tracing::info!(
                    vault_id = vault_id,
                    "shared env lane paused: the vault is frozen for reap"
                );
                let freeze = freeze.as_mut().expect("paused only with a freeze");
                let Some(admitted) = freeze.resumed(&mut stop).await else {
                    tracing::info!(vault_id = vault_id, "shared env lane stopped");
                    return;
                };
                _admitted = Some(admitted);
                tracing::info!(
                    vault_id = vault_id,
                    "shared env lane resumes: the vault thawed"
                );
            }
        }
    }
}

/// One lane's event observer: errors to the log, statuses to debug, the
/// rest ignored. A sync error here is never a leave.
fn lane_observer(vault_id: u64) -> impl FnMut(oneiron::sync::SyncEvent) + Send {
    move |event| match event {
        oneiron::sync::SyncEvent::StatusChanged(status) => {
            tracing::debug!(vault_id = vault_id, ?status, "shared env lane");
        }
        oneiron::sync::SyncEvent::Error(error) => {
            tracing::warn!(vault_id = vault_id, %error, "shared env lane");
        }
        _ => {}
    }
}

/// The direct-dial rule device sync dials by, applied before an env's
/// lane is built: `wss`, or `ws` to a loopback host. The leave check POSTs
/// the lane slip to the http(s) twin of this URL, so a `ws://` shared home
/// off this machine would send the slip over cleartext. `Err` skips the
/// env.
fn direct_home_url(home_url: &str, vault_id: u64) -> Result<(), String> {
    let uri: axum::http::Uri = home_url
        .parse()
        .map_err(|_| format!("shared env {vault_id} home_url is not a URL"))?;
    let loopback = uri.host().is_some_and(|host| {
        host.trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    });
    if uri.scheme_str() == Some("wss") || loopback {
        Ok(())
    } else {
        Err(format!(
            "shared env {vault_id} home_url must be wss:// (or ws:// to a loopback host)"
        ))
    }
}

/// Opens one validated spec: the vault, its leave state, and (while
/// unleft) its constructed lane connection. The caller starts the run.
/// The vault opens existing-only, and the home URL passes the direct-dial
/// rule first. `Err` is one log line for the caller; it names the path and
/// the vault id, never the member, the slip, or the credential.
fn open_one(
    spec: &SharedEnvSpec,
    vault_config: &oneiron::VaultConfig,
    lease_vault_id: u64,
) -> Result<OpenedEnv, String> {
    let vault_id = spec.vault_id;
    direct_home_url(&spec.home_url, vault_id)?;
    let key: SharedEnvKey = (vault_id, spec.member.clone());
    let vault = oneiron::Vault::open_existing(&spec.path, vault_config.clone())
        .map_err(|error| format!("open {path}: {error:#}", path = spec.path.display()))?;
    let vault = Arc::new(vault);
    // The canonical dir, for diagnostics; the open refuses a missing root,
    // so this reads back what the open holds.
    let path = spec
        .path
        .canonicalize()
        .unwrap_or_else(|_| spec.path.clone());
    let left = oneiron::sync::shared_leave::has_left(&vault)
        .map_err(|error| format!("shared env {vault_id} left state unreadable: {error:#}"))?;
    let lane = if left {
        None
    } else {
        Some(open_lane(Arc::clone(&vault), spec, lease_vault_id)?)
    };
    if left {
        tracing::info!(
            vault_id = vault_id,
            path = %path.display(),
            "shared env open: already left, no lane"
        );
    } else {
        tracing::info!(
            vault_id = vault_id,
            path = %path.display(),
            "shared env open"
        );
    }
    Ok(OpenedEnv {
        key,
        path,
        vault,
        lane,
    })
}

/// One env's lane connection: its own materializer and manager over its own
/// vault (mirroring `server/core/construction.rs`), and the retained
/// connection the run and the leave checks drive. Its credential binds the
/// transport and the NOTE session alike, as the device lane's does. A
/// failure past the attach needs no cleanup: the vault holds only a `Weak`
/// manager, and the vault handle drops with this error.
fn open_lane(
    vault: Arc<Vault>,
    spec: &SharedEnvSpec,
    lease_vault_id: u64,
) -> Result<Arc<SyncConnection>, String> {
    let vault_id = spec.vault_id;
    let manager = Arc::new(WindowManager::new(
        vault,
        Arc::new(Materializer::with_lease_vault_id(lease_vault_id)),
        SHARED_ENV_USER_ID,
    ));
    manager.attach_to_vault();
    let credential =
        crate::commands::credential_file::PairedCredentialFile::read(&spec.credential_file)
            .map_err(|error| format!("lane slip unreadable: {error:#}"))?;
    let key = credential
        .signing_key()
        .map_err(|error| format!("lane slip of shared env {vault_id} unusable: {error:#}"))?;
    let client_config = SyncClientConfig {
        server_url: spec.home_url.clone(),
        transport_credential: Some(oneiron::sync::SyncTransportCredential::new(
            credential.token.clone(),
            key.clone(),
        )),
        note_session: Some(oneiron::sync::client::NoteSyncSession::new(
            credential.token,
            key,
        )),
        ..SyncClientConfig::default()
    };
    let connection = SyncConnection::new(
        Arc::clone(&manager),
        ConnectionConfig {
            client_config,
            auto_reconnect: true,
        },
    )
    .map_err(|error| format!("lane of shared env {vault_id} unbuildable: {error:#}"))?;
    Ok(Arc::new(connection))
}

/// The check's failure, as a static kind only: a refusal's own fixed
/// words, anything else a bare kind. Nothing request-shaped is logged.
fn leave_check_refusal(error: &oneiron::sync::TransportError) -> &'static str {
    use oneiron::sync::TransportError;
    match *error {
        TransportError::InvalidPayload(reason) => reason,
        TransportError::InvalidWindowKey
        | TransportError::IndexRevisionChanged
        | TransportError::UnknownTag(_)
        | TransportError::FrameTooLarge { .. }
        | TransportError::VersionVectorDecode
        | TransportError::WebSocket(_)
        | TransportError::ConnectionClosed
        | TransportError::Storage(_) => "request failed",
        TransportError::AdmissionDenied(_) => "admission denied",
    }
}
