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

mod lane_events;
use lane_events::{LaneMark, RefusedUpgrades, lane_observer};

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
    /// The home sync endpoint, for the leave POST's transport guard: a
    /// non-direct URL keeps its retained reads but never sends the slip.
    home_url: String,
    /// Strong: the host keeps the env open for archive reads and the owed
    /// orphan-body collect. The last handle drop closes the env.
    vault: Arc<Vault>,
    /// Retained for leave checks and idempotent purge resume, whether or not a
    /// sync lane is running. Left envs never start a run on this connection.
    connection: Arc<SyncConnection>,
    /// None once the env has left (or left before this process opened it).
    lane: Option<ActiveLane>,
    /// The confirmed receipt finished every replica purge batch. The owed
    /// orphan-body collect continues independently in housekeeping.
    purge_complete: bool,
    /// The last unix second a leave check ran clean (`None` answered).
    /// Failures leave the stamp alone, so they retry on the next round.
    last_leave_check: u64,
    /// The lane's 401 upgrades, and those a clean check covers (FIX 12442).
    refused: RefusedUpgrades,
}

/// One opened env before its run starts: the vault, its leave state read, and
/// the connection leave checks keep even after the sync lane ends.
struct OpenedEnv {
    key: SharedEnvKey,
    path: PathBuf,
    home_url: String,
    vault: Arc<Vault>,
    connection: Arc<SyncConnection>,
    left: bool,
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

impl SharedEnvRegistry {
    /// An empty registry: no configured envs, or before [`Self::open_all`].
    pub(crate) fn empty() -> Self {
        Self::default()
    }

    /// Opens every configured env, runs each unleft lane, and returns the
    /// registry holding them. A malformed entry and a bad env (a missing
    /// dir, an unreadable leave state, an unreadable lane slip, an
    /// unbuildable lane, or an unleft non-loopback `ws://` home) each log
    /// one line and are skipped; serve runs on without them. A first admission refused
    /// by a reap freeze waits for thaw instead. A repeated membership keeps
    /// its first entry.
    ///
    /// `config` is the serve config the personal vault opened with. Each env
    /// gets a fresh `config.vault_config()` and its own page seal resolved for
    /// its path, existing roots only (a mistyped path refuses, it never mints
    /// a vault). `lease_vault_id` is the host's
    /// numeric lease scope, the same id the served vault's materializer
    /// carries. `admission` admits each env's first lane run, held through
    /// the whole run. `freeze` pauses lane runs for reap: `None` on
    /// plain/embedded (one run each), `Some` on managed (runs pause and
    /// resume with fresh admissions). Blocking opens run off the async
    /// worker.
    pub(crate) async fn open_all(
        entries: Vec<crate::config::SharedEnvConfig>,
        config: &crate::config::ServeConfig,
        lease_vault_id: u64,
        admission: crate::server::HousekeepingAdmission,
        freeze: Option<crate::device_sync::ReapFreeze>,
    ) -> Self {
        let registry = Self::empty();
        for entry in entries {
            registry
                .insert(
                    &entry,
                    config,
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
    /// malformed entry, failures, and repeated memberships log and leave the
    /// registry as it was. A refused first admission defers only the lane run;
    /// the opened env still joins housekeeping and wake scheduling.
    pub(crate) async fn insert(
        &self,
        entry: &crate::config::SharedEnvConfig,
        config: &crate::config::ServeConfig,
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
        let config = config.clone();
        let opened =
            tokio::task::spawn_blocking(move || open_one(&spec, &config, lease_vault_id)).await;
        match opened {
            Ok(Ok(env)) => {
                let lane = if env.left {
                    // Already left: no run needs an admission.
                    None
                } else {
                    let first = admission();
                    let (stop, stop_rx) = tokio::sync::oneshot::channel();
                    let task = tokio::spawn(run_lane(
                        Arc::clone(&env.connection),
                        stop_rx,
                        freeze,
                        first,
                        LaneMark::new(self, env.key.clone()),
                    ));
                    Some(ActiveLane {
                        connection: Arc::clone(&env.connection),
                        stop,
                        task,
                        vault_id: env.key.0,
                    })
                };
                // A completed purge stays complete across restarts: the
                // receipt persists it, so reconfirming never re-owes the
                // orphan-body collection. An unreadable receipt reads as
                // incomplete: the idempotent confirmation resumes it.
                let purge_complete =
                    match oneiron::sync::shared_leave::leave_purge_complete(&env.vault) {
                        Ok(complete) => complete,
                        Err(error) => {
                            tracing::warn!(
                                vault_id = env.key.0,
                                kind = ?error.kind(),
                                "shared env purge state unreadable; its leave reconfirms"
                            );
                            false
                        }
                    };
                self.lock().insert(
                    env.key,
                    SharedEnvEntry {
                        path: env.path,
                        home_url: env.home_url,
                        vault: env.vault,
                        connection: env.connection,
                        lane,
                        purge_complete,
                        last_leave_check: 0,
                        refused: RefusedUpgrades::default(),
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

    /// One leave-check round, called from the lifecycle tick: every env
    /// without a completed purge gets one bounded confirmation task. An
    /// already-recorded leave calls the same idempotent confirmation again,
    /// so an interrupted purge resumes instead of looking complete. The
    /// caller holds each handle so shutdown joins the checks. A refusal or
    /// failure (a 401 included) warns and retries, never reads as a leave.
    pub(crate) fn leave_check_round(&self, now: u64) -> Vec<tokio::task::JoinHandle<()>> {
        let due: Vec<(SharedEnvKey, Arc<Vault>, Arc<SyncConnection>, bool, u64)> = {
            let envs = self.lock();
            envs.iter()
                .filter_map(|(key, entry)| {
                    if entry.purge_complete
                        || (now.saturating_sub(entry.last_leave_check) < LEAVE_CHECK_EVERY_SECS
                            && !entry.refused.owed())
                    {
                        return None;
                    }
                    // The transport guard holds for every leave POST, not
                    // just the open-time lane build: a non-direct home URL
                    // keeps its retained reads but never sends the slip.
                    let direct = direct_home_url(&entry.home_url, key.0).is_ok();
                    Some((
                        key.clone(),
                        Arc::clone(&entry.vault),
                        Arc::clone(&entry.connection),
                        direct,
                        entry.refused.seen(),
                    ))
                })
                .collect()
        };
        let mut checks = Vec::with_capacity(due.len());
        for (key, vault, connection, direct, refused) in due {
            if !direct {
                // Throttled like a clean round, so the misconfiguration
                // warns hourly instead of every tick; the purge stays
                // unconfirmed until the URL is direct.
                self.note_leave_check(&key, now, refused);
                tracing::warn!(
                    vault_id = key.0,
                    "shared env home_url is not direct; its leave check stays unsent"
                );
                continue;
            }
            // A receipt is not purge completion: every recorded left gets the
            // same idempotent confirmation again until it finishes.
            match oneiron::sync::shared_leave::has_left(&vault) {
                Ok(_) => checks.push(self.spawn_leave_check(key, connection, now, refused)),
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
        for lane in lanes {
            let vault_id = lane.vault_id;
            let _ = lane.stop.send(());
            if let Err(error) = lane.task.await {
                tracing::warn!(vault_id = vault_id, %error, "shared env lane task");
            }
        }
        let envs = std::mem::take(&mut *self.lock());
        drop(envs);
    }

    /// One env's check: the POST, bounded; the outcome applied back to the
    /// registry from the task itself. A clean answer covers the `refused`
    /// 401 upgrades its round read.
    fn spawn_leave_check(
        &self,
        key: SharedEnvKey,
        connection: Arc<SyncConnection>,
        now: u64,
        refused: u64,
    ) -> tokio::task::JoinHandle<()> {
        let this = self.clone();
        let (vault_id, member) = key.clone();
        tokio::spawn(async move {
            let check = connection.check_shared_leave(vault_id, &member);
            match tokio::time::timeout(LEAVE_CHECK_TIMEOUT, check).await {
                Ok(Ok(Some(receipt))) => {
                    this.note_purge_complete(&key, now);
                    this.detach_lane(&key);
                    tracing::info!(
                        vault_id = vault_id,
                        kind = ?receipt.kind,
                        "shared env left; its lane is detached and its vault stays open"
                    );
                }
                Ok(Ok(None)) => this.note_leave_check(&key, now, refused),
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

    /// Marks the confirmed receipt's full replica purge complete. Owed
    /// orphan-body collection continues in housekeeping after this point.
    fn note_purge_complete(&self, key: &SharedEnvKey, now: u64) {
        if let Some(entry) = self.lock().get_mut(key) {
            entry.purge_complete = true;
            entry.last_leave_check = now;
        }
    }

    /// Notes a clean check round for one env: its next check is an hour
    /// out, unless a 401 upgrade came after the round read `refused`.
    /// Failures leave both alone, so they retry next round.
    fn note_leave_check(&self, key: &SharedEnvKey, now: u64, refused: u64) {
        if let Some(entry) = self.lock().get_mut(key) {
            entry.last_leave_check = now;
            entry.refused.covered(refused);
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
/// run, paused across reap freezes like device sync's. `first` is the
/// admission the insert could take, or `None` while frozen: that lane waits
/// for the thaw before its first run. Each admission is held only through
/// its run, and a stop while paused ends the task there. An ordinary end —
/// disconnect, stop, error — is never a leave: only the leave check's
/// confirmed receipt detaches, and this task only ends.
async fn run_lane(
    connection: Arc<SyncConnection>,
    mut stop: tokio::sync::oneshot::Receiver<()>,
    mut freeze: Option<crate::device_sync::ReapFreeze>,
    first: Option<Box<dyn Send>>,
    mark: LaneMark,
) {
    let vault_id = mark.vault_id();
    // Dropped only once the run it admits has ended; none while paused.
    let mut _admitted: Option<Box<dyn Send>> = first;
    if _admitted.is_none() {
        let Some(freeze) = freeze.as_mut() else {
            tracing::warn!(
                vault_id = vault_id,
                "shared env lane's first run is not admitted"
            );
            return;
        };
        let Some(admitted) = freeze.resumed(&mut stop).await else {
            tracing::info!(
                vault_id = vault_id,
                "shared env lane stopped before its first run"
            );
            return;
        };
        _admitted = Some(admitted);
        tracing::info!(vault_id = vault_id, "shared env lane starts after the thaw");
    }
    // How one run ended short of its own end.
    enum End {
        Stop,
        Done(Result<(), String>),
        Pause,
    }
    loop {
        let (stop_run, ended) = tokio::sync::oneshot::channel();
        let run = connection.run_observed(ended, lane_observer(mark.clone()));
        tokio::pin!(run);
        let outcome = match freeze.as_mut() {
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
        match outcome {
            End::Stop => {
                let _ = stop_run.send(());
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
                let _ = stop_run.send(());
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
        host.eq_ignore_ascii_case("localhost")
            || host
                .trim_matches(['[', ']'])
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
/// The vault opens existing-only; the home URL's direct-dial rule gates only
/// an unleft lane, never a left env's retained housekeeping. `Err` is one log
/// line for the caller; it names the path and vault id, never member/slip/secret.
fn open_one(
    spec: &SharedEnvSpec,
    config: &crate::config::ServeConfig,
    lease_vault_id: u64,
) -> Result<OpenedEnv, String> {
    let vault_id = spec.vault_id;
    let mut resolved = config.vault_config();
    let mut serve_path = config.clone();
    serve_path.vault_path = spec.path.clone();
    serve_path.maximum_tier = false;
    resolved.page_seal = if oneiron::world_keys::vault_is_sealed(&spec.path)
        .map_err(|error| format!("shared env {vault_id} seal state unreadable: {error:#}"))?
    {
        crate::commands::page_seal_at(&serve_path, &spec.path, None).map_err(|error| {
            format!("shared env {vault_id} page seal did not resolve: {error:#}")
        })?
    } else {
        // A personal seal never crosses into another env, sealed or plain.
        None
    };
    let key: SharedEnvKey = (vault_id, spec.member.clone());
    // Existing-only, but process-owned: precheck the vault file so a typo
    // never creates one, then take the same writer lease every served vault
    // holds. `open_existing` would skip that lease (FIX 2051).
    if !spec.path.join("data.mdb").is_file() {
        return Err(format!(
            "open {}: no existing vault (data.mdb is missing)",
            spec.path.display()
        ));
    }
    let vault = oneiron::Vault::open_owned(&spec.path, resolved)
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
    if !left {
        direct_home_url(&spec.home_url, vault_id)?;
    }
    // Left or not, this connection stays for idempotent leave confirmation;
    // only unleft entries start a sync run on it.
    let connection = open_lane(Arc::clone(&vault), spec, lease_vault_id)?;
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
        home_url: spec.home_url.clone(),
        vault,
        connection,
        left,
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
        Arc::clone(&vault),
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
    let residence_selector = shared_residence_selector(&vault, &credential.token)?;
    let residence_mode = if residence_selector.is_some() {
        oneiron::sync::SyncResidenceMode::Opened
    } else {
        // No live member grant: full replication has no Opened selector
        // gate. A saved Opened preference would still override this
        // fallback inside `SyncConnection::new` and fail every reconnect
        // with no selector, so the lane records All for a vault it owns
        // while open.
        let saved =
            oneiron::sync::residence::load_device_sync_preference(&vault).map_err(|error| {
                format!("shared env {vault_id} residence preference unreadable: {error:#}")
            })?;
        if saved.is_some_and(|preference| preference.mode != oneiron::sync::SyncResidenceMode::All)
        {
            oneiron::sync::residence::set_device_sync_preference(
                &vault,
                oneiron::sync::SyncResidenceMode::All,
            )
            .map_err(|error| {
                format!("shared env {vault_id} residence preference not writable: {error:#}")
            })?;
        }
        oneiron::sync::SyncResidenceMode::All
    };
    let client_config = SyncClientConfig {
        server_url: spec.home_url.clone(),
        residence_mode,
        transport_credential: Some(oneiron::sync::SyncTransportCredential::new(
            credential.token.clone(),
            key.clone(),
        )),
        note_session: Some(oneiron::sync::client::NoteSyncSession::new(
            credential.token,
            key,
        )),
        residence_selector,
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

/// The own-device member grant the paired slip names, for residence reads.
/// Never inferred from the home's root or peer bytes.
fn shared_residence_selector(
    vault: &oneiron::Vault,
    token: &str,
) -> Result<Option<oneiron::sync::SyncSelector>, String> {
    let slip = oneiron::authority::CapabilitySlip::from_token(token)
        .map_err(|error| format!("lane slip of shared env unusable: {error:#}"))?;
    let claims = &slip.claims;
    let Some(grant) = claims.grant_ref.as_deref() else {
        return Ok(None);
    };
    let grant = oneiron::EntityId::from_hex(grant)
        .map_err(|_| "the paired credential's grant_ref is not an entity id".to_owned())?;
    let holder = oneiron::EntityId::from_hex(&claims.holder_ref)
        .map_err(|_| "the paired credential's holder is not an actor".to_owned())?;
    let live_grant = vault
        .get_raw(&grant)
        .map_err(|error| format!("paired grant unreadable: {error:#}"))?
        .is_some_and(|raw| {
            raw.first() == Some(&oneiron_contracts::registry::ENTITY_TYPE_FEDERATION_GRANT)
        })
        && !vault
            .is_deleted_shell(&grant)
            .map_err(|error| format!("paired grant liveness unreadable: {error:#}"))?;
    if !live_grant {
        return Ok(None);
    }
    Ok(Some(oneiron::sync::SyncSelector::new(
        grant,
        holder,
        oneiron::sync::SyncSelectorWorld::All,
        Vec::new(),
        Vec::new(),
    )))
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
