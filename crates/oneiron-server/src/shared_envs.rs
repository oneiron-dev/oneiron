//! The host's dedicated shared-env registry (FIX 2051, FIX 11136): the
//! membership → env map a member device keeps its shared envs open through.
//!
//! Each entry holds one dedicated env strongly: its open [`Vault`] handle
//! plus, while the membership stands, its own sync lane. A confirmed leave
//! detaches the lane and keeps the handle, so post-leave removal-archive
//! reads and the owed orphan-body collect still have an open vault. Nothing
//! here is durable: restarts rebuild the registry from explicit host config,
//! left-ness is re-derived from each env's own receipt, and the owed collect
//! is the engine's own row. No second sync subsystem: leave checks run on
//! the engine's [`SyncConnection`], housekeeping runs on the engine's pass.
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

/// One env's sync lane: the retained connection the leave checks run on.
/// The connection holds the env's own manager (and through it the
/// materializer) alive, so dropping the lane frees all three. Never run
/// here: no steady loop, no renewal, no residence registration.
struct ActiveLane {
    connection: Arc<SyncConnection>,
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

    /// Opens every configured env and returns the registry holding them. A
    /// bad env (an unopenable dir, an unreadable leave state, an unreadable
    /// lane slip, an unbuildable lane) logs one line and is skipped; serve
    /// runs on without it. A repeated membership keeps its first entry.
    ///
    /// `vault_config` is the same engine config the served vault opened
    /// with (dimensions, map size, embedding space, seal); each env vault
    /// opens with a clone of it. `lease_vault_id` is the host's numeric
    /// lease scope, the same id the served vault's materializer carries.
    /// Blocking opens run off the async worker.
    pub(crate) async fn open_all(
        specs: Vec<SharedEnvSpec>,
        vault_config: &oneiron::VaultConfig,
        lease_vault_id: u64,
    ) -> Self {
        let registry = Self::empty();
        for spec in specs {
            registry.insert(&spec, vault_config, lease_vault_id).await;
        }
        registry
    }

    /// Opens one env and inserts it: the singular open behind [`Self::open_all`],
    /// and the seam the future join flow calls once it has enrolled a new
    /// membership. Failures and repeated memberships log and leave the
    /// registry as it was.
    pub(crate) async fn insert(
        &self,
        spec: &SharedEnvSpec,
        vault_config: &oneiron::VaultConfig,
        lease_vault_id: u64,
    ) {
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
        let spec = spec.clone();
        let vault_config = vault_config.clone();
        let opened =
            tokio::task::spawn_blocking(move || open_one(&spec, &vault_config, lease_vault_id))
                .await;
        match opened {
            Ok(Ok((key, entry))) => {
                self.lock().insert(key, entry);
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

    /// Stops the registry at shutdown: every lane first, so each connection
    /// detaches before any vault handle drops (the FIX 5772 order), then
    /// every vault handle. Async so the call site reads beside
    /// `DeviceSyncHost::stop().await`; the lanes were never run, so dropping
    /// them is the whole shutdown and nothing is awaited.
    #[allow(clippy::unused_async, reason = "async by call-site contract")]
    pub(crate) async fn stop(&self) {
        let lanes: Vec<ActiveLane> = {
            let mut envs = self.lock();
            envs.values_mut()
                .filter_map(|entry| entry.lane.take())
                .collect()
        };
        drop(lanes);
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
    /// detach a confirmed leave runs. Left-ness from then on is the env's
    /// own durable receipt, read through `has_left`.
    fn detach_lane(&self, key: &SharedEnvKey) {
        let mut envs = self.lock();
        let Some(entry) = envs.get_mut(key) else {
            return;
        };
        if entry.lane.take().is_some() {
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

/// Opens one validated spec: the vault, its leave state, and (while
/// unleft) its lane. `Err` is one log line for the caller; it names the
/// path and the vault id, never the member, the slip, or the credential.
fn open_one(
    spec: &SharedEnvSpec,
    vault_config: &oneiron::VaultConfig,
    lease_vault_id: u64,
) -> Result<(SharedEnvKey, SharedEnvEntry), String> {
    let vault_id = spec.vault_id;
    let key: SharedEnvKey = (vault_id, spec.member.clone());
    let vault = oneiron::Vault::open_owned(&spec.path, vault_config.clone())
        .map_err(|error| format!("open {path}: {error:#}", path = spec.path.display()))?;
    let vault = Arc::new(vault);
    // The canonical dir, for diagnostics; the open created it when it was
    // missing, so this reads back what the open holds.
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
    Ok((
        key,
        SharedEnvEntry {
            path,
            vault,
            lane,
            last_leave_check: 0,
        },
    ))
}

/// One env's lane: its own materializer and manager over its own vault
/// (mirroring `server/core/construction.rs`), and the retained connection
/// the leave checks run on. Its credential binds the transport and the
/// NOTE session alike, as the device lane's does. A failure past the
/// attach needs no cleanup: the vault holds only a `Weak` manager, and
/// the vault handle drops with this error.
fn open_lane(
    vault: Arc<Vault>,
    spec: &SharedEnvSpec,
    lease_vault_id: u64,
) -> Result<ActiveLane, String> {
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
    Ok(ActiveLane {
        connection: Arc::new(connection),
    })
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
