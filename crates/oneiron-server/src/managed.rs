//! Managed serve mode: the vault engine as a supervised child process.
//!
//! The engine boots from argv, serves on a socket the supervisor bound, opens
//! its vault from supervisor-delivered credentials, answers control verbs,
//! exports its wake ledger, and exits cleanly on SIGTERM. Every wire type,
//! framing rule and limit comes from [`oneiron_vault_contract`], which both
//! sides of the seam build against; nothing here reshapes them.
//!
//! Three properties hold this module together, and each one is a fail-closed
//! default rather than a convention:
//!
//! - **Off by default.** Managed mode is reachable only through
//!   `--managed-by-hypnos`. Without it, [`crate::commands::serve`] never
//!   enters this module and the unmanaged path is exactly what it was.
//! - **Argv is the whole configuration.** Managed mode never consults a config
//!   file, the `ONEIRON_*` environment (including `ONEIRON_AUTH_SECRET` —
//!   bearer auth is the supervisor's job) or the XDG layers. It reads exactly
//!   one environment variable, [`HYPNOS_LISTEN_FD`], and even the dictionary
//!   search roots come from argv rather than the usual `HOME`/`XDG_*` probe.
//! - **The engine schedules nothing.** There is no timer here. Alarms are
//!   pushed by the supervisor over the ctl socket; the ledger tells it when to
//!   push them.
//!
//! Real tenant data is refused in contract v1. A managed open needs the
//! credential gate AND a synthetic-canary marker, because the isolation this
//! mode would need for real data — an fscrypt policy on the data directory and
//! a dedicated per-vault UID owning it — has no probe in this build. The
//! refusal is the tripwire that keeps the gap visible.

use std::future::Future;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode, header::UPGRADE};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use loro::{LoroValue, ValueOrContainer};
use oneiron::sync::lease::{self, LeaseStatus, ROOT_LEASES_MAP};
use oneiron_vault_contract::{
    CONTRACT_VERSION, Credentials, CtlRequest, CtlResponse, DEK_LEN, LedgerAck, LedgerUpdate,
    MAX_CTL_LINE, READY_BYTE, Schedule, TokenHex, UnixTs, WakeEntry, now_ts, read_credentials,
    valid_vault_name, validate_wake_entries,
};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, watch};
use tracing_subscriber::EnvFilter;

use crate::build_app;
use crate::config::{ServeArgs, ServeConfig};
use crate::server::SyncServer;

/// The one environment variable managed mode consults. When set, it names an
/// already-bound listening unix socket the supervisor passed across spawn.
pub const HYPNOS_LISTEN_FD: &str = "HYPNOS_LISTEN_FD";

/// Marks a vault as a synthetic canary: the only thing a contract-v1 managed
/// open will accept in place of the (unimplemented) hardened-tenant
/// preconditions.
pub const CANARY_MARKER_KEY: &str = "managed:canary:v1";
/// Value the canary marker row must carry, so a blank or truncated row is not
/// mistaken for consent.
pub const CANARY_MARKER_VALUE: &[u8] = b"managed:canary:v1";
/// Keyed MAC of the vault's `vault_meta` head page under the delivered DEK.
pub const DEK_MAC_KEY: &str = "managed:dek_mac:v1";
/// Wake-ledger revision, persisted so it survives a restart and comes back as
/// `ledger_rev`.
pub const LEDGER_REV_KEY: &str = "managed:ledger_rev:v1";

/// Machine-readable tag on the refusals a frozen engine serves, so a client can
/// match on it rather than parse prose.
///
/// [`ManagedError::WritesFrozen`] is the only thing that emits it. That is what
/// keeps "the reap freeze refused this" distinguishable from every other way
/// this surface can be briefly unavailable — a 503 without the tag is a
/// different outage and means a different response from the caller.
pub const WRITES_FROZEN_TAG: &str = "writes_frozen";

/// Domain separator for the DEK MAC, so the same DEK over the same bytes in
/// another role cannot collide with this one.
const DEK_MAC_CONTEXT: &[u8] = b"oneiron:managed:dek_mac:v1";
/// Socket directories are owner-only; the socket file itself is owner-rw.
const SOCKET_DIR_MODE: u32 = 0o700;
const SOCKET_FILE_MODE: u32 = 0o600;
/// A failing ledger push is retried exactly once, after this delay, and then
/// left behind. Exit must never block on a dead supervisor.
const LEDGER_RETRY_DELAY: Duration = Duration::from_millis(200);
/// How long one whole push attempt — connect, write, and the supervisor's ack —
/// may take before it is abandoned.
///
/// "Exactly one retry, then proceed" bounds nothing unless an attempt is itself
/// bounded, and none of those three steps is bounded on its own. A supervisor
/// that accepted the connection and then went quiet is indistinguishable from a
/// live one that is about to answer, so this is the width of that doubt: long
/// enough that a loaded-but-live supervisor still gets its ack in, short enough
/// that two attempts and one backoff stay well inside a shutdown grace.
const LEDGER_PUSH_TIMEOUT: Duration = Duration::from_secs(2);
/// Lease expiry is swept on a cadence rather than at an instant, so the wake
/// it asks for is a window of that width, not a point. Waking anywhere inside
/// it does the same work.
const LEASE_WAKE_WINDOW_SECS: u64 = 60;
/// How long a sync session that upgraded but has not spoken yet is assumed to
/// still be there.
///
/// Such a session holds nothing this module can count: it subscribes to the
/// broadcast fan-out only after its protocol hello, and the handler's own
/// hello deadline is what closes it if the hello never comes. This is that
/// deadline with margin, because a freeze would rather delay a reap by a few
/// seconds than report quiescence over a writer it cannot see.
const SYNC_UPGRADE_SETTLE_SECS: u64 = 15;
/// Stable ids for the exported wake entries. The supervisor keys on these.
const WAKE_ID_JOB_READY: &str = "job_ready";
const WAKE_ID_SYNC_DEADLINE: &str = "sync_deadline";

/// Every way managed mode refuses. All of them are typed: a caller can tell a
/// missing flag from a rejected credential from a real-tenant refusal without
/// matching on prose.
#[derive(Debug, thiserror::Error)]
pub enum ManagedError {
    #[error("--managed-by-hypnos requires --{flag}")]
    MissingFlag { flag: &'static str },

    #[error("--managed-by-hypnos conflicts with --{flag}: {reason}")]
    ConflictingFlag {
        flag: &'static str,
        reason: &'static str,
    },

    #[error(
        "unknown --contract-version {found}; this build speaks supervisor contract version {expected} only"
    )]
    UnknownContractVersion { found: u32, expected: u32 },

    #[error("--vault-name {name:?} is not a DNS label")]
    InvalidVaultName { name: String },

    #[error("--{flag} must be a non-negative file descriptor, got {value}")]
    InvalidFd { flag: &'static str, value: i32 },

    #[error("{env} must be a non-negative file descriptor, got {value:?}")]
    InvalidListenFd { env: &'static str, value: String },

    #[error(
        "{first} and {second} both name file descriptor {fd}: managed mode adopts each delivered descriptor with unique ownership, so an alias would close one owner's descriptor under the other or write the ready byte into a reused number"
    )]
    AliasedFd {
        first: &'static str,
        second: &'static str,
        fd: RawFd,
    },

    #[error(
        "refusing to bind a unix socket at {path:?}: that path already exists and is {kind}, not a socket. Binding replaces what is there, and this process does not own that inode."
    )]
    SocketPathOccupied { path: PathBuf, kind: &'static str },

    #[error("the supervisor did not acknowledge the wake ledger push within {after:?}")]
    LedgerAckTimeout { after: Duration },

    #[error("credentials fd rejected: {reason}")]
    CredentialsRejected { reason: String },

    #[error(
        "refusing to open vault {vault:?} in managed mode: vault_meta carries no `{marker}` marker, and the hardened real-tenant preconditions are absent (managed mode would need an fscrypt policy on the data directory AND a dedicated per-vault UID owning it, neither of which this build can probe). Contract v1 serves synthetic canary vaults only; this refusal is the real-tenant tripwire."
    )]
    ManagedRealTenantRefused { vault: String, marker: &'static str },

    #[error(
        "managed vault {vault:?} DEK MAC mismatch at `{key}`: the delivered DEK does not match the one this vault was sealed under. Refused before reading any content."
    )]
    DekMacMismatch { vault: String, key: &'static str },

    #[error("vault is frozen for reap; new writes are refused")]
    WritesFrozen,

    #[error("ctl line of {len} bytes exceeds the {cap}-byte cap; rejected whole")]
    CtlLineTooLong { len: usize, cap: usize },

    #[error("ctl request refused: {reason}")]
    CtlRequestRefused { reason: String },

    #[error("ledger update refused: {reason}")]
    LedgerRefused { reason: String },

    #[error("vault metadata: {0}")]
    VaultMeta(String),

    #[error("managed serve io: {0}")]
    Io(#[from] std::io::Error),
}

/// The managed argv group, validated. Reaching this type means every required
/// flag was present, the contract version is one this build speaks, and no
/// unmanaged configuration layer was requested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedArgs {
    pub vault_name: String,
    pub data_dir: PathBuf,
    pub http_socket: PathBuf,
    pub ctl_socket: PathBuf,
    pub hypnos_socket: PathBuf,
    pub ready_fd: RawFd,
    pub credentials_fd: RawFd,
}

impl ManagedArgs {
    /// Returns `None` when `--managed-by-hypnos` is absent — the whole
    /// off-by-default guarantee lives in this one early return.
    ///
    /// Validation order is deliberate: the contract version is checked first,
    /// so an engine spawned against a wire it does not speak exits non-zero
    /// before touching a descriptor, a socket or the data directory.
    pub fn from_serve_args(args: &ServeArgs) -> Result<Option<Self>, ManagedError> {
        if !args.managed_by_hypnos {
            return Ok(None);
        }

        let found = require(args.contract_version, "contract-version")?;
        if found != CONTRACT_VERSION {
            return Err(ManagedError::UnknownContractVersion {
                found,
                expected: CONTRACT_VERSION,
            });
        }
        reject_unmanaged_layers(args)?;

        let vault_name = require(args.vault_name.clone(), "vault-name")?;
        if !valid_vault_name(&vault_name) {
            return Err(ManagedError::InvalidVaultName { name: vault_name });
        }

        let managed = Self {
            vault_name,
            // `--vault-path` stays the alias for the same directory.
            data_dir: require(
                args.data_dir.clone().or_else(|| args.vault_path.clone()),
                "data-dir",
            )?,
            http_socket: require(args.http_socket.clone(), "http-socket")?,
            ctl_socket: require(args.ctl_socket.clone(), "ctl-socket")?,
            hypnos_socket: require(args.hypnos_socket.clone(), "hypnos-socket")?,
            ready_fd: require_fd(args.ready_fd, "ready-fd")?,
            credentials_fd: require_fd(args.credentials_fd, "credentials-fd")?,
        };
        // Non-negative is not enough. Both descriptors are adopted by owners
        // that close what they hold — `read_managed_credentials` and
        // `signal_ready` each take theirs over with `from_raw_fd` — so one
        // number on both flags is not a harmless duplicate: the credential
        // frame's descriptor is closed under the ready write, or the ready byte
        // lands in the number the supervisor is still reading credentials from.
        // Refused here, before either is consumed.
        refuse_fd_alias(
            ("--ready-fd", managed.ready_fd),
            ("--credentials-fd", managed.credentials_fd),
        )?;
        Ok(Some(managed))
    }

    /// Refuses an inherited listening descriptor that aliases either argv fd.
    ///
    /// Three inputs, three distinct owners: a `UnixListener` over the inherited
    /// socket, a `File` over the credential frame, a `File` over the ready
    /// pipe. Each closes what it holds on drop, so a listener that is also
    /// `--credentials-fd` is read as a credential frame and closed under the
    /// listener, and one that is also `--ready-fd` has the ready byte written
    /// into it. Called before adoption, so neither becomes reachable.
    pub fn refuse_listen_fd_alias(&self, listen_fd: RawFd) -> Result<(), ManagedError> {
        refuse_fd_alias((HYPNOS_LISTEN_FD, listen_fd), ("--ready-fd", self.ready_fd))?;
        refuse_fd_alias(
            (HYPNOS_LISTEN_FD, listen_fd),
            ("--credentials-fd", self.credentials_fd),
        )
    }

    /// Serve configuration for managed mode, built from argv alone.
    ///
    /// The fields read here are exactly the [`ArgvUse::Read`] rows of
    /// [`MANAGED_ARGV`] that are not part of the managed group — dimensions,
    /// map size, dictionary roots and log level. Everything else on
    /// `ServeArgs` is refused before this runs, so nothing reaches here to be
    /// quietly dropped.
    ///
    /// `auth_secret` stays `None` and unauthenticated requests are allowed:
    /// bearer auth terminates at the supervisor, which owns the listening
    /// socket inside an owner-only directory. Consulting
    /// `ONEIRON_AUTH_SECRET` here would give the child a second, weaker
    /// opinion about who may talk to it.
    pub fn serve_config(&self, args: &ServeArgs) -> ServeConfig {
        let defaults = ServeConfig::default();
        let mut config = ServeConfig {
            vault_path: self.data_dir.clone(),
            auth_secret: None,
            allow_unauthenticated: true,
            dimensions: args.dimensions.unwrap_or(defaults.dimensions),
            map_size: args.map_size.unwrap_or(defaults.map_size),
            // Argv only: the usual resolver probes HOME and the XDG roots,
            // which managed mode does not get to read.
            dict_search_paths: args.dict_search_paths.clone().unwrap_or_default(),
            ..defaults
        };
        if let Some(log_level) = args.log_level.clone() {
            config.log_level = log_level;
        }
        config
    }
}

fn require<T>(value: Option<T>, flag: &'static str) -> Result<T, ManagedError> {
    value.ok_or(ManagedError::MissingFlag { flag })
}

fn require_fd(value: Option<i32>, flag: &'static str) -> Result<RawFd, ManagedError> {
    let raw = require(value, flag)?;
    if raw < 0 {
        return Err(ManagedError::InvalidFd { flag, value: raw });
    }
    Ok(raw)
}

/// Refuses two descriptor inputs that name the same number.
///
/// Managed mode's descriptors arrive as bare integers and every adoption path
/// assumes it is the only owner of the one it was given. Uniqueness is
/// therefore a precondition of the spawn contract rather than a preference, and
/// this is where it is enforced — pairwise, on the inputs, before any of them
/// is opened, read or written.
fn refuse_fd_alias(
    (first, fd): (&'static str, RawFd),
    (second, other): (&'static str, RawFd),
) -> Result<(), ManagedError> {
    if fd == other {
        return Err(ManagedError::AliasedFd { first, second, fd });
    }
    Ok(())
}

const NO_HOST_PORT_REASON: &str =
    "managed mode serves the supervisor's socket, never a host:port bind";
const NO_CONFIG_LAYER_REASON: &str = "managed mode reads its whole configuration from argv; config files, ONEIRON_* environment and XDG layers are never consulted";
const NO_AUTH_LAYER_REASON: &str = "bearer auth terminates at the supervisor, which owns the listening socket inside an owner-only directory; a managed child holds no second opinion about who may talk to it";
const NO_TUNING_LAYER_REASON: &str = "managed mode builds its whole ServeConfig from the vault, dimension, dictionary and log-level flags; this one would be parsed and then dropped";

/// What managed mode does with one `ServeArgs` field.
#[derive(Debug, Clone, Copy)]
enum ArgvUse {
    /// Read: either part of the managed group itself or one of the four
    /// fields [`ManagedArgs::serve_config`] consults.
    Read,
    /// Belongs to a layer managed mode never consults, and is refused with
    /// this reason rather than accepted and dropped.
    Refused(&'static str),
}

/// One [`MANAGED_ARGV`] row: the flag as the operator types it, the probe that
/// says whether they typed it, and what managed mode does with it.
type ArgvRule = (&'static str, fn(&ServeArgs) -> bool, ArgvUse);

/// The whole `ServeArgs` surface in one table: the flag as the operator types
/// it, the probe that says whether they typed it, and what managed mode does
/// with it.
///
/// One allowlist drives both halves of the rule. The [`ArgvUse::Read`] rows
/// are exactly what the managed group and [`ManagedArgs::serve_config`] read;
/// [`reject_unmanaged_layers`] refuses every other row that was set. Before
/// this table the two halves were written separately, and the gap between them
/// was silent: clap accepted `--auth-secret` and `serve_config` dropped it, so
/// an operator who typed it got neither the setting nor an error.
const MANAGED_ARGV: &[ArgvRule] = &[
    // The managed group: argv is the whole configuration.
    (
        "config",
        |args| args.config.is_some(),
        ArgvUse::Refused(NO_CONFIG_LAYER_REASON),
    ),
    (
        "vault-path",
        |args| args.vault_path.is_some(),
        ArgvUse::Read,
    ),
    (
        "managed-by-hypnos",
        |args| args.managed_by_hypnos,
        ArgvUse::Read,
    ),
    (
        "contract-version",
        |args| args.contract_version.is_some(),
        ArgvUse::Read,
    ),
    (
        "vault-name",
        |args| args.vault_name.is_some(),
        ArgvUse::Read,
    ),
    ("data-dir", |args| args.data_dir.is_some(), ArgvUse::Read),
    (
        "http-socket",
        |args| args.http_socket.is_some(),
        ArgvUse::Read,
    ),
    (
        "ctl-socket",
        |args| args.ctl_socket.is_some(),
        ArgvUse::Read,
    ),
    (
        "hypnos-socket",
        |args| args.hypnos_socket.is_some(),
        ArgvUse::Read,
    ),
    ("ready-fd", |args| args.ready_fd.is_some(), ArgvUse::Read),
    (
        "credentials-fd",
        |args| args.credentials_fd.is_some(),
        ArgvUse::Read,
    ),
    // The bind: the supervisor's socket, never a host:port.
    (
        "host",
        |args| args.host.is_some(),
        ArgvUse::Refused(NO_HOST_PORT_REASON),
    ),
    (
        "port",
        |args| args.port.is_some(),
        ArgvUse::Refused(NO_HOST_PORT_REASON),
    ),
    // The auth layer: the supervisor's, not this child's.
    (
        "auth-secret",
        |args| args.auth_secret.is_some(),
        ArgvUse::Refused(NO_AUTH_LAYER_REASON),
    ),
    (
        "oauth-issuer",
        |args| args.oauth_issuer.is_some(),
        ArgvUse::Refused(NO_AUTH_LAYER_REASON),
    ),
    (
        "oauth-jwks-uri",
        |args| args.oauth_jwks_uri.is_some(),
        ArgvUse::Refused(NO_AUTH_LAYER_REASON),
    ),
    (
        "oauth-resource-indicator",
        |args| args.oauth_resource_indicator.is_some(),
        ArgvUse::Refused(NO_AUTH_LAYER_REASON),
    ),
    (
        "insecure-allow-unauthenticated",
        |args| args.insecure_allow_unauthenticated.is_some(),
        ArgvUse::Refused(NO_AUTH_LAYER_REASON),
    ),
    (
        "allowed-origins",
        |args| args.allowed_origins.is_some(),
        ArgvUse::Refused(NO_AUTH_LAYER_REASON),
    ),
    // The tuning layer: defaults, except the four fields below.
    (
        "lease-vault-id",
        |args| args.lease_vault_id.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "dimensions",
        |args| args.dimensions.is_some(),
        ArgvUse::Read,
    ),
    ("map-size", |args| args.map_size.is_some(), ArgvUse::Read),
    ("log-level", |args| args.log_level.is_some(), ArgvUse::Read),
    (
        "dict-search-paths",
        |args| args.dict_search_paths.is_some(),
        ArgvUse::Read,
    ),
    (
        "default-window-count",
        |args| args.default_window_count.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "compaction-threshold-bytes",
        |args| args.compaction_threshold_bytes.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "compaction-throttle-secs",
        |args| args.compaction_throttle_secs.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "bulk-chunk-size",
        |args| args.bulk_chunk_size.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "max-frame-size",
        |args| args.max_frame_size.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "max-update-payload",
        |args| args.max_update_payload.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "max-windows-per-connection",
        |args| args.max_windows_per_connection.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "max-federation-windows-per-connection",
        |args| args.max_federation_windows_per_connection.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "federation-flood-pause-secs",
        |args| args.federation_flood_pause_secs.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "max-messages-per-sec",
        |args| args.max_messages_per_sec.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "ephemeral-timeout-ms",
        |args| args.ephemeral_timeout_ms.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "max-ephemeral-payload-bytes",
        |args| args.max_ephemeral_payload_bytes.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "max-ephemeral-snapshot-bytes",
        |args| args.max_ephemeral_snapshot_bytes.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "max-entity-blob",
        |args| args.max_entity_blob.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "max-bulk-decompressed",
        |args| args.max_bulk_decompressed.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    // The runtime routing layer: a managed child routes nothing on its own.
    (
        "runtime-mode",
        |args| args.runtime_mode.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "runtime-byo-key-env",
        |args| args.runtime_byo_key_env.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "runtime-orchestrator-mode",
        |args| args.runtime_orchestrator_mode.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "runtime-orchestrator-provider-kind",
        |args| args.runtime_orchestrator_provider_kind.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "runtime-orchestrator-model",
        |args| args.runtime_orchestrator_model.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "runtime-subagent-mode",
        |args| args.runtime_subagent_mode.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "runtime-subagent-provider-kind",
        |args| args.runtime_subagent_provider_kind.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "runtime-subagent-model",
        |args| args.runtime_subagent_model.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "runtime-summarizer-mode",
        |args| args.runtime_summarizer_mode.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "runtime-summarizer-provider-kind",
        |args| args.runtime_summarizer_provider_kind.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "runtime-summarizer-model",
        |args| args.runtime_summarizer_model.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
];

/// Managed mode takes its whole configuration from argv, and reads only part
/// of it. A flag it does not read is not harmless: `--host` would move a bind
/// that the supervisor owns, `--config` would open a layer this mode never
/// consults, and `--auth-secret` would look like a second answer to "who may
/// talk to this vault" while changing nothing. So every field outside the
/// [`MANAGED_ARGV`] allowlist is a loud refusal that names the conflict rather
/// than a flag clap accepts and nothing honours.
fn reject_unmanaged_layers(args: &ServeArgs) -> Result<(), ManagedError> {
    for &(flag, is_set, use_of) in MANAGED_ARGV {
        if let ArgvUse::Refused(reason) = use_of
            && is_set(args)
        {
            return Err(ManagedError::ConflictingFlag { flag, reason });
        }
    }
    Ok(())
}

/// Where the HTTP surface listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeListener {
    /// Unmanaged `host:port` bind — today's serve path, unchanged.
    Tcp(SocketAddr),
    /// Managed self-bind fallback, used when no listen fd was inherited.
    UnixPath(PathBuf),
    /// A socket the supervisor bound and passed across spawn. This process
    /// never binds, unlinks or chmods the path behind it.
    InheritedFd(RawFd),
}

impl ServeListener {
    /// Resolves the managed HTTP listener.
    ///
    /// [`HYPNOS_LISTEN_FD`] is the only environment variable managed mode
    /// reads, and its absence is not an error — it selects the self-bind
    /// fallback on `--http-socket`.
    pub fn for_managed(args: &ManagedArgs) -> Result<Self, ManagedError> {
        match std::env::var(HYPNOS_LISTEN_FD) {
            Ok(raw) => {
                let fd: RawFd = raw
                    .trim()
                    .parse()
                    .map_err(|_| ManagedError::InvalidListenFd {
                        env: HYPNOS_LISTEN_FD,
                        value: raw.clone(),
                    })?;
                if fd < 0 {
                    return Err(ManagedError::InvalidListenFd {
                        env: HYPNOS_LISTEN_FD,
                        value: raw,
                    });
                }
                // Resolution, not adoption: this is the last point before the
                // descriptor becomes a `ServeListener` that `bind` will take
                // ownership of, so an alias of either argv fd is refused while
                // refusing still costs nothing.
                args.refuse_listen_fd_alias(fd)?;
                Ok(Self::InheritedFd(fd))
            }
            Err(std::env::VarError::NotPresent) => Ok(Self::UnixPath(args.http_socket.clone())),
            Err(std::env::VarError::NotUnicode(raw)) => Err(ManagedError::InvalidListenFd {
                env: HYPNOS_LISTEN_FD,
                value: raw.to_string_lossy().into_owned(),
            }),
        }
    }

    /// Binds — or, for an inherited fd, adopts — the listener this variant
    /// names. Consuming `self` is what makes double-adoption of the inherited
    /// descriptor unrepresentable.
    pub async fn bind(self) -> Result<BoundServeListener, ManagedError> {
        match self {
            Self::Tcp(addr) => Ok(BoundServeListener::Tcp(
                tokio::net::TcpListener::bind(addr).await?,
            )),
            Self::UnixPath(path) => {
                let listener = bind_unix_socket(&path)?;
                Ok(BoundServeListener::Unix {
                    listener,
                    owned_path: Some(path),
                })
            }
            Self::InheritedFd(fd) => Ok(BoundServeListener::Unix {
                listener: adopt_listen_fd(fd)?,
                owned_path: None,
            }),
        }
    }
}

/// A listener that is bound and ready to serve.
#[derive(Debug)]
pub enum BoundServeListener {
    Tcp(tokio::net::TcpListener),
    Unix {
        listener: UnixListener,
        /// `Some` only when this process created the socket file. An inherited
        /// socket's path belongs to the supervisor and must outlive us.
        owned_path: Option<PathBuf>,
    },
}

impl BoundServeListener {
    /// The socket path this process is responsible for removing, if any.
    pub fn owned_path(&self) -> Option<&Path> {
        match self {
            Self::Tcp(_) => None,
            Self::Unix { owned_path, .. } => owned_path.as_deref(),
        }
    }

    /// Serves until the process ends — the unmanaged shape.
    pub async fn serve(self, app: Router) -> std::io::Result<()> {
        match self {
            Self::Tcp(listener) => axum::serve(listener, app).await,
            Self::Unix { listener, .. } => axum::serve(listener, app).await,
        }
    }

    /// Serves until `shutdown` resolves, then stops accepting and drains
    /// in-flight requests.
    pub async fn serve_until(
        self,
        app: Router,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> std::io::Result<()> {
        match self {
            Self::Tcp(listener) => {
                axum::serve(listener, app)
                    .with_graceful_shutdown(shutdown)
                    .await
            }
            Self::Unix { listener, .. } => {
                axum::serve(listener, app)
                    .with_graceful_shutdown(shutdown)
                    .await
            }
        }
    }
}

/// Binds a unix socket this process owns: owner-only directory, owner-rw
/// socket file.
///
/// Binding replaces whatever is already at the path, and the path comes from
/// argv. A socket left behind by a previous run is exactly what that
/// replacement is for; anything else at that path is somebody's data, and
/// `--ctl-socket` one character off from a config or vault file would delete it
/// with no way back. So the gate below is the whole difference between reusing
/// a stale socket and destroying a file, and it runs before this function
/// creates or tightens a directory, so a mistyped path changes nothing at all.
fn bind_unix_socket(path: &Path) -> Result<UnixListener, ManagedError> {
    // `symlink_metadata`, not `metadata`: a symlink is refused as itself rather
    // than judged by what it points at, so a link aimed at a live socket cannot
    // talk this into unlinking a path it never inspected.
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(metadata) => {
            return Err(ManagedError::SocketPathOccupied {
                path: path.to_path_buf(),
                kind: node_kind(&metadata.file_type()),
            });
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(SOCKET_DIR_MODE))?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_FILE_MODE))?;
    Ok(listener)
}

/// Names what is at a path, so the refusal tells an operator what they hit
/// rather than only that they hit something.
fn node_kind(file_type: &std::fs::FileType) -> &'static str {
    if file_type.is_file() {
        "a regular file"
    } else if file_type.is_dir() {
        "a directory"
    } else if file_type.is_symlink() {
        "a symlink"
    } else if file_type.is_fifo() {
        "a fifo"
    } else if file_type.is_block_device() {
        "a block device"
    } else if file_type.is_char_device() {
        "a character device"
    } else {
        "another kind of node"
    }
}

/// Adopts a listening unix socket the supervisor already bound.
///
/// The child must not bind, unlink or chmod the path: the inode is the
/// supervisor's, and a child that recreated it would strand every connection
/// already queued on the original.
pub fn adopt_listen_fd(fd: RawFd) -> Result<UnixListener, ManagedError> {
    // SAFETY: `fd` arrives through the supervisor's spawn contract (the
    // HYPNOS_LISTEN_FD environment variable) and names a bound, listening unix
    // socket handed to this process for its whole lifetime. Ownership moves
    // here exactly once: `ServeListener::InheritedFd` is consumed by
    // `ServeListener::bind`, so no second adoption can double-own the
    // descriptor, and the std listener below closes it on drop.
    let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
    std_listener.set_nonblocking(true)?;
    Ok(UnixListener::from_std(std_listener)?)
}

/// Reads the 64-byte DEK ‖ spawn-token frame from the inherited fd.
///
/// Fail-closed: a short, long or unreadable frame is a typed refusal, never a
/// fallback to some other credential source. Called before the data directory
/// is opened, as the contract requires.
pub fn read_managed_credentials(fd: RawFd) -> Result<Credentials, ManagedError> {
    // SAFETY: `fd` arrives on argv (`--credentials-fd`) through the
    // supervisor's spawn contract and is this process's to own. The `File`
    // takes it over exactly once and closes it on drop, which is also what
    // lets the contract's EOF check terminate once the supervisor's write end
    // is gone.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    read_credentials(file).map_err(|error| ManagedError::CredentialsRejected {
        reason: error.to_string(),
    })
}

/// Writes the ready byte.
///
/// Ordering is the whole point of this function existing separately: the
/// supervisor treats the byte as "this child is serving", so it may only be
/// written after both sockets are bound, the credentials are consumed, and the
/// vault open gates have passed.
pub fn signal_ready(fd: RawFd) -> Result<(), ManagedError> {
    // SAFETY: `fd` arrives on argv (`--ready-fd`) through the supervisor's
    // spawn contract and is this process's to own. The `File` takes it over
    // exactly once; closing it on drop is what the supervisor's read side
    // observes as EOF if this process dies before signalling.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    std::io::Write::write_all(&mut file, &[READY_BYTE])?;
    std::io::Write::flush(&mut file)?;
    Ok(())
}

/// Canonical bytes of the vault's `vault_meta` head page: the identity rows
/// the storage layer stamps at open (storage ABI, schema, text-index
/// identity), read back through the vault's own integrity report.
///
/// This is what the DEK MAC covers. It is stable across content writes and
/// changes only when the vault's storage identity does, so a wrong DEK is
/// caught by a MAC over metadata rather than by decrypting user content.
fn vault_meta_head_page(vault: &oneiron::Vault) -> Result<Vec<u8>, ManagedError> {
    let report = vault
        .doctor()
        .map_err(|error| ManagedError::VaultMeta(error.to_string()))?;
    let abi = report.storage_abi_version;
    let schema = report.storage_schema_version;
    let analyzer = report.analyzer_manifest_hash.as_deref().unwrap_or_default();
    let bm25 = report.bm25_field_schema_hash.as_deref().unwrap_or_default();
    let text_schema = report.text_index_schema_version;
    let page = format!(
        "oneiron:vault_meta:head:v1\nstorage_abi_version={abi:?}\nstorage_schema_version={schema:?}\nanalyzer_manifest_hash={analyzer}\nbm25_field_schema_hash={bm25}\ntext_index_schema_version={text_schema:?}\n"
    );
    Ok(page.into_bytes())
}

fn canary_marker_present(vault: &oneiron::Vault) -> Result<bool, ManagedError> {
    let row = vault
        .sync_state_get(CANARY_MARKER_KEY)
        .map_err(|error| ManagedError::VaultMeta(error.to_string()))?;
    Ok(row.is_some_and(|raw| raw.as_slice() == CANARY_MARKER_VALUE))
}

/// The waiver's other half: an fscrypt policy on the data directory AND a
/// dedicated per-vault UID owning it.
///
/// Neither is implemented in contract v1 and neither can be probed here, so
/// this is a constant `false` on purpose. Making it a named function rather
/// than an inline `false` is what keeps the missing work addressable: when the
/// preconditions land, this is the one place that learns to say yes, and the
/// canary marker stops being the only way through.
fn hardened_tenant_preconditions_present(_vault: &oneiron::Vault) -> bool {
    false
}

/// Verifies the delivered DEK against the vault's sealed MAC, or seals it on
/// a vault that has never been opened in managed mode.
///
/// Runs before any content is read: a supervisor that hands over the wrong DEK
/// finds out from a metadata MAC, not from garbled user data.
fn verify_or_seal_dek_mac(
    vault: &oneiron::Vault,
    vault_name: &str,
    dek: &[u8; DEK_LEN],
) -> Result<(), ManagedError> {
    let head = vault_meta_head_page(vault)?;
    let mut covered = Vec::with_capacity(DEK_MAC_CONTEXT.len() + head.len());
    covered.extend_from_slice(DEK_MAC_CONTEXT);
    covered.extend_from_slice(&head);
    let mac = blake3::keyed_hash(dek, &covered);

    let stored = vault
        .sync_state_get(DEK_MAC_KEY)
        .map_err(|error| ManagedError::VaultMeta(error.to_string()))?;
    match stored {
        Some(stored) => {
            // Constant time: a supervisor probing DEKs must not learn how many
            // leading MAC bytes it got right.
            if bool::from(stored.as_slice().ct_eq(mac.as_bytes().as_slice())) {
                Ok(())
            } else {
                Err(ManagedError::DekMacMismatch {
                    vault: vault_name.to_owned(),
                    key: DEK_MAC_KEY,
                })
            }
        }
        None => {
            vault
                .sync_state_put(DEK_MAC_KEY, mac.as_bytes())
                .map_err(|error| ManagedError::VaultMeta(error.to_string()))?;
            Ok(())
        }
    }
}

/// The managed open gates, in fail-closed order: the waiver gate first, then
/// the DEK MAC. Both run before any content is read.
///
/// The credential gate has already passed by the time a caller holds
/// `credentials` — [`read_managed_credentials`] is the only way to get one.
pub fn check_managed_open_gates(
    vault: &oneiron::Vault,
    vault_name: &str,
    credentials: &Credentials,
) -> Result<(), ManagedError> {
    if !canary_marker_present(vault)? && !hardened_tenant_preconditions_present(vault) {
        return Err(ManagedError::ManagedRealTenantRefused {
            vault: vault_name.to_owned(),
            marker: CANARY_MARKER_KEY,
        });
    }
    verify_or_seal_dek_mac(vault, vault_name, &credentials.dek)
}

/// Opens the vault for managed mode and runs the open gates over it.
pub fn open_managed_vault(
    data_dir: &Path,
    vault_config: oneiron::VaultConfig,
    vault_name: &str,
    credentials: &Credentials,
) -> Result<oneiron::Vault, ManagedError> {
    let vault = oneiron::Vault::open(data_dir, vault_config)
        .map_err(|error| ManagedError::VaultMeta(error.to_string()))?;
    check_managed_open_gates(&vault, vault_name, credentials)?;
    Ok(vault)
}

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

/// The vault's wake ledger: what the engine wants to be woken for, and when.
///
/// Two delivery paths over the same entries. The pull path rides the
/// `prepare_reap` reply; the push path is a `ledger_update` on the
/// supervisor's socket, sent when the entries change. The revision persists in
/// the vault so a restart resumes the supervisor's ordering rather than
/// replaying it from zero.
pub struct WakeLedger {
    vault: Arc<oneiron::Vault>,
    vault_name: String,
    hypnos_socket: PathBuf,
    token: TokenHex,
    rev: AtomicU64,
    last_exported: Mutex<Option<Vec<WakeEntry>>>,
}

impl std::fmt::Debug for WakeLedger {
    /// Manual, and deliberately not derived: the spawn token must never reach
    /// a diagnostic. `TokenHex` redacts itself, and this impl keeps that true
    /// even if the field type ever changes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WakeLedger")
            .field("vault_name", &self.vault_name)
            .field("hypnos_socket", &self.hypnos_socket)
            .field("token", &"<redacted>")
            .field("rev", &self.rev.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl WakeLedger {
    /// Loads the persisted revision and binds the ledger to a vault, a
    /// supervisor socket and the spawn token that authenticates pushes.
    pub fn load(
        vault: Arc<oneiron::Vault>,
        vault_name: String,
        hypnos_socket: PathBuf,
        credentials: &Credentials,
    ) -> Result<Self, ManagedError> {
        let rev = read_persisted_rev(&vault)?;
        Ok(Self {
            vault,
            vault_name,
            hypnos_socket,
            token: TokenHex::from_token(&credentials.token),
            rev: AtomicU64::new(rev),
            last_exported: Mutex::new(None),
        })
    }

    pub fn rev(&self) -> u64 {
        self.rev.load(Ordering::SeqCst)
    }

    /// Builds the current wake entries from the engine's own state: the
    /// job-ready head probe and the sync deadline.
    ///
    /// No timer is consulted and none is armed — the engine only reports what
    /// it would want; firing is the supervisor's job.
    pub fn export(&self, server: &SyncServer) -> Result<Vec<WakeEntry>, ManagedError> {
        let mut entries = Vec::new();
        if let Some(entry) = job_ready_head(&self.vault)? {
            entries.push(entry);
        }
        if let Some(entry) = sync_deadline(server) {
            entries.push(entry);
        }
        validate_wake_entries(&entries).map_err(|error| ManagedError::LedgerRefused {
            reason: error.to_string(),
        })?;
        Ok(entries)
    }

    /// Export-at-freeze for the pull path: refreshes the entries and, when
    /// they changed, advances and persists the revision so the `ledger_rev`
    /// the supervisor sees keeps moving forward across restarts.
    pub async fn export_at_freeze(
        &self,
        server: &SyncServer,
    ) -> Result<(u64, Vec<WakeEntry>), ManagedError> {
        let entries = self.export(server)?;
        let mut last = self.last_exported.lock().await;
        if last.as_ref() != Some(&entries) {
            self.advance_rev()?;
            *last = Some(entries.clone());
        }
        Ok((self.rev(), entries))
    }

    /// Push-on-change: sends a `ledger_update` only when the entries actually
    /// moved, so a quiet vault costs the supervisor nothing.
    ///
    /// Returns whether a push was both needed and accepted.
    pub async fn push_if_changed(&self, server: &SyncServer) -> Result<bool, ManagedError> {
        let entries = self.export(server)?;
        let mut last = self.last_exported.lock().await;
        if last.as_ref() == Some(&entries) {
            return Ok(false);
        }
        let rev = self.advance_rev()?;
        let accepted = self.push_with_retry(rev, &entries).await;
        if accepted {
            *last = Some(entries);
        }
        Ok(accepted)
    }

    /// One push attempt: validate, frame, send, await the ack — the whole
    /// attempt under a deadline.
    ///
    /// The deadline covers the attempt rather than the ack alone because all
    /// three of connect, write and read are unbounded against a supervisor that
    /// is connected and silent, and any one of them parking is the same
    /// outcome: this process never comes back. Both callers are on paths that
    /// must not stall — the opening push happens after the ready byte and
    /// before the HTTP serve, and the final one is the last thing before exit —
    /// and `push_with_retry`'s "one retry, then proceed" only bounds them if an
    /// attempt is itself bounded. Timing out is a typed refusal like any other
    /// push failure, so the retry policy above is unchanged by it.
    pub async fn push_once(&self, rev: u64, entries: &[WakeEntry]) -> Result<(), ManagedError> {
        match tokio::time::timeout(LEDGER_PUSH_TIMEOUT, self.push_attempt(rev, entries)).await {
            Ok(result) => result,
            Err(_elapsed) => Err(ManagedError::LedgerAckTimeout {
                after: LEDGER_PUSH_TIMEOUT,
            }),
        }
    }

    /// The attempt itself, with no deadline of its own: [`Self::push_once`] is
    /// the only caller and it is what bounds this.
    async fn push_attempt(&self, rev: u64, entries: &[WakeEntry]) -> Result<(), ManagedError> {
        let update = LedgerUpdate {
            op: "ledger_update".to_owned(),
            vault: self.vault_name.clone(),
            token: self.token.clone(),
            rev,
            entries: entries.to_vec(),
        };
        // Validate before sending, not after: an update this side would refuse
        // to receive is one this side must refuse to emit.
        update
            .validate()
            .map_err(|error| ManagedError::LedgerRefused {
                reason: error.to_string(),
            })?;
        let line = serde_json::to_string(&update).map_err(|error| ManagedError::LedgerRefused {
            reason: error.to_string(),
        })?;
        if line.len() > MAX_CTL_LINE {
            return Err(ManagedError::CtlLineTooLong {
                len: line.len(),
                cap: MAX_CTL_LINE,
            });
        }

        let stream = UnixStream::connect(&self.hypnos_socket).await?;
        let (reader, mut writer) = stream.into_split();
        writer.write_all(line.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;

        let mut reader = BufReader::new(reader.take(MAX_CTL_LINE as u64 + 2));
        let mut ack_line = String::new();
        reader.read_line(&mut ack_line).await?;
        let ack: LedgerAck = serde_json::from_str(ack_line.trim_end_matches(['\r', '\n']))
            .map_err(|error| ManagedError::LedgerRefused {
                reason: error.to_string(),
            })?;
        if ack.ok {
            Ok(())
        } else {
            Err(ManagedError::LedgerRefused {
                reason: ack
                    .error
                    .unwrap_or_else(|| "supervisor rejected the ledger update".to_owned()),
            })
        }
    }

    /// Retry discipline: exactly one retry, after 200 ms, then log and
    /// proceed. Shutdown must never be held open by a supervisor that is not
    /// answering.
    pub async fn push_with_retry(&self, rev: u64, entries: &[WakeEntry]) -> bool {
        match self.push_once(rev, entries).await {
            Ok(()) => return true,
            Err(error) => {
                tracing::warn!(%error, "wake ledger push failed; retrying once");
            }
        }
        tokio::time::sleep(LEDGER_RETRY_DELAY).await;
        match self.push_once(rev, entries).await {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "wake ledger push retry failed; proceeding without the supervisor"
                );
                false
            }
        }
    }

    fn advance_rev(&self) -> Result<u64, ManagedError> {
        let rev = self.rev.fetch_add(1, Ordering::SeqCst).saturating_add(1);
        self.vault
            .sync_state_put(LEDGER_REV_KEY, &rev.to_le_bytes())
            .map_err(|error| ManagedError::VaultMeta(error.to_string()))?;
        Ok(rev)
    }
}

fn read_persisted_rev(vault: &oneiron::Vault) -> Result<u64, ManagedError> {
    let Some(raw) = vault
        .sync_state_get(LEDGER_REV_KEY)
        .map_err(|error| ManagedError::VaultMeta(error.to_string()))?
    else {
        return Ok(0);
    };
    let len = raw.len();
    let bytes: [u8; 8] = raw.try_into().map_err(|_| {
        ManagedError::VaultMeta(format!("`{LEDGER_REV_KEY}` row is {len} bytes, expected 8"))
    })?;
    Ok(u64::from_le_bytes(bytes))
}

/// job_ready head probe: any durable row in the vault's sync queue means there
/// is work waiting, and the head of it is due now.
fn job_ready_head(vault: &Arc<oneiron::Vault>) -> Result<Option<WakeEntry>, ManagedError> {
    let queue = oneiron::sync::SyncQueue::new(Arc::clone(vault))
        .map_err(|error| ManagedError::VaultMeta(error.to_string()))?;
    let empty = queue
        .is_empty()
        .map_err(|error| ManagedError::VaultMeta(error.to_string()))?;
    if empty {
        return Ok(None);
    }
    Ok(Some(WakeEntry {
        id: WAKE_ID_JOB_READY.to_owned(),
        at: Schedule::Exact { at: now_ts() },
        reason_tag: WAKE_ID_JOB_READY.to_owned(),
    }))
}

/// Sync deadline: the earliest active device lease expiry. That is the next
/// moment the engine must be running to do durable work nobody else will do.
fn sync_deadline(server: &SyncServer) -> Option<WakeEntry> {
    let leases = server.root_doc.get_map(ROOT_LEASES_MAP);
    let mut earliest: Option<u64> = None;
    leases.for_each(|_key, value| {
        if let ValueOrContainer::Value(LoroValue::Binary(raw)) = value
            && let Ok(record) = lease::decode_lease_record(&raw)
            && record.status == LeaseStatus::Active
        {
            earliest =
                Some(earliest.map_or(record.expires_at, |seen: u64| seen.min(record.expires_at)));
        }
    });
    earliest.map(|at| WakeEntry {
        id: WAKE_ID_SYNC_DEADLINE.to_owned(),
        at: Schedule::Window {
            start: at,
            end: at.saturating_add(LEASE_WAKE_WINDOW_SECS),
        },
        reason_tag: "lease_expiry".to_owned(),
    })
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
    /// [`SYNC_UPGRADE_SETTLE_SECS`] covers that blind window instead.
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

/// The control socket: one JSON request line per connection, one response line
/// back, both under [`MAX_CTL_LINE`].
#[derive(Debug)]
pub struct ManagedCtl {
    listener: UnixListener,
    path: PathBuf,
}

impl ManagedCtl {
    /// Binds `ctl.sock`. This process owns the path, so it also owns removing
    /// it — unlike the inherited HTTP socket.
    pub fn bind(path: &Path) -> Result<Self, ManagedError> {
        Ok(Self {
            listener: bind_unix_socket(path)?,
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Serves control verbs until `shutdown` resolves, then closes the socket
    /// and removes the path it created.
    pub async fn serve(self, state: Arc<ManagedState>, shutdown: impl Future<Output = ()> + Send) {
        let mut shutdown = std::pin::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                accepted = self.listener.accept() => match accepted {
                    Ok((stream, _)) => {
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            if let Err(error) = handle_ctl_connection(stream, &state).await {
                                tracing::warn!(%error, "ctl connection failed");
                            }
                        });
                    }
                    Err(error) => tracing::warn!(%error, "ctl accept failed"),
                },
            }
        }
        drop(self.listener);
        if let Err(error) = std::fs::remove_file(&self.path)
            && error.kind() != ErrorKind::NotFound
        {
            tracing::warn!(%error, path = %self.path.display(), "ctl socket unlink failed");
        }
    }
}

async fn handle_ctl_connection(
    stream: UnixStream,
    state: &ManagedState,
) -> Result<(), ManagedError> {
    let (mut request_half, mut writer) = stream.into_split();
    // Cap + 2 leaves room for the terminating newline on a maximal valid line
    // while still stopping short of reading an over-cap one whole. Borrowed
    // rather than moved because the read half has to outlive this reader: the
    // request tail is drained through it once the reply is out.
    let mut reader = BufReader::new((&mut request_half).take(MAX_CTL_LINE as u64 + 2));
    let mut line = String::new();
    let response = match reader.read_line(&mut line).await {
        Ok(_) => dispatch_ctl_line(&line, state).await,
        Err(error) => {
            tracing::warn!(%error, "ctl line unreadable; rejected whole");
            CtlResponse::Ok { ok: false }
        }
    };

    let mut out =
        serde_json::to_string(&response).map_err(|error| ManagedError::CtlRequestRefused {
            reason: error.to_string(),
        })?;
    out.push('\n');
    writer.write_all(out.as_bytes()).await?;
    writer.flush().await?;
    // Written is not delivered. Dropping a socket that still has unread bytes
    // queued on it resets the peer, and the reset discards the reply the peer
    // had not read yet — which is precisely the refusal case, because an
    // over-cap line is rejected after `MAX_CTL_LINE + 2` bytes while the rest
    // of it is still arriving. The supervisor would see a connection error
    // where the engine sent it a considered answer.
    //
    // So the close is done in two halves. Ending the reply half first is what
    // gives the peer its EOF, so this drain can never leave it waiting; then
    // the tail of that one request line is consumed so nothing is queued when
    // the socket finally drops.
    writer.shutdown().await?;
    let mut sink = [0u8; 1024];
    let mut drained = 0usize;
    while drained < MAX_CTL_LINE {
        let Ok(read) = request_half.read(&mut sink).await else {
            break;
        };
        // EOF, or the end of the one line this connection was ever allowed.
        if read == 0 || sink[..read].contains(&b'\n') {
            break;
        }
        drained += read;
    }
    Ok(())
}

/// Parses and dispatches one ctl line.
///
/// Over-cap lines are rejected whole and never truncated: a truncated line can
/// parse into a different, smaller request than the supervisor sent, which is
/// worse than no request at all.
async fn dispatch_ctl_line(line: &str, state: &ManagedState) -> CtlResponse {
    let payload = line.trim_end_matches(['\r', '\n']);
    if payload.len() > MAX_CTL_LINE {
        let error = ManagedError::CtlLineTooLong {
            len: payload.len(),
            cap: MAX_CTL_LINE,
        };
        tracing::warn!(%error, "ctl line rejected");
        return CtlResponse::Ok { ok: false };
    }
    let request: CtlRequest = match serde_json::from_str(payload) {
        Ok(request) => request,
        Err(error) => {
            tracing::warn!(%error, "ctl line did not parse; rejected");
            return CtlResponse::Ok { ok: false };
        }
    };
    match state.handle_request(request).await {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(%error, "ctl request refused");
            CtlResponse::Ok { ok: false }
        }
    }
}

/// Managed mode's log filter comes from argv, never from the environment.
/// `EnvFilter::try_from_default_env` would read `RUST_LOG`, and the managed
/// environment surface is exactly `PATH` and [`HYPNOS_LISTEN_FD`].
fn init_managed_tracing(log_level: &str) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(log_level))
        .try_init();
}

/// Boots the engine as a supervised child process.
///
/// The startup order is the contract, not an implementation detail:
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

    let http = ServeListener::for_managed(&managed)?.bind().await?;
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
