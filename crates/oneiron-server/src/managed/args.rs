//! Managed argv group: validation, the argv allowlist, and unmanaged-layer refusals.

use std::os::fd::RawFd;
use std::path::PathBuf;
use std::time::Duration;

use oneiron_vault_contract::{CONTRACT_VERSION, valid_vault_name};

use crate::config::{ServeArgs, ServeConfig};

use super::listener::HYPNOS_LISTEN_FD;

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

    #[error("--managed-by-hypnos conflicts with {env}: {reason}")]
    ConflictingEnvironment {
        env: &'static str,
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
    /// into it. [`serve_managed`] calls this before any of the three is
    /// consumed and before the vault is opened, so neither the frame nor
    /// storage is touched on the way to the refusal.
    pub fn refuse_listen_fd_alias(&self, listen_fd: RawFd) -> Result<(), ManagedError> {
        refuse_fd_alias((HYPNOS_LISTEN_FD, listen_fd), ("--ready-fd", self.ready_fd))?;
        refuse_fd_alias(
            (HYPNOS_LISTEN_FD, listen_fd),
            ("--credentials-fd", self.credentials_fd),
        )
    }

    /// Serve configuration for managed mode, built from argv alone.
    ///
    /// Outside the managed group, the argv allowlist permits exactly the
    /// fields read here: dimensions, map size, dictionary roots and log level.
    /// Everything else on `ServeArgs` is refused before this runs, so nothing
    /// reaches here to be quietly dropped.
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
            assistant_display_names: args.assistant_display_names.clone().unwrap_or_default(),
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
    // Contract v1 has no managed privacy override: refuse instead of dropping it.
    (
        "privacy-posture",
        |args| args.privacy_posture.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
    ),
    (
        "hosted-kms-key-ref",
        |args| args.hosted_kms_key_ref.is_some(),
        ArgvUse::Refused(NO_TUNING_LAYER_REASON),
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
        "assistant-display-names",
        |args| args.assistant_display_names.is_some(),
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
    // Check presence only: never parse these values or load the requested file.
    // Even an empty or non-Unicode setting is an explicit unmanaged request,
    // not permission to fall back to the managed default custody.
    for env in [
        "ONEIRON_PRIVACY_POSTURE",
        "ONEIRON_HOSTED_KMS_KEY_REF",
        "ONEIRON_CONFIG",
    ] {
        if std::env::var_os(env).is_some() {
            return Err(ManagedError::ConflictingEnvironment {
                env,
                reason: NO_CONFIG_LAYER_REASON,
            });
        }
    }
    Ok(())
}
