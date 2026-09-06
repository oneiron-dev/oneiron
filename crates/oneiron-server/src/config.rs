use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::Args;
use oneiron::{HostingPrivacyPosture, VaultDataKeyCustody, VaultPrivacyConfig};
use serde::Deserialize;

use crate::runtime::{
    RuntimeConfig, RuntimeConfigOverride, RuntimeMode, RuntimeProviderKind, RuntimeRole,
    RuntimeRoleTargetOverride,
};
use crate::usage::UsageMode;

const DEFAULT_CONFIG_FILE: &str = "oneiron.toml";
const DEFAULT_CONFIG_DIR: &str = "oneiron";
const LEGACY_DEFAULT_VAULT_PATH: &str = "./vault";

/// Oneiron sync server configuration.
///
/// Server-side enforcement status of the per-client limits (ONE-1129
/// OWNER-DECISION, recorded in the PR body):
/// - `max_update_payload` — ENFORCED at the WindowSync UPDATE chokepoint
///   (oversized updates close the connection before any state mutates).
/// - `max_frame_size` — ENFORCED on the WebSocket frame size.
/// - `max_messages_per_sec` — ENFORCED as a per-connection inbound message
///   rate limit. Per-user limits still need per-user identity (Phase-1 auth is
///   a single shared secret).
/// - `max_windows_per_connection` — ENFORCED as a generous per-connection
///   distinct-window touch cap. The default is intentionally high enough for
///   legitimate historical-window tombstone sync; it stops fabricated-key
///   floods, not real history.
/// - `max_federation_windows_per_connection` — ENFORCED on grant-backed
///   selector connections as a tighter distinct-window quota with temporary
///   pause instead of closing the socket.
/// - `max_ephemeral_payload_bytes` / `max_ephemeral_snapshot_bytes` —
///   ENFORCED before ephemeral hub mutation and before late-join snapshot
///   send. Oversized late-join snapshots are skipped, not connection-fatal.
/// - `max_connections_per_user` — not enforced until auth has per-user
///   identity.
#[derive(Clone)]
pub struct SyncServerConfig {
    /// Number of default windows to load (current + previous months).
    /// Read when M5 default-window preloading lands.
    pub default_window_count: u8,
    /// Byte threshold that triggers CRDT Doc compaction (M5).
    pub compaction_threshold_bytes: u32,
    /// Minimum seconds between compaction runs (M5).
    pub compaction_throttle_secs: u32,
    /// Maximum uncompressed BulkTransfer chunk size in bytes (M5 Phase-3
    /// bulk sender).
    pub bulk_chunk_size: usize,
    /// Bearer trust root, checked on both the HTTP API and the `/ws` upgrade.
    ///
    /// Two roles: the constant-time-compared owner credential, and the
    /// BLAKE3 `derive_key` input for v2 token MACs. Rotate by replacing the
    /// value and restarting — rotation rewraps the MAC key, so previously
    /// minted tokens and derived credential hashes stop resolving. Revoking
    /// an individual token is a separate, explicit act.
    pub auth_secret: Option<String>,
    pub oauth_issuer: Option<String>,
    pub oauth_jwks_uri: Option<String>,
    pub oauth_resource_indicator: Option<String>,
    /// Explicit local/dev escape hatch for running without `auth_secret`.
    pub allow_unauthenticated: bool,
    /// Explicit CORS origins allowed to call the HTTP API. Empty is
    /// fail-closed: no cross-origin browser access is granted.
    pub allowed_origins: Vec<String>,
    /// Numeric vault scope for root lease registration/revocation.
    /// Hosted deployments must set a distinct value per tenant/vault; `0`
    /// preserves the legacy local single-vault scope.
    pub lease_vault_id: u64,
    /// Maximum WebSocket frame size in bytes.
    pub max_frame_size: usize,
    /// Maximum CRDT update payload in bytes (enforced on WindowSync UPDATE).
    pub max_update_payload: usize,
    /// Maximum distinct valid windows one connection may touch.
    pub max_windows_per_connection: usize,
    /// Maximum distinct valid windows one federated selector connection may touch.
    pub max_federation_windows_per_connection: usize,
    /// Seconds to pause a federated selector connection after quota overflow.
    pub federation_flood_pause_secs: u64,
    /// Maximum inbound protocol messages per connection per second.
    pub max_messages_per_sec: u32,
    /// Loro ephemeral-store inactivity timeout in milliseconds.
    pub ephemeral_timeout_ms: i64,
    /// Maximum Loro-native ephemeral payload bytes accepted from one frame.
    pub max_ephemeral_payload_bytes: usize,
    /// Maximum encoded hub snapshot bytes retained/sent to late joiners.
    pub max_ephemeral_snapshot_bytes: usize,
    /// Maximum entity blob size in bytes (M5/M6 bulk + materialization paths).
    pub max_entity_blob: usize,
    /// Maximum decompressed BulkTransfer chunk in bytes (M5 Phase-3).
    pub max_bulk_decompressed: usize,
    /// Runtime mode and per-role model routing defaults. The single source of
    /// usage-mode truth: `runtime_usage_mode()` derives from `runtime.mode`.
    pub runtime: RuntimeConfig,
}

impl Default for SyncServerConfig {
    fn default() -> Self {
        Self {
            default_window_count: 2,
            compaction_threshold_bytes: 524_288, // 512 KB
            compaction_throttle_secs: 30,
            bulk_chunk_size: 1_048_576, // 1 MB uncompressed
            auth_secret: None,
            oauth_issuer: None,
            oauth_jwks_uri: None,
            oauth_resource_indicator: None,
            allow_unauthenticated: false,
            allowed_origins: Vec::new(),
            lease_vault_id: 0,
            max_frame_size: 4 * 1024 * 1024,     // 4 MB
            max_update_payload: 2 * 1024 * 1024, // 2 MB
            max_windows_per_connection: 4096,
            max_federation_windows_per_connection:
                oneiron::sync::DEFAULT_MAX_FEDERATION_WINDOWS_PER_CONNECTION,
            federation_flood_pause_secs: oneiron::sync::DEFAULT_FEDERATION_FLOOD_PAUSE_SECS,
            max_messages_per_sec: 200,
            ephemeral_timeout_ms: 30_000,
            max_ephemeral_payload_bytes: 64 * 1024,   // 64 KB
            max_ephemeral_snapshot_bytes: 256 * 1024, // 256 KB
            max_entity_blob: 64 * 1024,               // 64 KB
            max_bulk_decompressed: 8 * 1024 * 1024,   // 8 MB
            runtime: RuntimeConfig::default(),
        }
    }
}

impl SyncServerConfig {
    /// Usage debit mode, derived from the runtime mode.
    pub fn runtime_usage_mode(&self) -> UsageMode {
        self.runtime.mode.usage_mode()
    }

    pub fn validate(&self) -> Result<(), oneiron::Error> {
        if self.ephemeral_timeout_ms <= 0 {
            return Err(oneiron::Error::sync_protocol(
                oneiron::SyncProtocolValidation::InvalidConfig {
                    field: oneiron::SyncConfigField::EphemeralTimeoutMs,
                },
            ));
        }
        if self.max_ephemeral_payload_bytes == 0 {
            return Err(oneiron::Error::sync_protocol(
                oneiron::SyncProtocolValidation::InvalidConfig {
                    field: oneiron::SyncConfigField::MaxEphemeralPayloadBytes,
                },
            ));
        }
        if self.max_ephemeral_snapshot_bytes == 0 {
            return Err(oneiron::Error::sync_protocol(
                oneiron::SyncProtocolValidation::InvalidConfig {
                    field: oneiron::SyncConfigField::MaxEphemeralSnapshotBytes,
                },
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for SyncServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyncServerConfig")
            .field("default_window_count", &self.default_window_count)
            .field(
                "compaction_threshold_bytes",
                &self.compaction_threshold_bytes,
            )
            .field("compaction_throttle_secs", &self.compaction_throttle_secs)
            .field("bulk_chunk_size", &self.bulk_chunk_size)
            .field("auth_secret", &redacted_secret(&self.auth_secret))
            .field("allow_unauthenticated", &self.allow_unauthenticated)
            .field("allowed_origins", &self.allowed_origins)
            .field("lease_vault_id", &self.lease_vault_id)
            .field("max_frame_size", &self.max_frame_size)
            .field("max_update_payload", &self.max_update_payload)
            .field(
                "max_windows_per_connection",
                &self.max_windows_per_connection,
            )
            .field(
                "max_federation_windows_per_connection",
                &self.max_federation_windows_per_connection,
            )
            .field(
                "federation_flood_pause_secs",
                &self.federation_flood_pause_secs,
            )
            .field("max_messages_per_sec", &self.max_messages_per_sec)
            .field("ephemeral_timeout_ms", &self.ephemeral_timeout_ms)
            .field(
                "max_ephemeral_payload_bytes",
                &self.max_ephemeral_payload_bytes,
            )
            .field(
                "max_ephemeral_snapshot_bytes",
                &self.max_ephemeral_snapshot_bytes,
            )
            .field("max_entity_blob", &self.max_entity_blob)
            .field("max_bulk_decompressed", &self.max_bulk_decompressed)
            .field("runtime", &self.runtime)
            .finish()
    }
}

/// Serve command flags. All fields are optional so the config merger can keep
/// the required precedence: file, then environment, then CLI flags.
///
/// The `--managed-by-hypnos` group is the exception: it selects managed serve
/// mode, where the merger is skipped entirely and the whole configuration
/// arrives on argv. See [`crate::managed`].
#[derive(Args, Clone, Default)]
pub struct ServeArgs {
    /// Path to a TOML config file. Defaults to the XDG oneiron config path
    /// when present.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Path to the LMDB vault directory.
    #[arg(long)]
    pub vault_path: Option<PathBuf>,

    /// Run as a supervised child process of the node supervisor.
    ///
    /// The single switch that selects managed serve mode. Absent, this binary
    /// behaves exactly as it always has.
    #[arg(long = "managed-by-hypnos")]
    pub managed_by_hypnos: bool,

    /// Supervisor⇄vault wire contract version this child was spawned against.
    /// Required in managed mode; an unknown version exits non-zero before any
    /// IO happens.
    #[arg(long = "contract-version")]
    pub contract_version: Option<u32>,

    /// Name of the vault this child serves, as a DNS label. Required in
    /// managed mode; it is what the supervisor addresses on the wire.
    #[arg(long = "vault-name")]
    pub vault_name: Option<String>,

    /// Vault data directory. Managed mode's spelling of `--vault-path`, which
    /// stays available as the alias; unmanaged serve keeps using either.
    #[arg(long = "data-dir")]
    pub data_dir: Option<PathBuf>,

    /// Path of the HTTP unix socket. In managed mode the supervisor normally
    /// binds it and passes the fd in `HYPNOS_LISTEN_FD`; this path is the
    /// self-bind fallback for when it does not.
    #[arg(long = "http-socket")]
    pub http_socket: Option<PathBuf>,

    /// Path of the control unix socket this child binds and owns.
    #[arg(long = "ctl-socket")]
    pub ctl_socket: Option<PathBuf>,

    /// Path of the supervisor's socket, where wake-ledger updates are pushed.
    #[arg(long = "hypnos-socket")]
    pub hypnos_socket: Option<PathBuf>,

    /// Inherited file descriptor the ready byte is written to once both
    /// sockets are bound, credentials are consumed and the vault open gates
    /// have passed. Rides argv, never a hardcoded constant.
    #[arg(long = "ready-fd")]
    pub ready_fd: Option<i32>,

    /// Inherited file descriptor carrying the 64-byte DEK ‖ spawn-token
    /// credential frame. Rides argv, never a hardcoded constant.
    #[arg(long = "credentials-fd")]
    pub credentials_fd: Option<i32>,

    /// Host address to bind to.
    #[arg(long)]
    pub host: Option<String>,

    /// Port to bind to.
    #[arg(long)]
    pub port: Option<u16>,

    /// Bearer trust root: the owner credential and the MAC key input for
    /// minted `v2` tokens. Rotating it invalidates all minted tokens.
    #[arg(long)]
    pub auth_secret: Option<String>,

    #[arg(long)]
    pub oauth_issuer: Option<String>,
    #[arg(long)]
    pub oauth_jwks_uri: Option<String>,
    #[arg(long)]
    pub oauth_resource_indicator: Option<String>,

    /// Insecure local/dev escape hatch: allow requests without auth_secret.
    #[arg(
        long = "insecure-allow-unauthenticated",
        num_args = 0..=1,
        default_missing_value = "true",
        value_parser = clap::value_parser!(bool)
    )]
    pub insecure_allow_unauthenticated: Option<bool>,

    /// Comma-separated CORS origins allowed to call the HTTP API.
    #[arg(
        long = "allowed-origins",
        visible_alias = "cors-origins",
        value_delimiter = ',',
        num_args = 1..
    )]
    pub allowed_origins: Option<Vec<String>>,

    /// Numeric vault scope for lease registration and revocation.
    #[arg(long)]
    pub lease_vault_id: Option<u64>,

    /// Embedding vector dimension for the vault.
    #[arg(long)]
    pub dimensions: Option<usize>,

    /// LMDB map size in bytes.
    #[arg(long)]
    pub map_size: Option<usize>,

    /// Log level filter (e.g., "info", "debug", "oneiron_server=debug").
    #[arg(long)]
    pub log_level: Option<String>,

    /// Comma-separated trusted roots containing ja/ko/zh dictionary assets.
    #[arg(long = "dict-search-paths", value_delimiter = ',', num_args = 1..)]
    pub dict_search_paths: Option<Vec<PathBuf>>,

    /// Number of default windows to preload.
    #[arg(long)]
    pub default_window_count: Option<u8>,

    /// Byte threshold that triggers CRDT Doc compaction.
    #[arg(long)]
    pub compaction_threshold_bytes: Option<u32>,

    /// Minimum seconds between compaction runs.
    #[arg(long)]
    pub compaction_throttle_secs: Option<u32>,

    /// Maximum uncompressed BulkTransfer chunk size in bytes.
    #[arg(long)]
    pub bulk_chunk_size: Option<usize>,

    /// Maximum WebSocket frame size in bytes.
    #[arg(long)]
    pub max_frame_size: Option<usize>,

    /// Maximum CRDT update payload in bytes.
    #[arg(long)]
    pub max_update_payload: Option<usize>,

    /// Maximum distinct valid windows one connection may touch.
    #[arg(long)]
    pub max_windows_per_connection: Option<usize>,

    /// Maximum distinct valid windows one federated selector connection may touch.
    #[arg(long)]
    pub max_federation_windows_per_connection: Option<usize>,

    /// Seconds to pause a federated selector connection after quota overflow.
    #[arg(long)]
    pub federation_flood_pause_secs: Option<u64>,

    /// Maximum inbound protocol messages per connection per second.
    #[arg(long)]
    pub max_messages_per_sec: Option<u32>,

    /// Loro ephemeral-store inactivity timeout in milliseconds.
    #[arg(long)]
    pub ephemeral_timeout_ms: Option<i64>,

    /// Maximum Loro-native ephemeral payload bytes accepted from one frame.
    #[arg(long)]
    pub max_ephemeral_payload_bytes: Option<usize>,

    /// Maximum encoded hub snapshot bytes retained/sent to late joiners.
    #[arg(long)]
    pub max_ephemeral_snapshot_bytes: Option<usize>,

    /// Maximum entity blob size in bytes.
    #[arg(long)]
    pub max_entity_blob: Option<usize>,

    /// Maximum decompressed BulkTransfer chunk in bytes.
    #[arg(long)]
    pub max_bulk_decompressed: Option<usize>,

    /// Runtime routing mode: local_free, byo_cloud_key, or oneiron_cloud.
    #[arg(long, value_parser = parse_runtime_mode)]
    pub runtime_mode: Option<RuntimeMode>,

    /// Environment variable name that holds the BYO provider API key.
    #[arg(long)]
    pub runtime_byo_key_env: Option<String>,

    /// Runtime mode for orchestrator routing.
    #[arg(long, value_parser = parse_runtime_mode)]
    pub runtime_orchestrator_mode: Option<RuntimeMode>,

    /// Provider kind for orchestrator routing.
    #[arg(long, value_parser = parse_runtime_provider_kind)]
    pub runtime_orchestrator_provider_kind: Option<RuntimeProviderKind>,

    /// Model id for orchestrator routing.
    #[arg(long)]
    pub runtime_orchestrator_model: Option<String>,

    /// Runtime mode for subagent routing.
    #[arg(long, value_parser = parse_runtime_mode)]
    pub runtime_subagent_mode: Option<RuntimeMode>,

    /// Provider kind for subagent routing.
    #[arg(long, value_parser = parse_runtime_provider_kind)]
    pub runtime_subagent_provider_kind: Option<RuntimeProviderKind>,

    /// Model id for subagent routing.
    #[arg(long)]
    pub runtime_subagent_model: Option<String>,

    /// Runtime mode for summarizer routing.
    #[arg(long, value_parser = parse_runtime_mode)]
    pub runtime_summarizer_mode: Option<RuntimeMode>,

    /// Provider kind for summarizer routing.
    #[arg(long, value_parser = parse_runtime_provider_kind)]
    pub runtime_summarizer_provider_kind: Option<RuntimeProviderKind>,

    /// Model id for summarizer routing.
    #[arg(long)]
    pub runtime_summarizer_model: Option<String>,

    /// Deployment privacy posture: `hosted` (an operator hosts and CAN read
    /// this vault) or `self_host_local` (owner-operated, owner-held key).
    /// Defaults to `self_host_local`; hosting is opt-in.
    #[arg(long, value_parser = parse_privacy_posture)]
    pub privacy_posture: Option<HostingPrivacyPosture>,

    /// Opaque host-managed KMS/HSM key reference (ARN / URI / key id), never
    /// key material. Required by `--privacy-posture hosted` and rejected by
    /// `self_host_local`.
    #[arg(long)]
    pub hosted_kms_key_ref: Option<String>,
}

impl fmt::Debug for ServeArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServeArgs")
            .field("config", &self.config)
            .field("vault_path", &self.vault_path)
            .field("managed_by_hypnos", &self.managed_by_hypnos)
            .field("contract_version", &self.contract_version)
            .field("vault_name", &self.vault_name)
            .field("data_dir", &self.data_dir)
            .field("http_socket", &self.http_socket)
            .field("ctl_socket", &self.ctl_socket)
            .field("hypnos_socket", &self.hypnos_socket)
            .field("ready_fd", &self.ready_fd)
            .field("credentials_fd", &self.credentials_fd)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("auth_secret", &redacted_secret(&self.auth_secret))
            .field(
                "insecure_allow_unauthenticated",
                &self.insecure_allow_unauthenticated,
            )
            .field("allowed_origins", &self.allowed_origins)
            .field("dimensions", &self.dimensions)
            .field("map_size", &self.map_size)
            .field("log_level", &self.log_level)
            .field("dict_search_paths", &self.dict_search_paths)
            .field("default_window_count", &self.default_window_count)
            .field(
                "compaction_threshold_bytes",
                &self.compaction_threshold_bytes,
            )
            .field("compaction_throttle_secs", &self.compaction_throttle_secs)
            .field("bulk_chunk_size", &self.bulk_chunk_size)
            .field("max_frame_size", &self.max_frame_size)
            .field("max_update_payload", &self.max_update_payload)
            .field(
                "max_windows_per_connection",
                &self.max_windows_per_connection,
            )
            .field(
                "max_federation_windows_per_connection",
                &self.max_federation_windows_per_connection,
            )
            .field(
                "federation_flood_pause_secs",
                &self.federation_flood_pause_secs,
            )
            .field("max_messages_per_sec", &self.max_messages_per_sec)
            .field("ephemeral_timeout_ms", &self.ephemeral_timeout_ms)
            .field(
                "max_ephemeral_payload_bytes",
                &self.max_ephemeral_payload_bytes,
            )
            .field(
                "max_ephemeral_snapshot_bytes",
                &self.max_ephemeral_snapshot_bytes,
            )
            .field("max_entity_blob", &self.max_entity_blob)
            .field("max_bulk_decompressed", &self.max_bulk_decompressed)
            .field("runtime_mode", &self.runtime_mode)
            .field("runtime_byo_key_env", &self.runtime_byo_key_env)
            .field("runtime_orchestrator_mode", &self.runtime_orchestrator_mode)
            .field(
                "runtime_orchestrator_provider_kind",
                &self.runtime_orchestrator_provider_kind,
            )
            .field(
                "runtime_orchestrator_model",
                &self.runtime_orchestrator_model,
            )
            .field("runtime_subagent_mode", &self.runtime_subagent_mode)
            .field(
                "runtime_subagent_provider_kind",
                &self.runtime_subagent_provider_kind,
            )
            .field("runtime_subagent_model", &self.runtime_subagent_model)
            .field("runtime_summarizer_mode", &self.runtime_summarizer_mode)
            .field(
                "runtime_summarizer_provider_kind",
                &self.runtime_summarizer_provider_kind,
            )
            .field("runtime_summarizer_model", &self.runtime_summarizer_model)
            .field("privacy_posture", &self.privacy_posture)
            .field(
                "hosted_kms_key_ref",
                &redacted_secret(&self.hosted_kms_key_ref),
            )
            .finish()
    }
}

/// Fully resolved serve configuration after defaults, config file, env vars,
/// and flags have been merged.
///
/// TLS terminates at a reverse proxy; native rustls support is out of scope for
/// this serve path. The default `0.0.0.0:9090` bind is self-host-by-design.
#[derive(Clone, PartialEq, Eq)]
pub struct ServeConfig {
    pub vault_path: PathBuf,
    pub host: String,
    pub port: u16,
    pub auth_secret: Option<String>,
    pub oauth_issuer: Option<String>,
    pub oauth_jwks_uri: Option<String>,
    pub oauth_resource_indicator: Option<String>,
    pub allow_unauthenticated: bool,
    pub allowed_origins: Vec<String>,
    pub lease_vault_id: u64,
    pub dimensions: usize,
    pub map_size: usize,
    pub log_level: String,
    pub dict_search_paths: Vec<PathBuf>,
    pub default_window_count: u8,
    pub compaction_threshold_bytes: u32,
    pub compaction_throttle_secs: u32,
    pub bulk_chunk_size: usize,
    pub max_frame_size: usize,
    pub max_update_payload: usize,
    pub max_windows_per_connection: usize,
    pub max_federation_windows_per_connection: usize,
    pub federation_flood_pause_secs: u64,
    pub max_messages_per_sec: u32,
    pub ephemeral_timeout_ms: i64,
    pub max_ephemeral_payload_bytes: usize,
    pub max_ephemeral_snapshot_bytes: usize,
    pub max_entity_blob: usize,
    pub max_bulk_decompressed: usize,
    pub runtime: RuntimeConfig,
    /// Deployment posture handed to the engine through [`Self::vault_config`].
    pub privacy_posture: HostingPrivacyPosture,
    /// Opaque host-managed KMS key reference. `Some` only for the hosted
    /// posture; self-host/local keeps no host reference at all. Never key
    /// material, and redacted in this struct's `Debug`.
    pub hosted_kms_key_ref: Option<String>,
}

impl Default for ServeConfig {
    fn default() -> Self {
        let server = SyncServerConfig::default();
        let vault = oneiron::VaultConfig::server();

        Self {
            vault_path: PathBuf::from(LEGACY_DEFAULT_VAULT_PATH),
            host: "0.0.0.0".to_owned(),
            port: 9090,
            auth_secret: server.auth_secret,
            oauth_issuer: server.oauth_issuer,
            oauth_jwks_uri: server.oauth_jwks_uri,
            oauth_resource_indicator: server.oauth_resource_indicator,
            allow_unauthenticated: server.allow_unauthenticated,
            allowed_origins: server.allowed_origins,
            lease_vault_id: server.lease_vault_id,
            dimensions: vault.dimensions,
            map_size: vault.map_size,
            log_level: "info".to_owned(),
            dict_search_paths: vault.dict_search_paths,
            default_window_count: server.default_window_count,
            compaction_threshold_bytes: server.compaction_threshold_bytes,
            compaction_throttle_secs: server.compaction_throttle_secs,
            bulk_chunk_size: server.bulk_chunk_size,
            max_frame_size: server.max_frame_size,
            max_update_payload: server.max_update_payload,
            max_windows_per_connection: server.max_windows_per_connection,
            max_federation_windows_per_connection: server.max_federation_windows_per_connection,
            federation_flood_pause_secs: server.federation_flood_pause_secs,
            max_messages_per_sec: server.max_messages_per_sec,
            ephemeral_timeout_ms: server.ephemeral_timeout_ms,
            max_ephemeral_payload_bytes: server.max_ephemeral_payload_bytes,
            max_ephemeral_snapshot_bytes: server.max_ephemeral_snapshot_bytes,
            max_entity_blob: server.max_entity_blob,
            max_bulk_decompressed: server.max_bulk_decompressed,
            runtime: server.runtime,
            // Hosting is opt-in: an operator must name the posture AND supply
            // its host-managed key reference before a vault is host-readable.
            privacy_posture: HostingPrivacyPosture::SelfHostLocal,
            hosted_kms_key_ref: None,
        }
    }
}

impl fmt::Debug for ServeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServeConfig")
            .field("vault_path", &self.vault_path)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("auth_secret", &redacted_secret(&self.auth_secret))
            .field("allow_unauthenticated", &self.allow_unauthenticated)
            .field("allowed_origins", &self.allowed_origins)
            .field("lease_vault_id", &self.lease_vault_id)
            .field("dimensions", &self.dimensions)
            .field("map_size", &self.map_size)
            .field("log_level", &self.log_level)
            .field("dict_search_paths", &self.dict_search_paths)
            .field("default_window_count", &self.default_window_count)
            .field(
                "compaction_threshold_bytes",
                &self.compaction_threshold_bytes,
            )
            .field("compaction_throttle_secs", &self.compaction_throttle_secs)
            .field("bulk_chunk_size", &self.bulk_chunk_size)
            .field("max_frame_size", &self.max_frame_size)
            .field("max_update_payload", &self.max_update_payload)
            .field(
                "max_windows_per_connection",
                &self.max_windows_per_connection,
            )
            .field(
                "max_federation_windows_per_connection",
                &self.max_federation_windows_per_connection,
            )
            .field(
                "federation_flood_pause_secs",
                &self.federation_flood_pause_secs,
            )
            .field("max_messages_per_sec", &self.max_messages_per_sec)
            .field("ephemeral_timeout_ms", &self.ephemeral_timeout_ms)
            .field(
                "max_ephemeral_payload_bytes",
                &self.max_ephemeral_payload_bytes,
            )
            .field(
                "max_ephemeral_snapshot_bytes",
                &self.max_ephemeral_snapshot_bytes,
            )
            .field("max_entity_blob", &self.max_entity_blob)
            .field("max_bulk_decompressed", &self.max_bulk_decompressed)
            .field("runtime", &self.runtime)
            .field("privacy_posture", &self.privacy_posture)
            .field(
                "hosted_kms_key_ref",
                &redacted_secret(&self.hosted_kms_key_ref),
            )
            .finish()
    }
}

impl ServeConfig {
    pub fn sync_server_config(&self) -> SyncServerConfig {
        let sync = SyncServerConfig {
            default_window_count: self.default_window_count,
            compaction_threshold_bytes: self.compaction_threshold_bytes,
            compaction_throttle_secs: self.compaction_throttle_secs,
            bulk_chunk_size: self.bulk_chunk_size,
            auth_secret: self.auth_secret.clone(),
            oauth_issuer: self.oauth_issuer.clone(),
            oauth_jwks_uri: self.oauth_jwks_uri.clone(),
            oauth_resource_indicator: self.oauth_resource_indicator.clone(),
            allow_unauthenticated: self.allow_unauthenticated,
            allowed_origins: self.allowed_origins.clone(),
            lease_vault_id: self.lease_vault_id,
            max_frame_size: self.max_frame_size,
            max_update_payload: self.max_update_payload,
            max_windows_per_connection: self.max_windows_per_connection,
            max_federation_windows_per_connection: self.max_federation_windows_per_connection,
            federation_flood_pause_secs: self.federation_flood_pause_secs,
            max_messages_per_sec: self.max_messages_per_sec,
            ephemeral_timeout_ms: self.ephemeral_timeout_ms,
            max_ephemeral_payload_bytes: self.max_ephemeral_payload_bytes,
            max_ephemeral_snapshot_bytes: self.max_ephemeral_snapshot_bytes,
            max_entity_blob: self.max_entity_blob,
            max_bulk_decompressed: self.max_bulk_decompressed,
            runtime: self.runtime.clone(),
        };
        if let Err(error) = crate::oauth_relay::warm_if_configured(&sync) {
            tracing::warn!(
                ?error,
                "OAuth relay JWKS warm failed; relay remains fail-closed"
            );
        }
        sync
    }

    pub fn vault_config(&self) -> oneiron::VaultConfig {
        let mut config = oneiron::VaultConfig::server();
        config.dimensions = self.dimensions;
        config.map_size = self.map_size;
        config.dict_search_paths = self.dict_search_paths.clone();
        config.privacy = self.vault_privacy_config();
        config
    }

    /// Maps the resolved posture onto the engine's posture/custody pairing.
    ///
    /// Hosted carries the opaque host-managed reference; self-host/local
    /// carries no host reference at all, so a stale reference cannot ride
    /// along into an owner-operated deployment. `validate_serve_config`
    /// already rejects a hosted config without a reference; the empty string
    /// left here in that impossible case is rejected again by
    /// `VaultPrivacyConfig::validate` before the store opens.
    fn vault_privacy_config(&self) -> VaultPrivacyConfig {
        let data_key_custody = match self.privacy_posture {
            HostingPrivacyPosture::Hosted => VaultDataKeyCustody::HostManagedKms {
                key_ref: self.hosted_kms_key_ref.clone().unwrap_or_default(),
            },
            HostingPrivacyPosture::SelfHostLocal => VaultDataKeyCustody::OwnerHeldLocal,
        };
        VaultPrivacyConfig {
            posture: self.privacy_posture,
            data_key_custody,
        }
    }
}

/// Environment-derived serve settings.
#[derive(Clone, Debug, Default)]
pub struct EnvConfig {
    pub config_path: Option<PathBuf>,
    values: PartialServeConfig,
}

impl EnvConfig {
    pub fn from_process() -> anyhow::Result<Self> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    pub fn from_pairs<I, K, V>(pairs: I) -> anyhow::Result<Self>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let values: HashMap<String, String> = pairs
            .into_iter()
            .map(|(key, value)| (key.as_ref().to_owned(), value.as_ref().to_owned()))
            .collect();
        Self::from_lookup(|key| values.get(key).cloned())
    }

    fn from_lookup(mut lookup: impl FnMut(&str) -> Option<String>) -> anyhow::Result<Self> {
        let mut values = PartialServeConfig::default();
        let config_path = lookup("ONEIRON_CONFIG").map(PathBuf::from);

        values.vault_path = lookup_path(&mut lookup, "ONEIRON_VAULT_PATH");
        values.host = lookup("ONEIRON_HOST");
        values.port = lookup_parse(&mut lookup, "ONEIRON_PORT")?;
        values.auth_secret = lookup("ONEIRON_AUTH_SECRET");
        values.oauth_issuer = lookup("ONEIRON_OAUTH_ISSUER");
        values.oauth_jwks_uri = lookup("ONEIRON_OAUTH_JWKS_URI");
        values.oauth_resource_indicator = lookup("ONEIRON_OAUTH_RESOURCE_INDICATOR");
        values.allow_unauthenticated =
            lookup_bool(&mut lookup, "ONEIRON_INSECURE_ALLOW_UNAUTHENTICATED")?;
        values.allowed_origins = lookup_list(&mut lookup, "ONEIRON_ALLOWED_ORIGINS");
        values.lease_vault_id = lookup_parse(&mut lookup, "ONEIRON_LEASE_VAULT_ID")?;
        values.dimensions = lookup_parse(&mut lookup, "ONEIRON_DIMENSIONS")?;
        values.map_size = lookup_parse(&mut lookup, "ONEIRON_MAP_SIZE")?;
        values.log_level = lookup("ONEIRON_LOG_LEVEL");
        values.dict_search_paths = lookup_path_list(&mut lookup, "ONEIRON_DICT_SEARCH_PATHS");
        values.default_window_count = lookup_parse(&mut lookup, "ONEIRON_DEFAULT_WINDOW_COUNT")?;
        values.compaction_threshold_bytes =
            lookup_parse(&mut lookup, "ONEIRON_COMPACTION_THRESHOLD_BYTES")?;
        values.compaction_throttle_secs =
            lookup_parse(&mut lookup, "ONEIRON_COMPACTION_THROTTLE_SECS")?;
        values.bulk_chunk_size = lookup_parse(&mut lookup, "ONEIRON_BULK_CHUNK_SIZE")?;
        values.max_frame_size = lookup_parse(&mut lookup, "ONEIRON_MAX_FRAME_SIZE")?;
        values.max_update_payload = lookup_parse(&mut lookup, "ONEIRON_MAX_UPDATE_PAYLOAD")?;
        values.max_windows_per_connection =
            lookup_parse(&mut lookup, "ONEIRON_MAX_WINDOWS_PER_CONNECTION")?;
        values.max_federation_windows_per_connection =
            lookup_parse(&mut lookup, "ONEIRON_MAX_FEDERATION_WINDOWS_PER_CONNECTION")?;
        values.federation_flood_pause_secs =
            lookup_parse(&mut lookup, "ONEIRON_FEDERATION_FLOOD_PAUSE_SECS")?;
        values.max_messages_per_sec = lookup_parse(&mut lookup, "ONEIRON_MAX_MESSAGES_PER_SEC")?;
        values.ephemeral_timeout_ms = lookup_parse(&mut lookup, "ONEIRON_EPHEMERAL_TIMEOUT_MS")?;
        values.max_ephemeral_payload_bytes =
            lookup_parse(&mut lookup, "ONEIRON_MAX_EPHEMERAL_PAYLOAD_BYTES")?;
        values.max_ephemeral_snapshot_bytes =
            lookup_parse(&mut lookup, "ONEIRON_MAX_EPHEMERAL_SNAPSHOT_BYTES")?;
        values.max_entity_blob = lookup_parse(&mut lookup, "ONEIRON_MAX_ENTITY_BLOB")?;
        values.max_bulk_decompressed = lookup_parse(&mut lookup, "ONEIRON_MAX_BULK_DECOMPRESSED")?;
        values.runtime = lookup_runtime_override(&mut lookup)?;
        values.privacy_posture = lookup_parse(&mut lookup, "ONEIRON_PRIVACY_POSTURE")?;
        values.hosted_kms_key_ref = lookup("ONEIRON_HOSTED_KMS_KEY_REF");

        Ok(Self {
            config_path,
            values,
        })
    }
}

pub fn resolve_serve_config(args: &ServeArgs) -> anyhow::Result<ServeConfig> {
    resolve_serve_config_with_sources(args, EnvConfig::from_process()?, default_config_path())
}

pub fn resolve_serve_config_with_sources(
    args: &ServeArgs,
    env: EnvConfig,
    default_config_path: Option<PathBuf>,
) -> anyhow::Result<ServeConfig> {
    let flag_values = PartialServeConfig::from(args);
    let config_path = args
        .config
        .clone()
        .or_else(|| env.config_path.clone())
        .or(default_config_path);
    let explicit_config = args.config.is_some() || env.config_path.is_some();
    let file_values = match config_path {
        Some(path) if path.exists() => load_file_config(&path)?,
        Some(path) if explicit_config => {
            anyhow::bail!("config file {} does not exist", path.display());
        }
        _ => PartialServeConfig::default(),
    };

    let mut resolved = ServeConfig::default();
    let mut posture_source = None;
    let mut key_ref_source = None;
    for (source, values) in [file_values, env.values, flag_values]
        .into_iter()
        .enumerate()
    {
        if values.privacy_posture.is_some() {
            posture_source = Some(source);
        }
        if values.hosted_kms_key_ref.is_some() {
            key_ref_source = Some(source);
        }
        values.apply_to(&mut resolved);
    }
    // Only the final posture may discard inherited custody. An intermediate
    // self-host layer can still be overridden by a later hosted layer, which
    // needs the highest-precedence reference even when it came from the file.
    if resolved.privacy_posture == HostingPrivacyPosture::SelfHostLocal
        && let (Some(posture_source), Some(key_ref_source)) = (posture_source, key_ref_source)
        && key_ref_source < posture_source
    {
        resolved.hosted_kms_key_ref = None;
    }
    // Same-source or higher-precedence references remain for validation to
    // refuse rather than silently fixing a contradictory self-host request.
    validate_serve_config(&resolved)?;
    Ok(resolved)
}

fn validate_serve_config(config: &ServeConfig) -> anyhow::Result<()> {
    if config.ephemeral_timeout_ms <= 0 {
        anyhow::bail!("ephemeral_timeout_ms must be positive");
    }
    if config.max_ephemeral_payload_bytes == 0 {
        anyhow::bail!("max_ephemeral_payload_bytes must be positive");
    }
    if config.max_ephemeral_snapshot_bytes == 0 {
        anyhow::bail!("max_ephemeral_snapshot_bytes must be positive");
    }
    // Mirrors `oneiron::VaultPrivacyConfig::validate`, so a bad pairing is
    // refused while it is still a config error with an operator-facing
    // remedy, not only at open time.
    match config.privacy_posture {
        HostingPrivacyPosture::Hosted => {
            let key_ref = config.hosted_kms_key_ref.as_deref().unwrap_or_default();
            if key_ref.trim().is_empty() {
                anyhow::bail!(
                    "hosted privacy posture requires a non-empty host-managed KMS key reference (--hosted-kms-key-ref / ONEIRON_HOSTED_KMS_KEY_REF)"
                );
            }
        }
        HostingPrivacyPosture::SelfHostLocal => {
            // ANY reference, including a whitespace-only one, is refused: a
            // self-hosted owner holds their own key and stores no host
            // reference.
            if config.hosted_kms_key_ref.is_some() {
                anyhow::bail!(
                    "self_host_local privacy posture rejects host-managed KMS key custody; drop --hosted-kms-key-ref / ONEIRON_HOSTED_KMS_KEY_REF or select --privacy-posture hosted"
                );
            }
        }
    }
    Ok(())
}

pub fn default_config_path() -> Option<PathBuf> {
    if let Some(base) = std::env::var_os("XDG_CONFIG_HOME") {
        return Some(
            PathBuf::from(base)
                .join(DEFAULT_CONFIG_DIR)
                .join(DEFAULT_CONFIG_FILE),
        );
    }

    std::env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join(".config")
            .join(DEFAULT_CONFIG_DIR)
            .join(DEFAULT_CONFIG_FILE)
    })
}

fn load_file_config(path: &Path) -> anyhow::Result<PartialServeConfig> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read config file {}", path.display()))?;
    let config: FileServeConfig =
        toml::from_str(&raw).with_context(|| format!("parse config file {}", path.display()))?;
    Ok(config.into())
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileServeConfig {
    vault_path: Option<PathBuf>,
    host: Option<String>,
    port: Option<u16>,
    auth_secret: Option<String>,
    oauth_issuer: Option<String>,
    oauth_jwks_uri: Option<String>,
    oauth_resource_indicator: Option<String>,
    allow_unauthenticated: Option<bool>,
    allowed_origins: Option<Vec<String>>,
    lease_vault_id: Option<u64>,
    dimensions: Option<usize>,
    map_size: Option<usize>,
    log_level: Option<String>,
    dict_search_paths: Option<Vec<PathBuf>>,
    default_window_count: Option<u8>,
    compaction_threshold_bytes: Option<u32>,
    compaction_throttle_secs: Option<u32>,
    bulk_chunk_size: Option<usize>,
    max_frame_size: Option<usize>,
    max_update_payload: Option<usize>,
    max_windows_per_connection: Option<usize>,
    max_federation_windows_per_connection: Option<usize>,
    federation_flood_pause_secs: Option<u64>,
    max_messages_per_sec: Option<u32>,
    ephemeral_timeout_ms: Option<i64>,
    max_ephemeral_payload_bytes: Option<usize>,
    max_ephemeral_snapshot_bytes: Option<usize>,
    max_entity_blob: Option<usize>,
    max_bulk_decompressed: Option<usize>,
    runtime: Option<RuntimeConfigOverride>,
    privacy_posture: Option<HostingPrivacyPosture>,
    hosted_kms_key_ref: Option<String>,
}

impl From<FileServeConfig> for PartialServeConfig {
    fn from(value: FileServeConfig) -> Self {
        Self {
            vault_path: value.vault_path,
            host: value.host,
            port: value.port,
            auth_secret: value.auth_secret,
            oauth_issuer: value.oauth_issuer,
            oauth_jwks_uri: value.oauth_jwks_uri,
            oauth_resource_indicator: value.oauth_resource_indicator,
            allow_unauthenticated: value.allow_unauthenticated,
            allowed_origins: value.allowed_origins,
            lease_vault_id: value.lease_vault_id,
            dimensions: value.dimensions,
            map_size: value.map_size,
            log_level: value.log_level,
            dict_search_paths: value.dict_search_paths,
            default_window_count: value.default_window_count,
            compaction_threshold_bytes: value.compaction_threshold_bytes,
            compaction_throttle_secs: value.compaction_throttle_secs,
            bulk_chunk_size: value.bulk_chunk_size,
            max_frame_size: value.max_frame_size,
            max_update_payload: value.max_update_payload,
            max_windows_per_connection: value.max_windows_per_connection,
            max_federation_windows_per_connection: value.max_federation_windows_per_connection,
            federation_flood_pause_secs: value.federation_flood_pause_secs,
            max_messages_per_sec: value.max_messages_per_sec,
            ephemeral_timeout_ms: value.ephemeral_timeout_ms,
            max_ephemeral_payload_bytes: value.max_ephemeral_payload_bytes,
            max_ephemeral_snapshot_bytes: value.max_ephemeral_snapshot_bytes,
            max_entity_blob: value.max_entity_blob,
            max_bulk_decompressed: value.max_bulk_decompressed,
            runtime: value.runtime,
            privacy_posture: value.privacy_posture,
            hosted_kms_key_ref: value.hosted_kms_key_ref,
        }
    }
}

#[derive(Clone, Default)]
struct PartialServeConfig {
    vault_path: Option<PathBuf>,
    host: Option<String>,
    port: Option<u16>,
    auth_secret: Option<String>,
    oauth_issuer: Option<String>,
    oauth_jwks_uri: Option<String>,
    oauth_resource_indicator: Option<String>,
    allow_unauthenticated: Option<bool>,
    allowed_origins: Option<Vec<String>>,
    lease_vault_id: Option<u64>,
    dimensions: Option<usize>,
    map_size: Option<usize>,
    log_level: Option<String>,
    dict_search_paths: Option<Vec<PathBuf>>,
    default_window_count: Option<u8>,
    compaction_threshold_bytes: Option<u32>,
    compaction_throttle_secs: Option<u32>,
    bulk_chunk_size: Option<usize>,
    max_frame_size: Option<usize>,
    max_update_payload: Option<usize>,
    max_windows_per_connection: Option<usize>,
    max_federation_windows_per_connection: Option<usize>,
    federation_flood_pause_secs: Option<u64>,
    max_messages_per_sec: Option<u32>,
    ephemeral_timeout_ms: Option<i64>,
    max_ephemeral_payload_bytes: Option<usize>,
    max_ephemeral_snapshot_bytes: Option<usize>,
    max_entity_blob: Option<usize>,
    max_bulk_decompressed: Option<usize>,
    runtime: Option<RuntimeConfigOverride>,
    privacy_posture: Option<HostingPrivacyPosture>,
    hosted_kms_key_ref: Option<String>,
}

// Hand-written so the unresolved layers redact the same fields `ServeArgs` and
// `ServeConfig` do: `EnvConfig` wraps this struct and derives `Debug`, so a
// derived impl here would print a host-managed key reference verbatim and
// bypass the redaction the resolved config is careful about.
impl fmt::Debug for PartialServeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PartialServeConfig")
            .field("vault_path", &self.vault_path)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("auth_secret", &redacted_secret(&self.auth_secret))
            .field("oauth_issuer", &self.oauth_issuer)
            .field("oauth_jwks_uri", &self.oauth_jwks_uri)
            .field("oauth_resource_indicator", &self.oauth_resource_indicator)
            .field("allow_unauthenticated", &self.allow_unauthenticated)
            .field("allowed_origins", &self.allowed_origins)
            .field("lease_vault_id", &self.lease_vault_id)
            .field("dimensions", &self.dimensions)
            .field("map_size", &self.map_size)
            .field("log_level", &self.log_level)
            .field("dict_search_paths", &self.dict_search_paths)
            .field("default_window_count", &self.default_window_count)
            .field(
                "compaction_threshold_bytes",
                &self.compaction_threshold_bytes,
            )
            .field("compaction_throttle_secs", &self.compaction_throttle_secs)
            .field("bulk_chunk_size", &self.bulk_chunk_size)
            .field("max_frame_size", &self.max_frame_size)
            .field("max_update_payload", &self.max_update_payload)
            .field(
                "max_windows_per_connection",
                &self.max_windows_per_connection,
            )
            .field(
                "max_federation_windows_per_connection",
                &self.max_federation_windows_per_connection,
            )
            .field(
                "federation_flood_pause_secs",
                &self.federation_flood_pause_secs,
            )
            .field("max_messages_per_sec", &self.max_messages_per_sec)
            .field("ephemeral_timeout_ms", &self.ephemeral_timeout_ms)
            .field(
                "max_ephemeral_payload_bytes",
                &self.max_ephemeral_payload_bytes,
            )
            .field(
                "max_ephemeral_snapshot_bytes",
                &self.max_ephemeral_snapshot_bytes,
            )
            .field("max_entity_blob", &self.max_entity_blob)
            .field("max_bulk_decompressed", &self.max_bulk_decompressed)
            .field("runtime", &self.runtime)
            .field("privacy_posture", &self.privacy_posture)
            .field(
                "hosted_kms_key_ref",
                &redacted_secret(&self.hosted_kms_key_ref),
            )
            .finish()
    }
}

impl PartialServeConfig {
    fn apply_to(self, resolved: &mut ServeConfig) {
        if let Some(value) = self.vault_path {
            resolved.vault_path = expand_home(value);
        }
        if let Some(value) = self.host {
            resolved.host = value;
        }
        if let Some(value) = self.port {
            resolved.port = value;
        }
        if let Some(value) = self.auth_secret {
            resolved.auth_secret = Some(value);
        }
        if let Some(value) = self.oauth_issuer {
            resolved.oauth_issuer = Some(value);
        }
        if let Some(value) = self.oauth_jwks_uri {
            resolved.oauth_jwks_uri = Some(value);
        }
        if let Some(value) = self.oauth_resource_indicator {
            resolved.oauth_resource_indicator = Some(value);
        }
        if let Some(value) = self.allow_unauthenticated {
            resolved.allow_unauthenticated = value;
        }
        if let Some(value) = self.allowed_origins {
            resolved.allowed_origins = normalize_list(value);
        }
        if let Some(value) = self.lease_vault_id {
            resolved.lease_vault_id = value;
        }
        if let Some(value) = self.dimensions {
            resolved.dimensions = value;
        }
        if let Some(value) = self.map_size {
            resolved.map_size = value;
        }
        if let Some(value) = self.log_level {
            resolved.log_level = value;
        }
        if let Some(value) = self.dict_search_paths {
            resolved.dict_search_paths = value.into_iter().map(expand_home).collect();
        }
        if let Some(value) = self.default_window_count {
            resolved.default_window_count = value;
        }
        if let Some(value) = self.compaction_threshold_bytes {
            resolved.compaction_threshold_bytes = value;
        }
        if let Some(value) = self.compaction_throttle_secs {
            resolved.compaction_throttle_secs = value;
        }
        if let Some(value) = self.bulk_chunk_size {
            resolved.bulk_chunk_size = value;
        }
        if let Some(value) = self.max_frame_size {
            resolved.max_frame_size = value;
        }
        if let Some(value) = self.max_update_payload {
            resolved.max_update_payload = value;
        }
        if let Some(value) = self.max_windows_per_connection {
            resolved.max_windows_per_connection = value;
        }
        if let Some(value) = self.max_federation_windows_per_connection {
            resolved.max_federation_windows_per_connection = value;
        }
        if let Some(value) = self.federation_flood_pause_secs {
            resolved.federation_flood_pause_secs = value;
        }
        if let Some(value) = self.max_messages_per_sec {
            resolved.max_messages_per_sec = value;
        }
        if let Some(value) = self.ephemeral_timeout_ms {
            resolved.ephemeral_timeout_ms = value;
        }
        if let Some(value) = self.max_ephemeral_payload_bytes {
            resolved.max_ephemeral_payload_bytes = value;
        }
        if let Some(value) = self.max_ephemeral_snapshot_bytes {
            resolved.max_ephemeral_snapshot_bytes = value;
        }
        if let Some(value) = self.max_entity_blob {
            resolved.max_entity_blob = value;
        }
        if let Some(value) = self.max_bulk_decompressed {
            resolved.max_bulk_decompressed = value;
        }
        if let Some(value) = self.runtime {
            resolved.runtime.apply_override(value);
        }
        if let Some(value) = self.privacy_posture {
            resolved.privacy_posture = value;
        }
        if let Some(value) = self.hosted_kms_key_ref {
            resolved.hosted_kms_key_ref = Some(value);
        }
    }
}

impl From<&ServeArgs> for PartialServeConfig {
    fn from(value: &ServeArgs) -> Self {
        Self {
            // `--data-dir` is the managed spelling of the same directory, so
            // the unmanaged merger honours it too rather than accepting it and
            // silently ignoring it. Strictly lower precedence than
            // `--vault-path`, so an argv without `--data-dir` resolves exactly
            // as it did before the flag existed.
            vault_path: value.vault_path.clone().or_else(|| value.data_dir.clone()),
            host: value.host.clone(),
            port: value.port,
            auth_secret: value.auth_secret.clone(),
            oauth_issuer: value.oauth_issuer.clone(),
            oauth_jwks_uri: value.oauth_jwks_uri.clone(),
            oauth_resource_indicator: value.oauth_resource_indicator.clone(),
            allow_unauthenticated: value.insecure_allow_unauthenticated,
            allowed_origins: value.allowed_origins.clone(),
            lease_vault_id: value.lease_vault_id,
            dimensions: value.dimensions,
            map_size: value.map_size,
            log_level: value.log_level.clone(),
            dict_search_paths: value.dict_search_paths.clone(),
            default_window_count: value.default_window_count,
            compaction_threshold_bytes: value.compaction_threshold_bytes,
            compaction_throttle_secs: value.compaction_throttle_secs,
            bulk_chunk_size: value.bulk_chunk_size,
            max_frame_size: value.max_frame_size,
            max_update_payload: value.max_update_payload,
            max_windows_per_connection: value.max_windows_per_connection,
            max_federation_windows_per_connection: value.max_federation_windows_per_connection,
            federation_flood_pause_secs: value.federation_flood_pause_secs,
            max_messages_per_sec: value.max_messages_per_sec,
            ephemeral_timeout_ms: value.ephemeral_timeout_ms,
            max_ephemeral_payload_bytes: value.max_ephemeral_payload_bytes,
            max_ephemeral_snapshot_bytes: value.max_ephemeral_snapshot_bytes,
            max_entity_blob: value.max_entity_blob,
            max_bulk_decompressed: value.max_bulk_decompressed,
            runtime: runtime_override_from_args(value),
            privacy_posture: value.privacy_posture,
            hosted_kms_key_ref: value.hosted_kms_key_ref.clone(),
        }
    }
}

fn lookup_runtime_override(
    lookup: &mut impl FnMut(&str) -> Option<String>,
) -> anyhow::Result<Option<RuntimeConfigOverride>> {
    let mut runtime = RuntimeConfigOverride::default();
    let mut has_runtime = false;

    if let Some(mode) = lookup_parse(lookup, "ONEIRON_RUNTIME_MODE")? {
        runtime.merge(RuntimeConfigOverride::mode(mode));
        has_runtime = true;
    }
    if let Some(byo_key_env) = lookup("ONEIRON_RUNTIME_BYO_KEY_ENV") {
        runtime.merge(RuntimeConfigOverride::with_byo_key_env(Some(byo_key_env)));
        has_runtime = true;
    }

    for role in RuntimeRole::ALL {
        let prefix = role_env_prefix(role);
        let mode_key = format!("{prefix}_MODE");
        let provider_key = format!("{prefix}_PROVIDER_KIND");
        let model_key = format!("{prefix}_MODEL");
        let mode = lookup(&mode_key)
            .map(|value| {
                value
                    .parse::<RuntimeMode>()
                    .map_err(|e| anyhow::anyhow!("parse {mode_key}={value:?}: {e}"))
            })
            .transpose()?;
        let provider_kind = lookup(&provider_key)
            .map(|value| {
                value
                    .parse::<RuntimeProviderKind>()
                    .map_err(|e| anyhow::anyhow!("parse {provider_key}={value:?}: {e}"))
            })
            .transpose()?;
        let model = lookup(&model_key);

        if mode.is_some() || provider_kind.is_some() || model.is_some() {
            runtime.merge(RuntimeConfigOverride::with_role_override(
                role,
                RuntimeRoleTargetOverride {
                    mode,
                    provider_kind,
                    model,
                },
            ));
            has_runtime = true;
        }
    }

    Ok(has_runtime.then_some(runtime))
}

fn runtime_override_from_args(args: &ServeArgs) -> Option<RuntimeConfigOverride> {
    let mut runtime = RuntimeConfigOverride::default();
    let mut has_runtime = false;

    if let Some(mode) = args.runtime_mode {
        runtime.merge(RuntimeConfigOverride::mode(mode));
        has_runtime = true;
    }
    if args.runtime_byo_key_env.is_some() {
        runtime.merge(RuntimeConfigOverride::with_byo_key_env(
            args.runtime_byo_key_env.clone(),
        ));
        has_runtime = true;
    }

    for (role, mode, provider_kind, model) in [
        (
            RuntimeRole::Orchestrator,
            args.runtime_orchestrator_mode,
            args.runtime_orchestrator_provider_kind,
            args.runtime_orchestrator_model.clone(),
        ),
        (
            RuntimeRole::Subagent,
            args.runtime_subagent_mode,
            args.runtime_subagent_provider_kind,
            args.runtime_subagent_model.clone(),
        ),
        (
            RuntimeRole::Summarizer,
            args.runtime_summarizer_mode,
            args.runtime_summarizer_provider_kind,
            args.runtime_summarizer_model.clone(),
        ),
    ] {
        if mode.is_some() || provider_kind.is_some() || model.is_some() {
            runtime.merge(RuntimeConfigOverride::with_role_override(
                role,
                RuntimeRoleTargetOverride {
                    mode,
                    provider_kind,
                    model,
                },
            ));
            has_runtime = true;
        }
    }

    has_runtime.then_some(runtime)
}

fn role_env_prefix(role: RuntimeRole) -> &'static str {
    match role {
        RuntimeRole::Orchestrator => "ONEIRON_RUNTIME_ORCHESTRATOR",
        RuntimeRole::Subagent => "ONEIRON_RUNTIME_SUBAGENT",
        RuntimeRole::Summarizer => "ONEIRON_RUNTIME_SUMMARIZER",
    }
}

fn lookup_parse<T>(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    key: &'static str,
) -> anyhow::Result<Option<T>>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    lookup(key)
        .map(|value| {
            value
                .parse::<T>()
                .map_err(|e| anyhow::anyhow!("parse {key}={value:?}: {e}"))
        })
        .transpose()
}

fn lookup_bool(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    key: &'static str,
) -> anyhow::Result<Option<bool>> {
    lookup(key).map(|value| parse_bool(key, &value)).transpose()
}

fn lookup_path(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    key: &'static str,
) -> Option<PathBuf> {
    lookup(key).map(PathBuf::from)
}

fn lookup_list(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    key: &'static str,
) -> Option<Vec<String>> {
    lookup(key).map(|value| split_list(&value))
}

fn lookup_path_list(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    key: &'static str,
) -> Option<Vec<PathBuf>> {
    lookup(key).map(|value| split_list(&value).into_iter().map(PathBuf::from).collect())
}

fn parse_bool(key: &'static str, value: &str) -> anyhow::Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => anyhow::bail!("parse {key}={value:?}: expected true/false, yes/no, on/off, or 1/0"),
    }
}

fn parse_runtime_mode(value: &str) -> Result<RuntimeMode, String> {
    value.parse()
}

fn parse_runtime_provider_kind(value: &str) -> Result<RuntimeProviderKind, String> {
    value.parse()
}

/// Clap value parser for `--privacy-posture`. Accepts only the two exact wire
/// values, so an unrecognized posture fails closed instead of resolving to a
/// default.
fn parse_privacy_posture(value: &str) -> Result<HostingPrivacyPosture, String> {
    value.parse()
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn normalize_list(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect()
}

fn expand_home(path: PathBuf) -> PathBuf {
    let Some(raw) = path.to_str() else {
        return path;
    };
    if raw == "~" {
        return std::env::var_os("HOME").map(PathBuf::from).unwrap_or(path);
    }
    if let Some(suffix) = raw.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(suffix);
    }
    path
}

fn redacted_secret(secret: &Option<String>) -> Option<&'static str> {
    secret.as_ref().map(|_| "<redacted>")
}

#[cfg(test)]
mod privacy_tests;
#[cfg(test)]
mod tests;
