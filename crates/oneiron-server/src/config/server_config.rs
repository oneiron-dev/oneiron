//! Resolved server configuration: `SyncServerConfig` and `ServeConfig`.

use std::fmt;
use std::path::PathBuf;

use oneiron::{HostingPrivacyPosture, VaultDataKeyCustody, VaultPrivacyConfig};

use super::lookup::{LEGACY_DEFAULT_VAULT_PATH, redacted_secret};
use crate::runtime::RuntimeConfig;
use crate::usage::UsageMode;

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
    pub assistant_display_names: Vec<String>,
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
            assistant_display_names: vault.assistant_display_names,
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
            .field("assistant_display_names", &self.assistant_display_names)
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
        config.assistant_display_names = self.assistant_display_names.clone();
        config.privacy = self.vault_privacy_config();
        config
    }

    /// Maps posture and custody without repairing invalid direct caller input.
    ///
    /// The resolver clears only lower-precedence references when self-host/local
    /// wins. A reference still present here must survive conversion so
    /// `VaultPrivacyConfig::validate` refuses contradictory custody before any
    /// store opens. Hosted without a reference retains an invalid empty one.
    fn vault_privacy_config(&self) -> VaultPrivacyConfig {
        let data_key_custody = match (self.privacy_posture, &self.hosted_kms_key_ref) {
            (_, Some(key_ref)) => VaultDataKeyCustody::HostManagedKms {
                key_ref: key_ref.clone(),
            },
            (HostingPrivacyPosture::Hosted, None) => VaultDataKeyCustody::HostManagedKms {
                key_ref: String::new(),
            },
            (HostingPrivacyPosture::SelfHostLocal, None) => VaultDataKeyCustody::OwnerHeldLocal,
        };
        VaultPrivacyConfig {
            posture: self.privacy_posture,
            data_key_custody,
        }
    }
}
