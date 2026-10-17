//! Resolved server configuration: `SyncServerConfig` and `ServeConfig`.

use std::fmt;
use std::path::PathBuf;

use oneiron::{HostingPrivacyPosture, VaultDataKeyCustody, VaultPrivacyConfig};

use super::backup::BackupConfig;
use super::embedder::EmbedderConfig;
use super::failure_signals::FailureSignalsConfig;
use super::feedback::{FeedbackConfig, FeedbackInboxConfig};
use super::keystore::KeystoreConfig;
use super::limits::LimitsConfig;
use super::lookup::{LEGACY_DEFAULT_VAULT_PATH, redacted_secret};
use super::oneironer::OneironerConfig;
use super::recall::RecallConfig;
use super::skills::SkillsConfig;
use super::trusted_proxy::TrustedProxy;
use crate::runtime::RuntimeConfig;
use crate::usage::UsageMode;

/// Oneiron sync server configuration.
///
/// Server-side enforcement status of the per-client limits (ONE-1129
/// OWNER-DECISION, recorded in the PR body):
/// - `max_update_payload` — ENFORCED at the WindowSync UPDATE chokepoint
///   (oversized updates close the connection before any state mutates).
/// - `max_frame_size` — ENFORCED on the WebSocket frame size.
/// - `max_messages_per_sec` — retained for configuration compatibility only.
///   RC42 counters ask typed questions and never refuse calls for rate.
/// - `max_windows_per_connection` — a row set far above fleet scale on what
///   one socket keeps per window and per document. Past it a v13 socket
///   forgets its least recently requested window subscription (the window's
///   next change reaches the peer as `WINDOW_INVALIDATE`) and the row asks
///   its OF-520 question once; no socket is refused for the count.
/// - `max_ephemeral_payload_bytes` — ENFORCED on each ephemeral frame. The
///   hub itself is charged to `limits.retained_memory_bytes`, never capped.
/// - `max_ephemeral_snapshot_bytes` — the most one late-join presence frame
///   carries; a larger hub is sent in parts.
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
    /// Retained host issuer key material. Never accepted as a bearer credential.
    /// Logged, holder-bound slips authorize HTTP and `/ws` on both transports;
    /// rotation requires new slips, and a named slip may be revoked separately.
    pub auth_secret: Option<String>,
    pub oauth_issuer: Option<String>,
    pub oauth_jwks_uri: Option<String>,
    pub oauth_resource_indicator: Option<String>,
    /// Explicit local/dev escape hatch for running without `auth_secret`.
    pub allow_unauthenticated: bool,
    /// Explicit CORS origins allowed to call the HTTP API. Empty is
    /// fail-closed: no cross-origin browser access is granted.
    pub allowed_origins: Vec<String>,
    /// Domains whose subdomains name vaults on the artifact listener
    /// (`<vault>.<domain>/<artifact>/…`). Empty: local `/a/` serving only.
    pub artifact_domains: Vec<String>,
    /// The subdomain label this server's vault answers to under every
    /// artifact domain. `None`: every vault subdomain answers as unknown.
    pub artifact_vault_name: Option<String>,
    /// Reverse proxies whose `X-Forwarded-For` the server believes when it
    /// keys a request by client address. Empty: every caller is keyed by its
    /// own connection, whatever headers it sends.
    pub trusted_proxies: Vec<TrustedProxy>,
    /// Numeric vault scope for root lease registration/revocation.
    /// Hosted deployments must set a distinct value per tenant/vault; `0`
    /// preserves the legacy local single-vault scope.
    pub lease_vault_id: u64,
    /// Maximum WebSocket frame size in bytes.
    pub max_frame_size: usize,
    /// Maximum CRDT update payload in bytes (enforced on WindowSync UPDATE).
    pub max_update_payload: usize,
    /// Window subscriptions one v13 connection keeps before it forgets the least recently
    /// requested, and the count past which a connection's windows or documents ask the row's
    /// question. Never a refusal.
    pub max_windows_per_connection: usize,
    /// Maximum inbound protocol messages per connection per second.
    pub max_messages_per_sec: u32,
    /// Loro ephemeral-store inactivity timeout in milliseconds.
    pub ephemeral_timeout_ms: i64,
    /// Maximum Loro-native ephemeral payload bytes accepted from one frame.
    pub max_ephemeral_payload_bytes: usize,
    /// Maximum presence bytes in one late-join frame; a larger hub is sent in
    /// parts.
    pub max_ephemeral_snapshot_bytes: usize,
    /// Maximum entity blob size in bytes (M5/M6 bulk + materialization paths).
    pub max_entity_blob: usize,
    /// Per-object LFS upload cap in bytes, `LFS_DEFAULT_OBJECT_CAP` unless
    /// set. Always finite: an upload past it is refused mid-stream, and one
    /// that declares a larger size is refused before it starts.
    pub max_lfs_object_bytes: u64,
    /// Maximum decompressed BulkTransfer chunk in bytes (M5 Phase-3).
    pub max_bulk_decompressed: usize,
    /// The bounds on work a remote caller can start: git and LFS transfers.
    pub limits: LimitsConfig,
    /// `[feedback.inbox]`: whether this server keeps the keyless open inbox,
    /// and its flood cap.
    pub feedback_inbox: FeedbackInboxConfig,
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
            artifact_domains: Vec::new(),
            artifact_vault_name: None,
            trusted_proxies: Vec::new(),
            lease_vault_id: 0,
            max_frame_size: 4 * 1024 * 1024,     // 4 MB
            max_update_payload: 2 * 1024 * 1024, // 2 MB
            max_windows_per_connection: 65_536,
            max_messages_per_sec: 200,
            ephemeral_timeout_ms: 30_000,
            max_ephemeral_payload_bytes: 64 * 1024,   // 64 KB
            max_ephemeral_snapshot_bytes: 256 * 1024, // 256 KB
            max_entity_blob: 64 * 1024,               // 64 KB
            max_lfs_object_bytes: oneiron::origin::lfs::LFS_DEFAULT_OBJECT_CAP,
            max_bulk_decompressed: 8 * 1024 * 1024, // 8 MB
            limits: LimitsConfig::default(),
            feedback_inbox: FeedbackInboxConfig::default(),
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
            .field("artifact_domains", &self.artifact_domains)
            .field("artifact_vault_name", &self.artifact_vault_name)
            .field("trusted_proxies", &self.trusted_proxies)
            .field("lease_vault_id", &self.lease_vault_id)
            .field("max_frame_size", &self.max_frame_size)
            .field("max_update_payload", &self.max_update_payload)
            .field(
                "max_windows_per_connection",
                &self.max_windows_per_connection,
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
            .field("max_lfs_object_bytes", &self.max_lfs_object_bytes)
            .field("max_bulk_decompressed", &self.max_bulk_decompressed)
            .field("limits", &self.limits)
            .field("feedback_inbox", &self.feedback_inbox)
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
    /// The artifact-only listener's port on `host`; `0` takes any free one,
    /// which `/api/health` advertises as `artifact_port`.
    pub artifact_port: u16,
    pub auth_secret: Option<String>,
    pub oauth_issuer: Option<String>,
    pub oauth_jwks_uri: Option<String>,
    pub oauth_resource_indicator: Option<String>,
    pub allow_unauthenticated: bool,
    pub allowed_origins: Vec<String>,
    pub artifact_domains: Vec<String>,
    pub artifact_vault_name: Option<String>,
    pub trusted_proxies: Vec<TrustedProxy>,
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
    pub max_messages_per_sec: u32,
    pub ephemeral_timeout_ms: i64,
    pub max_ephemeral_payload_bytes: usize,
    pub max_ephemeral_snapshot_bytes: usize,
    pub max_entity_blob: usize,
    /// Per-object LFS upload cap in bytes, `LFS_DEFAULT_OBJECT_CAP` unless
    /// set. Always finite: an upload past it is refused mid-stream, and one
    /// that declares a larger size is refused before it starts.
    pub max_lfs_object_bytes: u64,
    pub max_bulk_decompressed: usize,
    pub runtime: RuntimeConfig,
    /// The `[embedder]` section, absent until some layer names a key in it.
    /// Absent means rung 0: no worker, no query door, vectors supplied by the
    /// client exactly as before this section existed.
    pub embedder: Option<EmbedderConfig>,
    /// The `[oneironer]` tagger slot, absent until some layer names a key in
    /// it. Absent means no tagger and no tagging marker.
    pub oneironer: Option<OneironerConfig>,
    /// The `[backup]` section: local backup directory, schedule and retention.
    pub backup: BackupConfig,
    /// The `[feedback]` section: where the owner's feedback goes.
    pub feedback: FeedbackConfig,
    /// The `[failure_signals]` section: the publisher this deployment's
    /// failure signals go to.
    pub failure_signals: FailureSignalsConfig,
    /// The `[recall]` section: call mode's deadline.
    pub recall: RecallConfig,
    /// The `[skills]` section: the skill-edit gate's live pull budget.
    pub skills: SkillsConfig,
    /// The `[keystore]` section: this install's this-device-only key slots.
    pub keystore: KeystoreConfig,
    /// The `[limits]` section: the bounds on work a remote caller can start.
    pub limits: LimitsConfig,
    /// The `[import]` section: the queue a running `serve` imports session
    /// logs from, off unless set.
    pub import: super::ImportConfig,
    /// The `[models]` section, absent until the config file names it.
    /// Absent means no model seat is filled: every model-free path runs and
    /// the Dreamer reports idle for want of a model.
    pub models: Option<super::ModelsConfig>,
    /// The `[browser]` section, absent until the config file names it.
    /// Absent means code runs have no browser.
    pub browser: Option<super::BrowserConfig>,
    /// The `[desktop]` section, absent until the config file names it.
    /// Absent means code runs have no desktop.
    pub desktop: Option<super::DesktopConfig>,
    /// The `[gpu]` section: the batch lane's rented pods, absent until the
    /// config file names it. Absent means every batch runs where its slot's
    /// provider runs.
    pub gpu: Option<crate::runtime::GpuPoolConfig>,
    /// Deployment posture handed to the engine through [`Self::vault_config`].
    pub privacy_posture: HostingPrivacyPosture,
    pub failure_signal_export: bool,
    pub failure_signal_training: bool,
    /// Opaque host-managed KMS key reference. `Some` only for the managed
    /// posture; relay and self-host keep no host reference at all. Never key
    /// material, and redacted in this struct's `Debug`.
    pub hosted_kms_key_ref: Option<String>,
    /// Whether serve starts the fact-hook runner; `--no-hooks` turns it off.
    pub hooks: bool,
}

impl Default for ServeConfig {
    fn default() -> Self {
        let server = SyncServerConfig::default();
        let vault = oneiron::VaultConfig::server();

        Self {
            vault_path: PathBuf::from(LEGACY_DEFAULT_VAULT_PATH),
            host: "0.0.0.0".to_owned(),
            port: 9090,
            artifact_port: 0,
            auth_secret: server.auth_secret,
            oauth_issuer: server.oauth_issuer,
            oauth_jwks_uri: server.oauth_jwks_uri,
            oauth_resource_indicator: server.oauth_resource_indicator,
            allow_unauthenticated: server.allow_unauthenticated,
            allowed_origins: server.allowed_origins,
            artifact_domains: server.artifact_domains,
            artifact_vault_name: server.artifact_vault_name,
            trusted_proxies: server.trusted_proxies,
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
            max_messages_per_sec: server.max_messages_per_sec,
            ephemeral_timeout_ms: server.ephemeral_timeout_ms,
            max_ephemeral_payload_bytes: server.max_ephemeral_payload_bytes,
            max_ephemeral_snapshot_bytes: server.max_ephemeral_snapshot_bytes,
            max_entity_blob: server.max_entity_blob,
            max_lfs_object_bytes: server.max_lfs_object_bytes,
            max_bulk_decompressed: server.max_bulk_decompressed,
            runtime: server.runtime,
            embedder: None,
            oneironer: None,
            backup: BackupConfig::default(),
            feedback: FeedbackConfig::default(),
            failure_signals: FailureSignalsConfig::default(),
            recall: RecallConfig::default(),
            skills: SkillsConfig::default(),
            keystore: KeystoreConfig::default(),
            limits: LimitsConfig::default(),
            import: super::ImportConfig::default(),
            models: None,
            browser: None,
            desktop: None,
            gpu: None,
            // Hosting is opt-in: an operator must name the posture AND supply
            // its host-managed key reference before a vault is host-readable.
            privacy_posture: HostingPrivacyPosture::SelfHostLocal,
            failure_signal_export: false,
            failure_signal_training: false,
            hosted_kms_key_ref: None,
            hooks: true,
        }
    }
}

impl fmt::Debug for ServeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServeConfig")
            .field("vault_path", &self.vault_path)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("artifact_port", &self.artifact_port)
            .field("auth_secret", &redacted_secret(&self.auth_secret))
            .field("allow_unauthenticated", &self.allow_unauthenticated)
            .field("allowed_origins", &self.allowed_origins)
            .field("artifact_domains", &self.artifact_domains)
            .field("artifact_vault_name", &self.artifact_vault_name)
            .field("trusted_proxies", &self.trusted_proxies)
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
            .field("max_lfs_object_bytes", &self.max_lfs_object_bytes)
            .field("max_bulk_decompressed", &self.max_bulk_decompressed)
            .field("runtime", &self.runtime)
            .field("embedder", &self.embedder)
            .field("oneironer", &self.oneironer)
            .field("backup", &self.backup)
            .field("feedback", &self.feedback)
            .field("failure_signals", &self.failure_signals)
            .field("recall", &self.recall)
            .field("skills", &self.skills)
            .field("keystore", &self.keystore)
            .field("limits", &self.limits)
            .field("import", &self.import)
            .field("models", &self.models)
            .field("browser", &self.browser)
            .field("desktop", &self.desktop)
            .field("gpu", &self.gpu)
            .field("privacy_posture", &self.privacy_posture)
            .field(
                "hosted_kms_key_ref",
                &redacted_secret(&self.hosted_kms_key_ref),
            )
            .field("hooks", &self.hooks)
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
            artifact_domains: self.artifact_domains.clone(),
            artifact_vault_name: self.artifact_vault_name.clone(),
            trusted_proxies: self.trusted_proxies.clone(),
            lease_vault_id: self.lease_vault_id,
            max_frame_size: self.max_frame_size,
            max_update_payload: self.max_update_payload,
            max_windows_per_connection: self.max_windows_per_connection,
            max_messages_per_sec: self.max_messages_per_sec,
            ephemeral_timeout_ms: self.ephemeral_timeout_ms,
            max_ephemeral_payload_bytes: self.max_ephemeral_payload_bytes,
            max_ephemeral_snapshot_bytes: self.max_ephemeral_snapshot_bytes,
            max_entity_blob: self.max_entity_blob,
            max_lfs_object_bytes: self.max_lfs_object_bytes,
            max_bulk_decompressed: self.max_bulk_decompressed,
            limits: self.limits.clone(),
            feedback_inbox: self.feedback.inbox,
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
        config.limits = self.limits.engine.clone();
        config.call_mode_deadline = std::time::Duration::from_millis(self.recall.call_deadline_ms);
        config.failure_signals = oneiron::config::failure_signals::FailureSignalConfig {
            deployment: if self.privacy_posture == HostingPrivacyPosture::Hosted {
                oneiron::config::failure_signals::DeploymentTier::Managed
            } else {
                oneiron::config::failure_signals::DeploymentTier::SelfHost
            },
            export_opt_in: self.failure_signal_export,
            training_opt_in: self.failure_signal_training,
        };
        // An active embedder pins the vault's embedding space. The engine then
        // refuses any embedder whose `model_id` disagrees with what the vault
        // already holds, which is the door that keeps one vault to one space.
        // No `fast_dims`: the default local model has no MRL to truncate to.
        let embedder = self
            .embedder
            .as_ref()
            .filter(|embedder| embedder.is_active());
        config.embedding_model = embedder.map(|embedder| embedder.model_id.clone());
        // Beside it, how the embedder turns that model's output into stored
        // vectors, when the section says so before the provider loads.
        config.embedding_transform = embedder.and_then(crate::embedder::declared_transform);
        // And where a vector hit counts as evidence in that space.
        config.vector_evidence = embedder
            .map(crate::embedder::evidence_floors)
            .unwrap_or_default();
        // An active tagger arms the outbox marker: every witnessed turn owes
        // it a pass, committed with the turn (ARCH-0036, serving the tagger).
        config.tagging = self
            .oneironer
            .as_ref()
            .and_then(OneironerConfig::marker_config);
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
            (HostingPrivacyPosture::SelfHostLocal | HostingPrivacyPosture::Relay, None) => {
                VaultDataKeyCustody::OwnerHeldLocal
            }
        };
        VaultPrivacyConfig {
            posture: self.privacy_posture,
            data_key_custody,
        }
    }
}
