//! Resolved server configuration: `SyncServerConfig` and `ServeConfig`.

use std::path::PathBuf;

use oneiron::{HostingPrivacyPosture, VaultDataKeyCustody, VaultPrivacyConfig};

use super::backup::BackupConfig;
use super::embedder::EmbedderConfig;
use super::failure_signals::FailureSignalsConfig;
use super::feedback::{FeedbackConfig, FeedbackInboxConfig};
use super::keystore::KeystoreConfig;
use super::limits::LimitsConfig;
use super::line::LineConfig;
use super::linear::LinearConfig;
use super::lookup::LEGACY_DEFAULT_VAULT_PATH;
use super::oneironer::OneironerConfig;
use super::recall::RecallConfig;
use super::self_heal::SelfHealConfig;
use super::skills::SkillsConfig;
use super::trusted_proxy::TrustedProxy;
use crate::runtime::RuntimeConfig;
use crate::usage::UsageMode;

/// The default inbound WebSocket frame bound (Engine 10:44 for parked L14):
/// the sync protocol's frame floor as base64 carries it, plus a window pad
/// envelope's header allowance and a window frame's lead (tag, key length,
/// key, sub-tag), so no frame the protocol sends within its floor is refused
/// at the socket.
const DEFAULT_MAX_FRAME_SIZE: usize =
    oneiron::sync::transport::MAX_DECODED_PAYLOAD_BYTES.div_ceil(3) * 4
        + oneiron::sync::transport::WINDOW_PAD_HEADER_BYTES
        + 3
        + oneiron::sync::transport::MAX_WINDOW_KEY_LEN;

/// The two configs' redacting `Debug`.
mod debug;

/// Oneiron sync server configuration.
///
/// Server-side enforcement status of the per-client limits (ONE-1129
/// OWNER-DECISION, recorded in the PR body):
/// - `max_update_payload` — ENFORCED at the WindowSync UPDATE chokepoint on
///   each frame or part a peer sends (an oversized frame closes the
///   connection before any state mutates); a payload joined from parts is
///   bounded by its envelope (FIX 8247, L14 s45 10:34).
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
    /// Every public URL a kit fetch may be signed for, as for a home behind
    /// several tunnel aliases (FIX 4404). Empty: `oauth_resource_indicator`.
    pub kit_bundle_public_urls: Vec<String>,
    /// The operator's cloud registration pins file (G7), as on
    /// [`ServeConfig`]: the server's client reads it once at start.
    pub cloud_registration_pins: Option<PathBuf>,
    /// The `[native_mail]` server the native mail pack's check reaches.
    pub native_mail: Option<super::NativeMailConfig>,
    /// The `[connectors.<name>]` transports the generic connector call
    /// reaches, by normalized catalog name.
    pub connectors: std::collections::BTreeMap<String, super::ConnectorHostConfig>,
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
    /// A managed vault's id, which managed serve alone sets when the vault
    /// serves an artifact origin: the listener then answers on that vault's
    /// internal authority (`<vault_id>.artifact.invalid`, FIX 6716) and on no
    /// artifact domain. No config file, environment or flag sets it.
    pub artifact_internal_vault_id: Option<String>,
    /// Reverse proxies whose `X-Forwarded-For` the server believes when it
    /// keys a request by client address. Empty: every caller is keyed by its
    /// own connection, whatever headers it sends.
    pub trusted_proxies: Vec<TrustedProxy>,
    /// Numeric vault scope for root lease registration/revocation.
    /// Hosted deployments must set a distinct value per tenant/vault; `0`
    /// preserves the legacy local single-vault scope.
    pub lease_vault_id: u64,
    /// Maximum inbound WebSocket frame size in bytes; the default holds the
    /// sync protocol's frame floor with its framing (`DEFAULT_MAX_FRAME_SIZE`).
    pub max_frame_size: usize,
    /// Maximum CRDT update bytes in one received frame or part (enforced on
    /// WindowSync UPDATE); the default is the frame floor.
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
    /// `[skills]`: resolved skill settings, including the conversion prompt.
    pub skills: SkillsConfig,
    /// `[line]`: the plan of the LINE Official Account the built-in LINE
    /// pack serves, and the pushes it includes each month.
    pub line: LineConfig,
    /// `[linear]`: the Linear mirror this server runs and its webhook's
    /// tracker mapping, nonsecret. A plain serve with no section reads its
    /// `ONEIRON_LINEAR_*` environment into this before the server starts
    /// ([`LinearConfig::or_environment`]); `None`, no mirror runs and the
    /// webhook maps nothing.
    pub linear: Option<LinearConfig>,
    /// Who authenticates the requests this server takes.
    pub ingress: IngressAuth,
    /// `[merge_queue]`: the queue checker's executor (FIX 6868). `None` is
    /// isolated and unconfigured.
    pub merge_queue: Option<super::MergeQueueCheckerConfig>,
    /// The organ builds this server runs as first party, by blake3 (64 lowercase
    /// hex), from `--trusted-organ-build` alone (FIX 7644), which a vault VM's
    /// init passes from its config drive's list (FIX 7889). Listing a digest is
    /// the operator's statement that the build is reviewed first-party code
    /// (ARCH-0075: first party means reviewed repo code). A pack organ build not
    /// listed here installs as third party, which the organ host refuses to start
    /// until filesystem confinement for organs lands. No config file, settings
    /// file or environment sets it, and nothing a pack carries (manifest, facet,
    /// receipt, publisher, hub or name) adds to it. Empty: every pack organ build
    /// is third party; a seal organ program the host names stays first party.
    pub trusted_organ_builds: std::collections::BTreeSet<String>,
    /// The private origins a managed node's egress guard admits, from
    /// `--hosted-private-origin` in managed boot alone (FIX 7657); empty
    /// everywhere else, and no config file, settings file or environment sets it.
    pub hosted_private_origins: std::collections::BTreeSet<oneiron::web_fetch::HostedPrivateOrigin>,
}

/// Who authenticates the requests a server takes, as its serve entry
/// declares it. The Linear mirror runs only behind authenticated ingress,
/// so no anonymous core writer can hand it TASKs to send.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum IngressAuth {
    /// The server's own `auth_secret` and `allow_unauthenticated` decide:
    /// every plain serve.
    #[default]
    Configured,
    /// The managed supervisor authenticates ingress on the private socket
    /// it owns, and the vault attests the owner on each route it forwards;
    /// a request with no credential is anonymous and stands for no one.
    Supervisor,
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
            kit_bundle_public_urls: Vec::new(),
            cloud_registration_pins: None,
            native_mail: None,
            connectors: std::collections::BTreeMap::new(),
            allow_unauthenticated: false,
            allowed_origins: Vec::new(),
            artifact_domains: Vec::new(),
            artifact_vault_name: None,
            artifact_internal_vault_id: None,
            trusted_proxies: Vec::new(),
            lease_vault_id: 0,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            // The frame floor (L14 s45 10:34).
            max_update_payload: oneiron::sync::transport::MAX_DECODED_PAYLOAD_BYTES,
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
            skills: SkillsConfig::default(),
            line: LineConfig::default(),
            linear: None,
            ingress: IngressAuth::Configured,
            merge_queue: None,
            trusted_organ_builds: std::collections::BTreeSet::new(),
            hosted_private_origins: std::collections::BTreeSet::new(),
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
    pub kit_bundle_public_urls: Vec<String>,
    /// `--cloud-registration-pins`, argv only, plain or managed: the public
    /// pins the native cloud registration client trusts (G7). Unset, that
    /// feature alone is not configured.
    pub cloud_registration_pins: Option<PathBuf>,
    pub allow_unauthenticated: bool,
    pub allowed_origins: Vec<String>,
    pub artifact_domains: Vec<String>,
    pub artifact_vault_name: Option<String>,
    /// Managed serve's alone, as on [`SyncServerConfig`].
    pub artifact_internal_vault_id: Option<String>,
    pub trusted_proxies: Vec<TrustedProxy>,
    pub lease_vault_id: u64,
    pub dimensions: usize,
    /// MRL graph prefix, fixed at vault open; unset until the model's prefix is measured.
    pub fast_dims: Option<u16>,
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
    /// The `[self_heal]` section: the model-graded detectors over retrieval
    /// telemetry.
    pub self_heal: SelfHealConfig,
    /// The `[recall]` section: call mode's deadline.
    pub recall: RecallConfig,
    /// The `[policy]` section: the owner plane's notice wording and settings,
    /// each absent key the engine's default (FIX 5042).
    pub policy: super::PolicyConfig,
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
    /// The `[merge_queue]` section: the queue checker's executor.
    pub merge_queue: Option<super::MergeQueueCheckerConfig>,
    /// The `[gpu]` section: the batch lane's rented pods, absent until the
    /// config file names it. Absent means every batch runs where its slot's
    /// provider runs.
    pub gpu: Option<crate::runtime::GpuPoolConfig>,
    /// The `[native_mail]` section: the host's own mail server, absent until
    /// the config file names it.
    pub native_mail: Option<super::NativeMailConfig>,
    /// The `[device_sync]` section: the home this machine dials, absent until
    /// the config file names it. Absent means it dials no one.
    pub device_sync: Option<super::DeviceSyncConfig>,
    /// The `[connectors.<name>]` sections: each catalog connector's installed
    /// transport and endpoint, empty until the config file names one.
    pub connectors: std::collections::BTreeMap<String, super::ConnectorHostConfig>,
    /// The `[embedding]` section: spaces and kind slots seeded at start,
    /// absent until the config file names it.
    pub embedding: Option<super::EmbeddingConfig>,
    /// The `[line]` section: the LINE Official Account's plan, a free
    /// account unless the config file names one.
    pub line: LineConfig,
    /// The `[linear]` section: the Linear mirror and its webhook's tracker
    /// mapping, absent until the config file names it.
    pub linear: Option<LinearConfig>,
    /// Deployment posture handed to the engine through [`Self::vault_config`].
    pub privacy_posture: HostingPrivacyPosture,
    /// The owner's "Help improve Oneiron" choice, as given: `None` takes the
    /// deployment's default, on for our managed serve and off on every plain
    /// serve ([`oneiron::config::failure_signals::default_exports`]).
    pub failure_signal_export: Option<bool>,
    /// The owner's training choice on what that switch sends, as given:
    /// `None` follows the switch (FIX 5188).
    pub failure_signal_training: Option<bool>,
    /// Opaque host-managed KMS key reference. `Some` only for the managed
    /// posture; relay and self-host keep no host reference at all. Never key
    /// material, and redacted in this struct's `Debug`.
    pub hosted_kms_key_ref: Option<String>,
    /// Whether serve starts the fact-hook runner; `--no-hooks` turns it off.
    pub hooks: bool,
    /// `maximum_tier = true`: a vault created here seals every page (OF-570,
    /// [`oneiron::PAGE_SEAL_WARNING`]). The tier is chosen when the vault is
    /// created; a sealed vault opens sealed whatever this says.
    pub maximum_tier: bool,
    /// `device_class = "phone"` or `"computer"`: what kind of machine this
    /// install is, as this host declares it (FIX 3349). Its enrolment carries
    /// it for the owner to approve; it is never read off the operating
    /// system. A computer unless the file says otherwise.
    pub device_class: oneiron::authority::MachineDeviceClass,
    /// `--esign-delivery-outbox-dir`, argv only: where the e-sign delivery
    /// outbox hands authorized mail to the host's sender (OF-415). Unset, no
    /// outbox worker runs.
    pub esign_delivery_outbox_dir: Option<PathBuf>,
    /// `--publisher-training-outbox-dir`, argv only: where the publisher
    /// training outbox writes offers and withdrawals and reads the intake's
    /// receipts (OF-420). Unset, no outbox worker runs.
    pub publisher_training_outbox_dir: Option<PathBuf>,
    /// `--publisher-training-self-host-shipper`, argv only: plain serve's
    /// self-host training shipper (TL-6), off by default. It rides the
    /// outbox; without one it warns once and stays inactive. Managed serve
    /// leaves it off whatever argv says: the supervisor ships there.
    pub publisher_training_self_host_shipper: bool,
    /// `--publisher-training-intake-origin`, argv only: the intake the
    /// self-host shipper reaches, `https://oneiron.dev` by default.
    pub publisher_training_intake_origin: String,
    /// `--shared-model-root`, managed and argv only: the node's read-only
    /// shared model root as its check accepted it, where a model directory
    /// the settings file names may lie
    /// ([`oneiron_vault_contract::settings_paths::SharedModelRoot`]). Unset
    /// on a plain serve, and where the supervisor declared none or its
    /// check ignored the one declared.
    pub shared_model_root: Option<oneiron_vault_contract::settings_paths::SharedModelRoot>,
    /// `--trusted-organ-build`, argv only, plain or managed: the organ builds
    /// this server runs as first party, as on [`SyncServerConfig`].
    pub trusted_organ_builds: std::collections::BTreeSet<String>,
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
            kit_bundle_public_urls: server.kit_bundle_public_urls,
            cloud_registration_pins: server.cloud_registration_pins,
            allow_unauthenticated: server.allow_unauthenticated,
            allowed_origins: server.allowed_origins,
            artifact_domains: server.artifact_domains,
            artifact_vault_name: server.artifact_vault_name,
            artifact_internal_vault_id: server.artifact_internal_vault_id,
            trusted_proxies: server.trusted_proxies,
            lease_vault_id: server.lease_vault_id,
            dimensions: vault.dimensions,
            fast_dims: vault.fast_dims,
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
            self_heal: SelfHealConfig::default(),
            recall: RecallConfig::default(),
            policy: super::PolicyConfig::default(),
            skills: SkillsConfig::default(),
            keystore: KeystoreConfig::default(),
            limits: LimitsConfig::default(),
            import: super::ImportConfig::default(),
            models: None,
            browser: None,
            desktop: None,
            merge_queue: None,
            gpu: None,
            native_mail: None,
            device_sync: None,
            connectors: std::collections::BTreeMap::new(),
            embedding: None,
            line: server.line,
            linear: None,
            // Hosting is opt-in: an operator must name the posture AND supply
            // its host-managed key reference before a vault is host-readable.
            privacy_posture: HostingPrivacyPosture::SelfHostLocal,
            failure_signal_export: None,
            failure_signal_training: None,
            hosted_kms_key_ref: None,
            hooks: true,
            maximum_tier: false,
            device_class: vault.machine_device_class,
            esign_delivery_outbox_dir: None,
            publisher_training_outbox_dir: None,
            publisher_training_self_host_shipper: false,
            publisher_training_intake_origin: crate::conversation_training::DEFAULT_INTAKE_ORIGIN
                .to_owned(),
            shared_model_root: None,
            trusted_organ_builds: server.trusted_organ_builds,
        }
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
            kit_bundle_public_urls: self.kit_bundle_public_urls.clone(),
            cloud_registration_pins: self.cloud_registration_pins.clone(),
            native_mail: self.native_mail.clone(),
            connectors: self
                .connectors
                .iter()
                .map(|(name, connector)| {
                    (super::connectors::normalize_name(name), connector.clone())
                })
                .collect(),
            allow_unauthenticated: self.allow_unauthenticated,
            allowed_origins: self.allowed_origins.clone(),
            artifact_domains: self.artifact_domains.clone(),
            artifact_vault_name: self.artifact_vault_name.clone(),
            artifact_internal_vault_id: self.artifact_internal_vault_id.clone(),
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
            skills: self.skills.clone(),
            line: self.line,
            linear: self.linear.clone(),
            // A plain serve's own auth config; a managed vault declares its
            // supervisor's.
            ingress: IngressAuth::Configured,
            merge_queue: self.merge_queue.clone(),
            trusted_organ_builds: self.trusted_organ_builds.clone(),
            // Managed boot alone sets it (FIX 7657).
            hosted_private_origins: std::collections::BTreeSet::new(),
        };
        if let Err(error) = crate::oauth_relay::warm_if_configured(&sync) {
            tracing::warn!(
                ?error,
                "OAuth relay JWKS warm failed; relay remains fail-closed"
            );
        }
        sync
    }

    /// [`Self::base_vault_config`], a sealed vault's page seal unlocked with
    /// this device's keystore.
    pub fn vault_config(&self) -> oneiron::VaultConfig {
        let mut config = self.base_vault_config();
        config.page_seal = self.device_page_seal();
        config
    }

    /// The vault config these settings name, with no page seal: this
    /// device's keystore is not tried, so nothing is probed or logged for a
    /// sealed vault. A caller that unlocks the vault its own way (a managed
    /// node's delivered key, the seal a restore chose) sets that seal alone
    /// (FIX 2544, 2709).
    pub fn base_vault_config(&self) -> oneiron::VaultConfig {
        let mut config = oneiron::VaultConfig::server();
        config.dimensions = self.dimensions;
        config.fast_dims = self.fast_dims;
        config.map_size = self.map_size;
        config.dict_search_paths = self.dict_search_paths.clone();
        config.assistant_display_names = self.assistant_display_names.clone();
        config.privacy = self.vault_privacy_config();
        config.machine_device_class = self.device_class;
        config.limits = self.limits.engine.clone();
        config.call_mode_deadline = std::time::Duration::from_millis(self.recall.call_deadline_ms);
        // A plain serve is self-run whatever posture it declares, so "Help
        // improve Oneiron" and training on what it sends stay off until its
        // owner turns them on; only the managed serve entry sets the managed
        // deployment (CALLS 1459).
        config.failure_signals = oneiron::config::failure_signals::FailureSignalConfig {
            deployment: oneiron::config::failure_signals::DeploymentTier::SelfHost,
            export_opt_in: self.failure_signal_export,
            training_opt_in: self.failure_signal_training,
        };
        // An active embedder pins the vault's embedding space. The engine then
        // refuses any embedder whose `model_id` disagrees with what the vault
        // already holds, which is the door that keeps one vault to one space.
        // The prefix stays unset unless the host explicitly selects a measured MRL width.
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
    /// The resolver clears only lower-precedence references when a relay
    /// wins; a self-hosted vault keeps one as its own KMS key's custody. A
    /// reference still present here must survive conversion so
    /// `VaultPrivacyConfig::validate` refuses contradictory custody before any
    /// store opens. No reference is an owner-held key on any posture.
    fn vault_privacy_config(&self) -> VaultPrivacyConfig {
        let data_key_custody = match &self.hosted_kms_key_ref {
            Some(key_ref) => VaultDataKeyCustody::HostManagedKms {
                key_ref: key_ref.clone(),
            },
            None => VaultDataKeyCustody::OwnerHeldLocal,
        };
        VaultPrivacyConfig {
            posture: self.privacy_posture,
            data_key_custody,
        }
    }
}
