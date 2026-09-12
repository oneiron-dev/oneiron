//! CLI surface: `ServeArgs`, its redacting `Debug`, and argv-derived overrides.

use std::fmt;
use std::path::PathBuf;

use clap::Args;
use oneiron::HostingPrivacyPosture;

use super::embedder::EmbedderArgs;
use super::lookup::redacted_secret;
use crate::runtime::{
    RuntimeConfigOverride, RuntimeMode, RuntimeProviderKind, RuntimeRole, RuntimeRoleTargetOverride,
};

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

    /// `--embedder-*` flags. Flattened rather than inlined so the twenty keys
    /// of one optional section stay in the file that owns the section.
    #[command(flatten)]
    pub embedder: EmbedderArgs,

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

    /// Comma-separated host display names that classify a stored turn speaker
    /// as the assistant during dreamer consolidation.
    #[arg(long = "assistant-display-names", value_delimiter = ',', num_args = 1..)]
    pub assistant_display_names: Option<Vec<String>>,

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
            .field("embedder", &self.embedder)
            .field("privacy_posture", &self.privacy_posture)
            .field(
                "hosted_kms_key_ref",
                &redacted_secret(&self.hosted_kms_key_ref),
            )
            .finish()
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

pub(super) fn runtime_override_from_args(args: &ServeArgs) -> Option<RuntimeConfigOverride> {
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
