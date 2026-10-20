//! CLI surface: `ServeArgs`, its redacting `Debug`, and argv-derived overrides.

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Args;
use oneiron::HostingPrivacyPosture;

use super::embedder::EmbedderArgs;
use super::lookup::redacted_secret;
use super::oneironer::OneironerArgs;
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

    /// `--oneironer-*` flags: the tagger slot's section.
    #[command(flatten)]
    pub oneironer: OneironerArgs,

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

    /// Non-secret account or organization id (32 bytes in hexadecimal), supplied
    /// by the trusted supervisor. Required in managed mode. Never derived from
    /// the vault name, per-vault key, or a tenant request.
    #[arg(long = "derivation-owner")]
    pub derivation_owner: Option<String>,

    /// Trusted organization hosting id (32 bytes in hexadecimal). With no
    /// --member-vault, this is also the shared vault's derivation owner.
    #[arg(long = "organization-owner", requires = "managed_by_hypnos")]
    pub organization_owner: Option<String>,

    /// This organization's member vault, sealed to --derivation-owner rather
    /// than to the organization. The personal vault can leave with its member.
    #[arg(long = "member-vault", requires = "organization_owner")]
    pub member_vault: bool,

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

    /// Inherited file descriptor, the read end of a pipe, carrying the owner
    /// credential the custody anchor door (`[backup] custody_anchor_url`)
    /// admits: one JSON object, `{"bearer": "<token>", "binding_seed":
    /// null}` or with a capability slip's 32-byte binding seed as an array of
    /// 32 numbers, then EOF. Read once, before the vault opens, by managed and
    /// plain serve, `oneiron backup` and a restore where no vault is yet;
    /// never argv, the environment or a file. Without it the door is not
    /// called.
    #[arg(long = "custody-anchor-credentials-fd")]
    pub custody_anchor_credentials_fd: Option<i32>,

    /// Managed mode's cold restore start (LC FIX 5384/5385): the vault the
    /// plan on `--restore-input-fd` names is restored into `--data-dir` from
    /// its signed artifact, verified and kept, then served as an ordinary
    /// start serves it. Nothing listens before it is kept.
    #[arg(long = "restore", requires = "managed_by_hypnos")]
    pub restore: bool,

    /// Inherited file descriptor, the read end of a pipe, carrying a cold
    /// restore's plan: one JSON object
    /// (`oneiron_vault_contract::restore::ManagedRestoreInput`), then EOF.
    /// Read first, before the credential frame. It carries no secret.
    #[arg(long = "restore-input-fd", requires = "restore")]
    pub restore_input_fd: Option<i32>,

    /// Inherited file descriptor, the write end of a pipe, that a cold
    /// restore writes its result frames to, one JSON line each
    /// (`oneiron_vault_contract::restore::ManagedRestoreResultFrame`), and
    /// closes after its last.
    #[arg(long = "restore-result-fd", requires = "restore")]
    pub restore_result_fd: Option<i32>,

    /// Managed mode as a Firecracker vault VM's only process. The credential
    /// frame and the ready byte ride the vsock boot channel instead of
    /// `--credentials-fd` and `--ready-fd`, and the host reaches the HTTP and
    /// ctl sockets through vsock ports (`oneiron_vault_contract::vm`).
    #[arg(long = "vsock-guest")]
    pub vsock_guest: bool,

    /// This install's key directory, an absolute path outside the vault: where
    /// the this-device-only keystore keeps the machine encryption seed. Managed
    /// mode installs a keystore only from this flag; unmanaged serve reads it
    /// as `[keystore] dir`.
    #[arg(long = "keystore-dir")]
    pub keystore_dir: Option<PathBuf>,

    /// Managed mode: the node's managed escrow recipient, an absolute path to
    /// the file the node's operator installed it in, holding its hybrid
    /// public key's bytes. The vault seals its data key to it at start
    /// (CROSS-ARCH-0022 #ov-custody).
    #[arg(long = "escrow-recipient-file")]
    pub escrow_recipient_file: Option<PathBuf>,

    /// Managed mode: the owner-held offline break-glass recipient, an
    /// absolute path to the file holding its hybrid public key's bytes. The
    /// vault seals its data key to it at start, beside the managed one.
    #[arg(long = "break-glass-recipient-file")]
    pub break_glass_recipient_file: Option<PathBuf>,

    /// Managed mode: the directory the vault spools its escrow capsules to,
    /// an absolute path the supervisor chose and ships from. The node
    /// removes each report only after the registry's durable acknowledgement
    /// (CROSS-ARCH-0022 #ov-custody, invariant 03;
    /// `oneiron_vault_contract::escrow`).
    #[arg(long = "escrow-outbox-dir")]
    pub escrow_outbox_dir: Option<PathBuf>,

    /// Managed mode: a vault created at this start seals every page under the
    /// data key the supervisor delivers (the maximum tier, OF-570). Off unless
    /// given; a vault keeps the tier it was created with, and a sealed one
    /// reopens with the delivered key either way.
    #[arg(long = "maximum-tier", num_args = 0..=1, default_missing_value = "true")]
    pub maximum_tier: Option<bool>,

    /// Managed mode: the unix socket the vault's artifact origin listens on,
    /// an absolute path the supervisor chose. The edge forwards this vault's
    /// artifact names to it on the vault's internal authority,
    /// `<vault-name>.artifact.invalid` and `<app>.<vault-name>.artifact.invalid`
    /// (`oneiron_vault_contract::artifact_origin`, FIX 6716), the one host it
    /// answers on. Without it a managed vault serves `/a/` on its API socket
    /// alone.
    #[arg(long = "artifact-http-socket")]
    pub artifact_http_socket: Option<PathBuf>,

    /// The vault's owner settings, one TOML file in the server's own config
    /// schema, `[models]`, `[embedder]` and `[gpu]` included. Flags stand
    /// over it. On a plain serve it is read as a config file layered over
    /// `--config`, beneath the environment (FIX 5016). Managed mode: an
    /// absolute path, the one layer settings are read from, settled once; a
    /// leaf the supervisor owns (the listener, ingress and auth, tenant
    /// identity, custody, sockets, the key directory), a key named by an
    /// environment variable, and an owner path outside the vault's data
    /// directory and this file's own directory (a model directory may lie
    /// in `--shared-model-root` instead) are refused. Without it a managed
    /// vault runs on the defaults.
    #[arg(long = "settings-file")]
    pub settings_file: Option<PathBuf>,

    /// Where the server's own voice loop listens, an absolute path in an
    /// owner-only directory, over `[models.voice].socket`. The config's
    /// `[models.voice]` turns the loop on; this names its socket, and names
    /// none where no voice is configured. Managed mode: the path the
    /// supervisor chose, which the settings file never names (FIX 2391).
    #[arg(long = "voice-socket")]
    pub voice_socket: Option<PathBuf>,

    /// Managed mode: this vault's e-sign seal key, an absolute path to its
    /// PKCS#8 file (PEM or DER), in place of `ONEIRON_SEAL_KEY`, which
    /// managed mode never reads (FIX 3487).
    #[arg(long = "seal-key-file")]
    pub seal_key_file: Option<PathBuf>,

    /// Managed mode: the seal key's certificate chain, an absolute path to
    /// its PEM file, the signer first (`ONEIRON_SEAL_CHAIN`).
    #[arg(long = "seal-chain-file")]
    pub seal_chain_file: Option<PathBuf>,

    /// Managed mode: the seal's trust anchors, an absolute path to a PEM
    /// file (`ONEIRON_SEAL_TRUST`); the chain's last certificate without it.
    #[arg(long = "seal-trust-file")]
    pub seal_trust_file: Option<PathBuf>,

    /// Managed mode: the seal's timestamp authority URL (`ONEIRON_SEAL_TSA`):
    /// a B-T seal, B-B without one.
    #[arg(long = "seal-tsa-url")]
    pub seal_tsa_url: Option<String>,

    /// Managed mode: the signing page seal evidence names
    /// (`ONEIRON_SEAL_URL`); the sign page at the vault's public origin
    /// without it.
    #[arg(long = "seal-signing-url")]
    pub seal_signing_url: Option<String>,

    /// Managed mode: the seal organ's program, an absolute path
    /// (`ONEIRON_SEAL_ORGAN`), in place of the build an installed pack
    /// carries.
    #[arg(long = "seal-organ")]
    pub seal_organ: Option<PathBuf>,

    /// The directory the vault hands its authorized e-sign mail to (OF-415):
    /// each `esign.delivery` intent is written there as
    /// `esign-delivery-<key>.json` for the host's sender, which answers with
    /// `esign-delivery-<key>.ack.json`. Self-hosted or managed (an absolute
    /// path there); without it no outbox runs and the intents stay queued.
    #[arg(long = "esign-delivery-outbox-dir")]
    pub esign_delivery_outbox_dir: Option<PathBuf>,

    /// The directory the vault hands conversation text toward training the
    /// models Oneiron ships through (OF-420, "Learn from my conversations"),
    /// an absolute path: released offers in `offers/`, id-only withdrawals
    /// in `controls/`, the intake's receipts in `receipts/`, beside the
    /// intake's key files (`oneiron_vault_contract::conversation_training`).
    /// Self-hosted or managed (the supervisor's there); without it no outbox
    /// runs and nothing is shared.
    #[arg(long = "publisher-training-outbox-dir")]
    pub publisher_training_outbox_dir: Option<PathBuf>,

    /// Managed mode: the browser guest's container CLI, an absolute path on
    /// the vault's own host or root filesystem, which the supervisor binds.
    /// It stands as `[browser] runtime` when the settings file has a
    /// `[browser]` section, and never turns the guest on by itself (FIX 5015).
    #[arg(long = "browser-runtime", requires = "managed_by_hypnos")]
    pub browser_runtime: Option<PathBuf>,

    /// Managed mode: the desktop guest's container CLI, as
    /// `--browser-runtime` is the browser's, for a `[desktop]` section.
    #[arg(long = "desktop-runtime", requires = "managed_by_hypnos")]
    pub desktop_runtime: Option<PathBuf>,

    /// Managed mode: where pack organ builds are written, an absolute path on
    /// the tenant's own storage, in place of `ONEIRON_ORGAN_DIR` and the OS
    /// temp directory, which managed mode never uses (FIX 3565). Without it
    /// they go to `organs` under the data directory.
    #[arg(long = "organ-dir", requires = "managed_by_hypnos")]
    pub organ_dir: Option<PathBuf>,

    /// Managed mode: where the paired-machine mesh listener binds
    /// (`ip:port`), in place of `ONEIRON_MESH_BIND`, which managed mode never
    /// reads. Without it the mesh is off.
    #[arg(long = "mesh-bind", requires = "managed_by_hypnos")]
    pub mesh_bind: Option<SocketAddr>,

    /// Managed mode: comma-separated private relay URLs for the mesh, in
    /// place of `ONEIRON_MESH_RELAYS`. Without them the mesh takes direct
    /// paths only.
    #[arg(
        long = "mesh-relays",
        value_delimiter = ',',
        num_args = 1..,
        requires = "managed_by_hypnos"
    )]
    pub mesh_relays: Option<Vec<String>>,

    /// Managed mode: the node's shared model root, an absolute path where
    /// the supervisor installs each model bundle once for every vault,
    /// owned by root and writable by no vault's UID
    /// (`oneiron_vault_contract::settings_paths::SharedModelRoot`). A model
    /// directory the settings file names may be a bundle's own directory
    /// there, `<root>/<class>/<stack_sha16>`. A root that fails its check is
    /// ignored with a warning, never a refused start.
    #[arg(long = "shared-model-root", requires = "managed_by_hypnos")]
    pub shared_model_root: Option<PathBuf>,

    /// Host address to bind to.
    #[arg(long)]
    pub host: Option<String>,

    /// Port to bind to.
    #[arg(long)]
    pub port: Option<u16>,

    /// Port, on the same host, of the listener that serves artifacts (`/a/`)
    /// on an origin of their own. Defaults to any free port.
    #[arg(long = "artifact-port")]
    pub artifact_port: Option<u16>,

    /// Comma-separated domains whose subdomains name vaults on the artifact
    /// listener: `<vault>.<domain>/<artifact>/…` serves that vault's synced,
    /// pinned artifacts. DNS, certificates and the edge stay static config.
    /// Managed mode refuses it: a managed vault answers on its internal
    /// authority alone.
    #[arg(long = "artifact-domains", value_delimiter = ',', num_args = 1..)]
    pub artifact_domains: Option<Vec<String>>,

    /// The subdomain label (a DNS label) this server's vault answers to
    /// under every artifact domain.
    #[arg(long = "artifact-vault-name")]
    pub artifact_vault_name: Option<String>,

    /// Host issuer key material (never a bearer credential) and input for
    /// minted `v2` tokens. Rotating it invalidates all minted tokens.
    #[arg(long)]
    pub auth_secret: Option<String>,

    #[arg(long)]
    pub oauth_issuer: Option<String>,
    #[arg(long)]
    pub oauth_jwks_uri: Option<String>,
    /// The host's public https origin: the resource OAuth relay tokens are
    /// checked against, and the origin the host's app URLs, sign pages and
    /// kit fetches name. In managed mode the supervisor passes it, as it
    /// owns the vault's public addresses, and it builds no auth layer there:
    /// the relay also needs `--oauth-issuer` and `--oauth-jwks-uri`, which
    /// managed mode refuses.
    #[arg(long)]
    pub oauth_resource_indicator: Option<String>,

    /// Comma-separated public URLs a recovery kit may dial and sign its
    /// fetches for, one per address the home answers on
    /// (`ONEIRON_KIT_BUNDLE_PUBLIC_URLS`). Empty: `--oauth-resource-indicator`.
    /// In managed mode the supervisor passes them, as it owns the vault's
    /// public addresses.
    #[arg(long = "kit-bundle-public-urls", value_delimiter = ',', num_args = 1..)]
    pub kit_bundle_public_urls: Option<Vec<String>>,

    /// Insecure local/dev escape hatch: allow requests without auth_secret.
    /// Serve refuses it unless the listener is loopback.
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

    /// Comma-separated reverse proxies (`ip` or `ip/prefix`) whose
    /// `X-Forwarded-For` the server believes when it keys a caller by address.
    #[arg(long = "trusted-proxies", value_delimiter = ',', num_args = 1..)]
    pub trusted_proxies: Option<Vec<String>>,

    /// Numeric vault scope for lease registration and revocation.
    #[arg(long)]
    pub lease_vault_id: Option<u64>,

    /// Embedding vector dimension for the vault.
    #[arg(long)]
    pub dimensions: Option<usize>,

    /// Measured MRL prefix width: 1 <= fast-dims < dimensions, fixed at vault open.
    #[arg(long)]
    pub fast_dims: Option<u16>,

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

    /// Window subscriptions one connection keeps before it forgets the least
    /// recently requested; past it the row asks its question, never refuses.
    #[arg(long)]
    pub max_windows_per_connection: Option<usize>,

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

    /// Maximum bytes per LFS upload object (default 2 GiB).
    #[arg(long)]
    pub max_lfs_object_bytes: Option<u64>,

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

    /// Deployment privacy posture: `managed` (an operator hosts and CAN read
    /// this vault), `relay` (blind relay, no host keys), or `self-host`
    /// (owner-operated, owner-held key). Defaults to `self-host`; managed
    /// hosting is opt-in.
    #[arg(long, value_parser = parse_privacy_posture)]
    pub privacy_posture: Option<HostingPrivacyPosture>,
    /// "Help improve Oneiron": send the content-free failure counts and the
    /// Coach's code-fix records. Default on for a hosted vault, which can
    /// turn it off; off on self-host until set true.
    #[arg(long, action = clap::ArgAction::Set)]
    pub failure_signal_export: Option<bool>,
    /// Training on what "Help improve Oneiron" sends, as its own yes or no.
    /// Unset, it follows that switch: on exactly when the vault exports.
    #[arg(long, action = clap::ArgAction::Set)]
    pub failure_signal_training: Option<bool>,

    /// Opaque host-managed KMS/HSM key reference (ARN / URI / key id), never
    /// key material. Required by `--privacy-posture managed` and rejected by
    /// `relay` and `self-host`.
    #[arg(long)]
    pub hosted_kms_key_ref: Option<String>,

    /// Start no fact-hook runner for this run: the clean baseline
    /// (ARCH-0080 §10).
    #[arg(long = "no-hooks")]
    pub no_hooks: bool,
}

impl fmt::Debug for ServeArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServeArgs")
            .field("config", &self.config)
            .field("vault_path", &self.vault_path)
            .field("managed_by_hypnos", &self.managed_by_hypnos)
            .field("contract_version", &self.contract_version)
            .field("vault_name", &self.vault_name)
            .field("organization_owner", &self.organization_owner)
            .field("member_vault", &self.member_vault)
            .field("data_dir", &self.data_dir)
            .field("http_socket", &self.http_socket)
            .field("ctl_socket", &self.ctl_socket)
            .field("hypnos_socket", &self.hypnos_socket)
            .field("ready_fd", &self.ready_fd)
            .field("credentials_fd", &self.credentials_fd)
            .field(
                "custody_anchor_credentials_fd",
                &self.custody_anchor_credentials_fd,
            )
            .field("restore", &self.restore)
            .field("restore_input_fd", &self.restore_input_fd)
            .field("restore_result_fd", &self.restore_result_fd)
            .field("vsock_guest", &self.vsock_guest)
            .field("keystore_dir", &self.keystore_dir)
            .field("escrow_recipient_file", &self.escrow_recipient_file)
            .field(
                "break_glass_recipient_file",
                &self.break_glass_recipient_file,
            )
            .field("escrow_outbox_dir", &self.escrow_outbox_dir)
            .field("maximum_tier", &self.maximum_tier)
            .field("artifact_http_socket", &self.artifact_http_socket)
            .field("settings_file", &self.settings_file)
            .field("voice_socket", &self.voice_socket)
            .field("seal_key_file", &self.seal_key_file)
            .field("seal_chain_file", &self.seal_chain_file)
            .field("seal_trust_file", &self.seal_trust_file)
            .field("seal_tsa_url", &self.seal_tsa_url)
            .field("seal_signing_url", &self.seal_signing_url)
            .field("seal_organ", &self.seal_organ)
            .field("esign_delivery_outbox_dir", &self.esign_delivery_outbox_dir)
            .field(
                "publisher_training_outbox_dir",
                &self.publisher_training_outbox_dir,
            )
            .field("browser_runtime", &self.browser_runtime)
            .field("desktop_runtime", &self.desktop_runtime)
            .field("organ_dir", &self.organ_dir)
            .field("mesh_bind", &self.mesh_bind)
            .field("mesh_relays", &self.mesh_relays)
            .field("shared_model_root", &self.shared_model_root)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("artifact_port", &self.artifact_port)
            .field("artifact_domains", &self.artifact_domains)
            .field("artifact_vault_name", &self.artifact_vault_name)
            .field("kit_bundle_public_urls", &self.kit_bundle_public_urls)
            .field("auth_secret", &redacted_secret(&self.auth_secret))
            .field(
                "insecure_allow_unauthenticated",
                &self.insecure_allow_unauthenticated,
            )
            .field("allowed_origins", &self.allowed_origins)
            .field("trusted_proxies", &self.trusted_proxies)
            .field("dimensions", &self.dimensions)
            .field("fast_dims", &self.fast_dims)
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
            .field("oneironer", &self.oneironer)
            .field("privacy_posture", &self.privacy_posture)
            .field(
                "hosted_kms_key_ref",
                &redacted_secret(&self.hosted_kms_key_ref),
            )
            .field("no_hooks", &self.no_hooks)
            .finish()
    }
}

fn parse_runtime_mode(value: &str) -> Result<RuntimeMode, String> {
    value.parse()
}

fn parse_runtime_provider_kind(value: &str) -> Result<RuntimeProviderKind, String> {
    value.parse()
}

/// Clap value parser for `--privacy-posture`. Accepts only the three exact wire
/// values (`managed`, `relay`, `self-host`), so an unrecognized posture fails
/// closed instead of resolving to a default.
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
