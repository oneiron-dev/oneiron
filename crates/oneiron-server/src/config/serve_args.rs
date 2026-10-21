//! CLI surface: `ServeArgs`, its redacting `Debug`, and argv-derived overrides.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Args;
use oneiron::HostingPrivacyPosture;

use super::embedder::EmbedderArgs;
use super::oneironer::OneironerArgs;
use crate::runtime::{
    RuntimeConfigOverride, RuntimeMode, RuntimeProviderKind, RuntimeRole, RuntimeRoleTargetOverride,
};

/// Its redacting `Debug`.
mod debug;

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

    /// A vault VM's cold restore handoff (FIX 6584), which only the image's
    /// `oneiron-vm-init` passes: the revision of the restore channel its
    /// host answered on, beside `--restore` and the two pipes the bootstrap
    /// made and carries over that channel. With it a `--vsock-guest` start
    /// takes `--restore`; without it the pair stays refused.
    #[arg(long = "vm-restore-revision", requires_all = ["vsock_guest", "restore"])]
    pub vm_restore_revision: Option<u32>,

    /// A vault VM's custody anchor handoff (FIX 6517), which only the
    /// image's `oneiron-vm-init` passes: the revision of the anchor exchange
    /// its host answered on. With it a `--vsock-guest` start takes
    /// `--custody-anchor-credentials-fd`, the pipe the bootstrap carries the
    /// host's credential into, beside `--vm-anchor-url`; without it that
    /// pipe stays refused.
    #[arg(long = "vm-anchor-revision", requires = "vsock_guest")]
    pub vm_anchor_revision: Option<u32>,

    /// The custody anchor URL a vault VM's host bound its boot to, exactly as
    /// the vault's settings or a restore's plan spell it: the start refuses
    /// a credential for any other (FIX 6517). Never logged.
    #[arg(long = "vm-anchor-url", requires_all = ["vm_anchor_revision", "vm_anchor_socket"])]
    pub vm_anchor_url: Option<String>,

    /// The bootstrap's socket that reaches `--vm-anchor-url`, and nothing
    /// else, through the host (FIX 6517).
    #[arg(long = "vm-anchor-socket", requires_all = ["vm_anchor_revision", "vm_anchor_url"])]
    pub vm_anchor_socket: Option<PathBuf>,

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

    /// Plain serve: the self-host training shipper (TL-6), off without it.
    /// With `--publisher-training-outbox-dir`, the vault fetches the intake's
    /// public descriptor at start and hourly, installs its keys in the
    /// outbox and writes offers for the anonymous training window. Managed
    /// serve reads it and leaves it inactive: the supervisor ships there.
    #[arg(long = "publisher-training-self-host-shipper")]
    pub publisher_training_self_host_shipper: bool,

    /// The intake the self-host shipper reaches: an HTTPS origin (HTTP only
    /// on loopback), `https://oneiron.dev` without it.
    #[arg(long = "publisher-training-intake-origin")]
    pub publisher_training_intake_origin: Option<String>,

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

    /// An organ build this server runs as first party, by its blake3 (64
    /// hex); repeat it for each (FIX 7644). Listing one is the operator's
    /// statement that the build is reviewed first-party code. A pack organ
    /// build not listed runs as third party, which the organ host refuses to
    /// start until filesystem confinement for organs lands. Plain or managed
    /// serve; no config file, settings file or environment sets it.
    #[arg(long = "trusted-organ-build", value_parser = blake3_hex)]
    pub trusted_organ_builds: Vec<String>,

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

    /// Managed mode: the `HOME` the guests' container CLI runs with, an
    /// absolute directory on the vault's own host that the supervisor
    /// provisions for the vault's UID (FIX 6876). Only the CLI's environment
    /// gets it; the engine reads no HOME. One that fails its check is
    /// ignored with a warning, never a refused start.
    #[arg(long = "container-home", requires = "managed_by_hypnos")]
    pub container_home: Option<PathBuf>,

    /// Managed mode: the guests' container CLI's `XDG_RUNTIME_DIR`, as
    /// `--container-home` is its `HOME`.
    #[arg(long = "container-runtime-dir", requires = "managed_by_hypnos")]
    pub container_runtime_dir: Option<PathBuf>,

    /// Managed mode: what the supervisor observed of the guest runtime it
    /// provisioned for the vault's UID, one of the ten closed spellings
    /// (`oneiron_vault_contract::GUEST_RUNTIME_FACT_ARG`, FIX 7670). It
    /// moves only the browser's readiness, and no fact refuses the start;
    /// without it the supervisor observed none.
    #[arg(long = "guest-runtime-fact", requires = "managed_by_hypnos")]
    pub guest_runtime_fact: Option<oneiron_vault_contract::GuestRuntimeFact>,

    /// Managed mode: a private origin the hosted node's web fetch may reach,
    /// `http|https://<dns-name>[:port]`; repeat it for each (FIX 7657). A
    /// hosted node refuses RFC1918, CGNAT and ULA addresses except at a
    /// listed origin, and never infrastructure. Without it, none; an entry
    /// that does not parse stops the start.
    #[arg(long = "hosted-private-origin", requires = "managed_by_hypnos")]
    pub hosted_private_origins: Vec<oneiron::web_fetch::HostedPrivateOrigin>,

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

/// Clap value parser for `--trusted-organ-build`: a blake3 digest, 64 hex,
/// kept in lowercase as a pack's `ORGAN.json` names its builds, so a typo
/// stops the start instead of trusting nothing.
fn blake3_hex(value: &str) -> Result<String, String> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(value.to_ascii_lowercase())
    } else {
        Err("a blake3 digest is 64 hex characters".to_owned())
    }
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
