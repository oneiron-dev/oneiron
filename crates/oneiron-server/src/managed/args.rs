//! Managed argv group: validation, the argv allowlist, and unmanaged-layer refusals.

use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::path::PathBuf;
use std::time::Duration;

use oneiron::federation::derivation::DerivationOwner;
use oneiron_vault_contract::{CONTRACT_VERSION, valid_vault_name};

use crate::config::{KeystoreBackend, KeystoreConfig, ServeArgs, ServeConfig};

use self::policy::reject_unmanaged_layers;
use super::listener::HYPNOS_LISTEN_FD;

mod policy;
mod start_mode;

pub use self::start_mode::ManagedStartMode;

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

    #[error("--derivation-owner must be a 32-byte account or organization id in hexadecimal")]
    InvalidDerivationOwner,

    #[error("managed vault {vault:?} rejected its derivation owner: {reason}")]
    DerivationOwnerRejected { vault: String, reason: String },

    #[error("managed vault routing refused: {reason}")]
    VaultRoutingRejected { reason: String },

    #[error("--keystore-dir must be an absolute path")]
    RelativeKeystoreDir,

    #[error("--{flag} must be an absolute path")]
    RelativeRecipientFile { flag: &'static str },

    /// One leaf of the owner's settings file that a managed vault does not
    /// take, named by its dotted field and never by its value. `cause` is
    /// the finer reason an owner path was refused, when there is one: the
    /// contract's path reason (FIX 6874).
    #[error(
        "--settings-file sets `{field}`, which a managed vault refuses: {reason}{}",
        .cause.map_or_else(String::new, |cause| format!(" ({cause})"))
    )]
    SettingsRefused {
        section: String,
        field: String,
        reason: SettingsRefusal,
        cause: Option<&'static str>,
    },

    #[error("--artifact-http-socket must be an absolute path")]
    RelativeArtifactSocket,

    #[error("--{flag} must be a non-negative file descriptor, got {value}")]
    InvalidFd { flag: &'static str, value: i32 },

    #[error("{env} must be a non-negative file descriptor, got {value:?}")]
    InvalidListenFd { env: &'static str, value: String },

    #[error(
        "{env} names file descriptor {fd}, which is not a unix socket: managed mode serves only the supervisor's unix listener"
    )]
    ListenFdNotUnix { env: &'static str, fd: RawFd },

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

    /// The custody anchor door's credentials pipe was refused: `reason` says
    /// what was wrong with it, never what it carried.
    #[error("custody anchor credentials fd rejected: {reason}")]
    CustodyAnchorCredentialsRejected { reason: String },

    /// The cold restore start's flags, given where they do not apply.
    #[error("cold restore start refused: {reason}")]
    RestoreFlagsRejected { reason: &'static str },

    /// The real-tenant tripwire: `missing` names each isolation facility the
    /// probe did not find, so the operator knows what to provision.
    #[error(
        "refusing to open vault {vault:?} in managed mode, and it was not opened: vault_meta carries no `{marker}` marker, and this host has not provisioned the isolation a real tenant needs. Missing: {}. Provision them and start the vault again; only an explicitly marked synthetic canary opens without them, and marking a real tenant as one is no workaround.",
        missing.join("; ")
    )]
    ManagedRealTenantRefused {
        vault: String,
        marker: &'static str,
        missing: Vec<&'static str>,
    },

    #[error(
        "managed vault {vault:?} DEK MAC mismatch at `{key}`: the delivered DEK does not match the one this vault was sealed under. Refused before reading any content."
    )]
    DekMacMismatch { vault: String, key: &'static str },

    #[error("{}", super::state_serve::WRITES_FROZEN_MESSAGE)]
    WritesFrozen,

    #[error("ctl line of {len} bytes exceeds the {cap}-byte cap; rejected whole")]
    CtlLineTooLong { len: usize, cap: usize },

    #[error("ctl request refused: {reason}")]
    CtlRequestRefused { reason: String },

    #[error("ledger update refused: {reason}")]
    LedgerRefused { reason: String },

    #[error("vault metadata: {0}")]
    VaultMeta(String),

    /// The engine's embedded owner id and the vault contract's copy, which
    /// the supervisor names a personal vault's owner by, differ.
    #[error(
        "the embedded owner's holder id drifted: the engine derives {engine}, the vault contract gives {contract}; a supervisor naming the owner by the contract's id would name no one this vault knows"
    )]
    EmbeddedOwnerDrift { engine: String, contract: String },

    #[error("managed serve io: {0}")]
    Io(#[from] std::io::Error),
}

/// Why a managed vault refuses one leaf of its settings file. Presence alone
/// refuses: an empty value, `false` or the supervisor's own value does too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SettingsRefusal {
    /// A binding the supervisor owns: the listener, ingress and auth, the
    /// tenant's identity and custody, the broker and voice sockets, and the
    /// key directory.
    #[error("the supervisor owns this binding, so the owner's settings never set it")]
    SupervisorOwned,
    /// A key named by an environment variable, which managed mode never reads.
    #[error("it names a key in the environment, which managed mode never reads")]
    EnvironmentSecret,
    /// A path that lies neither in this vault's own storage nor, for a model
    /// directory, in the supervisor's shared model root as its bundle's own
    /// directory.
    #[error(
        "an owner path must be absolute, hold no `~` or `..`, exist, and lie under the vault's data directory or the settings file's own directory, or, for a model directory, be its bundle's own directory `<root>/<class>/<stack_sha16>` in the supervisor's read-only shared model root, named by the stack the settings pin beside it and by its manifest"
    )]
    OutsideVault,
    /// A key the server's config schema does not have.
    #[error("the server's config schema has no such field")]
    UnknownField,
}

/// The managed argv group, validated. Reaching this type means every required
/// flag was present, the contract version is one this build speaks, and no
/// unmanaged configuration layer was requested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedArgs {
    pub vault_name: String,
    pub derivation_owner: DerivationOwner,
    pub organization_owner: Option<DerivationOwner>,
    pub member_vault: bool,
    pub data_dir: PathBuf,
    pub http_socket: PathBuf,
    pub ctl_socket: PathBuf,
    pub hypnos_socket: PathBuf,
    /// [`NO_FD`] in a vault VM, whose boot channel carries the ready byte.
    pub ready_fd: RawFd,
    /// [`NO_FD`] in a vault VM, whose boot channel carries the frame.
    pub credentials_fd: RawFd,
    /// The pipe the custody anchor door's owner credential arrives on
    /// (`--custody-anchor-credentials-fd`), read before storage on each
    /// start the supervisor hands one. Never in a vault VM, which inherits
    /// no descriptors.
    pub custody_anchor_credentials_fd: Option<RawFd>,
    /// Whether this start opens its vault or restores it first (`--restore`).
    pub start_mode: ManagedStartMode,
    /// The process is a Firecracker vault VM's engine (`--vsock-guest`).
    pub vsock_guest: bool,
    /// Where this install keeps its this-device-only key slots, a place the
    /// supervisor chose. Without it managed mode installs no keystore, and
    /// serves on with that facility named missing in its readiness unless
    /// the settings file turns the keystore off (WILL-PLAN L14 row 17).
    pub keystore_dir: Option<PathBuf>,
    /// The node's managed escrow recipient's public key file
    /// (`--escrow-recipient-file`).
    pub escrow_recipient: Option<PathBuf>,
    /// The owner's break-glass recipient's public key file
    /// (`--break-glass-recipient-file`).
    pub break_glass_recipient: Option<PathBuf>,
    /// Where the vault spools its escrow capsules for the node to ship
    /// (`--escrow-outbox-dir`).
    pub escrow_outbox: Option<PathBuf>,
    /// A vault created at this start seals its pages under the delivered
    /// data key (`--maximum-tier`). Unless given, the settings file's
    /// `maximum_tier` decides, then `MANAGED_MAXIMUM_TIER_DEFAULT`.
    pub maximum_tier: bool,
    /// The artifact origin's socket (`--artifact-http-socket`), when the
    /// supervisor gave the vault one. The origin answers on the vault's
    /// internal authority alone, bound to `vault_name` (FIX 6716).
    pub artifact_socket: Option<PathBuf>,
    /// The owner's settings file (`--settings-file`), in the server's own
    /// config schema (`managed::settings`).
    pub settings_file: Option<PathBuf>,
    /// Where the server's voice loop listens (`--voice-socket`): a binding
    /// the supervisor owns, taken when the settings file's `[models.voice]`
    /// turns the loop on.
    pub voice_socket: Option<PathBuf>,
    /// This vault's e-sign seal key file (`--seal-key-file`).
    pub seal_key: Option<PathBuf>,
    /// Its certificate chain file (`--seal-chain-file`).
    pub seal_chain: Option<PathBuf>,
    /// The seal's trust anchors file (`--seal-trust-file`).
    pub seal_trust: Option<PathBuf>,
    /// The seal's timestamp authority URL (`--seal-tsa-url`).
    pub seal_tsa: Option<String>,
    /// The signing page seal evidence names (`--seal-signing-url`).
    pub seal_signing_url: Option<String>,
    /// The seal organ's program (`--seal-organ`).
    pub seal_organ: Option<PathBuf>,
    /// Where this vault hands its authorized e-sign mail to the supervisor's
    /// sender (`--esign-delivery-outbox-dir`); no outbox runs without it.
    pub esign_delivery_outbox: Option<PathBuf>,
    /// Where this vault writes its training offers and withdrawals for the
    /// supervisor to ship, and reads the intake's receipts
    /// (`--publisher-training-outbox-dir`); no outbox runs without it.
    pub publisher_training_outbox: Option<PathBuf>,
    /// The browser guest's container CLI the supervisor binds
    /// (`--browser-runtime`), set on the settings file's `[browser]`.
    pub browser_runtime: Option<PathBuf>,
    /// The desktop guest's (`--desktop-runtime`), set on its `[desktop]`.
    pub desktop_runtime: Option<PathBuf>,
    /// Where pack organ builds are written (`--organ-dir`); `organs` under
    /// the data directory without it.
    pub organ_dir: Option<PathBuf>,
    /// Where the mesh listener binds (`--mesh-bind`); the mesh is off
    /// without it.
    pub mesh_bind: Option<SocketAddr>,
    /// The mesh's private relays (`--mesh-relays`); direct paths only
    /// without them.
    pub mesh_relays: Vec<String>,
    /// The node's shared model root as the supervisor declared it
    /// (`--shared-model-root`), checked when the start configures
    /// (`managed::settings`): one that fails is ignored with a warning.
    pub shared_model_root: Option<PathBuf>,
    /// The guests' container CLI's `HOME` as the supervisor declared it
    /// (`--container-home`), checked when the start configures
    /// (`managed::container_dirs`): one that fails is ignored with a warning.
    pub container_home: Option<PathBuf>,
    /// Its `XDG_RUNTIME_DIR` (`--container-runtime-dir`), checked the same way.
    pub container_runtime_dir: Option<PathBuf>,
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
            if args.organization_owner.is_some() || args.member_vault {
                return Err(ManagedError::VaultRoutingRejected {
                    reason: "organization flags require managed mode".into(),
                });
            }
            if args.restore || args.restore_input_fd.is_some() || args.restore_result_fd.is_some() {
                return Err(ManagedError::RestoreFlagsRejected {
                    reason: "a cold restore start is managed mode's (--managed-by-hypnos)",
                });
            }
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

        let owner_text = require(args.derivation_owner.as_deref(), "derivation-owner")?;
        if !owner_text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ManagedError::InvalidDerivationOwner);
        }
        let owner = decode_hex(owner_text).ok_or(ManagedError::InvalidDerivationOwner)?;
        let organization_owner = args
            .organization_owner
            .as_deref()
            .map(|text| {
                decode_hex(text)
                    .filter(|_| text.bytes().all(|byte| byte.is_ascii_hexdigit()))
                    .map(DerivationOwner)
                    .ok_or_else(|| ManagedError::VaultRoutingRejected {
                        reason: "--organization-owner must be a 32-byte id in hexadecimal".into(),
                    })
            })
            .transpose()?;

        let (ready_fd, credentials_fd) = if args.vsock_guest {
            for (flag, given) in [
                ("ready-fd", args.ready_fd.is_some()),
                ("credentials-fd", args.credentials_fd.is_some()),
            ] {
                if given {
                    return Err(ManagedError::ConflictingFlag {
                        flag,
                        reason: VSOCK_BOOT_REASON,
                    });
                }
            }
            (NO_FD, NO_FD)
        } else {
            (
                require_fd(args.ready_fd, "ready-fd")?,
                require_fd(args.credentials_fd, "credentials-fd")?,
            )
        };
        if args.vsock_guest && args.custody_anchor_credentials_fd.is_some() {
            return Err(ManagedError::ConflictingFlag {
                flag: "custody-anchor-credentials-fd",
                reason: VSOCK_NO_PIPE_REASON,
            });
        }
        let custody_anchor_credentials_fd = args
            .custody_anchor_credentials_fd
            .map(|fd| require_fd(Some(fd), "custody-anchor-credentials-fd"))
            .transpose()?;
        let start_mode = ManagedStartMode::of(args)?;
        let managed = Self {
            vault_name,
            derivation_owner: DerivationOwner(owner),
            organization_owner,
            member_vault: args.member_vault,
            // `--vault-path` stays the alias for the same directory.
            data_dir: require(
                args.data_dir.clone().or_else(|| args.vault_path.clone()),
                "data-dir",
            )?,
            http_socket: require(args.http_socket.clone(), "http-socket")?,
            ctl_socket: require(args.ctl_socket.clone(), "ctl-socket")?,
            hypnos_socket: require(args.hypnos_socket.clone(), "hypnos-socket")?,
            ready_fd,
            credentials_fd,
            custody_anchor_credentials_fd,
            start_mode,
            vsock_guest: args.vsock_guest,
            keystore_dir: args.keystore_dir.clone(),
            escrow_recipient: args.escrow_recipient_file.clone(),
            break_glass_recipient: args.break_glass_recipient_file.clone(),
            escrow_outbox: args.escrow_outbox_dir.clone(),
            maximum_tier: args.maximum_tier.unwrap_or(MANAGED_MAXIMUM_TIER_DEFAULT),
            artifact_socket: args.artifact_http_socket.clone(),
            settings_file: args.settings_file.clone(),
            voice_socket: args.voice_socket.clone(),
            seal_key: args.seal_key_file.clone(),
            seal_chain: args.seal_chain_file.clone(),
            seal_trust: args.seal_trust_file.clone(),
            seal_tsa: nonempty(args.seal_tsa_url.as_deref()),
            seal_signing_url: nonempty(args.seal_signing_url.as_deref()),
            seal_organ: args.seal_organ.clone(),
            esign_delivery_outbox: args.esign_delivery_outbox_dir.clone(),
            publisher_training_outbox: args.publisher_training_outbox_dir.clone(),
            browser_runtime: args.browser_runtime.clone(),
            desktop_runtime: args.desktop_runtime.clone(),
            organ_dir: args.organ_dir.clone(),
            mesh_bind: args.mesh_bind,
            mesh_relays: crate::config::normalize_list(
                args.mesh_relays.clone().unwrap_or_default(),
            ),
            // Not among the absolute paths refused below: a root that fails
            // its check is ignored, never a refused start.
            shared_model_root: args.shared_model_root.clone(),
            // Nor are the container CLI's directories (FIX 6876).
            container_home: args.container_home.clone(),
            container_runtime_dir: args.container_runtime_dir.clone(),
        };
        if managed
            .artifact_socket
            .as_deref()
            .is_some_and(std::path::Path::is_relative)
        {
            return Err(ManagedError::RelativeArtifactSocket);
        }
        if managed
            .keystore_dir
            .as_deref()
            .is_some_and(std::path::Path::is_relative)
        {
            return Err(ManagedError::RelativeKeystoreDir);
        }
        for (flag, path) in [
            ("escrow-recipient-file", &managed.escrow_recipient),
            ("break-glass-recipient-file", &managed.break_glass_recipient),
            ("escrow-outbox-dir", &managed.escrow_outbox),
            ("settings-file", &managed.settings_file),
            ("voice-socket", &managed.voice_socket),
            ("seal-key-file", &managed.seal_key),
            ("seal-chain-file", &managed.seal_chain),
            ("seal-trust-file", &managed.seal_trust),
            ("seal-organ", &managed.seal_organ),
            ("esign-delivery-outbox-dir", &managed.esign_delivery_outbox),
            (
                "publisher-training-outbox-dir",
                &managed.publisher_training_outbox,
            ),
            ("browser-runtime", &managed.browser_runtime),
            ("desktop-runtime", &managed.desktop_runtime),
            ("organ-dir", &managed.organ_dir),
        ] {
            if path.as_deref().is_some_and(std::path::Path::is_relative) {
                return Err(ManagedError::RelativeRecipientFile { flag });
            }
        }
        // Non-negative is not enough. Both descriptors are adopted by owners
        // that close what they hold — `read_managed_credentials` and
        // `signal_ready` each take theirs over with `from_raw_fd` — so one
        // number on both flags is not a harmless duplicate: the credential
        // frame's descriptor is closed under the ready write, or the ready byte
        // lands in the number the supervisor is still reading credentials from.
        // Refused here, before either is consumed. The custody anchor
        // credentials pipe is adopted the same way, so it aliases neither.
        if !managed.vsock_guest {
            refuse_fd_alias(
                ("--ready-fd", managed.ready_fd),
                ("--credentials-fd", managed.credentials_fd),
            )?;
            if let Some(anchor) = managed.custody_anchor_credentials_fd {
                for other in [
                    ("--ready-fd", managed.ready_fd),
                    ("--credentials-fd", managed.credentials_fd),
                ] {
                    refuse_fd_alias(("--custody-anchor-credentials-fd", anchor), other)?;
                }
            }
            // A cold restore's two pipes are adopted the same way: each is
            // refused when it names any descriptor before it.
            if let ManagedStartMode::Restore {
                input_fd,
                result_fd,
            } = managed.start_mode
            {
                let mut taken = vec![
                    ("--ready-fd", managed.ready_fd),
                    ("--credentials-fd", managed.credentials_fd),
                ];
                taken.extend(
                    managed
                        .custody_anchor_credentials_fd
                        .map(|anchor| ("--custody-anchor-credentials-fd", anchor)),
                );
                for pipe in [
                    ("--restore-input-fd", input_fd),
                    ("--restore-result-fd", result_fd),
                ] {
                    for other in &taken {
                        refuse_fd_alias(pipe, *other)?;
                    }
                    taken.push(pipe);
                }
            }
        }
        managed.vault_binding()?;
        Ok(Some(managed))
    }

    /// Refuses an inherited listening descriptor that aliases any argv fd.
    ///
    /// Three inputs, three distinct owners: a `UnixListener` over the inherited
    /// socket, a `File` over the credential frame, a `File` over the ready
    /// pipe. Each closes what it holds on drop, so a listener that is also
    /// `--credentials-fd` is read as a credential frame and closed under the
    /// listener, and one that is also `--ready-fd` has the ready byte written
    /// into it. The custody anchor credentials pipe, when handed, is a fourth,
    /// and a cold restore's two pipes a fifth and a sixth.
    /// [`serve_managed`](crate::managed::serve_managed) calls this before any of them is
    /// consumed and before the vault is opened, so neither the frame nor
    /// storage is touched on the way to the refusal.
    pub fn refuse_listen_fd_alias(&self, listen_fd: RawFd) -> Result<(), ManagedError> {
        refuse_fd_alias((HYPNOS_LISTEN_FD, listen_fd), ("--ready-fd", self.ready_fd))?;
        if let Some(anchor) = self.custody_anchor_credentials_fd {
            refuse_fd_alias(
                (HYPNOS_LISTEN_FD, listen_fd),
                ("--custody-anchor-credentials-fd", anchor),
            )?;
        }
        if let ManagedStartMode::Restore {
            input_fd,
            result_fd,
        } = self.start_mode
        {
            refuse_fd_alias(
                (HYPNOS_LISTEN_FD, listen_fd),
                ("--restore-input-fd", input_fd),
            )?;
            refuse_fd_alias(
                (HYPNOS_LISTEN_FD, listen_fd),
                ("--restore-result-fd", result_fd),
            )?;
        }
        refuse_fd_alias(
            (HYPNOS_LISTEN_FD, listen_fd),
            ("--credentials-fd", self.credentials_fd),
        )
    }

    /// The vault's own e-sign seal settings, from its argv alone (FIX 3487).
    #[cfg(unix)]
    pub(crate) fn seal_config(&self) -> crate::api::EsignSealConfig {
        crate::api::EsignSealConfig {
            key: self.seal_key.clone(),
            chain: self.seal_chain.clone(),
            trust: self.seal_trust.clone(),
            tsa: self.seal_tsa.clone(),
            signing_url: self.seal_signing_url.clone(),
            organ: self.seal_organ.clone(),
            argv: true,
        }
    }

    /// Serve configuration for managed mode as argv builds it, the base the
    /// owner's settings file is settled over (`managed::settings`).
    ///
    /// Outside the managed group, the argv allowlist permits exactly the
    /// fields read here: dimensions, the MRL prefix, map size, dictionary
    /// roots, log level, `--no-hooks`, the maximum tier and the owner's
    /// failure-signal export and training choices. Each of them, given,
    /// stands over the settings file's own value. The supervisor's own
    /// bindings read here too (browser origins, the host's public origin and
    /// the kit fetch URLs) are ones the settings file never sets. Everything
    /// else on `ServeArgs` is refused before this runs, so nothing reaches
    /// here to be quietly dropped.
    ///
    /// `auth_secret` stays `None`: bearer auth terminates at the supervisor,
    /// which owns the listening socket inside an owner-only directory.
    /// Consulting `ONEIRON_AUTH_SECRET` here would give the child a second,
    /// weaker opinion about who may talk to it. Unauthenticated requests are
    /// not allowed: a request the supervisor forwards is its caller's own
    /// slip, the owner it attested, or anonymous, and an anonymous one never
    /// takes the dev mode's owner credential at a door that reads headers
    /// alone (FIX 2222, FIX 5255); the public doors serve it on their own
    /// proofs.
    pub fn serve_config(&self, args: &ServeArgs) -> ServeConfig {
        let defaults = ServeConfig::default();
        let mut config = ServeConfig {
            vault_path: self.data_dir.clone(),
            auth_secret: None,
            allow_unauthenticated: false,
            // Browser origins are argv policy too, for the external shared UI.
            allowed_origins: args.allowed_origins.clone().unwrap_or_default(),
            // The host's public https origin and the URLs a kit dials, as
            // the supervisor, which owns them, passes them. Neither builds an
            // auth layer: the OAuth relay also needs the issuer and JWKS
            // flags, which managed mode refuses.
            oauth_resource_indicator: nonempty(args.oauth_resource_indicator.as_deref()),
            kit_bundle_public_urls: crate::config::normalize_list(
                args.kit_bundle_public_urls.clone().unwrap_or_default(),
            ),
            dimensions: args.dimensions.unwrap_or(defaults.dimensions),
            fast_dims: args.fast_dims,
            map_size: args.map_size.unwrap_or(defaults.map_size),
            // Argv only: the usual resolver probes HOME and the XDG roots,
            // which managed mode does not get to read.
            dict_search_paths: args.dict_search_paths.clone().unwrap_or_default(),
            assistant_display_names: args.assistant_display_names.clone().unwrap_or_default(),
            // Fact and verb hooks run unless the supervisor passes `--no-hooks`.
            hooks: !args.no_hooks,
            maximum_tier: self.maximum_tier,
            // The supervisor's key directory or none: the platform default
            // lies under HOME and the XDG roots, which managed mode never reads.
            keystore: KeystoreConfig {
                backend: if self.keystore_dir.is_some() {
                    KeystoreBackend::Platform
                } else {
                    KeystoreBackend::Off
                },
                dir: self.keystore_dir.clone(),
                service: None,
            },
            // Our cloud sends feedback to our own inbox unless the settings
            // file chooses otherwise (ARCH-0056 r6); every send still asks the
            // owner first.
            feedback: crate::config::FeedbackConfig::cloud_default(),
            // The owner's "Help improve Oneiron" choice as the supervisor
            // passes it, either way; unset, the settings file's, then the
            // managed default.
            failure_signal_export: args.failure_signal_export,
            // Training on what it sends: unset, the settings file's, then
            // whatever the switch is (FIX 5188).
            failure_signal_training: args.failure_signal_training,
            // The supervisor's e-sign delivery outbox, when it runs a sender.
            esign_delivery_outbox_dir: self.esign_delivery_outbox.clone(),
            // The supervisor's training outbox, when it ships for one.
            publisher_training_outbox_dir: self.publisher_training_outbox.clone(),
            // Read and inactive whatever argv says (TL-6): the supervisor
            // pushes the intake's keys and ships, so this vault never fetches
            // the intake's descriptor or ships through the anonymous window.
            publisher_training_self_host_shipper: false,
            ..defaults
        };
        if let Some(log_level) = args.log_level.clone() {
            config.log_level = log_level;
        }
        // The artifact origin answers on this vault's internal authority,
        // `<vault_name>.artifact.invalid` and `<app>.<vault_name>.artifact.invalid`,
        // and on no artifact domain (FIX 6716): the edge checks the public
        // name and forwards that authority, so no public name reaches here.
        if self.artifact_socket.is_some() {
            config.artifact_internal_vault_id = Some(self.vault_name.clone());
        }
        config
    }
}

/// An argv text that says something: an empty one is none.
fn nonempty(text: Option<&str>) -> Option<String> {
    text.filter(|text| !text.is_empty()).map(str::to_owned)
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

/// A vault VM inherits no descriptors: its vsock boot channel carries the
/// credential frame in and the ready byte out.
pub const NO_FD: RawFd = -1;

/// Whether a managed vault created without `--maximum-tier` seals its pages:
/// no. Canon keeps managed vaults plain unless the supervisor opts in
/// (CROSS-ARCH-0019); a vault keeps the tier it was created with.
pub(crate) const MANAGED_MAXIMUM_TIER_DEFAULT: bool = false;

const VSOCK_BOOT_REASON: &str =
    "a vault VM reads its credentials and signals ready over the vsock boot channel";

const VSOCK_NO_PIPE_REASON: &str = "a vault VM inherits no descriptors, and its vsock boot channel carries no custody anchor credentials";

fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let mut bytes = [0; N];
    for (dest, pair) in bytes.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let text = std::str::from_utf8(pair).ok()?;
        *dest = u8::from_str_radix(text, 16).ok()?;
    }
    Some(bytes)
}
