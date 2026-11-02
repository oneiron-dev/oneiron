//! Managed argv group: validation, the argv allowlist, and unmanaged-layer refusals.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::path::PathBuf;
use std::time::Duration;

use oneiron::federation::derivation::DerivationOwner;
use oneiron::web_fetch::HostedPrivateOrigin;
use oneiron_vault_contract::{CONTRACT_VERSION, GuestRuntimeFact, valid_vault_name};

use crate::config::{KeystoreBackend, KeystoreConfig, ServeArgs, ServeConfig};

use self::policy::reject_unmanaged_layers;
use super::listener::HYPNOS_LISTEN_FD;

mod policy;
mod resolve;
mod start_mode;
/// A vault VM's cold restore and custody anchor handoffs (FIX 6584, FIX
/// 6517).
mod vm_transport;

pub use self::start_mode::ManagedStartMode;
pub(crate) use self::vm_transport::VmAnchorHandoff;

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
    /// start the supervisor hands one. In a vault VM only the bootstrap's,
    /// beside its anchor handoff (`vm_anchor`).
    pub custody_anchor_credentials_fd: Option<RawFd>,
    /// A vault VM's custody anchor handoff from its bootstrap (FIX 6517):
    /// the URL its host bound and the socket that reaches it.
    pub(crate) vm_anchor: Option<VmAnchorHandoff>,
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
    /// Its seal key in secret custody, by handle (`--seal-key-handle`).
    pub seal_key_handle: Option<String>,
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
    /// The supervisor's guest runtime fact for the vault's UID
    /// (`--guest-runtime-fact`), which seeds the browser's readiness.
    pub guest_runtime_fact: Option<GuestRuntimeFact>,
    /// The private origins the operator lets the hosted egress guard admit
    /// (`--hosted-private-origin`, FIX 7657); none without it.
    pub hosted_private_origins: BTreeSet<HostedPrivateOrigin>,
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

const VSOCK_NO_PIPE_REASON: &str = "a vault VM takes a custody anchor credential pipe only from its bootstrap's anchor exchange (--vm-anchor-revision)";

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
