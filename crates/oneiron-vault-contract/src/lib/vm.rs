//! The vault-VM wire: vsock ports and boot-channel frames.
//!
//! One engine runs one vault in one Firecracker guest (VAULT-VM = B, built
//! now and adopted later). Firecracker maps the guest's vsock ports onto host
//! unix sockets: a host-initiated connection writes `CONNECT <port>\n` on the
//! device socket and reads `OK <n>\n` back; a guest-initiated connection to
//! the host's port P lands on the unix socket `<device socket>_P`. The guest
//! adapter and the host's VMM driver both build against the names here.
//!
//! The boot port carries what a node's process child gets from inherited
//! descriptors. On a cold boot the guest's root bootstrap first dials the
//! restore channel ([`VM_RESTORE_PORT`], [`crate::vm_restore`]), where the
//! host names the boot's mode, then the boot port's provision connection
//! ([`crate::vm_provision`]): it takes the
//! vault's binding and its fscrypt key there, lays out the encrypted storage
//! and the UID table, and only then starts the engine as the vault's own
//! non-root UID (FIX 6308). The engine's first connection is the credential
//! connection: the host writes the credential frame and half-closes, and the
//! guest answers with the ready byte. Every later connection is the lifecycle
//! connection: the guest opens it with [`VmGuestFrame::Join`], then both
//! sides speak one JSON line per frame. A snapshot restore resets vsock, so
//! the guest joins again after each one; it runs no second provision. The
//! guest's outbox companion dials [`VM_OUTBOX_PORT`] on its own
//! ([`crate::vm_outbox`]) and dials again after a reset. Between the
//! provision connection and the engine, a serving boot's bootstrap dials the
//! custody anchor exchange ([`VM_ANCHOR_PORT`], [`crate::vm_anchor`]), and
//! each stream to the vault's custody anchor door leaves through
//! [`VM_ANCHOR_PROXY_PORT`]. A supervisor may also attach one NIC for the
//! guest's outbound IPv4 (FIX 6808, [`VmTapAttachment`] and
//! [`VmGuestNetworkConfig`]); every host surface stays on vsock. Its config
//! drive may carry the vault's managed profile too, as five typed files
//! (FIX 6809, [`VM_MANAGED_PROFILE_REVISION`]), and the guests' container
//! runtime bindings, which the root bootstrap checks against the image's
//! guest runtime descriptor (FIX 7671, [`VM_GUEST_RUNTIME_REVISION`],
//! [`VmGuestRuntimeDescriptor`]).
//!
//! The provision connection rides contract version 3 with a build floor, the
//! first engine revision that ships `oneiron-vm-init`: a host speaks it only
//! to an image built at or after that floor, which the image manifest pins.
//! An older image's engine would read the provision frame as its credential
//! frame and refuse it, so it never starts.

mod guest_runtime;
mod network;

pub use self::guest_runtime::{VmGuestImageArchive, VmGuestRuntimeDescriptor, VmGuestRuntimeFile};
pub use self::network::{VmGuestNetworkConfig, VmTapAttachment, parse_vm_guest_mac};

use crate::UnixTs;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The guest's context id. One vault per VM, so every guest uses the same id.
pub const VM_GUEST_CID: u32 = 3;
/// The host's context id, the only peer a guest can reach.
pub const VM_HOST_CID: u32 = 2;
/// Guest to host: on a cold boot the provision connection, then the
/// credential connection, then the lifecycle connection.
pub const VM_BOOT_PORT: u32 = 1024;
/// Host to guest: the vault's HTTP surface.
pub const VM_HTTP_PORT: u32 = 1025;
/// Host to guest: control verbs, one JSON line per connection as on a node.
pub const VM_CTL_PORT: u32 = 1026;
/// Guest to host: wake-ledger pushes, one JSON line per connection.
pub const VM_LEDGER_PORT: u32 = 1027;
/// Host to guest: the vault's artifact origin, when the supervisor gave the
/// vault one (`--artifact-http-socket`).
pub const VM_ARTIFACT_PORT: u32 = 1028;
/// Host to guest: the vault's voice loop, when its `[models.voice]` names a
/// socket (FIX 2391). The socket's directory is [`VM_VOICE_DIR`].
pub const VM_VOICE_PORT: u32 = 1029;
/// Guest to host: the outbox carrier, one persistent duplex stream that
/// carries every outbox kind both ways (FIX 5235, `crate::vm_outbox`).
pub const VM_OUTBOX_PORT: u32 = 1030;
/// Guest to host: the custody anchor exchange (FIX 6517,
/// [`crate::vm_anchor`]), dialled once on every cold boot that serves, after
/// the provision connection and before the engine starts.
pub const VM_ANCHOR_PORT: u32 = 1031;
/// Guest to host: the restore channel (FIX 6584, [`crate::vm_restore`]),
/// dialled once on every cold boot before the provision connection.
pub const VM_RESTORE_PORT: u32 = 1032;
/// Guest to host: the custody anchor proxy (FIX 6517, [`crate::vm_anchor`]),
/// one stream per connection to the anchor URL the host bound the boot to.
pub const VM_ANCHOR_PROXY_PORT: u32 = 1033;
/// The owner-only directory a vault VM's `[models.voice]` socket lies in.
pub const VM_VOICE_DIR: &str = "/run/oneiron/voice";
/// Where the guest mounts the vault's read-only config drive: its settings
/// file, and the files the settings' owner paths name beside it. A
/// supervisor maps a guest owner path below it onto the vault's own config
/// directory (`crate::settings_paths`).
pub const VM_GUEST_CONFIG_DIR: &str = "/config";
/// The guest's view of its network plan on the config drive (FIX 6808,
/// [`VmGuestNetworkConfig`]): one JSON object, read whole by the root
/// bootstrap before the vault's key goes in. Without it the guest sets up no
/// NIC.
pub const VM_GUEST_NETWORK_FILE: &str = "/config/network.json";
/// The guest network's revision (FIX 6808): an image that sets up the NIC a
/// host attaches names it as its manifest's `vm_network_revision`. Revision 1
/// is IPv4 only.
pub const VM_NETWORK_REVISION: u32 = 1;
/// The longest typed file the root bootstrap reads whole from the config
/// drive: a bound on one file's codec, not on what it configures.
pub const MAX_VM_CONFIG_FILE_BYTES: usize = 16384;
/// The managed profile's organization hosting id on the config drive
/// (FIX 6809): exactly 64 hex digits, either case. The root bootstrap passes
/// it to the engine as `--organization-owner`.
///
/// Each of the managed profile's five files holds its one value with at most
/// one final LF and nothing else, and is read before the vault's key goes in
/// on a boot that serves. One that is not there gives the engine no flag,
/// never a `false`; one that is there but not in its form refuses the boot.
pub const VM_GUEST_ORGANIZATION_OWNER_FILE: &str = "/config/organization-owner";
/// The managed profile's member-vault choice (FIX 6809): `true` or `false`.
/// `true` gives the engine a bare `--member-vault`, and `false` no flag, the
/// engine's own false.
pub const VM_GUEST_MEMBER_VAULT_FILE: &str = "/config/member-vault";
/// The managed profile's "Help improve Oneiron" choice (FIX 6809): `true` or
/// `false`, passed as `--failure-signal-export` with its value, `false`
/// included.
pub const VM_GUEST_FAILURE_SIGNAL_EXPORT_FILE: &str = "/config/failure-signal-export";
/// The managed profile's training choice (FIX 6809), apart from the export
/// one: `true` or `false`, passed as `--failure-signal-training` with its
/// value, `false` included.
pub const VM_GUEST_FAILURE_SIGNAL_TRAINING_FILE: &str = "/config/failure-signal-training";
/// The managed profile's MRL prefix width (FIX 6809): decimal digits, a
/// nonzero width a u16 holds, passed as `--fast-dims`. The engine checks it
/// against the vault's dimensions, as on a node.
pub const VM_GUEST_FAST_DIMS_FILE: &str = "/config/fast-dims";
/// The managed profile files' revision (FIX 6809): an image whose root
/// bootstrap reads the five files and passes the engine their flags names it
/// as its manifest's `vm_managed_profile_revision`.
pub const VM_MANAGED_PROFILE_REVISION: u32 = 1;
/// The guest runtime's revision (FIX 7671): an image that stages the whole
/// guest runtime its descriptor ([`VM_GUEST_RUNTIME_DESCRIPTOR`]) names,
/// whose root bootstrap prepares it for the vault's UID and binds it to the
/// engine, names 1 as its manifest's `vm_guest_runtime_revision`, beside the
/// descriptor itself as its manifest's `guest_runtime`. An image built
/// without one names 0, with a `null` descriptor. Neither says a browser
/// started or that a deployment turned the guests on.
pub const VM_GUEST_RUNTIME_REVISION: u32 = 1;
/// The image's guest runtime descriptor ([`VmGuestRuntimeDescriptor`]), one
/// JSON object in the read-only root filesystem, the same one the manifest's
/// `guest_runtime` holds.
pub const VM_GUEST_RUNTIME_DESCRIPTOR: &str = "/usr/lib/oneiron/guest-runtimes/manifest.json";
/// The browser guest's image archive in the read-only root filesystem.
pub const VM_GUEST_BROWSER_IMAGE_ARCHIVE: &str =
    "/usr/lib/oneiron/guest-runtimes/images/browser.tar";
/// The desktop guest's image archive in the read-only root filesystem.
pub const VM_GUEST_DESKTOP_IMAGE_ARCHIVE: &str =
    "/usr/lib/oneiron/guest-runtimes/images/desktop.tar";
/// The supervisor's binding of the browser guest's container CLI on the
/// config drive (FIX 7671): the descriptor's `cli`, with at most one final
/// LF and nothing else. The root bootstrap reads it, and passes it to the
/// engine as `--browser-runtime` only once the runtime is prepared. Without
/// it, and without [`VM_GUEST_DESKTOP_RUNTIME_FILE`], the guests stay dark.
pub const VM_GUEST_BROWSER_RUNTIME_FILE: &str = "/config/browser-runtime";
/// The desktop guest's binding, as [`VM_GUEST_BROWSER_RUNTIME_FILE`] is the
/// browser's, passed as `--desktop-runtime`.
pub const VM_GUEST_DESKTOP_RUNTIME_FILE: &str = "/config/desktop-runtime";
/// The container CLI's `HOME` in a vault VM (`--container-home`), holding
/// the vault UID's own image store: the vault UID's, mode 0700, in the
/// encrypted storage beside the data directory, never in it.
pub const VM_GUEST_CONTAINER_HOME: &str = "/vault/storage/container/home";
/// The container CLI's `XDG_RUNTIME_DIR` in a vault VM
/// (`--container-runtime-dir`), beside [`VM_GUEST_CONTAINER_HOME`] and as it
/// is.
pub const VM_GUEST_CONTAINER_RUNTIME_DIR: &str = "/vault/storage/container/runtime";
/// The first subordinate UID and GID the vault UID maps in its guests'
/// user namespaces, local to the VM: the one vault UID's one row in each of
/// `/etc/subuid` and `/etc/subgid`.
pub const VM_GUEST_SUBID_BASE: u32 = 100_000;
/// How many subordinate IDs that row holds.
pub const VM_GUEST_SUBID_COUNT: u32 = 65_536;
/// The vault's fscrypt v2 storage on its own disk: owned by the vault's UID,
/// mode 0700, encrypted under the provisioned key. It holds the data
/// directory and the engine's siblings of it (backups, rehearsals).
pub const VM_GUEST_STORAGE_DIR: &str = "/vault/storage";
/// The guest engine's data directory (`--data-dir`), inside the encrypted
/// storage; `oneiron-vm-init` passes this path, and the guest's UID table
/// binds it. A supervisor maps a guest owner path below it onto the vault
/// disk's data view (`crate::settings_paths`).
pub const VM_GUEST_DATA_DIR: &str = "/vault/storage/data";
/// The engine's key directory (`--keystore-dir`), on the vault's own disk
/// beside the storage, under the same owner, mode and fscrypt policy.
pub const VM_GUEST_KEYS_DIR: &str = "/vault/keys";
/// One boot-channel frame, newline included.
pub const MAX_VM_FRAME: usize = 1024;

/// Host-to-guest frames on the boot channel, after the credential frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum VmHostFrame {
    /// The host wants the vault idle. The guest answers with [`VmGuestFrame::Idle`].
    Sleep,
    /// The guest runs again: after a pause, or after a snapshot restore and
    /// the guest's [`VmGuestFrame::Join`].
    Resumed,
    /// Drain, flush and exit. The host kills the VM when its grace runs out.
    Stop,
}

/// Guest-to-host frames on the boot channel, after the ready byte.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum VmGuestFrame {
    /// The vault is idle until `next_wake`. `snapshot_ok` is false while an
    /// off-record stretch is open: the guest's RAM must then never reach
    /// disk, so the host stops the vault or leaves it running instead
    /// (OFFREC-SNAPSHOT = A).
    Idle {
        next_wake: Option<UnixTs>,
        snapshot_ok: bool,
    },
    /// Opens a lifecycle connection: after the ready byte, and again after a
    /// snapshot restore reset vsock. After a restore the host answers
    /// `Resumed`.
    Join { vault: String },
    /// The engine began its stop.
    Stopping,
}

/// One frame as the line the boot channel carries.
pub fn encode_vm_frame(frame: &impl Serialize) -> anyhow::Result<String> {
    let mut line = serde_json::to_string(frame)?;
    line.push('\n');
    anyhow::ensure!(line.len() <= MAX_VM_FRAME, "vm frame over its cap");
    Ok(line)
}

/// Parses one boot-channel line. Over-cap lines are refused whole.
pub fn decode_vm_frame<T: for<'de> Deserialize<'de>>(line: &str) -> anyhow::Result<T> {
    anyhow::ensure!(line.len() <= MAX_VM_FRAME, "vm frame over its cap");
    Ok(serde_json::from_str(line.trim_end_matches(['\r', '\n']))?)
}

/// The host unix socket a guest-initiated connection to `port` reaches.
pub fn guest_initiated_socket(device_socket: &Path, port: u32) -> PathBuf {
    let mut path = device_socket.as_os_str().to_owned();
    path.push(format!("_{port}"));
    PathBuf::from(path)
}

/// The line a host writes on the device socket to reach a guest port.
pub fn host_connect_line(port: u32) -> String {
    format!("CONNECT {port}\n")
}
