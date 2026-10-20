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
//! descriptors. On a cold boot the guest's first connection is the provision
//! connection ([`crate::vm_provision`]): the guest's root bootstrap takes the
//! vault's binding and its fscrypt key there, lays out the encrypted storage
//! and the UID table, and only then starts the engine as the vault's own
//! non-root UID (FIX 6308). The engine's first connection is the credential
//! connection: the host writes the credential frame and half-closes, and the
//! guest answers with the ready byte. Every later connection is the lifecycle
//! connection: the guest opens it with [`VmGuestFrame::Join`], then both
//! sides speak one JSON line per frame. A snapshot restore resets vsock, so
//! the guest joins again after each one; it runs no second provision. The
//! guest's outbox companion dials [`VM_OUTBOX_PORT`] on its own
//! ([`crate::vm_outbox`]) and dials again after a reset.
//!
//! The provision connection rides contract version 3 with a build floor, the
//! first engine revision that ships `oneiron-vm-init`: a host speaks it only
//! to an image built at or after that floor, which the image manifest pins.
//! An older image's engine would read the provision frame as its credential
//! frame and refuse it, so it never starts.

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
/// The owner-only directory a vault VM's `[models.voice]` socket lies in.
pub const VM_VOICE_DIR: &str = "/run/oneiron/voice";
/// Where the guest mounts the vault's read-only config drive: its settings
/// file, and the files the settings' owner paths name beside it. A
/// supervisor maps a guest owner path below it onto the vault's own config
/// directory (`crate::settings_paths`).
pub const VM_GUEST_CONFIG_DIR: &str = "/config";
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
