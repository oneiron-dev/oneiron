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
//! descriptors. The guest's first connection is the credential connection:
//! the host writes the credential frame and half-closes, and the guest
//! answers with the ready byte. Every later connection is the lifecycle
//! connection: the guest opens it with [`VmGuestFrame::Join`], then both
//! sides speak one JSON line per frame. A snapshot restore resets vsock, so
//! the guest joins again after each one.

use crate::UnixTs;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The guest's context id. One vault per VM, so every guest uses the same id.
pub const VM_GUEST_CID: u32 = 3;
/// The host's context id, the only peer a guest can reach.
pub const VM_HOST_CID: u32 = 2;
/// Guest to host: the credential connection, then the lifecycle connection.
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
