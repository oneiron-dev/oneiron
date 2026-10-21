//! A vault VM's restore channel (FIX 6584): the cold restore start mode
//! (`crate::restore`) carried into a Firecracker guest, and the commit
//! marker read back out of one whose result was lost.
//!
//! The guest's root bootstrap dials [`VM_RESTORE_PORT`](crate::vm::VM_RESTORE_PORT)
//! once on every cold boot, before its provision connection, and says
//! [`VmRestoreHello`]; the host answers the boot's [`VmRestoreBoot`]. Both
//! are control records: a big-endian u32 length, then that many bytes of one
//! JSON object, at most [`MAX_VM_RESTORE_CONTROL_BYTES`].
//!
//! - [`VmRestoreBoot::Open`] ends the exchange, and the boot goes on as every
//!   cold boot before the channel did.
//! - [`VmRestoreBoot::Restore`] keeps the connection for the restore. The
//!   bootstrap lays out the storage without the data directory, makes the
//!   engine's two restore pipes and starts it with the same `--restore`
//!   flags a node's child takes. The host sends the supervisor's input pipe
//!   as [`VmRestoreRecord::InputChunk`] records, exactly its bytes, then
//!   [`VmRestoreRecord::InputEnd`] and a half-close; the guest sends the
//!   engine's result pipe back the same way as
//!   [`VmRestoreRecord::ResultChunk`] and [`VmRestoreRecord::ResultEnd`].
//!   Nothing is parsed or rewritten on the way: the native frames decide
//!   the restore's outcome, and an end record only tells the producer's EOF
//!   from a channel that broke. An input that breaks before its end never
//!   reaches the engine as an EOF: the bootstrap ends the engine first.
//! - [`VmRestoreBoot::InspectMarker`] provisions the disk with no engine,
//!   companion or listener, reads the [`RestoreCommitMarker`] the vault's
//!   data directory holds, and answers one [`VmRestoreMarkerReply`].
//!
//! The bounds here are the channel's codec only: the restore's input, its
//! result and the receipt they carry have none.

use crate::restore::{ManagedRestoreDestination, ManagedRestoreIdentity, RestoreCommitMarker};
use crate::vm_provision::VmProvisionBinding;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// The restore channel's wire revision. An image manifest names it as
/// `restore_wire_revision`; a host speaks the channel only to an image that
/// does.
pub const VM_RESTORE_WIRE_REVISION: u32 = 1;
/// The longest control record's JSON: a hello, a boot or a marker reply.
pub const MAX_VM_RESTORE_CONTROL_BYTES: usize = 4 * crate::MAX_CTL_LINE;
/// The longest stream record's payload.
pub const VM_RESTORE_CHUNK_BYTES: usize = 64 * 1024;
/// A stream record's header: its kind, then its payload's length as a
/// big-endian u32.
pub const VM_RESTORE_RECORD_HEADER_BYTES: usize = 5;
/// Where the guest mounts a restore's source drive, read-only, when the host
/// attaches one: the sealed artifact and its keyless custody head, at the
/// paths the plan names below it.
pub const VM_GUEST_RESTORE_DIR: &str = "/restore";

/// The guest's first control record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmRestoreHello {
    pub revision: u32,
    /// The vault the guest's boot arguments name.
    pub vault: String,
}

/// What this cold boot does, the host's answer to the hello.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum VmRestoreBoot {
    /// It opens the vault on its disk.
    Open,
    /// It restores the vault from the plan the input records carry.
    Restore {
        /// The restore's source drive, when the host attached one; `null`
        /// when the plan's sources are already the guest's to read.
        #[serde(deserialize_with = "Option::deserialize")]
        source_device: Option<VmRestoreSourceDevice>,
    },
    /// It reads the commit marker for `identity` and runs nothing.
    InspectMarker { identity: ManagedRestoreIdentity },
}

/// The guest drive a restore's source is, after the vault's own drives: the
/// third without a config drive, the fourth with one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmRestoreSourceDevice {
    Vdc,
    Vdd,
}

impl VmRestoreSourceDevice {
    /// The drive's device node in the guest.
    #[must_use]
    pub fn path(self) -> &'static str {
        match self {
            Self::Vdc => "/dev/vdc",
            Self::Vdd => "/dev/vdd",
        }
    }
}

/// A stream record's kind: host to guest the input's, guest to host the
/// result's. A chunk carries 1 to [`VM_RESTORE_CHUNK_BYTES`] bytes; an end
/// carries none and is its direction's last record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmRestoreRecord {
    InputChunk = 1,
    InputEnd = 2,
    ResultChunk = 3,
    ResultEnd = 4,
}

impl VmRestoreRecord {
    /// Whether this is its direction's end.
    #[must_use]
    pub fn is_end(self) -> bool {
        matches!(self, Self::InputEnd | Self::ResultEnd)
    }

    /// The header of one record of this kind carrying `len` bytes; refused
    /// when `len` does not fit the kind.
    pub fn header(self, len: usize) -> anyhow::Result<[u8; VM_RESTORE_RECORD_HEADER_BYTES]> {
        anyhow::ensure!(
            self.fits(len),
            "a vm restore record of {len} bytes is not a {self:?}"
        );
        let mut header = [self as u8, 0, 0, 0, 0];
        header[1..].copy_from_slice(&u32::try_from(len)?.to_be_bytes());
        Ok(header)
    }

    /// A header's kind and payload length; refused when the kind is unknown
    /// or the length does not fit it.
    pub fn parse(header: [u8; VM_RESTORE_RECORD_HEADER_BYTES]) -> anyhow::Result<(Self, usize)> {
        let kind = match header[0] {
            1 => Self::InputChunk,
            2 => Self::InputEnd,
            3 => Self::ResultChunk,
            4 => Self::ResultEnd,
            tag => anyhow::bail!("vm restore record tag {tag} is unknown"),
        };
        let len = usize::try_from(u32::from_be_bytes([
            header[1], header[2], header[3], header[4],
        ]))?;
        anyhow::ensure!(
            kind.fits(len),
            "a vm restore record of {len} bytes is not a {kind:?}"
        );
        Ok((kind, len))
    }

    fn fits(self, len: usize) -> bool {
        if self.is_end() {
            len == 0
        } else {
            (1..=VM_RESTORE_CHUNK_BYTES).contains(&len)
        }
    }
}

/// The guest's answer to [`VmRestoreBoot::InspectMarker`]: the provisioned
/// vault and binding and the queried identity, echoed, and what it found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmRestoreMarkerReply {
    pub revision: u32,
    pub vault: String,
    pub binding: VmProvisionBinding,
    pub identity: ManagedRestoreIdentity,
    pub observation: VmRestoreMarkerObservation,
}

/// What an inspection found on the vault's disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum VmRestoreMarkerObservation {
    /// The storage read: whether the data directory is there, and the
    /// marker in it, `null` when it holds none.
    Observed {
        data_present: bool,
        #[serde(deserialize_with = "Option::deserialize")]
        marker: Option<RestoreCommitMarker>,
    },
    /// What the disk holds could not be told.
    Unreadable { reason: VmRestoreMarkerUnreadable },
}

/// Why an inspection told nothing, in closed names: never a path or an
/// error's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmRestoreMarkerUnreadable {
    /// The storage, or the reply, is not this vault's binding's.
    BindingMismatch,
    /// The storage or its data directory did not read.
    DataUnreadable,
    /// A marker is there and is not one marker.
    MarkerUnreadable,
    /// The reply is not one marker reply.
    FrameInvalid,
}

impl VmRestoreMarkerObservation {
    /// What the observation proves of `identity`'s restore, as a lost
    /// result's reconciliation reads it: kept and not serving when the
    /// marker names it; removed when neither the data directory nor a
    /// marker is there; anything else uncertain, held, and never opened as
    /// ordinary or overwritten.
    #[must_use]
    pub fn destination(&self, identity: &ManagedRestoreIdentity) -> ManagedRestoreDestination {
        match self {
            Self::Observed {
                marker: Some(marker),
                ..
            } if marker.names(identity) => ManagedRestoreDestination::CommittedNotServing,
            Self::Observed {
                data_present: false,
                marker: None,
            } => ManagedRestoreDestination::Removed,
            Self::Observed { .. } | Self::Unreadable { .. } => ManagedRestoreDestination::Uncertain,
        }
    }
}

/// One control record: its length prefix, then `record` as JSON.
pub fn encode_vm_restore_control(record: &impl Serialize) -> anyhow::Result<Vec<u8>> {
    let body = serde_json::to_vec(record)?;
    anyhow::ensure!(
        body.len() <= MAX_VM_RESTORE_CONTROL_BYTES,
        "vm restore control record over its cap"
    );
    let mut bytes = u32::try_from(body.len())?.to_be_bytes().to_vec();
    bytes.extend_from_slice(&body);
    Ok(bytes)
}

/// A control record's body length from its prefix: refused when empty or
/// over the cap, before any of the body is read.
pub fn vm_restore_control_len(prefix: [u8; 4]) -> anyhow::Result<usize> {
    let len = usize::try_from(u32::from_be_bytes(prefix))?;
    anyhow::ensure!(
        (1..=MAX_VM_RESTORE_CONTROL_BYTES).contains(&len),
        "vm restore control record of {len} bytes"
    );
    Ok(len)
}

/// Parses one control record's body.
pub fn decode_vm_restore_control<T: DeserializeOwned>(body: &[u8]) -> anyhow::Result<T> {
    Ok(serde_json::from_slice(body)?)
}

/// Reads one whole control record from a blocking reader.
pub fn read_vm_restore_control<T: DeserializeOwned>(
    reader: &mut impl std::io::Read,
) -> anyhow::Result<T> {
    let mut prefix = [0u8; 4];
    reader.read_exact(&mut prefix)?;
    let mut body = vec![0u8; vm_restore_control_len(prefix)?];
    reader.read_exact(&mut body)?;
    decode_vm_restore_control(&body)
}
