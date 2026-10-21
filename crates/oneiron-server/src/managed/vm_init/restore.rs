//! The bootstrap's half of the restore channel (FIX 6584,
//! [`oneiron_vault_contract::vm_restore`]): the boot's mode, asked before
//! the provision connection, and then what the mode needs.
//!
//! - A cold restore gets its source drive mounted read-only at
//!   [`VM_GUEST_RESTORE_DIR`] when the host attached one, and two ordinary
//!   pipes: the engine takes their ends with the same `--restore` flags a
//!   node's child takes, and reads and writes them as it would there. The
//!   bootstrap keeps the other ends and pumps them over the channel, the
//!   input as it arrives and the result as the engine writes it. An input
//!   that breaks before its end never reaches the engine as an EOF: the
//!   bootstrap ends the engine first, and only then lets the pipe go. A
//!   result the host no longer takes is read on and dropped, so the engine
//!   never stalls on it and nothing it kept is undone.
//! - An inspection reads the vault's data directory and its commit marker
//!   through held directories, without following a link and without making
//!   anything, and answers once. No engine, companion or listener runs.

use super::Refusal;
use super::fscrypt::{self, KeyIdentifier, Policy};
use super::layout::{DATA_LEAF, STORAGE_LEAF};
use anyhow::Context as _;
use oneiron_vault_contract::host_adapters::connect_blocking;
use oneiron_vault_contract::restore::{ManagedRestoreIdentity, RestoreCommitMarker};
use oneiron_vault_contract::vm::{VM_HOST_CID, VM_RESTORE_PORT};
use oneiron_vault_contract::vm_provision::{VmProvision, VmProvisionFailure};
use oneiron_vault_contract::vm_restore::{
    VM_GUEST_RESTORE_DIR, VM_RESTORE_CHUNK_BYTES, VM_RESTORE_RECORD_HEADER_BYTES,
    VM_RESTORE_WIRE_REVISION, VmRestoreBoot, VmRestoreHello, VmRestoreMarkerObservation,
    VmRestoreMarkerReply, VmRestoreMarkerUnreadable, VmRestoreRecord, VmRestoreSourceDevice,
    encode_vm_restore_control, read_vm_restore_control,
};
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;
use std::ffi::{CString, OsString};
use std::fs::File;
use std::io::{PipeReader, PipeWriter, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::process::{Child, ExitStatus};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

/// How often the bootstrap looks at its engine while the input may still be
/// lost.
const ENGINE_POLL: Duration = Duration::from_millis(100);

/// Dials the restore channel and says hello for `vault`; the host's answer
/// is this boot's mode. The connection stays open for the mode's use.
pub(super) fn exchange(vault: &str) -> anyhow::Result<(VmRestoreBoot, File)> {
    let mut channel = connect_blocking(VM_HOST_CID, VM_RESTORE_PORT)
        .context("dialling the host's restore channel")?;
    let hello = VmRestoreHello {
        revision: VM_RESTORE_WIRE_REVISION,
        vault: vault.to_owned(),
    };
    channel.write_all(&encode_vm_restore_control(&hello)?)?;
    let boot = read_vm_restore_control(&mut channel)
        .context("the host's answer on its restore channel")?;
    Ok((boot, channel))
}

/// A cold restore's source drive, mounted read-only, without devices,
/// set-ID or execution, at [`VM_GUEST_RESTORE_DIR`] until dropped.
pub(super) struct SourceMount(CString);

impl SourceMount {
    /// Mounts `device`, an ext4 image, refused unless it is a block device.
    pub(super) fn mount(device: VmRestoreSourceDevice) -> Result<Self, Refusal> {
        let refused = |error: std::io::Error| {
            Refusal::new(
                VmProvisionFailure::ProvisionFailed,
                format!("mounting the restore's source drive: {error}"),
            )
        };
        let metadata = std::fs::metadata(device.path()).map_err(refused)?;
        if !metadata.file_type().is_block_device() {
            return Err(refused(std::io::Error::other("it is not a block device")));
        }
        let source = CString::new(device.path()).map_err(|error| refused(error.into()))?;
        let target = CString::new(VM_GUEST_RESTORE_DIR).map_err(|error| refused(error.into()))?;
        let flags = libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
        // SAFETY: each pointer is a NUL-terminated string that outlives the
        // call, and ext4 takes no data argument here.
        let mounted = unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                c"ext4".as_ptr(),
                flags,
                std::ptr::null(),
            )
        };
        if mounted != 0 {
            return Err(refused(std::io::Error::last_os_error()));
        }
        Ok(Self(target))
    }
}

impl Drop for SourceMount {
    fn drop(&mut self) {
        // SAFETY: the pointer is the NUL-terminated mountpoint this mounted.
        if unsafe { libc::umount2(self.0.as_ptr(), 0) } != 0 {
            eprintln!(
                "oneiron-vm-init: unmounting the restore's source drive failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

/// A cold restore's engine, its input pipe's hand-back when the input is
/// lost, and the pump carrying its result to the host.
pub(super) struct Restoring {
    engine: Child,
    lost: mpsc::Receiver<PipeWriter>,
    result: JoinHandle<()>,
}

/// Makes the restore's two pipes, starts their pumps over `channel`, and
/// starts the engine through `spawn`, which gets each engine end as an
/// `(ours, theirs)` pair and the flags that name them. The bootstrap's
/// copies of the engine's ends are closed once it has started.
pub(super) fn start(
    channel: File,
    spawn: impl FnOnce(&[(RawFd, RawFd)], &[OsString]) -> anyhow::Result<Child>,
) -> anyhow::Result<Restoring> {
    let (input_read, input_write) = std::io::pipe()?;
    let (result_read, result_write) = std::io::pipe()?;
    let reader = channel.try_clone()?;
    let (lost_sender, lost) = mpsc::channel();
    std::thread::Builder::new()
        .name("vm-restore-input".into())
        .spawn(move || feed(reader, input_write, &lost_sender))?;
    let result = std::thread::Builder::new()
        .name("vm-restore-result".into())
        .spawn(move || drain(result_read, channel))?;
    let (input_fd, result_fd) = (input_read.as_raw_fd(), result_write.as_raw_fd());
    let flags: Vec<OsString> = vec![
        "--restore".into(),
        "--restore-input-fd".into(),
        input_fd.to_string().into(),
        "--restore-result-fd".into(),
        result_fd.to_string().into(),
        "--vm-restore-revision".into(),
        VM_RESTORE_WIRE_REVISION.to_string().into(),
    ];
    let engine = spawn(&[(input_fd, input_fd), (result_fd, result_fd)], &flags);
    drop(input_read);
    drop(result_write);
    Ok(Restoring {
        engine: engine?,
        lost,
        result,
    })
}

impl Restoring {
    /// Waits for the engine. When the input is lost before its end, the
    /// engine is ended and waited for first, and only then is its input
    /// pipe let go.
    pub(super) fn wait(&mut self) -> anyhow::Result<ExitStatus> {
        loop {
            match self.lost.recv_timeout(ENGINE_POLL) {
                Ok(input) => {
                    let _ = self.engine.kill();
                    let status = self.engine.wait().context("waiting for the engine");
                    drop(input);
                    return status;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return self.engine.wait().context("waiting for the engine");
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if let Some(status) =
                        self.engine.try_wait().context("waiting for the engine")?
                    {
                        return Ok(status);
                    }
                }
            }
        }
    }

    /// Waits until the result's last record is out, once nothing the
    /// engine started is left to hold its result pipe.
    pub(super) fn finish(self) {
        if self.result.join().is_err() {
            eprintln!("oneiron-vm-init: the restore's result pump failed");
        }
    }
}

/// Writes the host's input records into the engine's input pipe until the
/// input's end, then closes the pipe: the engine's EOF. A channel that ends
/// or breaks first, or a record that is not the input's, hands the open
/// pipe to the bootstrap instead.
fn feed(mut channel: File, mut input: PipeWriter, lost: &mpsc::Sender<PipeWriter>) {
    let mut chunk = vec![0u8; VM_RESTORE_CHUNK_BYTES];
    loop {
        let mut header = [0u8; VM_RESTORE_RECORD_HEADER_BYTES];
        let record = channel
            .read_exact(&mut header)
            .map_err(anyhow::Error::from)
            .and_then(|()| VmRestoreRecord::parse(header));
        let received = match record {
            Ok((VmRestoreRecord::InputEnd, _)) => return,
            Ok((VmRestoreRecord::InputChunk, len)) => {
                channel.read_exact(&mut chunk[..len]).map(|()| len)
            }
            _ => Err(std::io::Error::other("not an input record")),
        };
        let Ok(len) = received else {
            eprintln!(
                "oneiron-vm-init: the restore's input broke before its end; ending the engine"
            );
            let _ = lost.send(input);
            return;
        };
        // An engine that closed its input has ended, and reads no more.
        if input.write_all(&chunk[..len]).is_err() {
            return;
        }
    }
}

/// Sends the engine's result pipe to the host as it reads, in chunks, then
/// the result's end and a half-close. A channel that takes no more is let
/// go, and the pipe is read on to its end.
fn drain(mut result: PipeReader, mut channel: File) {
    let mut chunk = vec![0u8; VM_RESTORE_CHUNK_BYTES];
    let mut open = true;
    loop {
        let read = match result.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            // A pipe that failed is no producer's end: the host is told none.
            Err(_) => return,
        };
        if open && send(&mut channel, VmRestoreRecord::ResultChunk, &chunk[..read]).is_err() {
            eprintln!(
                "oneiron-vm-init: the host took no more of the restore's result; restore_status answers for it once the vault serves"
            );
            open = false;
        }
    }
    if open && send(&mut channel, VmRestoreRecord::ResultEnd, &[]).is_ok() {
        // SAFETY: shutdown takes no pointers, on a socket `channel` holds.
        unsafe { libc::shutdown(channel.as_raw_fd(), libc::SHUT_WR) };
    }
}

fn send(channel: &mut File, record: VmRestoreRecord, bytes: &[u8]) -> anyhow::Result<()> {
    channel.write_all(&record.header(bytes.len())?)?;
    Ok(channel.write_all(bytes)?)
}

/// What the provisioned disk holds for an inspection: whether the vault's
/// data directory is there, and the commit marker in it. The storage must
/// be under the provisioned key's policy and the vault UID's.
pub(super) fn observe(
    root: &File,
    identifier: &KeyIdentifier,
    uid: u32,
) -> VmRestoreMarkerObservation {
    read_marker(root, identifier, uid)
        .unwrap_or_else(|reason| VmRestoreMarkerObservation::Unreadable { reason })
}

fn read_marker(
    root: &File,
    identifier: &KeyIdentifier,
    uid: u32,
) -> Result<VmRestoreMarkerObservation, VmRestoreMarkerUnreadable> {
    use VmRestoreMarkerUnreadable as Unreadable;
    let absent = VmRestoreMarkerObservation::Observed {
        data_present: false,
        marker: None,
    };
    let Some(storage) = held_dir(root, STORAGE_LEAF)? else {
        return Ok(absent);
    };
    match fscrypt::policy(&storage) {
        Ok(Policy::Ours(found)) if found == *identifier => {}
        Ok(_) => return Err(Unreadable::BindingMismatch),
        Err(_) => return Err(Unreadable::DataUnreadable),
    }
    let metadata = storage.metadata().map_err(|_| Unreadable::DataUnreadable)?;
    if metadata.uid() != uid || metadata.gid() != uid || metadata.mode() & 0o7777 != 0o700 {
        return Err(Unreadable::BindingMismatch);
    }
    let Some(data) = held_dir(&storage, DATA_LEAF)? else {
        return Ok(absent);
    };
    // Through the held directory itself, not its path.
    let held = format!("/proc/self/fd/{}", data.as_raw_fd());
    let marker = RestoreCommitMarker::read(std::path::Path::new(&held))
        .map_err(|_| Unreadable::MarkerUnreadable)?;
    Ok(VmRestoreMarkerObservation::Observed {
        data_present: true,
        marker,
    })
}

/// The directory `leaf` of `parent`, opened without following a link;
/// `None` when nothing is there.
fn held_dir(parent: &File, leaf: &str) -> Result<Option<File>, VmRestoreMarkerUnreadable> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    match rustix::fs::openat(parent, leaf, flags, Mode::empty()) {
        Ok(fd) => Ok(Some(File::from(fd))),
        Err(Errno::NOENT) => Ok(None),
        Err(_) => Err(VmRestoreMarkerUnreadable::DataUnreadable),
    }
}

/// Answers the inspection on `channel`: the provisioned vault and binding
/// from `frame`, the queried `identity`, and `observation`.
pub(super) fn answer_inspection(
    mut channel: File,
    frame: &VmProvision,
    identity: ManagedRestoreIdentity,
    observation: VmRestoreMarkerObservation,
) -> anyhow::Result<()> {
    let reply = VmRestoreMarkerReply {
        revision: VM_RESTORE_WIRE_REVISION,
        vault: frame.vault.clone(),
        binding: frame.binding.clone(),
        identity,
        observation,
    };
    channel
        .write_all(&encode_vm_restore_control(&reply)?)
        .context("answering the host's inspection")
}
