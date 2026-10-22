//! The host's half of a vault VM's restore channel (FIX 6584,
//! [`oneiron_vault_contract::vm_restore`]): every cold boot's mode, a cold
//! restore carried into the guest, and the commit marker read back out of
//! a disk whose restore result was lost.
//!
//! A cold restore takes the supervisor's pipes as a node's engine does: the
//! input pipe R carries the plan, the result pipe W takes the result frames,
//! and the credential frame C follows R's end. The host starts the VM on the
//! fscrypt key alone, provisions it and streams R into the guest as it
//! reads, so a supervisor that writes R, then C, never waits on a host that
//! waits on C; it hands the key before R or beside it. W is drained into the
//! supervisor's pipe all the while. Only the boot's own steps wait at most
//! the boot timeout: the restore has no deadline, and a guest that ends
//! closes the channel. The VM listens for nothing before the restore is
//! verified and kept and says ready only after the `verified` frame, as a
//! node's engine does. A restore's boot never loads a RAM snapshot, and no
//! snapshot is taken while it runs. The custody anchor's credential follows
//! C, as on a node (FIX 6517, [`super::anchor`]). The VMM's exit ends the
//! restore early, as a SIGTERM to the runner does, and ending it wakes C's
//! read, which has no deadline of its own (FIX 7078, [`super::credentials`]).
//!
//! When W was lost and no generation of the vault serves, the supervisor,
//! having confirmed every earlier one dead, asks the disk instead
//! ([`VaultVm::inspect_restore_marker`]): a cold boot of the same disk that
//! provisions it, runs no engine, companion or listener, and reads the
//! commit marker once.

use super::credentials::read_credential_frame;
use super::{API_TIMEOUT, STOP_GRACE, VaultVm, VaultVmConfig, VmExitWatch, provision};
use crate::managed::restore::{adopt, pipe_end};
use oneiron_vault_contract::restore::ManagedRestoreIdentity;
use oneiron_vault_contract::vm_provision::VmFscryptKey;
use oneiron_vault_contract::vm_restore::{
    MAX_VM_RESTORE_CONTROL_BYTES, VM_RESTORE_CHUNK_BYTES, VM_RESTORE_RECORD_HEADER_BYTES,
    VM_RESTORE_WIRE_REVISION, VmRestoreBoot, VmRestoreHello, VmRestoreMarkerObservation,
    VmRestoreMarkerReply, VmRestoreMarkerUnreadable, VmRestoreRecord, VmRestoreSourceDevice,
    decode_vm_restore_control, encode_vm_restore_control, vm_restore_control_len,
};
use oneiron_vault_contract::{Credentials, READY_BYTE};
use std::io::{Read as _, Write as _};
use std::os::fd::{FromRawFd as _, OwnedFd, RawFd};
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::net::unix::pipe;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

/// A cold restore's supervisor pipes, each this process's to own: the read
/// end of R, which carries one native restore input and EOF; the write end
/// of W, which takes the native result frames and is closed after the last;
/// and C's descriptor, which carries the credential frame and is read only
/// once R has ended.
pub struct VmRestoreHostIo {
    pub input: OwnedFd,
    pub result: OwnedFd,
    pub credentials: OwnedFd,
}

/// `host vm --restore`'s two pipes (`--restore-input-fd`,
/// `--restore-result-fd`): the VM starts at once with a cold restore, and
/// the runner serves it once it is ready.
#[derive(Debug, Clone, Copy)]
pub struct VmRestoreFds {
    pub input_fd: RawFd,
    pub result_fd: RawFd,
}

impl VmRestoreFds {
    /// The restore's descriptors taken over, once, before any is read: each
    /// refused when it names another flag's descriptor, and each pipe when
    /// it is not its pipe's right end.
    pub(super) fn adopt(
        self,
        credentials_fd: RawFd,
        fscrypt_key_fd: RawFd,
    ) -> anyhow::Result<VmRestoreHostIo> {
        distinct(&[
            ("--credentials-fd", credentials_fd),
            ("--fscrypt-key-fd", fscrypt_key_fd),
            ("--restore-input-fd", self.input_fd),
            ("--restore-result-fd", self.result_fd),
        ])?;
        proven("--restore-input-fd", self.input_fd, false)?;
        proven("--restore-result-fd", self.result_fd, true)?;
        // SAFETY: `credentials_fd` arrives on argv from the supervisor and is
        // this process's to own; nothing else takes it over, and it is read
        // once R has ended.
        let credentials = unsafe { OwnedFd::from_raw_fd(credentials_fd) };
        Ok(VmRestoreHostIo {
            input: adopt(self.input_fd).into(),
            result: adopt(self.result_fd).into(),
            credentials,
        })
    }
}

/// `oneiron-server host vm --restore-marker-identity-fd Q
/// --restore-marker-result-fd S`: one inspection of a vault VM's disk, then
/// exit. It takes the profile, the vault and the fscrypt key, and no
/// credential frame or socket.
pub struct VaultVmInspect {
    pub config: PathBuf,
    pub vault_name: String,
    pub fscrypt_key_fd: RawFd,
    /// The read end of a pipe carrying the restore's
    /// `ManagedRestoreIdentity`, one JSON object, then EOF.
    pub identity_fd: RawFd,
    /// The write end of a pipe the observation goes out on: one
    /// `VmRestoreMarkerObservation` JSON object, then EOF. Nothing is written
    /// when the inspection did not complete.
    pub result_fd: RawFd,
}

/// Runs one inspection (`VaultVmInspect`).
pub async fn inspect_vault_vm(run: VaultVmInspect) -> anyhow::Result<()> {
    let config: VaultVmConfig = serde_json::from_slice(&std::fs::read(&run.config)?)?;
    distinct(&[
        ("--fscrypt-key-fd", run.fscrypt_key_fd),
        ("--restore-marker-identity-fd", run.identity_fd),
        ("--restore-marker-result-fd", run.result_fd),
    ])?;
    proven("--restore-marker-identity-fd", run.identity_fd, false)?;
    proven("--restore-marker-result-fd", run.result_fd, true)?;
    let (identity_pipe, mut result_pipe) = (adopt(run.identity_fd), adopt(run.result_fd));
    let mut identity = Vec::new();
    identity_pipe
        .take(MAX_VM_RESTORE_CONTROL_BYTES as u64 + 1)
        .read_to_end(&mut identity)?;
    anyhow::ensure!(
        identity.len() <= MAX_VM_RESTORE_CONTROL_BYTES,
        "--restore-marker-identity-fd carries more than one restore identity"
    );
    let identity: ManagedRestoreIdentity = serde_json::from_slice(&identity)?;
    let fscrypt_key = provision::read_fscrypt_key(run.fscrypt_key_fd)?;
    let mut vm = VaultVm::prepare(config, run.vault_name)?;
    let observation = vm
        .inspect_restore_marker(&identity, &fscrypt_key, API_TIMEOUT)
        .await?;
    result_pipe.write_all(&serde_json::to_vec(&observation)?)?;
    Ok(())
}

/// Refuses two of `fds` that name one descriptor.
pub(super) fn distinct(fds: &[(&str, RawFd)]) -> anyhow::Result<()> {
    for (index, (flag, fd)) in fds.iter().enumerate() {
        if let Some((other, _)) = fds[index + 1..].iter().find(|(_, other)| other == fd) {
            anyhow::bail!("{flag} and {other} name one descriptor");
        }
    }
    Ok(())
}

/// Refuses `fd` unless it is a pipe's read end (`write` false) or write end.
pub(super) fn proven(flag: &str, fd: RawFd, write: bool) -> anyhow::Result<()> {
    pipe_end(fd, write).map_err(|reason| anyhow::anyhow!("{flag} {fd} refused: {reason}"))
}

impl VaultVm {
    /// Refuses a restore or an inspection while a VM runs, or while a RAM
    /// snapshot is published: that generation may resume, and its RAM's
    /// view of the disk would not survive another boot of it.
    fn cold_only(&self) -> anyhow::Result<()> {
        anyhow::ensure!(!self.is_running(), "the vault VM is already running");
        anyhow::ensure!(
            !self.has_snapshot(),
            "the vault VM has a RAM snapshot published; resume it rather than boot its disk again"
        );
        Ok(())
    }

    /// The restore channel, a cold boot's first connection: the guest's
    /// hello, checked, then `boot`, this boot's mode. Each wait is within
    /// the caller's boot `timeout`.
    pub(super) async fn answer_hello(
        &mut self,
        boot: &VmRestoreBoot,
        timeout: Duration,
    ) -> anyhow::Result<UnixStream> {
        let (mut stream, _) = tokio::time::timeout(timeout, self.restore.accept()).await??;
        let hello = tokio::time::timeout(timeout, read_control(&mut stream)).await??;
        let hello: VmRestoreHello = decode_vm_restore_control(&hello)?;
        anyhow::ensure!(
            hello.revision == VM_RESTORE_WIRE_REVISION,
            "vault VM's restore channel speaks revision {}, not {VM_RESTORE_WIRE_REVISION}",
            hello.revision
        );
        anyhow::ensure!(
            hello.vault == self.vault,
            "vault VM said its restore hello as another vault"
        );
        stream.write_all(&encode_vm_restore_control(boot)?).await?;
        Ok(stream)
    }

    /// Cold-restores the vault into a fresh VM from `io`: a cold boot of its
    /// disk, never a snapshot, with the profile's restore source drive when
    /// it names one; the guest provisioned with `fscrypt_key`; R streamed in
    /// as it reads and W drained beside it; then C read and handed over.
    /// Returns C's frame once the vault was verified and kept, said ready
    /// and joined, and W's last record is in the supervisor's pipe. A
    /// failure stops the VM, letting the guest's last result records out
    /// within the stop's grace first.
    pub async fn start_restore(
        &mut self,
        io: VmRestoreHostIo,
        fscrypt_key: &VmFscryptKey,
        timeout: Duration,
    ) -> anyhow::Result<Credentials> {
        self.cold_only()?;
        let input = pipe::Receiver::from_owned_fd(io.input)?;
        let result = pipe::Sender::from_owned_fd(io.result)?;
        if let Some(outbox) = &self.outbox {
            outbox.resume();
        }
        let with_source = self.config.restore_source_disk.is_some();
        let source_device = with_source.then_some(if self.config.config_disk.is_some() {
            VmRestoreSourceDevice::Vdd
        } else {
            VmRestoreSourceDevice::Vdc
        });
        let (channel, anchor) = match self.restore_boot(source_device, fscrypt_key, timeout).await {
            Ok(channels) => channels,
            Err(error) => {
                self.kill().await;
                return Err(error);
            }
        };
        let (reader, writer) = channel.into_split();
        let mut draining = Draining(tokio::spawn(drain(reader, result)));
        let exit = self.exit_watch();
        let restoring = self.restore_stream(input, writer, io.credentials, anchor, timeout);
        let restored = until_exit(restoring, exit).await;
        if restored.is_err() {
            let _ = self.stop(STOP_GRACE).await;
        }
        let _ = (&mut draining.0).await;
        restored
    }

    /// The restore's boot, up to its engine: the restore channel, and the
    /// custody anchor's exchange, its header sent.
    async fn restore_boot(
        &mut self,
        source_device: Option<VmRestoreSourceDevice>,
        fscrypt_key: &VmFscryptKey,
        timeout: Duration,
    ) -> anyhow::Result<(UnixStream, UnixStream)> {
        self.boot_vmm(source_device.is_some()).await?;
        self.source_attached = source_device.is_some();
        let channel = self
            .answer_hello(&VmRestoreBoot::Restore { source_device }, timeout)
            .await?;
        self.provision(fscrypt_key, timeout).await?;
        let anchor = self.send_anchor_header(timeout).await?;
        Ok((channel, anchor))
    }

    async fn restore_stream(
        &mut self,
        input: pipe::Receiver,
        writer: OwnedWriteHalf,
        credentials: OwnedFd,
        anchor: UnixStream,
        timeout: Duration,
    ) -> anyhow::Result<Credentials> {
        feed(input, writer).await?;
        let credentials = read_credential_frame(credentials).await?;
        let mut stream = self.send_credentials(&credentials, timeout).await?;
        // R, then C, then the anchor's credential, as on a node.
        self.deliver_anchor(anchor, timeout).await?;
        // No deadline: the restore runs until it is kept or fails, and a
        // guest that ends closes the connection.
        anyhow::ensure!(
            stream.read_u8().await? == READY_BYTE,
            "vault VM sent a wrong ready byte"
        );
        self.accept_join(timeout).await?;
        Ok(credentials)
    }

    /// Reads the restore commit marker on the vault's disk for `identity`,
    /// for a restore whose result was lost while no guest serves it (FIX
    /// 6584): a cold boot of the same disk, never a snapshot, provisioned
    /// with `fscrypt_key` and running nothing, whose one reply is checked to
    /// answer for this vault, its binding and `identity`. A reply that does
    /// not parse, or answers for another, is observed unreadable. The VM is
    /// stopped before this returns. The supervisor runs it only once every
    /// other generation of the vault is confirmed dead; a matching marker
    /// says kept and not serving, and nothing here opens the vault.
    pub async fn inspect_restore_marker(
        &mut self,
        identity: &ManagedRestoreIdentity,
        fscrypt_key: &VmFscryptKey,
        timeout: Duration,
    ) -> anyhow::Result<VmRestoreMarkerObservation> {
        self.cold_only()?;
        let observed = self.inspect(identity, fscrypt_key, timeout).await;
        let _ = self.stop(STOP_GRACE).await;
        observed
    }

    async fn inspect(
        &mut self,
        identity: &ManagedRestoreIdentity,
        fscrypt_key: &VmFscryptKey,
        timeout: Duration,
    ) -> anyhow::Result<VmRestoreMarkerObservation> {
        self.boot_vmm(false).await?;
        let boot = VmRestoreBoot::InspectMarker {
            identity: identity.clone(),
        };
        let mut channel = self.answer_hello(&boot, timeout).await?;
        self.provision(fscrypt_key, timeout).await?;
        let reply = tokio::time::timeout(timeout, read_control(&mut channel)).await??;
        let Ok(reply) = decode_vm_restore_control::<VmRestoreMarkerReply>(&reply) else {
            return Ok(VmRestoreMarkerObservation::Unreadable {
                reason: VmRestoreMarkerUnreadable::FrameInvalid,
            });
        };
        let answers = reply.revision == VM_RESTORE_WIRE_REVISION
            && reply.vault == self.vault
            && reply.binding == self.config.provision
            && reply.identity == *identity;
        Ok(if answers {
            reply.observation
        } else {
            VmRestoreMarkerObservation::Unreadable {
                reason: VmRestoreMarkerUnreadable::BindingMismatch,
            }
        })
    }
}

/// `booting`, a restore or a cold boot past its VMM's start, ended early by
/// the VMM's exit when `exit` watches it: the exit drops the boot, and with
/// it a supervisor pipe's read (FIX 9501). With no watch, or one that fails,
/// the boot runs on as it does with none.
pub(super) async fn until_exit<T>(
    booting: impl Future<Output = anyhow::Result<T>>,
    exit: Option<VmExitWatch>,
) -> anyhow::Result<T> {
    let mut booting = std::pin::pin!(booting);
    if let Some(exit) = exit {
        tokio::select! {
            biased;
            booted = &mut booting => return booted,
            exited = exit.wait() => match exited {
                Ok(status) => {
                    anyhow::bail!("the vault VM's VMM exited before its boot ended ({status})")
                }
                Err(error) => tracing::warn!(
                    reason = "vm_exit_unread",
                    %error,
                    "the vault VM's exit watch failed; its boot runs on without it"
                ),
            },
        }
    }
    booting.await
}

/// One control record's body.
async fn read_control(stream: &mut (impl AsyncRead + Unpin)) -> anyhow::Result<Vec<u8>> {
    let mut prefix = [0u8; 4];
    stream.read_exact(&mut prefix).await?;
    let mut body = vec![0u8; vm_restore_control_len(prefix)?];
    stream.read_exact(&mut body).await?;
    Ok(body)
}

/// Streams R to the guest as it reads, its exact bytes in chunks, then the
/// input's end and a half-close. A read that fails sends no end: the
/// channel's half-close without it is the input lost, and the guest ends
/// its engine before that engine reads an EOF.
async fn feed(mut input: pipe::Receiver, mut channel: OwnedWriteHalf) -> anyhow::Result<()> {
    let mut chunk = vec![0u8; VM_RESTORE_CHUNK_BYTES];
    loop {
        let read = input.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        channel
            .write_all(&VmRestoreRecord::InputChunk.header(read)?)
            .await?;
        channel.write_all(&chunk[..read]).await?;
    }
    channel
        .write_all(&VmRestoreRecord::InputEnd.header(0)?)
        .await?;
    Ok(channel.shutdown().await?)
}

/// The W drainer's task, aborted when this drops: a restore dropped before
/// its end, by a SIGTERM say, leaves nothing writing W. A restore that ends
/// awaits it first.
struct Draining(tokio::task::JoinHandle<()>);

impl Drop for Draining {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Writes the guest's result records into W until the result's end, or
/// until the channel ends or breaks, then closes W: its EOF. A W that takes
/// no more is let go and the records are read on and dropped, so the
/// guest's pump never stalls; the restore goes on, and `restore_status`
/// answers for it once the vault serves.
async fn drain(mut channel: OwnedReadHalf, result: pipe::Sender) {
    let mut result = Some(result);
    let mut chunk = vec![0u8; VM_RESTORE_CHUNK_BYTES];
    loop {
        let mut header = [0u8; VM_RESTORE_RECORD_HEADER_BYTES];
        if channel.read_exact(&mut header).await.is_err() {
            tracing::warn!(
                reason = "vm_restore_result_lost",
                "the vault VM's restore channel ended before the result's end"
            );
            return;
        }
        let len = match VmRestoreRecord::parse(header) {
            Ok((VmRestoreRecord::ResultEnd, _)) => return,
            Ok((VmRestoreRecord::ResultChunk, len)) => len,
            _ => {
                tracing::warn!(
                    reason = "vm_restore_result_lost",
                    "the vault VM sent a record that is not a result's"
                );
                return;
            }
        };
        if channel.read_exact(&mut chunk[..len]).await.is_err() {
            return;
        }
        if let Some(pipe) = result.as_mut()
            && pipe.write_all(&chunk[..len]).await.is_err()
        {
            tracing::warn!(
                reason = "restore_result_pipe_lost",
                "the restore result pipe took no more frames; restore_status answers for the attempt once the vault serves"
            );
            result = None;
        }
    }
}
