//! The host's half of a vault VM's provision connection (FIX 6308): on a
//! cold boot, before the credential connection, the vault's binding and its
//! fscrypt key go to the guest's root bootstrap
//! ([`oneiron_vault_contract::vm_provision`]).

use super::{VaultVm, VaultVmConfig};
use oneiron_vault_contract::vm::{MAX_VM_FRAME, decode_vm_frame, encode_vm_frame};
use oneiron_vault_contract::vm_provision::{
    VM_PROVISION_REVISION, VmFscryptKey, VmProvision, VmProvisionReply,
};
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::fs::FileExt;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

/// Where an ext4 filesystem's superblock starts on its disk.
const EXT4_SUPERBLOCK_OFFSET: u64 = 1024;
const EXT4_MAGIC: u16 = 0xef53;

impl VaultVm {
    /// The provision connection, the guest's first dial on a cold boot: the
    /// binding line, the key frame and a half-close, then the guest's one
    /// reply line. The boot goes on to the credential connection only on an
    /// echo of exactly what was sent; that echo is not readiness. Each wait
    /// is within the caller's boot `timeout`.
    pub(super) async fn provision(
        &mut self,
        key: &VmFscryptKey,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        let (mut stream, _) = tokio::time::timeout(timeout, self.boot.accept()).await??;
        let sent = VmProvision {
            revision: VM_PROVISION_REVISION,
            vault: self.vault.clone(),
            binding: self.config.provision.clone(),
        };
        stream.write_all(encode_vm_frame(&sent)?.as_bytes()).await?;
        stream.write_all(key.as_bytes()).await?;
        stream.shutdown().await?;
        let mut line = String::new();
        let mut reader = BufReader::new(stream).take(MAX_VM_FRAME as u64 + 1);
        anyhow::ensure!(
            tokio::time::timeout(timeout, reader.read_line(&mut line)).await?? > 0,
            "vault VM closed its provision connection unanswered"
        );
        match decode_vm_frame::<VmProvisionReply>(&line)? {
            VmProvisionReply::Provisioned {
                revision,
                vault,
                binding,
            } if revision == sent.revision && vault == sent.vault && binding == sent.binding => {
                Ok(())
            }
            VmProvisionReply::Provisioned { .. } => {
                anyhow::bail!("vault VM echoed another provisioning")
            }
            VmProvisionReply::Refused { code, detail, .. } => {
                anyhow::bail!("vault VM refused its provisioning ({code}): {detail}")
            }
        }
    }
}

/// Refuses a vault disk that is not the one the profile's provision binding
/// names, read on the host before its VMM starts (FIX 6632): a disk that is
/// not ext4, or whose filesystem UUID is another, never reaches the guest or
/// its key frame. A disk this host cannot read is said and left to the
/// guest's own check, which refuses it before the key goes in.
pub(super) fn check_vault_disk(config: &VaultVmConfig) -> anyhow::Result<()> {
    let mut superblock = [0u8; 1024];
    let read = std::fs::File::open(&config.vault_disk)
        .and_then(|disk| disk.read_exact_at(&mut superblock, EXT4_SUPERBLOCK_OFFSET));
    if let Err(error) = read {
        tracing::warn!(
            reason = "vm_vault_disk_unread",
            %error,
            "the vault disk does not read on the host; the guest checks it"
        );
        return Ok(());
    }
    anyhow::ensure!(
        u16::from_le_bytes([superblock[0x38], superblock[0x39]]) == EXT4_MAGIC,
        "the vault disk is not ext4 (disk_mismatch)"
    );
    let id = &superblock[0x68..0x78];
    let hex = oneiron_vault_contract::hex;
    let found = format!(
        "{}-{}-{}-{}-{}",
        hex(&id[..4]),
        hex(&id[4..6]),
        hex(&id[6..8]),
        hex(&id[8..10]),
        hex(&id[10..])
    );
    anyhow::ensure!(
        found == config.provision.vault_disk_uuid,
        "the vault disk's filesystem UUID is {found}, not the provision binding's (disk_mismatch)"
    );
    Ok(())
}

/// The standalone host's fscrypt key (`--fscrypt-key-fd`): exactly the
/// key's bytes, then the descriptor's end.
pub(super) fn read_fscrypt_key(fd: RawFd) -> anyhow::Result<VmFscryptKey> {
    // SAFETY: `fd` arrives on argv from the standalone supervisor and is this
    // process's to own; the `File` takes it over exactly once and closes it
    // on drop, which is also what lets the EOF check end once the
    // supervisor's write end is gone.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    VmFscryptKey::read_from(file)
}
