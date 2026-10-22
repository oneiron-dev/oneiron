//! A vault VM's RAM snapshot (FIX 9497): where a sleep may write it, how the
//! sleep takes it and a start's restore consumes it, and the custody that
//! protects it.
//!
//! The guest's RAM holds its fscrypt key and decrypted vault pages, so it
//! reaches only protected backing, from its first byte
//! ([`VaultVm::snapshot_dir`]): the supervisor's snapshot custody when the
//! profile binds one ([`VmSnapshotCustody`]), or else a state directory that
//! is already protected, an fscrypt v2 directory whose key is present or a
//! RAM-backed filesystem. With neither, the sleep withholds the snapshot
//! and stops the vault, as an off-record sleep does, and says why.
//!
//! A bound custody is a socket the supervisor answers and a directory it
//! protects: the driver asks it to unlock the vault's directory before any
//! snapshot file is written or looked for, checks that the directory is an
//! fscrypt v2 directory whose key is present, and holds that unlock
//! ([`SnapshotLease`]) while a VMM generation may write or map the files.
//! Once that generation is reaped, and only then, it asks the custody to
//! evict the key and checks it is gone. A drop's reaper thread takes the
//! lease with the VMM and evicts after its own reap. The driver never holds
//! the key: the supervisor's custody keeps and installs it.
//!
//! The custody socket takes one JSON line per connection,
//! `{"op":"unlock"|"evict","vault":"<name>"}`, and answers one,
//! `{"ok":true,"error":null}` or `{"ok":false,"error":"<why>"}`.

use super::{API_TIMEOUT, STOP_GRACE, SleepOutcome, VaultVm};
use anyhow::Context as _;
use oneiron_vault_contract::vm::{VmGuestFrame, VmHostFrame};
use oneiron_vault_contract::{CtlRequest, CtlResponse, LedgerPulledRequest, TokenHex};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::{BufRead as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// The most a custody answer's line may hold.
const MAX_CUSTODY_LINE: u64 = 4096;
/// A tmpfs's and a ramfs's `statfs` magic: RAM-backed, never on a disk.
const TMPFS_MAGIC: u64 = 0x0102_1994;
const RAMFS_MAGIC: u64 = 0x8584_58f6;

/// The supervisor's snapshot custody for one vault VM (FIX 9497): the socket
/// it answers unlock and evict on, and the vault's protected snapshot
/// directory, an fscrypt v2 directory whose key the custody holds. The
/// snapshot, its RAM file and the anchor URL kept beside them live only in
/// `dir`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmSnapshotCustody {
    pub socket: PathBuf,
    pub dir: PathBuf,
}

/// A start found its bound snapshot custody would not unlock (FIX 9497): it
/// boots nothing, since a cold boot would run the vault's disk past a RAM
/// snapshot it cannot see, and the snapshot is kept as it is. The supervisor
/// starts it again once its custody answers.
#[derive(Debug, thiserror::Error)]
#[error(
    "the vault VM's snapshot custody did not unlock ({reason}); the start waits for it and the snapshot is kept"
)]
pub struct VmSnapshotCustodyUnavailable {
    pub reason: String,
}

/// An unlock of the bound custody this driver holds, from the unlock until
/// the VMM generation it backs is reaped (FIX 9497). Evicted explicitly then;
/// one dropped while still held is evicted on a thread of its own.
pub(super) struct SnapshotLease {
    custody: VmSnapshotCustody,
    vault: String,
    held: bool,
}

#[derive(Serialize)]
struct CustodyRequest<'a> {
    op: &'a str,
    vault: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CustodyReply {
    ok: bool,
    #[serde(deserialize_with = "Option::deserialize")]
    error: Option<String>,
}

impl SnapshotLease {
    /// Asks the custody to evict the key and checks it is gone. A failure is
    /// logged: nothing here can take the key back.
    pub(super) async fn evict(mut self) {
        self.held = false;
        let evicted = ask(&self.custody.socket, "evict", &self.vault)
            .await
            .and_then(|()| evicted(&self.custody.dir));
        if let Err(error) = evicted {
            warn_not_evicted(&self.vault, &error);
        }
    }

    /// [`Self::evict`] on a thread that may block: a drop's reaper, after its
    /// reap.
    pub(super) fn evict_blocking(mut self) {
        self.held = false;
        evict_blocking(&self.custody, &self.vault);
    }

    /// Lets go of the lease without an eviction: a VMM that may still map
    /// its files was not reaped, so the supervisor's custody evicts it.
    pub(super) fn leave_held(mut self) {
        self.held = false;
    }
}

impl Drop for SnapshotLease {
    fn drop(&mut self) {
        if !self.held {
            return;
        }
        let (custody, vault) = (self.custody.clone(), self.vault.clone());
        let spawned = std::thread::Builder::new()
            .name("vm-snapshot-evict".into())
            .spawn(move || evict_blocking(&custody, &vault));
        if let Err(error) = spawned {
            warn_not_evicted(&self.vault, &anyhow::Error::from(error));
        }
    }
}

fn evict_blocking(custody: &VmSnapshotCustody, vault: &str) {
    let evicted =
        ask_blocking(&custody.socket, "evict", vault).and_then(|()| evicted(&custody.dir));
    if let Err(error) = evicted {
        warn_not_evicted(vault, &error);
    }
}

fn warn_not_evicted(vault: &str, error: &anyhow::Error) {
    tracing::warn!(
        reason = "vm_snapshot_custody_not_evicted",
        vault,
        error = %format!("{error:#}"),
        "the vault VM's snapshot custody was not evicted; its supervisor's custody must evict it"
    );
}

/// One custody exchange over its socket, within [`API_TIMEOUT`] as the
/// driver's other calls to its host's own services are.
async fn ask(socket: &Path, op: &str, vault: &str) -> anyhow::Result<()> {
    let exchange = async {
        let mut line = serde_json::to_string(&CustodyRequest { op, vault })?;
        line.push('\n');
        let stream = UnixStream::connect(socket).await?;
        let (reader, mut writer) = stream.into_split();
        writer.write_all(line.as_bytes()).await?;
        let mut reply = String::new();
        BufReader::new(reader.take(MAX_CUSTODY_LINE))
            .read_line(&mut reply)
            .await?;
        answered(&reply)
    };
    tokio::time::timeout(API_TIMEOUT, exchange)
        .await
        .with_context(|| format!("the snapshot custody did not answer {op}"))?
}

fn ask_blocking(socket: &Path, op: &str, vault: &str) -> anyhow::Result<()> {
    let mut line = serde_json::to_string(&CustodyRequest { op, vault })?;
    line.push('\n');
    let mut stream = std::os::unix::net::UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(API_TIMEOUT))?;
    stream.set_write_timeout(Some(API_TIMEOUT))?;
    stream.write_all(line.as_bytes())?;
    let mut reply = String::new();
    std::io::BufReader::new(std::io::Read::take(stream, MAX_CUSTODY_LINE)).read_line(&mut reply)?;
    answered(&reply)
}

fn answered(reply: &str) -> anyhow::Result<()> {
    let reply: CustodyReply = serde_json::from_str(reply.trim_end_matches(['\r', '\n']))
        .context("the snapshot custody's answer does not read")?;
    anyhow::ensure!(
        reply.ok,
        "the snapshot custody refused: {}",
        reply.error.as_deref().unwrap_or("no reason given")
    );
    Ok(())
}

/// The directory `dir`, opened without following a last link.
fn open_dir(dir: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)
}

/// Whether `dir` is an fscrypt v2 directory whose key is present now.
fn fscrypt_unlocked(dir: &std::fs::File) -> std::io::Result<bool> {
    use crate::managed::vm_init::fscrypt;
    match fscrypt::v2_key(dir)? {
        Some(identifier) => fscrypt::key_present(dir, &identifier),
        None => Ok(false),
    }
}

/// Checks the custody's directory reads only through its key, and that the
/// key is present.
fn unlocked(dir: &Path) -> anyhow::Result<()> {
    let held = open_dir(dir).context("the snapshot custody's directory does not open")?;
    anyhow::ensure!(
        fscrypt_unlocked(&held)?,
        "the snapshot custody's directory is not an fscrypt v2 directory with its key present"
    );
    Ok(())
}

/// Checks the custody's key is gone once evicted.
fn evicted(dir: &Path) -> anyhow::Result<()> {
    let held = open_dir(dir).context("the snapshot custody's directory does not open")?;
    anyhow::ensure!(
        !fscrypt_unlocked(&held)?,
        "the snapshot custody's key is still present after its eviction"
    );
    Ok(())
}

/// Whether the state directory already keeps a snapshot from any disk in
/// the clear: RAM-backed, or an fscrypt v2 directory whose key is present.
fn state_dir_protected(dir: &Path) -> anyhow::Result<bool> {
    let held = open_dir(dir)?;
    let kind = rustix::fs::fstatfs(&held)?.f_type as u64;
    if kind == TMPFS_MAGIC || kind == RAMFS_MAGIC {
        return Ok(true);
    }
    Ok(fscrypt_unlocked(&held)?)
}

impl VaultVm {
    /// Where the published snapshot lives: the bound custody's directory, or
    /// else the state directory.
    pub(super) fn snapshot_home(&self) -> PathBuf {
        self.config.snapshot_custody.as_ref().map_or_else(
            || self.config.state_dir.clone(),
            |custody| custody.dir.clone(),
        )
    }

    /// Unlocks the bound custody for this vault, or keeps the unlock this
    /// driver holds, and checks its directory is protected now. The lease is
    /// held from here until the VMM generation it backs is reaped.
    pub(super) async fn unlock_custody(&mut self) -> anyhow::Result<()> {
        let Some(custody) = self.config.snapshot_custody.clone() else {
            return Ok(());
        };
        if self.snapshot_lease.is_none() {
            ask(&custody.socket, "unlock", &self.vault).await?;
            self.snapshot_lease = Some(SnapshotLease {
                custody: custody.clone(),
                vault: self.vault.clone(),
                held: true,
            });
        }
        unlocked(&custody.dir)
    }

    /// A start's unlock, before its snapshot is looked for: a locked
    /// custody's names do not read. One that does not unlock is
    /// [`VmSnapshotCustodyUnavailable`].
    pub(super) async fn unlock_for_start(&mut self) -> anyhow::Result<()> {
        self.unlock_custody().await.map_err(|error| {
            VmSnapshotCustodyUnavailable {
                reason: format!("{error:#}"),
            }
            .into()
        })
    }

    /// Evicts the custody this driver holds once no VMM generation it backs
    /// is left: after a reap, never before. A VMM not reaped keeps it, for
    /// the driver's drop to evict after its reaper's reap.
    pub(super) async fn evict_after_reap(&mut self) {
        if self.child.is_none()
            && let Some(lease) = self.snapshot_lease.take()
        {
            lease.evict().await;
        }
    }

    /// Where this sleep may write the guest's RAM, the one rule a later
    /// ruling changes (FIX 9497): the bound custody's directory once unlocked
    /// and checked, or with none bound, the state directory when it is
    /// already protected. `None` withholds the snapshot, and says why.
    async fn snapshot_dir(&mut self) -> Option<PathBuf> {
        if self.config.snapshot_custody.is_some() {
            return match self.unlock_custody().await {
                Ok(()) => Some(self.snapshot_home()),
                Err(error) => {
                    tracing::warn!(
                        reason = "vm_snapshot_custody_unavailable",
                        vault = %self.vault,
                        error = %format!("{error:#}"),
                        "snapshot withheld: the bound snapshot custody did not unlock; the vault stops instead"
                    );
                    None
                }
            };
        }
        match state_dir_protected(&self.config.state_dir) {
            Ok(true) => Some(self.config.state_dir.clone()),
            Ok(false) => {
                tracing::warn!(
                    reason = "vm_snapshot_unprotected",
                    vault = %self.vault,
                    "snapshot withheld: the state dir is unprotected, and bound snapshot custody would allow it"
                );
                None
            }
            Err(error) => {
                tracing::warn!(
                    reason = "vm_snapshot_unprotected",
                    vault = %self.vault,
                    error = %format!("{error:#}"),
                    "snapshot withheld: the state dir's protection did not read, and bound snapshot custody would allow it"
                );
                None
            }
        }
    }

    /// Freezes the vault, takes its whole wake ledger report and commits it
    /// before telling the vault it was taken (FIX 9549), asks the guest to
    /// go idle, and snapshots or stops it. The next wake is the host's own:
    /// each window at its kept second (FIX 9498). `token` is the vault's
    /// spawn token, which its ledger pulls carry.
    pub async fn sleep(
        &mut self,
        token: &TokenHex,
        timeout: Duration,
    ) -> anyhow::Result<SleepOutcome> {
        let CtlResponse::PrepareReap { quiescent, ledger } =
            self.ctl(&CtlRequest::PrepareReap).await?
        else {
            anyhow::bail!("prepare_reap answered with another verb");
        };
        let report = self.pull_ledger(token, ledger).await?;
        let request = LedgerPulledRequest {
            vault: self.vault.clone(),
            token: token.clone(),
            rev: report.head.rev,
            report_digest: report.head.report_digest.clone(),
        };
        self.schedule.replace(report)?;
        let pulled = self.ctl(&CtlRequest::LedgerPulled { request }).await?;
        anyhow::ensure!(
            matches!(pulled, CtlResponse::Ok { ok: true }),
            "ledger_pulled was not acknowledged"
        );
        if !quiescent {
            self.ctl(&CtlRequest::ReapAbort).await?;
            return Ok(SleepOutcome::Busy);
        }
        self.send(&VmHostFrame::Sleep).await?;
        let snapshot_ok = loop {
            if let VmGuestFrame::Idle { snapshot_ok, .. } = self.read_guest(timeout).await? {
                break snapshot_ok;
            }
        };
        let next_wake = self.schedule.next_wake();
        let dir = if snapshot_ok && !self.source_attached {
            self.snapshot_dir().await
        } else {
            None
        };
        let Some(dir) = dir else {
            self.stop(STOP_GRACE).await?;
            return Ok(SleepOutcome::Stopped { next_wake });
        };
        // No carrier commit is in flight on this end when RAM is taken.
        if let Some(outbox) = &self.outbox {
            outbox.park();
        }
        self.pause().await?;
        let written = self.write_snapshot(&dir).await;
        if written.is_err() {
            // Nothing half-written stays: an unpublished file never resumes.
            for name in ["vm.snap.tmp", "vm.mem.tmp", "vm.anchor.tmp"] {
                let _ = std::fs::remove_file(dir.join(name));
            }
        }
        written?;
        // Reaped, then the custody evicted.
        self.kill().await;
        Ok(SleepOutcome::Snapshotted { next_wake })
    }

    /// The paused guest's RAM and state into `dir`, synced, then published
    /// by rename.
    async fn write_snapshot(&self, dir: &Path) -> anyhow::Result<()> {
        let (snap_tmp, mem_tmp) = (dir.join("vm.snap.tmp"), dir.join("vm.mem.tmp"));
        self.api(
            "PUT",
            "/snapshot/create",
            json!({
                "snapshot_type": "Full", "snapshot_path": snap_tmp, "mem_file_path": mem_tmp,
            }),
        )
        .await?;
        for file in [&mem_tmp, &snap_tmp] {
            std::fs::File::open(file)?.sync_all()?;
        }
        // Beside the RAM, the anchor URL its guest was handed (FIX 7183).
        self.keep_snapshot_anchor(dir)?;
        std::fs::rename(&mem_tmp, dir.join("vm.mem"))?;
        // The state file last, once the files beside it are durable: its
        // presence is what publishes the snapshot.
        std::fs::File::open(dir)?.sync_all()?;
        std::fs::rename(&snap_tmp, dir.join("vm.snap"))?;
        std::fs::File::open(dir)?.sync_all()?;
        Ok(())
    }

    pub(super) async fn restore(&mut self, timeout: Duration) -> anyhow::Result<()> {
        // Consumed before load: a crash from here on never resumes this RAM
        // a second time, it boots cold from the vault disk instead. A restore
        // that fails, or is dropped, after a rename unlinks the name it took
        // (FIX 7702). A bound custody stays unlocked while the RAM file backs
        // the guest, until this generation is reaped.
        let dir = self.snapshot_home();
        let snap = TakenSnapshotFile::take(dir.join("vm.snap"), dir.join("vm.snap.taken"))?;
        let mem = TakenSnapshotFile::take(dir.join("vm.mem"), dir.join("vm.mem.taken"))?;
        let anchor = self.take_snapshot_anchor(&dir)?;
        self.spawn_vmm().await?;
        let loaded = self
            .api(
                "PUT",
                "/snapshot/load",
                json!({
                    "snapshot_path": snap.taken,
                    "mem_backend": { "backend_type": "File", "backend_path": mem.taken },
                    "resume_vm": true,
                }),
            )
            .await;
        snap.remove();
        loaded?;
        // The guest's anchor is the one its cold boot was handed, kept with
        // its snapshot whatever was attached since (FIX 7183).
        self.resume_anchor_proxy(anchor);
        self.accept_join(timeout).await?;
        self.send(&VmHostFrame::Resumed).await?;
        // The memory file backs guest RAM until the VMM exits; unlinking it
        // keeps the pages and leaves nothing to resume twice.
        mem.remove();
        // Thaw the reap freeze taken before the snapshot.
        self.ctl(&CtlRequest::ReapAbort).await?;
        Ok(())
    }
}

/// A published snapshot file its restore consumed: renamed to its `.taken`
/// name, which only this restore holds. Dropped while armed, as a restore
/// that failed returns or is dropped, it unlinks that name, so no RAM-sized
/// file is left behind (FIX 7702). It never names the published file, which
/// the rename gave up.
struct TakenSnapshotFile {
    taken: PathBuf,
    /// Still to unlink when dropped: false once [`Self::remove`] did.
    armed: bool,
}

impl TakenSnapshotFile {
    /// Renames `source` to `taken`; the guard exists only once that rename
    /// did.
    fn take(source: PathBuf, taken: PathBuf) -> std::io::Result<Self> {
        std::fs::rename(source, &taken)?;
        Ok(Self { taken, armed: true })
    }

    /// Unlinks the taken name now, where the restore is done with it, and
    /// disarms the guard.
    fn remove(mut self) {
        self.armed = false;
        let _ = std::fs::remove_file(&self.taken);
    }
}

impl Drop for TakenSnapshotFile {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.taken);
        }
    }
}
