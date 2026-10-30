//! Process-owner writer lease, shared by the server and embedded SDK.

use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::{Error, Result, VaultConfig};

#[cfg(unix)]
use super::root_directory::{file_identity, named_directory_identity, open_root_directory};
use super::{DefaultPolicySeedMode, STORAGE_ABI_VERSION, Store};

#[cfg(test)]
mod tests;

/// Lock-file name for the process-owner single-writer lease (ONE-1441 WIRE-P1).
///
/// Deliberately its own file, NOT a reuse of the off-record sweep lock: that
/// one is dedicated to off-record recovery and pairs a different lifetime with
/// a different owner. Two unrelated exclusions sharing one inode would make
/// either feature's hold silently deny the other.
pub const VAULT_WRITER_LOCK_FILE: &str = "oneiron.writer.lock";

/// The `Error::ConcurrentWrite` message that means "another process holds this
/// vault directory's writer lease" (ONE-1441 WIRE-P1).
///
/// Load-bearing as an EXACT string: the SDK's embedded constructor maps
/// `Error::ConcurrentWrite(message)` to the typed
/// `VAULT_LOCKED_SINGLE_WRITER` binding code ONLY when
/// `message == VAULT_WRITER_LEASE_HELD`. Every other `ConcurrentWrite` keeps
/// the existing `From<Error>` mapping to `INVALID_STATE`, and that impl is not
/// amended.
pub const VAULT_WRITER_LEASE_HELD: &str = "vault writer lease is held by another process";

/// An exclusive, process-scoped hold on one vault directory's write side
/// (ONE-1441 WIRE-P1 single-writer ownership).
///
/// The AUTHORITY is the live OS lock held on the open file description, never
/// the file's contents. The bytes are diagnostics only — the acquiring PID and
/// a newline — so a stale pidfile left by a crashed owner blocks nothing: the
/// kernel dropped its lock when the process died, and the next acquirer
/// truncates and rewrites the line.
///
/// The guard OWNS the open file. Releasing is `Drop` and nothing else: there
/// is deliberately no public unlock method, because an explicit release could
/// run while another in-process handle still believed it held the lease. A
/// shared native vault keeps one lease value alive (behind an `Arc`) for its
/// whole lifetime, so the single drop that releases it is the last one.
///
/// That drop releases the lease before it returns, even when a forked child
/// still holds an inherited copy of the lock descriptor. The OS lock lives on
/// the open file description, and every `fork` duplicates it: a sibling
/// thread's `Command` spawn between fork and exec, or a forked worker still
/// running, would otherwise keep the vault leased after its owner let go, and
/// the owner's own next open would be refused. So the acquiring process
/// unlocks explicitly before it closes the descriptor.
///
/// [`Self::pid`] records the acquiring process. A post-`fork` child inherits
/// the descriptor — and therefore the kernel's lock — without ever having
/// acquired it, so the SDK dispatcher compares [`Self::pid`] against the
/// current PID before every verb and fails closed when they differ. That check
/// is [`Self::held_by_current_process`]; the lease does not enforce it itself,
/// because the enforcement point is the dispatcher, not the handle.
pub struct VaultWriterLease {
    /// Held for the lease's whole lifetime: dropping the file closes the
    /// descriptor, and closing the descriptor is what releases the OS lock.
    ///
    /// Stored as an option so Drop can close the descriptor explicitly.
    file: Option<std::fs::File>,
    pid: u32,
    #[cfg(unix)]
    directory: std::fs::File,
}

impl Store {
    pub(crate) fn open_with_writer_lease(
        path: &Path,
        config: &VaultConfig,
        lease: &VaultWriterLease,
    ) -> Result<Self> {
        Self::open_with_lease(
            path,
            config,
            STORAGE_ABI_VERSION,
            DefaultPolicySeedMode::Required,
            Some(lease),
        )
    }
}

impl VaultWriterLease {
    /// Acquires the exclusive writer lease on `vault_dir`, or refuses.
    ///
    /// Non-blocking: a directory already owned by another process fails
    /// immediately with `Error::ConcurrentWrite(VAULT_WRITER_LEASE_HELD)`
    /// rather than parking. Contention is a fact about the deployment, not a
    /// transient the caller should wait out.
    ///
    /// Non-contention failures — a missing directory, a permission denial, a
    /// read-only filesystem — keep their ordinary typed `Error::Io` and never
    /// masquerade as lock contention, so an operator's diagnosis is not
    /// redirected at a process that does not exist.
    ///
    /// Unix uses `flock`. Other targets refuse rather than claim exclusion
    /// without an OS locking primitive.
    pub fn acquire(vault_dir: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            Self::acquire_held(open_root_directory(vault_dir)?, vault_dir)
        }
        #[cfg(not(unix))]
        {
            let _ = vault_dir;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "vault writer leases require a supported OS locking primitive",
            )
            .into())
        }
    }

    /// Refuses reuse when the pathname no longer names the leased directory.
    /// The live descriptor pins the inode, so delete/recreate cannot recycle it.
    pub fn validate_directory(&self, vault_dir: &Path) -> Result<()> {
        if !self.held_by_current_process() {
            return Err(Error::ConcurrentWrite(VAULT_WRITER_LEASE_HELD));
        }
        #[cfg(unix)]
        if named_directory_identity(vault_dir)?.as_ref()
            == Some(&file_identity(&self.directory.metadata()?))
        {
            return Ok(());
        }
        #[cfg(not(unix))]
        let _ = vault_dir;
        Err(Error::InvalidConfig(
            "vault directory identity changed while its writer lease was held".to_owned(),
        ))
    }

    /// Clone the leased root descriptor so store-local telemetry locks bind
    /// the same directory inode as the process-owned LMDB environment.
    #[cfg(unix)]
    pub(super) fn clone_directory(&self) -> Result<std::fs::File> {
        Ok(self.directory.try_clone()?)
    }

    /// The same descriptor-bound path used by the existing-only store door.
    #[cfg(target_os = "linux")]
    pub(super) fn environment_path(&self) -> PathBuf {
        use std::os::fd::AsRawFd;
        PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))
    }

    /// The process that acquired this lease.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// Whether the CALLING process is the one that acquired this lease.
    ///
    /// `false` in a post-`fork` child holding an inherited handle: the child
    /// never took the lock, so it must not write through it even though the
    /// inherited descriptor would let the kernel say yes.
    #[must_use]
    pub fn held_by_current_process(&self) -> bool {
        self.pid == std::process::id()
    }

    /// [`Self::acquire`] on `directory`, a vault root this process already
    /// holds open: the lock file is opened through that descriptor, never
    /// following a link, so nothing is created, locked or written in a
    /// directory moved in under `vault_dir`'s name. A link at the lock's name
    /// is refused with an I/O error that names it. Refuses unless `vault_dir`
    /// still names `directory`.
    #[cfg(unix)]
    pub(crate) fn acquire_held(directory: std::fs::File, vault_dir: &Path) -> Result<Self> {
        use rustix::fs::{AtFlags, FileType, Mode, OFlags, openat, statat};
        let pid = std::process::id();
        let file = std::fs::File::from(
            openat(
                &directory,
                VAULT_WRITER_LOCK_FILE,
                OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|errno| {
                let error = std::io::Error::from(errno);
                // A loop at this one-component name is a link, never followed,
                // or a mount walk too deep (review r6, Astra F1). Name the link
                // only when the entry is one, so its owner knows to remove it.
                let link = errno == rustix::io::Errno::LOOP
                    && statat(&directory, VAULT_WRITER_LOCK_FILE, AtFlags::SYMLINK_NOFOLLOW)
                        .is_ok_and(|named| {
                            FileType::from_raw_mode(named.st_mode) == FileType::Symlink
                        });
                if link {
                    let cause = format!(
                        "the vault's writer lock {VAULT_WRITER_LOCK_FILE} is a symbolic link; remove it"
                    );
                    return std::io::Error::new(error.kind(), cause);
                }
                error
            })?,
        );
        Self::lock_file(&file)?;
        // A lease from here: a refusal below unlocks before it closes, so a
        // child forked meanwhile never keeps the lock (review r4, Sol F1).
        let lease = Self {
            file: Some(file),
            pid,
            directory,
        };
        let writable = lease.bind_lock_file()?;
        lease.validate_directory(vault_dir)?;
        if let Some(file) = lease.file.as_ref().filter(|_| writable) {
            Self::write_pid_line(file, pid)?;
        }
        Ok(lease)
    }

    /// Refuses the file just locked unless the directory's lock name still
    /// holds that very file. A removal unlinks the lock last, under its own
    /// lease; a lock opened before that and granted after it is no one's,
    /// and another owner may already hold a fresh lock under the name
    /// (review r3, Sol F1). Answers whether the PID line may be written: a
    /// regular file with no other link is the directory's alone, and one
    /// linked elsewhere is locked but never written (Sol F2).
    #[cfg(unix)]
    fn bind_lock_file(&self) -> Result<bool> {
        use rustix::fs::{AtFlags, FileType, fstat, statat};
        let Some(file) = self.file.as_ref() else {
            return Ok(false);
        };
        let locked = fstat(file).map_err(std::io::Error::from)?;
        let named = match statat(
            &self.directory,
            VAULT_WRITER_LOCK_FILE,
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(named) => named,
            Err(rustix::io::Errno::NOENT) => {
                return Err(Error::ConcurrentWrite(VAULT_WRITER_LEASE_HELD));
            }
            Err(error) => return Err(std::io::Error::from(error).into()),
        };
        if (named.st_dev, named.st_ino) != (locked.st_dev, locked.st_ino) {
            return Err(Error::ConcurrentWrite(VAULT_WRITER_LEASE_HELD));
        }
        Ok(
            FileType::from_raw_mode(locked.st_mode) == FileType::RegularFile
                && locked.st_nlink == 1,
        )
    }

    /// Takes `file`'s exclusive lock without waiting.
    #[cfg(unix)]
    fn lock_file(file: &std::fs::File) -> Result<()> {
        use std::os::fd::AsRawFd;

        #[cfg(test)]
        if let Some(callback) = BEFORE_LOCK.with(|slot| slot.borrow_mut().take()) {
            callback();
        }

        // SAFETY: `file` is a live, open `std::fs::File` borrowed for the
        // whole call, so `as_raw_fd()` yields a valid descriptor. `flock`
        // reads only that descriptor and the flag word, and writes nothing
        // through a pointer.
        let granted = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if granted == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        // EWOULDBLOCK (EAGAIN on Linux and macOS) is the ONLY contention
        // answer. Everything else is a real I/O failure and keeps its typed
        // error, so a permission problem is never reported as a busy vault.
        if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Err(Error::ConcurrentWrite(VAULT_WRITER_LEASE_HELD));
        }
        Err(error.into())
    }

    /// Records the owning PID for humans reading the directory. Diagnostics
    /// only: nothing reads this back to decide who owns the lease.
    #[cfg(unix)]
    fn write_pid_line(mut file: &std::fs::File, pid: u32) -> Result<()> {
        use std::io::{Seek, SeekFrom, Write};

        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(format!("{pid}\n").as_bytes())?;
        file.flush()?;
        Ok(())
    }
}

#[cfg(test)]
thread_local! {
    static BEFORE_LOCK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

/// Runs `callback` once, on this thread, between the next acquirer's open of
/// a lock file and its lock.
#[cfg(test)]
pub(crate) fn arm_before_lock(callback: impl FnOnce() + 'static) {
    BEFORE_LOCK.with(|slot| *slot.borrow_mut() = Some(Box::new(callback)));
}

impl Drop for VaultWriterLease {
    fn drop(&mut self) {
        let Some(file) = self.file.take() else {
            return;
        };
        // Only the acquiring process unlocks. A post-fork child shares the
        // SAME open file description, so LOCK_UN through its duplicate would
        // release the parent's live hold; the child only closes, and closing
        // its duplicate cannot unlock the parent.
        //
        // The owner does unlock, BEFORE closing: closing alone releases the
        // lock only once every duplicate is closed, and a child forked while
        // the lease was held keeps one until it execs or exits.
        #[cfg(unix)]
        if self.held_by_current_process() {
            use std::os::fd::AsRawFd;

            // SAFETY: `file` is a live, open `std::fs::File` owned by this
            // frame and closed only after this call, so `as_raw_fd()` yields a
            // valid descriptor. `flock` reads only that descriptor and the
            // flag word, and writes nothing through a pointer. A failed unlock
            // leaves the close below as the release, exactly as before.
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
        }
        drop(file);
    }
}

impl std::fmt::Debug for VaultWriterLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultWriterLease")
            .field("pid", &self.pid)
            .finish_non_exhaustive()
    }
}

/// Hook (FIX 5885; CALLS "rekeylease owned-open wait"): how long an owned
/// open ([`crate::Vault::open_owned`]) that meets a lease held for one owner
/// act ([`crate::Vault::hold_writer_lease_for_owner_act`]) waits for it,
/// trying again, before it refuses as it does today.
const OWNER_ACT_LEASE_WAIT: Duration = Duration::from_secs(5);
/// How often that wait tries the lease again; not a bound.
const OWNER_ACT_LEASE_POLL: Duration = Duration::from_millis(100);
/// The word after the PID on the lock file's diagnostics line while a lease
/// is held for one owner act.
const OWNER_ACT_MARK: &str = "owner-act";

impl VaultWriterLease {
    /// [`Self::acquire`] for an owned open. A lease held for one owner act
    /// is waited out, trying again every `OWNER_ACT_LEASE_POLL` for up to
    /// `OWNER_ACT_LEASE_WAIT`, so a host that starts while the owner's act
    /// holds the lease for a moment does not fail (FIX 5885). Any other
    /// holder refuses as before after one look again, since the act's mark
    /// follows its lock by a moment; past the bound the refusal is today's.
    pub(crate) fn acquire_after_owner_act(vault_dir: &Path) -> Result<Self> {
        Self::wait_out_owner_act(vault_dir, || Self::acquire(vault_dir))
    }

    /// [`Self::acquire_held`] for a held owned open, waiting out a lease
    /// held for one owner act as [`Self::acquire_after_owner_act`] does (FIX
    /// 5897). `directory` stays the caller's root: each try locks through a
    /// clone of it, never a path opened again, and a failed clone is an
    /// error, not a held lease.
    #[cfg(unix)]
    pub(crate) fn acquire_held_after_owner_act(
        directory: std::fs::File,
        vault_dir: &Path,
    ) -> Result<Self> {
        Self::wait_out_owner_act(vault_dir, || {
            Self::acquire_held(directory.try_clone()?, vault_dir)
        })
    }

    /// Runs `acquire` until it takes the lease, waiting out a lease held for
    /// one owner act up to `OWNER_ACT_LEASE_WAIT`, as the two doors above
    /// share it. The owner act's mark only chooses to wait: `acquire` alone
    /// takes the lock.
    fn wait_out_owner_act(
        vault_dir: &Path,
        mut acquire: impl FnMut() -> Result<Self>,
    ) -> Result<Self> {
        let deadline = Instant::now() + OWNER_ACT_LEASE_WAIT;
        let mut looked_again = false;
        loop {
            match acquire() {
                Err(Error::ConcurrentWrite(VAULT_WRITER_LEASE_HELD))
                    if Instant::now() < deadline =>
                {
                    if !held_for_owner_act(vault_dir) {
                        if looked_again {
                            return Err(Error::ConcurrentWrite(VAULT_WRITER_LEASE_HELD));
                        }
                        looked_again = true;
                    }
                    std::thread::sleep(OWNER_ACT_LEASE_POLL);
                }
                outcome => return outcome,
            }
        }
    }

    /// Rewrites the diagnostics line as `<pid> owner-act`, so an owned open
    /// that meets this lease waits for it. A lock file linked elsewhere is
    /// locked but never written, as at acquire.
    #[cfg(unix)]
    fn mark_owner_act(&self) -> Result<()> {
        use std::io::{Seek, SeekFrom, Write};

        let Some(mut file) = self.file.as_ref() else {
            return Ok(());
        };
        if !self.bind_lock_file()? {
            return Ok(());
        }
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(format!("{} {OWNER_ACT_MARK}\n", self.pid).as_bytes())?;
        file.flush()?;
        Ok(())
    }
}

/// Whether the lease on `vault_dir` is marked as held for one owner act. It
/// reads at most a line, never follows a link and never waits on a pipe;
/// anything it cannot read says no. The mark decides only whether to wait,
/// never who holds the lease: that is the lock's alone.
#[cfg(unix)]
fn held_for_owner_act(vault_dir: &Path) -> bool {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    let Ok(file) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(vault_dir.join(VAULT_WRITER_LOCK_FILE))
    else {
        return false;
    };
    if !file.metadata().is_ok_and(|meta| meta.is_file()) {
        return false;
    }
    let mut line = String::new();
    file.take(64).read_to_string(&mut line).is_ok() && line.trim_end().ends_with(OWNER_ACT_MARK)
}

#[cfg(not(unix))]
fn held_for_owner_act(_vault_dir: &Path) -> bool {
    false
}

impl crate::Vault {
    /// This process's writer lease on the very directory this handle opened,
    /// for one owner act by a host that opened without it (FIX 5885: the
    /// desktop re-key). Taken without waiting: another holder, this handle's
    /// own lease included, refuses `ConcurrentWrite(VAULT_WRITER_LEASE_HELD)`
    /// at once. It is marked on the lock file, so an owned open that meets it
    /// waits up to `OWNER_ACT_LEASE_WAIT` before it refuses as today.
    /// Dropping it releases the lease: hold it for the act alone.
    pub fn hold_writer_lease_for_owner_act(&self) -> Result<VaultWriterLease> {
        let lease = self.try_acquire_writer_lease()?;
        #[cfg(unix)]
        lease.mark_owner_act()?;
        Ok(lease)
    }

    /// This process's writer lease on the very directory this handle opened,
    /// for a host that opened without it, taken without waiting and without
    /// a mark: another holder, this handle's own lease included, refuses
    /// `ConcurrentWrite(VAULT_WRITER_LEASE_HELD)` at once. An owned open
    /// that meets it looks once again before it refuses as today. Dropping
    /// it releases the lease: a writer's nonce spend holds it for that spend
    /// alone (FIX 12023 W0).
    pub(crate) fn try_acquire_writer_lease(&self) -> Result<VaultWriterLease> {
        #[cfg(unix)]
        {
            let root = self
                .store
                .owner
                .env
                ._bound_root_dir
                .as_ref()
                .ok_or(Error::InvariantViolation("vault root descriptor missing"))?;
            VaultWriterLease::acquire_held(
                root.try_clone()?,
                &self.store.owner._registered_path.path,
            )
        }
        #[cfg(not(unix))]
        {
            let _ = self;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "vault writer leases require a supported OS locking primitive",
            )
            .into())
        }
    }
}
