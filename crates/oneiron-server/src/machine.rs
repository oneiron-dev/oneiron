//! What this machine has: cores, memory, descriptors, free disk. The bounds
//! that are the machine's own (the descriptor floor, the disk floor, the
//! memory work may take, how many code runs fit) are sized from these, never
//! from fleet scale.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// Logical cores this process may run on.
pub(crate) fn cores() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
}

pub(crate) use oneiron::host_memory::{MachineMemory, MemoryLease, MemoryRefusal, memory_bytes};

// Descriptors this process may hold open at once, which the process's one
// descriptor floor is sized from (FIX 6299).
pub(crate) use oneiron::host_descriptors::open_file_limit;

/// The most descriptors serving raises its soft open-file limit to: hard
/// limits are often far higher (524,288 on many Linux hosts; unlimited, as
/// macOS reports it).
const OPEN_FILES_WANTED: u64 = 65_536;

/// Raises this process's soft open-file limit to its hard limit, at most to
/// [`OPEN_FILES_WANTED`], and answers the limit it then holds. A raise the
/// platform refuses keeps the limit there was, and says so.
pub(crate) fn raise_open_file_limit() -> Option<u64> {
    #[cfg(unix)]
    {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `getrlimit` writes the struct on the stack and nothing else.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) } == 0 {
            let wanted = limit.rlim_max.min(OPEN_FILES_WANTED);
            if limit.rlim_cur < wanted {
                let raised = libc::rlimit {
                    rlim_cur: wanted,
                    rlim_max: limit.rlim_max,
                };
                // SAFETY: `setrlimit` reads the struct on the stack and nothing else.
                let refused = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const raised) };
                if refused != 0 {
                    tracing::warn!(
                        kind = "open_file_limit",
                        held = limit.rlim_cur,
                        wanted,
                        "the open-file limit was not raised; transfers are bounded by the one held"
                    );
                }
            }
        }
    }
    open_file_limit()
}

/// Bytes an unprivileged writer may still use on the filesystem holding
/// `path`.
pub(crate) fn free_disk_bytes(path: &Path) -> std::io::Result<u64> {
    #[cfg(unix)]
    {
        let stat = rustix::fs::statvfs(path)?;
        Ok(stat.f_bavail.saturating_mul(stat.f_frsize))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(u64::MAX)
    }
}

/// The disk the vault lives on, the free space it keeps, and the room work in
/// flight has claimed on it. Free space alone is not the floor: two uploads
/// that each see room for one stored copy would both take it, so each claims
/// the bytes it has still to write, and every check counts the others' claims.
/// The owner's backups and rehearsals claim theirs on it too (FIX 5479).
#[derive(Clone, Debug)]
pub(crate) struct DiskFloor {
    dir: PathBuf,
    reserve: u64,
    claimed: Arc<Mutex<u64>>,
    /// The free space a test has the disk show; `None` reads the disk.
    #[cfg(test)]
    shown_free: Arc<Mutex<Option<u64>>>,
}

/// Room one piece of work holds on the disk: bytes it has still to write.
/// Dropping it gives the room back.
pub(crate) struct DiskClaim {
    claimed: Arc<Mutex<u64>>,
    /// Changed only under the floor's lock.
    bytes: AtomicU64,
}

impl DiskFloor {
    pub(crate) fn new(dir: PathBuf, reserve: u64) -> Self {
        Self {
            dir,
            reserve,
            claimed: Arc::default(),
            #[cfg(test)]
            shown_free: Arc::default(),
        }
    }

    /// Has every clone of this floor see `bytes` free on its disk, whatever
    /// the disk holds.
    #[cfg(test)]
    pub(crate) fn show_free(&self, bytes: u64) {
        *lock(&self.shown_free) = Some(bytes);
    }

    /// Whether `bytes` more still leave the reserve free, past every claim.
    pub(crate) fn has_room_for(&self, bytes: u64) -> bool {
        let claimed = lock(&self.claimed);
        self.room(*claimed, bytes)
    }

    /// A claim on no room yet.
    pub(crate) fn claim(&self) -> Arc<DiskClaim> {
        Arc::new(DiskClaim {
            claimed: Arc::clone(&self.claimed),
            bytes: AtomicU64::new(0),
        })
    }

    /// Sets `claim` to `bytes` if they leave the reserve free past every
    /// other claim; a claim that does not fit stays as it was.
    pub(crate) fn hold(&self, claim: &DiskClaim, bytes: u64) -> bool {
        debug_assert!(Arc::ptr_eq(&self.claimed, &claim.claimed));
        let mut claimed = lock(&self.claimed);
        let others = claimed.saturating_sub(claim.bytes.load(Ordering::Relaxed));
        if !self.room(others, bytes) {
            return false;
        }
        *claimed = others.saturating_add(bytes);
        claim.bytes.store(bytes, Ordering::Relaxed);
        true
    }

    /// Whether `path` lies on the disk this floor measures: one filesystem.
    /// A side that cannot be read is taken as another disk, so work landing
    /// there is floored there as well.
    pub(crate) fn measures(&self, path: &Path) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            match (std::fs::metadata(&self.dir), std::fs::metadata(path)) {
                (Ok(ours), Ok(theirs)) => ours.dev() == theirs.dev(),
                _ => false,
            }
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            true
        }
    }

    /// A floor of this one's reserve on the disk `dir` lies on, with no claim
    /// yet: what work that lands there, off this floor's disk, claims on
    /// (FIX 5612). Uploads never claim on it.
    pub(crate) fn on_disk_of(&self, dir: PathBuf) -> Self {
        Self {
            dir,
            reserve: self.reserve,
            claimed: Arc::default(),
            #[cfg(test)]
            shown_free: Arc::clone(&self.shown_free),
        }
    }

    /// A dedicated scratch filesystem's floor, sharing pending claims across
    /// servers that select the same actual filesystem. Each keeps its own
    /// configured reserve; existing vault floors are not replaced.
    pub(crate) fn on_shared_disk_of(&self, dir: PathBuf) -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            use std::sync::{OnceLock, Weak};

            type Claims = Mutex<u64>;
            static FLOORS: OnceLock<Mutex<std::collections::BTreeMap<u64, Weak<Claims>>>> =
                OnceLock::new();
            let device = std::fs::metadata(&dir)?.dev();
            let vault_device = std::fs::metadata(&self.dir)?.dev();
            if device == vault_device {
                return Err(std::io::Error::other(
                    "configured renderer scratch must be a separate filesystem from the vault",
                ));
            }
            let mut floors = lock(FLOORS.get_or_init(Mutex::default));
            floors.retain(|_, claims| claims.strong_count() > 0);
            let claimed = match floors.get(&device).and_then(Weak::upgrade) {
                Some(claimed) => claimed,
                None => {
                    let claimed = Arc::new(Mutex::new(0));
                    floors.insert(device, Arc::downgrade(&claimed));
                    claimed
                }
            };
            let mut floor = self.on_disk_of(dir);
            floor.claimed = claimed;
            Ok(floor)
        }
        #[cfg(not(unix))]
        {
            let _ = dir;
            Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
        }
    }

    /// A disk that cannot be read is taken as full: a floor that cannot be
    /// checked holds.
    fn room(&self, claimed: u64, bytes: u64) -> bool {
        self.free()
            .is_ok_and(|free| free >= self.reserve.saturating_add(claimed).saturating_add(bytes))
    }

    fn free(&self) -> std::io::Result<u64> {
        #[cfg(test)]
        if let Some(free) = *lock(&self.shown_free) {
            return Ok(free);
        }
        free_disk_bytes(&self.dir)
    }
}

/// What a git exchange holds past memory keeps the reserve uploads keep,
/// counting the room they have claimed.
impl oneiron::origin::smart_http::SpillFloor for DiskFloor {
    fn has_room_for(&self, bytes: u64) -> bool {
        DiskFloor::has_room_for(self, bytes)
    }

    /// `spool` in the directory this floor measures, made on first use, so
    /// the floor guards the disk a spool fills. `None` when it cannot be made.
    fn spool_dir(&self) -> Option<PathBuf> {
        let dir = self.dir.join("spool");
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(&dir).ok()?;
        Some(dir)
    }
}

/// A foreign guest's proposal spool keeps the reserve uploads keep, on the
/// same claims (FIX 7650): each append holds its bytes until they are on the
/// disk, so concurrent runs, uploads and backups count one another's pending
/// writes, and nothing written is counted twice.
impl oneiron::code_sandbox::ProposalSpoolFloor for DiskFloor {
    /// `spool` in the directory this floor measures, made on first use; an
    /// error making it is the caller's, never a fall back to another disk.
    fn spool_dir(&self) -> std::io::Result<PathBuf> {
        let dir = self.dir.join("spool");
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(&dir)?;
        Ok(dir)
    }

    fn claim(&self) -> Box<dyn oneiron::code_sandbox::ProposalSpoolClaim> {
        Box::new(SpoolClaim {
            floor: self.clone(),
            claim: DiskFloor::claim(self),
        })
    }
}

/// One proposal spool file's claim on the shared disk floor (FIX 7650).
struct SpoolClaim {
    floor: DiskFloor,
    claim: Arc<DiskClaim>,
}

impl oneiron::code_sandbox::ProposalSpoolClaim for SpoolClaim {
    fn admit(&self, bytes: u64) -> Result<(), oneiron::code_sandbox::SpoolFloorRefusal> {
        self.floor.admit(&self.claim, bytes)
    }

    fn landed(&self) {
        self.floor.landed(&self.claim);
    }

    fn full(&self, bytes: u64) -> oneiron::code_sandbox::SpoolAtFloor {
        self.floor.at_floor(&self.claim, bytes)
    }
}

impl DiskFloor {
    /// Sets `claim` to `bytes` as [`Self::hold`] does, naming why not
    /// (FIX 7650): the measured shortfall, or the error that kept the disk
    /// from being read.
    fn admit(
        &self,
        claim: &DiskClaim,
        bytes: u64,
    ) -> Result<(), oneiron::code_sandbox::SpoolFloorRefusal> {
        debug_assert!(Arc::ptr_eq(&self.claimed, &claim.claimed));
        let mut claimed = lock(&self.claimed);
        let others = claimed.saturating_sub(claim.bytes.load(Ordering::Relaxed));
        let available = self
            .free()
            .map_err(oneiron::code_sandbox::SpoolFloorRefusal::Unmeasured)?;
        let needed = self.reserve.saturating_add(others).saturating_add(bytes);
        if available < needed {
            return Err(oneiron::code_sandbox::SpoolFloorRefusal::AtFloor(
                oneiron::code_sandbox::SpoolAtFloor {
                    needed,
                    available,
                    reserve: self.reserve,
                },
            ));
        }
        *claimed = others.saturating_add(bytes);
        claim.bytes.store(bytes, Ordering::Relaxed);
        Ok(())
    }

    /// The transfer-accounting step (FIX 7650): `claim`'s held bytes are on
    /// the disk now, where its free space counts them, so the hold ends and
    /// no write is counted twice.
    fn landed(&self, claim: &DiskClaim) {
        debug_assert!(Arc::ptr_eq(&self.claimed, &claim.claimed));
        let mut claimed = lock(&self.claimed);
        *claimed = claimed.saturating_sub(claim.bytes.swap(0, Ordering::Relaxed));
    }

    /// What this floor measures now for `bytes` its disk refused room for
    /// (FIX 7650). A disk that cannot be read shows no room, as it said.
    fn at_floor(&self, claim: &DiskClaim, bytes: u64) -> oneiron::code_sandbox::SpoolAtFloor {
        let claimed = lock(&self.claimed);
        let others = claimed.saturating_sub(claim.bytes.load(Ordering::Relaxed));
        oneiron::code_sandbox::SpoolAtFloor {
            needed: self.reserve.saturating_add(others).saturating_add(bytes),
            available: self.free().unwrap_or(0),
            reserve: self.reserve,
        }
    }
}

impl DiskClaim {
    /// The bytes this claim holds now.
    pub(crate) fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }
}

impl Drop for DiskClaim {
    fn drop(&mut self) {
        let mut claimed = lock(&self.claimed);
        *claimed = claimed.saturating_sub(*self.bytes.get_mut());
    }
}

#[cfg(unix)]
mod organ;
#[cfg(unix)]
pub(crate) use organ::OrganFloor;

/// The claim count changes in one step under its lock, so a holder that
/// panicked left it whole.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
