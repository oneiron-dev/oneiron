//! The floor uploads keep, lent to this vault's backups and rehearsals (FIX
//! 5479).
//!
//! A serving host lends its ingress `DiskFloor` (`Transfers::disk`, kept at
//! `limits.disk_reserve_bytes`, with no default of its own here) to its
//! `OwnerHost`. A backup's artifact, scheduled or asked for, and a
//! rehearsal's copy claim their room on that very floor before they write,
//! as an upload claims its own, and each counts the other's claims. A claim
//! is held while its work writes and given back on every outcome. A backup
//! that meets the floor is not taken and says capacity: the schedule logs it
//! and takes it at a later tick, and an owner's request is answered with it.
//! It is never skipped, capped by size or refused for its path. A stopped
//! vault's command lends no floor: no upload shares its disk in that process.
//!
//! A disk that refuses a write for want of room (ENOSPC, the typed
//! `StorageFull` I/O error, under an engine error or a host one) says the
//! same capacity, in words of its own (FIX 5615): logged with its reason, the
//! schedule's backup taken at a later tick, an owner's request answered with
//! `disk_capacity`. It is told by type, never by a message.
//!
//! A rehearsal's copy claims on the disk it lands on (FIX 5612). Its scratch
//! is made under the vault's own directory unless the host names another, so
//! by default the floor measures the disk the copy fills. A scratch directory
//! on another disk claims there too, at the same reserve, beside the claim on
//! the vault's floor. A backup's artifact claims the same way on the disk of
//! the `[backup] dir` it lands in (FIX 5675).

use std::path::Path;
use std::sync::Arc;

use oneiron::recovery::checkpoint::{AtWriteFloor, RecoveryWriteBudget, SideRestoreSource};

use super::{BackupPlan, Rehearsal};
use crate::machine::{DiskClaim, DiskFloor};
use crate::owner::OwnerError;
use crate::owner::schedule::OwnerHost;

/// The `INVALID_STATE` state of a backup or a rehearsal stopped at the
/// disk's floor, or by a full disk.
pub(crate) const CAPACITY_STATE: &str = "disk_capacity";

/// What a backup or a rehearsal stopped at a disk's floor says.
pub(crate) const CAPACITY_REFUSAL: &str = "a disk this operation writes to has no room for this \
     past the free-space reserve uploads keep (limits.disk_reserve_bytes): it stopped there, and \
     nothing it wrote was kept";

/// What a backup or a rehearsal a full disk stopped says (FIX 5615). A disk
/// can fill after a backup's file is in place, so it promises nothing about
/// what was kept.
pub(crate) const DISK_FULL_REFUSAL: &str = "the disk this writes to has no room left: it \
     stopped where the disk refused a write, and may not have finished";

/// What the owner can do about it.
pub(crate) const CAPACITY_REMEDY: &str = "Free room on the vault's disk, or on the disk the \
     backups or a rehearsal's copy are written to. A scheduled backup is taken at the schedule's \
     next tick with room; ask again for a backup or a rehearsal asked for here.";

/// Why a backup or a rehearsal had no room.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Capacity {
    /// The floor uploads keep refused its claim ([`AtWriteFloor`]).
    Floor,
    /// A disk refused a write for want of room (FIX 5615).
    DiskFull,
}

impl Capacity {
    /// The capacity an engine error names: the floor's refusal, or a full
    /// disk under its I/O or storage error.
    pub(crate) fn of(error: &oneiron::Error) -> Option<Self> {
        match error {
            oneiron::Error::Io(io) | oneiron::Error::Storage(heed::Error::Io(io)) => {
                Self::of_io(io)
            }
            _ => None,
        }
    }

    /// [`Self::of`] for a host error: the first cause in its chain, an
    /// engine error or an I/O one, that names capacity.
    pub(crate) fn of_host(error: &anyhow::Error) -> Option<Self> {
        error.chain().find_map(|cause| {
            if let Some(engine) = cause.downcast_ref::<oneiron::Error>() {
                return Self::of(engine);
            }
            match cause.downcast_ref::<heed::Error>() {
                Some(heed::Error::Io(io)) => Self::of_io(io),
                _ => cause.downcast_ref::<std::io::Error>().and_then(Self::of_io),
            }
        })
    }

    /// [`Self::of`] for an owner's error, engine or host.
    pub(crate) fn of_owner(error: &OwnerError) -> Option<Self> {
        match error {
            OwnerError::Engine(error) => Self::of(error),
            OwnerError::Host(error) => Self::of_host(error),
            _ => None,
        }
    }

    fn of_io(io: &std::io::Error) -> Option<Self> {
        if io.get_ref().is_some_and(|inner| inner.is::<AtWriteFloor>()) {
            return Some(Self::Floor);
        }
        (io.kind() == std::io::ErrorKind::StorageFull).then_some(Self::DiskFull)
    }

    /// What the owner is answered with.
    pub(crate) fn refusal(self) -> &'static str {
        match self {
            Self::Floor => CAPACITY_REFUSAL,
            Self::DiskFull => DISK_FULL_REFUSAL,
        }
    }

    /// Which capacity a log line names, beside `reason = "capacity"`.
    pub(crate) fn cause(self) -> &'static str {
        match self {
            Self::Floor => "floor",
            Self::DiskFull => "disk_full",
        }
    }
}

/// One backup's or rehearsal's claim on each floor its writes land under:
/// the bytes it has still to write. Dropped, on every outcome, it gives its
/// room back.
pub(crate) struct WriteClaim {
    held: Vec<(DiskFloor, Arc<DiskClaim>)>,
}

impl WriteClaim {
    /// A claim on each of `floors`, holding no room yet: every one must have
    /// the room. With no floors it claims nothing and refuses nothing.
    pub(crate) fn on_each(floors: &[DiskFloor]) -> Self {
        Self {
            held: floors
                .iter()
                .map(|floor| (floor.clone(), floor.claim()))
                .collect(),
        }
    }
}

impl RecoveryWriteBudget for WriteClaim {
    fn hold(&self, bytes: u64) -> bool {
        let before: Vec<u64> = self.held.iter().map(|(_, claim)| claim.bytes()).collect();
        for (at, (floor, claim)) in self.held.iter().enumerate() {
            if !floor.hold(claim, bytes) {
                // The floors already set go back to what they held, as far
                // as their room still allows; the claim stays at most that.
                for ((floor, claim), held) in self.held.iter().zip(&before).take(at) {
                    floor.hold(claim, *held);
                }
                return false;
            }
        }
        true
    }

    fn floored(&self) -> bool {
        !self.held.is_empty()
    }
}

impl OwnerHost {
    /// This host's backups and rehearsals claim their writes on `floor`, the
    /// one its uploads keep.
    pub(crate) fn claiming_on(mut self, floor: &DiskFloor) -> Self {
        self.backups.floor = Some(floor.clone());
        self
    }
}

/// [`super::rehearse_in`] for the owner host: the copy's writes claim their
/// room on the floor `plan` was lent, and on the disk under `temp` when that
/// is another one (FIX 5612).
pub(crate) fn rehearse_claiming(
    temp: &Path,
    backup: &Path,
    config: oneiron::VaultConfig,
    source: &SideRestoreSource<'_>,
    plan: &BackupPlan,
) -> anyhow::Result<Rehearsal> {
    let floors = landing_floors(plan.floor.as_ref(), temp);
    super::rehearse_in_with(temp, backup, config, None, source, None, &floors)
}

/// The floors a write landing in `dir`, a rehearsal's scratch or a backup's
/// directory, claims on: the vault's, as its host lent it, and, when `dir`
/// lies on another disk, that disk's at the same reserve. None without a lent
/// floor.
pub(super) fn landing_floors(floor: Option<&DiskFloor>, dir: &Path) -> Vec<DiskFloor> {
    let Some(floor) = floor else {
        return Vec::new();
    };
    if floor.measures(dir) {
        vec![floor.clone()]
    } else {
        vec![floor.clone(), floor.on_disk_of(dir.to_path_buf())]
    }
}

/// A rehearsal's failure as the owner's: a capacity stop, the floor's or a
/// full disk's, logged and kept as the engine's error where it is one, so
/// the answer names capacity; any other failure as it was.
pub(crate) fn rehearsal_error(error: anyhow::Error) -> OwnerError {
    let Some(capacity) = Capacity::of_host(&error) else {
        return OwnerError::Host(error);
    };
    tracing::warn!(
        reason = "capacity",
        cause = capacity.cause(),
        refusal = capacity.refusal(),
        "rehearsal stopped: no room on the disk it writes to"
    );
    match error.downcast::<oneiron::Error>() {
        Ok(engine) => OwnerError::from(engine),
        Err(error) => OwnerError::Host(error),
    }
}
