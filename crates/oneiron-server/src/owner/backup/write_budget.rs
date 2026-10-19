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

use std::path::Path;
use std::sync::Arc;

use oneiron::recovery::checkpoint::{AtWriteFloor, RecoveryWriteBudget, SideRestoreSource};

use super::{BackupPlan, Rehearsal};
use crate::machine::{DiskClaim, DiskFloor};
use crate::owner::OwnerError;
use crate::owner::schedule::OwnerHost;

/// The `INVALID_STATE` state of a backup or a rehearsal stopped at the
/// disk's floor.
pub(crate) const CAPACITY_STATE: &str = "disk_capacity";

/// What a backup or a rehearsal stopped at the disk's floor says.
pub(crate) const CAPACITY_REFUSAL: &str = "the vault's disk has no room for this past the \
     free-space reserve uploads keep (limits.disk_reserve_bytes): it stopped there, and nothing \
     it wrote was kept";

/// What the owner can do about it.
pub(crate) const CAPACITY_REMEDY: &str = "Free room on the vault's disk. A scheduled backup is \
     taken at the schedule's next tick with room; ask again for a backup or a rehearsal asked for \
     here.";

/// One backup's or rehearsal's claim on the floor: the bytes it has still to
/// write. Dropped, on every outcome, it gives its room back.
pub(crate) struct WriteClaim {
    held: Option<(DiskFloor, Arc<DiskClaim>)>,
}

impl WriteClaim {
    /// A claim on `floor`, holding no room yet. With no floor it claims
    /// nothing and refuses nothing.
    pub(crate) fn on(floor: Option<&DiskFloor>) -> Self {
        Self {
            held: floor.map(|floor| (floor.clone(), floor.claim())),
        }
    }
}

impl RecoveryWriteBudget for WriteClaim {
    fn hold(&self, bytes: u64) -> bool {
        self.held
            .as_ref()
            .is_none_or(|(floor, claim)| floor.hold(claim, bytes))
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
/// room on the floor `plan` was lent.
pub(crate) fn rehearse_claiming(
    temp: &Path,
    backup: &Path,
    config: oneiron::VaultConfig,
    source: &SideRestoreSource<'_>,
    plan: &BackupPlan,
) -> anyhow::Result<Rehearsal> {
    super::rehearse_in_with(
        temp,
        backup,
        config,
        None,
        source,
        None,
        plan.floor.as_ref(),
    )
}

/// Whether `error` is the floor's refusal ([`AtWriteFloor`]): capacity.
pub(crate) fn at_floor(error: &oneiron::Error) -> bool {
    AtWriteFloor::is_in(error)
}

/// [`at_floor`] for a backup's or a rehearsal's host error.
pub(crate) fn host_at_floor(error: &anyhow::Error) -> bool {
    error.downcast_ref::<oneiron::Error>().is_some_and(at_floor)
}

/// A rehearsal's failure as the owner's: the floor's refusal logged and kept
/// as the engine's error, so the answer names capacity; any other failure as
/// it was.
pub(crate) fn rehearsal_error(error: anyhow::Error) -> OwnerError {
    if !host_at_floor(&error) {
        return OwnerError::Host(error);
    }
    tracing::warn!(
        reason = "capacity",
        refusal = CAPACITY_REFUSAL,
        "rehearsal stopped: the vault's disk is at its floor"
    );
    match error.downcast::<oneiron::Error>() {
        Ok(engine) => OwnerError::from(engine),
        Err(error) => OwnerError::Host(error),
    }
}
