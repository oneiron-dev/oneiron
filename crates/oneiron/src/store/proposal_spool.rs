//! Where a proposal body is spooled, and the disk floor each of its appends
//! keeps (FIX 7650). The host lends its one measured floor, shared by every
//! run; the engine never makes a floor of its own per run or per guest.

use crate::error::CodeError;
use crate::{Error, Vault};
use std::{io, path::PathBuf, sync::Arc};

impl Vault {
    /// Lends the proposal spools of this vault's runs the host's measured
    /// disk floor (FIX 7650): the one its uploads keep, never one per run.
    /// The first lend holds.
    pub fn lend_proposal_spool(&self, spool: Arc<dyn ProposalSpoolFloor>) {
        let _ = self.proposal_spool.set(spool);
    }

    /// The floor this vault's host lent proposal spools, if it lent one.
    #[must_use]
    pub fn proposal_spool(&self) -> Option<Arc<dyn ProposalSpoolFloor>> {
        self.proposal_spool.get().cloned()
    }
}

/// A host's measured disk for proposal spools: the directory spool files are
/// made in, on the disk the floor measures, and the claims their appends are
/// admitted on. The server lends its shared disk floor, so each append is
/// counted against every other admitted write still pending on that disk.
pub trait ProposalSpoolFloor: Send + Sync {
    /// The directory, on the disk this floor measures, that spool files are
    /// made in.
    ///
    /// # Errors
    /// The directory cannot be made.
    fn spool_dir(&self) -> io::Result<PathBuf>;

    /// A claim on no room yet, held by one spool file until its last body
    /// drops.
    fn claim(&self) -> Box<dyn ProposalSpoolClaim>;
}

/// The room one spool file holds on its floor's disk: the bytes of its next
/// append, admitted before they are written and given back once they are on
/// the disk, where its free space counts them. Dropping it gives back what
/// it still holds.
pub trait ProposalSpoolClaim: Send + Sync {
    /// Holds `bytes` for the next append when the disk's free space keeps
    /// the floor's reserve after them, past every other claim's held bytes.
    ///
    /// # Errors
    /// [`SpoolFloorRefusal::AtFloor`] when it would not;
    /// [`SpoolFloorRefusal::Unmeasured`] when the free space cannot be read.
    fn admit(&self, bytes: u64) -> Result<(), SpoolFloorRefusal>;

    /// The bytes [`Self::admit`] held are on the disk now: their hold ends.
    fn landed(&self);

    /// What the floor measures now for `bytes` the disk refused room for:
    /// a real full disk is named as the floor's refusal is.
    fn full(&self, bytes: u64) -> SpoolAtFloor;
}

/// An append the floor did not admit: `needed` bytes free (the reserve,
/// every other claim's held bytes and the append) against the `available`
/// bytes the disk has, and the configured `reserve`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpoolAtFloor {
    pub needed: u64,
    pub available: u64,
    pub reserve: u64,
}

/// Why a proposal spool append was not admitted.
#[derive(Debug)]
pub enum SpoolFloorRefusal {
    /// The append would cross the floor.
    AtFloor(SpoolAtFloor),
    /// The disk's free space could not be read: its own I/O error, never a
    /// floor that was measured.
    Unmeasured(io::Error),
}

impl From<SpoolAtFloor> for Error {
    fn from(floor: SpoolAtFloor) -> Self {
        Self::Code(CodeError::SandboxProposalDiskFloor {
            needed: floor.needed,
            available: floor.available,
            reserve: floor.reserve,
        })
    }
}

impl From<SpoolFloorRefusal> for Error {
    fn from(refusal: SpoolFloorRefusal) -> Self {
        match refusal {
            SpoolFloorRefusal::AtFloor(floor) => floor.into(),
            SpoolFloorRefusal::Unmeasured(error) => error.into(),
        }
    }
}
