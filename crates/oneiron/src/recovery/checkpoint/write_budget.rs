//! The room a backup's or a rehearsal's writes claim on a disk they share
//! with a serving host's uploads (FIX 5479).
//!
//! A host that keeps a free-space floor under its uploads lends it to the
//! work ([`RecoveryWriteBudget`]). Before it writes, the work claims the bytes
//! it has still to write, so no upload counts that room as free meanwhile,
//! and every upload's claim counts against it. A claim that would take the
//! disk below the floor stops the work with [`AtWriteFloor`]: capacity, never
//! a size cap or a refused path. The claim shrinks as bytes land; the host
//! gives it back on every outcome.
//!
//! What is claimed is what the work's own inputs say it writes, never a guess
//! at a compressed size:
//! - a backup's artifact, at the most its streams can seal to (the artifact's
//!   bound), claimed before its first byte and set to what is left at each
//!   frame;
//! - a rehearsal's copy, at the bytes of the bodies and rows its image
//!   carries, claimed before the copy is made or opened, the rest set before
//!   each body lands and before the rows do (the custody fork lands with
//!   them). What the copy derives after them, its reopen, its index rebuild
//!   and its epoch, is admitted at the floor before each step: it goes ahead
//!   only while the disk still holds the floor past every other claim.

use super::CheckpointImage;
use super::carried_bodies::SealedFile;
use crate::{Error, Result};

/// The free-space floor a host keeps under what it writes, lent to a backup
/// or a rehearsal for its own writes. Each call replaces the claim the work
/// held so far.
pub trait RecoveryWriteBudget: Send + Sync {
    /// Claims `bytes` still to write in place of the claim held so far;
    /// `false`, the claim staying as it was, when they would take the disk
    /// below its floor past every other claim.
    fn hold(&self, bytes: u64) -> bool;
}

/// Why a backup's or a rehearsal's write was refused: the disk is at the
/// floor its host keeps ([`RecoveryWriteBudget`]). It comes as an
/// [`std::io::ErrorKind::StorageFull`] error, so a caller names capacity as
/// the reason and tells the floor from a full disk.
#[derive(Debug)]
pub struct AtWriteFloor;

impl AtWriteFloor {
    /// Whether `error` is this refusal.
    #[must_use]
    pub fn is_in(error: &Error) -> bool {
        let Error::Io(io) = error else {
            return false;
        };
        matches!(io.get_ref(), Some(inner) if inner.is::<Self>())
    }
}

impl std::fmt::Display for AtWriteFloor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "the disk is at its free-space floor: the writes would take it below the reserve its \
             host keeps",
        )
    }
}

impl std::error::Error for AtWriteFloor {}

/// The budget of work no host lends a floor to: it claims nothing and never
/// refuses.
pub(super) struct Unfloored;

impl RecoveryWriteBudget for Unfloored {
    fn hold(&self, _: u64) -> bool {
        true
    }
}

/// Claims `bytes` still to write on `budget`, or refuses at its floor.
pub(super) fn hold(budget: &dyn RecoveryWriteBudget, bytes: u64) -> Result<()> {
    if budget.hold(bytes) {
        Ok(())
    } else {
        Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::StorageFull,
            AtWriteFloor,
        )))
    }
}

/// The bytes a carried body lands as: its own length, or its envelope's as it
/// rests when that is more.
pub(super) fn landing_len(len: u64, sealed: Option<&SealedFile>) -> u64 {
    sealed.map_or(len, |sealed| sealed.stored_len.max(len))
}

/// The room a restore's copy claims as it lands: the image's bodies and rows,
/// less what has landed.
pub(super) struct RestoreRoom<'b> {
    budget: &'b dyn RecoveryWriteBudget,
    /// The bodies' bytes still to land.
    bodies: u64,
    /// The rows' bytes still to land.
    rows: u64,
}

impl<'b> RestoreRoom<'b> {
    /// The room `image` takes as it lands, claimed on `budget`.
    pub(super) fn new(budget: &'b dyn RecoveryWriteBudget, image: &CheckpointImage) -> Self {
        let bodies = image
            .bodies
            .iter()
            .enumerate()
            .map(|(index, (_, len))| landing_len(*len, image.sealed_bodies.get(&(index as u64))))
            .fold(0_u64, u64::saturating_add);
        Self {
            budget,
            bodies,
            rows: rows_len(image),
        }
    }

    /// Claims the whole copy before anything of it is made or opened.
    pub(super) fn admit(&self) -> Result<()> {
        hold(self.budget, self.bodies.saturating_add(self.rows))
    }

    /// Claims what is left before a body of `len` bytes lands, that body
    /// with it.
    pub(super) fn landing_body(&mut self, len: u64) -> Result<()> {
        hold(self.budget, self.bodies.saturating_add(self.rows))?;
        self.bodies = self.bodies.saturating_sub(len);
        Ok(())
    }

    /// Claims the rows before they land, as `image` holds them now: the key
    /// rows a sealed copy's bodies added among them.
    pub(super) fn landing_rows(&mut self, image: &CheckpointImage) -> Result<()> {
        self.bodies = 0;
        self.rows = rows_len(image);
        hold(self.budget, self.rows)
    }

    /// Admits one write the copy derives once its rows landed: nothing more
    /// is claimed, and the floor must still hold.
    pub(super) fn admit_derived(&mut self) -> Result<()> {
        self.rows = 0;
        hold(self.budget, 0)
    }
}

/// The bytes of every row `image` carries, keys and values.
fn rows_len(image: &CheckpointImage) -> u64 {
    image
        .databases
        .values()
        .flatten()
        .map(|(key, value)| (key.len() as u64).saturating_add(value.len() as u64))
        .fold(0_u64, u64::saturating_add)
}
