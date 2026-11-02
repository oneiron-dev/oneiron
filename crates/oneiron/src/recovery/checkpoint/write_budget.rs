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
//!   carries, each row at the length it lands at with its inline body or
//!   response back in it (`landing_lengths`, FIX 6025, 6232), claimed before
//!   the copy is made or opened, the rest set before each body lands and
//!   before the rows do (the custody fork lands with them);
//! - with them, from the same start, the bound on everything the copy writes
//!   past them (FIX 5613, `write_estimate`): its pages, the index rows it
//!   stages, its reopen, its rebuilt indexes and projections, the pages its
//!   later transactions copy, and its epoch. It stays claimed across the
//!   reopen and every step; before each one the claim is set to what is left
//!   of it, less what the copy's file has grown by past its rows, so pages
//!   already landed are not claimed twice. Past the bound a step goes ahead
//!   only while the disk still holds the floor past every other claim.

use std::path::Path;

use super::CheckpointImage;
use super::carried_bodies::SealedFile;
use super::landing_lengths::LandingRowLengths;
use super::write_estimate::RestoreWriteEstimate;
use crate::store::PageLayout;
use crate::{Error, Result, VaultConfig};

/// The free-space floor a host keeps under what it writes, lent to a backup
/// or a rehearsal for its own writes. Each call replaces the claim the work
/// held so far.
pub trait RecoveryWriteBudget: Send + Sync {
    /// Claims `bytes` still to write in place of the claim held so far;
    /// `false`, the claim staying as it was, when they would take the disk
    /// below its floor past every other claim.
    fn hold(&self, bytes: u64) -> bool;

    /// Whether this budget keeps a floor at all. Work under one that keeps
    /// none claims nothing ahead, so a restore does not work out its bound.
    fn floored(&self) -> bool {
        true
    }
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

    fn floored(&self) -> bool {
        false
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
/// less what has landed, and the bound on what it writes past them.
pub(super) struct RestoreRoom<'b> {
    budget: &'b dyn RecoveryWriteBudget,
    /// The bodies' bytes still to land.
    bodies: u64,
    /// The rows' bytes still to land.
    rows: u64,
    /// The bound on what the copy writes past its bodies and rows
    /// (`write_estimate`); none under a budget that keeps no floor.
    derived: u64,
    /// The rows' bytes once they landed: the copy's file holds them, and
    /// what it grows by past them is what the bound has spent.
    landed_rows: u64,
    /// The opened payload rows' bytes among the rows' (KS-7).
    payload: u64,
}

impl<'b> RestoreRoom<'b> {
    /// The room `image` takes as it lands under `config`, claimed on
    /// `budget`, each row at the length `lengths` says it lands at.
    pub(super) fn new(
        budget: &'b dyn RecoveryWriteBudget,
        image: &CheckpointImage,
        lengths: &LandingRowLengths,
        config: &VaultConfig,
    ) -> Self {
        let bodies = image
            .bodies
            .iter()
            .enumerate()
            .map(|(index, (_, len))| landing_len(*len, image.sealed_bodies.get(&(index as u64))))
            .fold(0_u64, u64::saturating_add);
        let derived = if budget.floored() {
            RestoreWriteEstimate::of(image, lengths, config, PageLayout::for_new_env()).total()
        } else {
            0
        };
        Self {
            budget,
            bodies,
            rows: rows_len(image, lengths),
            derived,
            landed_rows: 0,
            payload: 0,
        }
    }

    /// Adds, once, the opened payload rows a restore lands besides the
    /// image's (KS-7), each its key and value lengths: their bytes join the
    /// rows', and what they write past them the bound. None open while
    /// CHECKPOINT_PAYLOADS_ENABLED is off.
    pub(super) fn with_payload(mut self, rows: &[(u64, u64)]) -> Self {
        let bytes = rows.iter().map(|(key, value)| key.saturating_add(*value));
        self.payload = bytes.fold(0_u64, u64::saturating_add);
        self.rows = self.rows.saturating_add(self.payload);
        if self.budget.floored() {
            let past =
                RestoreWriteEstimate::default().with_payload(rows, PageLayout::for_new_env());
            self.derived = self.derived.saturating_add(past.total());
        }
        self
    }

    /// Claims the whole copy before anything of it is made or opened.
    pub(super) fn admit(&self) -> Result<()> {
        hold(
            self.budget,
            self.bodies
                .saturating_add(self.rows)
                .saturating_add(self.derived),
        )
    }

    /// Claims what is left before a body of `len` bytes lands, that body
    /// with it.
    pub(super) fn landing_body(&mut self, len: u64) -> Result<()> {
        hold(
            self.budget,
            self.bodies
                .saturating_add(self.rows)
                .saturating_add(self.derived),
        )?;
        self.bodies = self.bodies.saturating_sub(len);
        Ok(())
    }

    /// Claims the rows before they land, as `image` holds them now: the key
    /// rows a sealed copy's bodies added among them.
    pub(super) fn landing_rows(&mut self, image: &CheckpointImage) -> Result<()> {
        self.bodies = 0;
        let landed = LandingRowLengths::default();
        self.rows = rows_len(image, &landed).saturating_add(self.payload);
        hold(self.budget, self.rows.saturating_add(self.derived))
    }

    /// Claims, before one write the copy derives once its rows landed, what
    /// the bound has left: the bound less what the copy's file at
    /// `destination` has grown by past the rows. Past the bound nothing more
    /// is claimed, and the floor must still hold.
    pub(super) fn admit_derived(&mut self, destination: &Path) -> Result<()> {
        if self.rows > 0 {
            self.landed_rows = self.rows;
            self.rows = 0;
        }
        // A file that cannot be read has spent nothing: the bound stays.
        let file = std::fs::metadata(destination.join("data.mdb")).map_or(0, |file| file.len());
        let spent = file.saturating_sub(self.landed_rows);
        hold(self.budget, self.derived.saturating_sub(spent))
    }
}

/// The bytes of every row `image` carries, keys and values, each value at
/// the length `lengths` says it lands at.
fn rows_len(image: &CheckpointImage, lengths: &LandingRowLengths) -> u64 {
    image
        .databases
        .iter()
        .flat_map(|(name, rows)| rows.iter().map(move |row| (name, row)))
        .map(|(name, (key, value))| {
            (key.len() as u64).saturating_add(lengths.value_len(name, key, value))
        })
        .fold(0_u64, u64::saturating_add)
}
