//! Moved from `crates/oneiron/src/recovery/checkpoint/custody_head/issuer_transfer.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Serialize;

/// What an explicit head transfer kept in current local custody. These
/// counts do not assert that a keystore exists or that this install can sign.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IssuerSeedTransferReport {
    pub candidates: usize,
    pub published_generations: usize,
    pub already_held: usize,
    /// The archive or the destination's current root did not select them.
    pub not_selected: usize,
    /// Rollback is not proven when the source had no configured anchor.
    pub custody_note: Option<String>,
}
