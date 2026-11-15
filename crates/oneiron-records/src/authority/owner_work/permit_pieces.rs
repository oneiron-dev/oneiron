//! Moved from `crates/oneiron/src/authority/owner_work/permit_pieces.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::authority::owner_work::*;

/// The key a kept piece is found under: its signer, its commitment and its
/// place.
pub type PermitPieceKey = ([u8; 32], CustodyPermitPieces, u32);
