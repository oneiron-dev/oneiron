//! Moved from `crates/oneiron/src/context_board/room_offer.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// How long a room-wide card with no fixed deadline stays open after its
/// last engagement: a day (OF-530 ruling A).
pub const ROOM_OFFER_IDLE_SECS: u64 = 24 * 60 * 60;
