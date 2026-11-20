//! Moved from `crates/oneiron/src/failure_signals/count_delivery.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// One count a batch carries: the aggregate row it was read from (BLAKE3 of
/// its dimensions' JSON) and the quantity the batch froze. Settlement takes
/// exactly that quantity, so a count recorded into the same row since stays
/// for the next batch.
pub type CountShare = ([u8; 32], u64);
