//! Moved from `crates/oneiron/src/store/body_envelope/frames.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

/// What one envelope of a file is.
#[derive(Clone, Copy)]
pub enum Role {
    Chunk = 0,
    Last = 1,
    Terminal = 2,
}
