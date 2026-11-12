//! Moved from `crates/oneiron/src/store/note_body.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

/// The stored spelling's prefix for [`NoteActor::Imported`]: `imported:`
/// and the source id in hex.
pub const IMPORTED_ACTOR_PREFIX: &str = "imported:";
