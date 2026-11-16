//! Moved from `crates/oneiron/src/memory/witness/codec.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// The TURN and CONVERSATION body key naming the source an imported transcript
/// came from (ARCH-0027). Its presence is what makes a turn imported evidence:
/// the Dreamer classifies such a turn `Imported` whatever its speaker.
pub const IMPORTED_SOURCE_KEY: &str = "import_source";
