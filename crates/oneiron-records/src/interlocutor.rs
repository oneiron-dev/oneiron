//! Moved from `crates/oneiron/src/interlocutor.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// Display label for a supplied voice roster that could not be resolved. The
/// entry exists so an unresolvable roster narrows disclosure instead of
/// silently leaving the caller in owner-alone mode.
pub const VOICE_ROSTER_UNRESOLVED_LABEL: &str = "unresolved voice roster";

pub const LIVE_ROOM_SPEAKER_LABEL: &str = "live room speaker";
