//! The setting keys `actor_claims` declares (restriction wave 8): the crate's build script lists
//! each row in the setting catalogue.

use super::rows::{ACTOR_NOTE_MAX_BYTES, ActorNoteMaxBytes};
use crate::setting::{Kind, lower_is_tighter};

fn default_note_max_bytes() -> ActorNoteMaxBytes {
    ActorNoteMaxBytes(u32::try_from(ACTOR_NOTE_MAX_BYTES).unwrap_or(u32::MAX))
}

crate::setting::setting_keys! {
    /// The most UTF-8 bytes one actor note (a lesson, failure mode or scope note) this vault
    /// writes holds, between 128 and 16384; the distiller splits a longer note into parts of this
    /// size. Every stored row is held to the fixed 16384 ceiling, so lowering the cap leaves the
    /// notes already written readable.
    pub(crate) NOTE_MAX_BYTES: ActorNoteMaxBytes = "actor_claims.note.max_bytes" {
        kind: Kind::new(default_note_max_bytes).tighter(lower_is_tighter::<ActorNoteMaxBytes>),
    };
}
