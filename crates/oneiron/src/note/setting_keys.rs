//! The setting keys `note` declares (restriction wave 8): the crate's build script lists each row
//! in the setting catalogue.

use super::write_gate::AUTO_NOTE_MIN_CHARS;
use crate::setting::{Kind, higher_is_tighter};

fn default_agent_min_chars() -> u32 {
    u32::try_from(AUTO_NOTE_MIN_CHARS).unwrap_or(u32::MAX)
}

crate::setting::setting_keys! {
    /// The fewest characters an agent's NOTE is born with (ARCH-0032 stage 1, the minimum
    /// auto-note length): Unicode scalar values of the trimmed markdown. 0 turns the floor off; a
    /// person's or the engine's own NOTE has none, and a kind that never feeds extraction sets none.
    pub(crate) AGENT_NOTE_MIN_CHARS: u32 = "note.birth.agent_min_chars" {
        kind: Kind::new(default_agent_min_chars).tighter(higher_is_tighter::<u32>),
    };
}
