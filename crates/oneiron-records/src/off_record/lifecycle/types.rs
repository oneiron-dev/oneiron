//! Moved from `crates/oneiron/src/off_record/lifecycle/types.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::off_record::lifecycle::types::OffRecordBackendClass;
pub use oneiron_verb_wire::off_record::lifecycle::types::OffRecordMode;
pub use oneiron_verb_wire::off_record::lifecycle::types::OffRecordNoticeAct;
use serde::Deserialize;
use serde::Serialize;

/// Read-only projection of one in-process off-record session record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffRecordSessionRecord {
    pub version: u8,
    pub session_ref: String,
    /// This live instance's existing overlay-shell identity, distinct when
    /// the same session ref is entered again after close. Not authority.
    pub instance_ref: oneiron_contracts::entity_id::EntityId,
    pub mode: OffRecordMode,
    pub backend: OffRecordBackendClass,
    pub entered_at: u64,
    /// Turns promoted into base; close keeps them.
    pub promoted_turns: Vec<[u8; 16]>,
    /// Set by the first close transaction. While `true`, every mutator
    /// (promote, mode flip, emit-receipt record) rejects with
    /// [`OffRecordError::OffRecordSessionClosing`](oneiron_base::error::OffRecordError::OffRecordSessionClosing) — close drains leases and drops the
    /// overlay across several steps, and a mutation landing in that window
    /// would write into a room that is already going away.
    #[serde(default)]
    pub closing: bool,
    /// The room (a conversation) this stretch runs in, when a participant
    /// started it there. `None` is the stretch a vault's owner entered alone:
    /// a 1:1 with their own companion, where no other person is present.
    #[serde(default)]
    pub room: Option<[u8; 16]>,
    /// The person who started the stretch in its room.
    #[serde(default)]
    pub started_by: Option<[u8; 16]>,
    /// The actor who entered a stretch alone, when the door that entered it
    /// named one (`OffRecordSessionVault::enter_anonymous_as`): the one
    /// caller an anonymous 1:1's no-record exception serves
    /// (`Vault::off_record_session_is_anonymous_for`). `None` on a stretch
    /// in a room, whose roster decides, and on one entered with no actor.
    #[serde(default)]
    pub entered_by: Option<[u8; 16]>,
    /// The room's timeline of saves, exports and save suggestions (ARCH-0052
    /// D5, the notice model), oldest first. Only a stretch in a room has
    /// one: a 1:1 posts no notice. It names who and what, never the content,
    /// and it evaporates with the room.
    #[serde(default)]
    pub notices: Vec<OffRecordNotice>,
    /// Agents' save suggestions waiting for a holder of this vault's write
    /// grant to confirm or decline them (ARCH-0052 #d5-save-grant), oldest
    /// first, one per agent. A save answers every one of them.
    #[serde(default)]
    pub suggestions: Vec<OffRecordSaveSuggestion>,
}

/// One notice in the room's timeline: who did what, and when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffRecordNotice {
    pub act: OffRecordNoticeAct,
    /// The person or agent that acted.
    pub by: [u8; 16],
    pub at: u64,
}

/// An agent's save suggestion, waiting for a holder's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffRecordSaveSuggestion {
    /// The agent that suggested it.
    pub by: [u8; 16],
    pub at: u64,
}
