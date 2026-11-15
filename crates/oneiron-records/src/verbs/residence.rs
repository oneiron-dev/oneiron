//! Moved from `crates/oneiron/src/verbs/residence.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::verbs::residence::ResidenceActView;
pub use oneiron_verb_wire::verbs::residence::ResidenceDirectiveView;
pub use oneiron_verb_wire::verbs::residence::ResidenceDirectivesRequest;
pub use oneiron_verb_wire::verbs::residence::ResidenceMachineRequest;
pub use oneiron_verb_wire::verbs::residence::ResidenceModeName;
pub use oneiron_verb_wire::verbs::residence::ResidenceModeRequest;
pub use oneiron_verb_wire::verbs::residence::ResidenceOpenRequest;
pub use oneiron_verb_wire::verbs::residence::ResidencePruneRequest;
pub use oneiron_verb_wire::verbs::residence::ResidenceResultStatusName;
pub use oneiron_verb_wire::verbs::residence::ResidenceResultView;
use serde::Deserialize;
use serde::Serialize;

/// A residence row the host relayed as the owner's residence directive,
/// because the named machine runs no sync connection it reaches (FIX 3570):
/// accepted, not executed. The machine applies it once when it next syncs
/// and records the directive's result; the same row again, while this one
/// is pending, answers this same directive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidenceQueued {
    /// The queued residence directive, 32 hex.
    pub directive: EntityId,
    /// The machine it waits for, 32 hex.
    pub machine: EntityId,
}

/// `vault.residence.mode`'s answer: what the switch did on the machine, or
/// the directive queued for it. `state` says which; an applied answer
/// carries [`ResidenceModeChanged`]'s fields beside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ResidenceModeAnswer {
    Applied(ResidenceModeChanged),
    Queued(ResidenceQueued),
}

/// `vault.residence.index`'s answer: the machine's thin index, or the
/// directive queued for it. `state` says which; an applied answer carries
/// [`ResidenceIndex`]'s fields beside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ResidenceIndexAnswer {
    Applied(ResidenceIndex),
    Queued(ResidenceQueued),
}

/// `vault.residence.prune`'s answer: what the prune dropped on the
/// machine, or the directive queued for it. `state` says which; an applied
/// answer carries [`ResidencePruned`]'s fields beside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ResidencePruneAnswer {
    Applied(ResidencePruned),
    Queued(ResidenceQueued),
}

/// What switching the machine's residence mode did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidenceModeChanged {
    /// The mode the machine runs now; the elected home always runs `all`.
    pub mode: ResidenceModeName,
    /// Held windows the home granted again, kept as promoted windows.
    pub retained: Vec<String>,
    /// Held windows the home did not grant again: still on disk, unsynced.
    pub unsynced: Vec<String>,
    /// Opened-item caches dropped on the way to `all`.
    pub pruned_items: usize,
}

/// One entry of a window's thin index: what exists, never a body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidenceIndexEntry {
    pub entity_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub learned_at: u64,
}

/// One current window's thin index on the machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidenceIndexWindowView {
    pub window: String,
    pub items: Vec<ResidenceIndexEntry>,
}

/// The machine's thin index, window by window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidenceIndex {
    pub windows: Vec<ResidenceIndexWindowView>,
}

/// What a prune dropped on the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidencePruned {
    /// Opened-item caches dropped.
    pub dropped: usize,
}
