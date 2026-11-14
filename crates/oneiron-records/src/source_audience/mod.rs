//! Moved from `crates/oneiron/src/source_audience/mod.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::source_audience::SourceAudienceEventView;
pub use oneiron_verb_wire::source_audience::SourceAudienceOp;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// Who reads under one policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceAudienceKind {
    /// One source's readers: a personal mailbox's owner, a group address's
    /// members, a calendar's owner. `open` stands the source open to the
    /// whole vault, restricting nothing (a calendar shared in detail).
    Source {
        readers: BTreeSet<EntityId>,
        open: bool,
    },
    /// One thread of a source: the source's readers now, and the people the
    /// thread was shared with.
    Thread {
        source: EntityId,
        /// The BLAKE3 of the source's own thread key: where the thread index
        /// files it, here and on every replica that merges it (fix list row
        /// 17204).
        thread: [u8; 32],
        shared_with: BTreeSet<EntityId>,
    },
}

/// Why a row reads to no one here meanwhile (FIX 12559 follow-up). Either
/// way it never leaves this vault while held, and no read of it, or of a
/// row whose words came from it, passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HeldBack {
    /// Its carried binding names a policy that has not arrived; it lifts
    /// once the binding lands.
    Pending,
    /// The vault it came from withheld it after it travelled (its words
    /// joined a row bound otherwise); it lifts once its carrier comes back
    /// with no marker.
    Withheld,
}
