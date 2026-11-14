//! Moved from `crates/oneiron/src/authority/conversation_training/door.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::authority::conversation_training::*;
use crate::authority::*;
use oneiron_contracts::entity_id::EntityId;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// A person's own opt-out, as their own surface shows it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConversationTrainingView {
    /// The PERSON whose choice this is: the proof's own.
    pub person: EntityId,
    /// Whether they asked to leave their own messages out. A conflict reads
    /// as left out.
    pub leave_out: bool,
    /// Whether the vault's setting lets people opt out now: while it does
    /// not, `leave_out` is kept and ignored.
    pub allowed: bool,
    /// The revision to present back as `seen`: the digest of the person's
    /// live choices, zero when none.
    pub revision: PolicyRevision,
    /// Whether the person's live choices conflict.
    pub conflicted: bool,
    /// The authority entry of the choice in force; `None` while no choice
    /// counts or the choices conflict.
    pub act: Option<AuthorityEntryHash>,
}
