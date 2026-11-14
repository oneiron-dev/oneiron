//! Moved from `crates/oneiron/src/authority/conversation_training_vault.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::authority::*;
use oneiron_contracts::entity_id::EntityId;

/// The vault's setting, as a member's or guest's surface shows it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConversationLearningView {
    /// Whether the setting is on now. No choice, an off and a conflict read
    /// as off.
    pub on: bool,
    /// Whether people may leave their own messages out now.
    pub allow_opt_out: bool,
    /// The revision to present back as `seen`: the digest of the vault's
    /// live setting choices, zero when none.
    pub revision: PolicyRevision,
    /// Whether the live setting choices conflict. While they do, it reads
    /// as off until a choice that saw them all supersedes them.
    pub conflicted: bool,
    /// The authority entry of the choice in force; `None` while none counts
    /// or the choices conflict.
    pub act: Option<AuthorityEntryHash>,
    /// The admin's PERSON whose act the choice in force is; `None` while
    /// none counts, or its row is not stored here.
    pub set_by: Option<EntityId>,
    /// The one read-only line a member's surface shows while it is on;
    /// `None` while off.
    pub line: Option<String>,
}
