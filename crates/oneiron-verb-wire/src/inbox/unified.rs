//! Moved from `crates/oneiron/src/inbox/unified.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::edge::EdgeActorClass;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::bytes_to_hex_lower;
use oneiron_store::inbox::model::InboxBulkVerb;
use oneiron_store::write_envelope::WriteActor;
use serde::Deserialize;
use serde::Serialize;
use std::cmp::Reverse;

/// Which projection a group comes from.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum InboxGroupKind {
    /// A Dreamer run's gate-held proposals, keyed by its run-tree root.
    Dreamer,
    /// A vault shape apply's items waiting for the owner's word.
    Shape,
}

impl InboxGroupKind {
    const fn byte(self) -> u8 {
        match self {
            Self::Dreamer => 0,
            Self::Shape => 1,
        }
    }

    const fn of_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Dreamer),
            1 => Some(Self::Shape),
            _ => None,
        }
    }
}

/// The host's compilation target for a Dreamer answer, as the wire carries
/// it: the [`CompilationTarget`] shape with a schema derive. Present it is
/// authoritative (ARCH-0056).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", content = "text", rename_all = "snake_case")]
pub enum InboxGroupResolveTarget {
    /// Preserve the existing lexical-claim/content-skill-edit chooser.
    Fallback,
    /// Propose a prohibition. Does not install an enforcement rule.
    Ban(String),
    /// Propose an OF-332 style token. Does not supersede an expression head.
    StyleRule(String),
    /// Propose a line for the acting charter. Does not change its authority.
    CharterLine(String),
    /// Propose a brief update. Does not mutate a brief.
    BriefUpdate(String),
}

/// The owner's answer to one inbox group of either kind.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InboxGroupResolveRequest {
    pub kind: InboxGroupKind,
    /// The group's key, as the page lists it.
    pub group_key: String,
    pub verb: InboxBulkVerb,
    /// Narrows a Dreamer group's bundle to its `new_claim`, `update` or
    /// `conflict` rows. A shape group has no verb classes.
    #[serde(default)]
    pub verb_class: Option<String>,
    /// The host's compilation target for a Dreamer answer. Absent keeps
    /// today's path: no principal, no learning. Present is authoritative
    /// (ARCH-0056). A shape group ignores it.
    #[serde(default)]
    pub target: Option<InboxGroupResolveTarget>,
}
