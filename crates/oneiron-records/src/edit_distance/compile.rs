//! Moved from `crates/oneiron/src/edit_distance/compile.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::edit_distance::miner::config::PREDICATE_PREFERENCE_PHRASING;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// What a revision changes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActingTarget {
    /// The generating actor's standing instructions.
    Charter { actor: EntityId },
    /// The brief the generator's reviewed work was written to, named by the
    /// review scope.
    Brief { actor: EntityId, scope: String },
}

/// The kind of one compiled line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledLineKind {
    Ban,
    StyleRule,
    Phrasing,
    Affirmed,
    CharterLine,
    BriefPreference,
}

impl CompiledLineKind {
    fn from_predicate(predicate: &str) -> Option<Self> {
        Some(match predicate {
            "preference.ban" => Self::Ban,
            "preference.style_rule" => Self::StyleRule,
            "preference.affirmed" => Self::Affirmed,
            "charter.line" => Self::CharterLine,
            "brief.preference" => Self::BriefPreference,
            p if p == PREDICATE_PREFERENCE_PHRASING => Self::Phrasing,
            _ => return None,
        })
    }

    const fn heading(self) -> &'static str {
        match self {
            Self::Ban => "Never",
            Self::StyleRule => "Style",
            Self::Phrasing => "Wording",
            Self::Affirmed => "Keep doing",
            Self::CharterLine => "Charter",
            Self::BriefPreference => "Brief",
        }
    }
}

/// One compiled line and the approved preference claim it came from.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CompiledLine {
    pub kind: CompiledLineKind,
    pub text: String,
    pub claim: EntityId,
}

/// Where a revision stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RevisionStatus {
    /// Waiting for the responsible role.
    Pending,
    /// Accepted by `by`: the published revision its target's owner applies.
    Accepted { by: EntityId, at: u64 },
    /// Declined by `by`, with the reason as written.
    Declined {
        by: EntityId,
        at: u64,
        reason: String,
    },
    /// Replaced, before an answer, by a newer compilation.
    Superseded { by_revision: String, at: u64 },
    /// Accepted, then applied by `by` at `at`: `version` of its target is
    /// the first that carries its text.
    Applied {
        accepted_by: EntityId,
        accepted_at: u64,
        by: EntityId,
        at: u64,
        version: String,
    },
}

/// One compiled acting revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActingRevision {
    pub id: String,
    /// Whose preferences it compiles.
    pub principal: EntityId,
    pub target: ActingTarget,
    pub lines: Vec<CompiledLine>,
    /// The revision text the target gains.
    pub text: String,
    /// Who may answer, in escalation order: the principal first, the vault
    /// owner role last.
    pub responsible: Vec<EntityId>,
    pub status: RevisionStatus,
    pub at: u64,
}
