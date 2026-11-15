//! Moved from `crates/oneiron/src/team/receipt.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::team::receipt::PatternSkillRef;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// Longest reference or model id kept.
pub const MAX_REF_BYTES: usize = 256;

/// How many agents, in which roles.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamShape {
    pub width: u32,
    /// Role name to head count, such as `lead`, `member`, `critic`.
    pub roles: BTreeMap<String, u32>,
}

impl TeamShape {
    /// A stable signature for grouping: `width` then `role:count` pairs.
    #[must_use]
    pub fn signature(&self) -> String {
        let roles: Vec<String> = self
            .roles
            .iter()
            .map(|(role, n)| format!("{role}:{n}"))
            .collect();
        format!("{}|{}", self.width, roles.join(","))
    }
}

/// Who decided the team's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DecidedBy {
    Leader {
        actor: EntityId,
    },
    Chair {
        actor: EntityId,
    },
    Vote {
        tally: BTreeMap<String, u32>,
    },
    /// A rule signed before the work: a test suite, a holdout, a pinned judge.
    Referee {
        rule: String,
        signed_at: u64,
    },
}

impl DecidedBy {
    /// The decider kind token.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Leader { .. } => "leader",
            Self::Chair { .. } => "chair",
            Self::Vote { .. } => "vote",
            Self::Referee { .. } => "referee",
        }
    }
}

/// How much of the campaign's cell grid the team's outputs covered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    pub cells_filled: u32,
    pub cells_total: u32,
}

pub fn bounded(text: &str, what: &'static str) -> Result<()> {
    if text.is_empty() || text.len() > MAX_REF_BYTES || text.contains('\0') {
        return Err(Error::InvalidClaimBody(what));
    }
    Ok(())
}
