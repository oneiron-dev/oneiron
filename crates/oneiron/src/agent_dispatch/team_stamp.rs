//! OF-540 (c): the team run a dispatch works in, frozen at dispatch.
//!
//! A spawn admitted into a team run carries one [`TeamRunStamp`]: the exact
//! `TeamReceipt.team_ref` of the run and its [`TeamPattern`]. Who decides is
//! the pattern's decider kind, so it is derived, never stored: actors, a
//! vote's tally and a referee's signed rule stay in the run's `TeamReceipt`,
//! and nothing here freezes a result before the team reaches it. The stamp
//! rides the dispatch payload, so a retry keeps it and a child inherits it
//! unless it names its own (a nested team). Solo is not a team and never
//! stamps.

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::team::TeamPattern;

use super::team_shape::CoordinationPattern;

/// Longest team reference kept, the bound `TeamReceipt` applies.
const MAX_TEAM_REF_BYTES: usize = 256;

/// The team run one dispatch works in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamRunStamp {
    /// The exact `TeamReceipt.team_ref` of the run.
    pub team_ref: String,
    pub pattern: TeamPattern,
}

impl TeamRunStamp {
    /// A validated stamp.
    ///
    /// # Errors
    ///
    /// [`ArtifactError::InvalidAgentDispatchInput`](crate::error::ArtifactError::InvalidAgentDispatchInput)
    /// for a team reference `TeamReceipt` would refuse.
    pub fn new(team_ref: impl Into<String>, pattern: TeamPattern) -> Result<Self> {
        let stamp = Self {
            team_ref: team_ref.into(),
            pattern,
        };
        stamp.validate()?;
        Ok(stamp)
    }

    /// The team reference rule `TeamReceipt` applies: 1..=256 bytes, no NUL.
    ///
    /// # Errors
    ///
    /// [`ArtifactError::InvalidAgentDispatchInput`](crate::error::ArtifactError::InvalidAgentDispatchInput)
    /// naming the broken rule.
    pub fn validate(&self) -> Result<()> {
        if self.team_ref.is_empty()
            || self.team_ref.len() > MAX_TEAM_REF_BYTES
            || self.team_ref.contains('\0')
        {
            return Err(super::widen_record::invalid(
                "a team reference is 1..=256 bytes without NUL",
            ));
        }
        Ok(())
    }
}

/// The team pattern a planned coordination pattern runs. `None` for solo:
/// one agent is not a team, so a solo shape never produces a stamp.
#[must_use]
pub const fn team_pattern(pattern: CoordinationPattern) -> Option<TeamPattern> {
    match pattern {
        CoordinationPattern::Solo => None,
        CoordinationPattern::CeoDecides => Some(TeamPattern::CeoDecides),
        CoordinationPattern::Committee => Some(TeamPattern::Committee),
        CoordinationPattern::Vote => Some(TeamPattern::Vote),
        CoordinationPattern::Market => Some(TeamPattern::Market),
        CoordinationPattern::Rotation => Some(TeamPattern::Rotation),
    }
}
