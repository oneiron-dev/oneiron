//! The team-shape skill's engine half (ARCH-0079 #planner, OF-541): the
//! closed shape vocabulary the planner commits to.
//!
//! The skill itself is a workflow skill (`skills/team-shape/SKILL.md`,
//! seeded into the hub like every bootstrap skill and revised by the loop
//! from receipts). The planner loads it at spawn through the ordinary pack
//! door and reads its content, its task-type tree and the planner card; the
//! estimates are the vault's (`team::planner_card`), never a parallel table
//! here. Its first lesson is *solo first*: models carry weak priors about
//! collaboration and a naive team often loses to one agent, so when one
//! agent already succeeds often, adding agents tends to hurt (RESEARCH-0366).
//! Solo is a shape, not a pattern skill.

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::team::TeamPattern;

/// Hub name of the seeded team-shape workflow skill.
pub const TEAM_SHAPE_SKILL_NAME: &str = "team-shape";

/// The installed team-shape skill: the bootstrap-derived vault skill. A
/// project's fork is found from it by lineage.
///
/// # Errors
///
/// Only an id derivation failure.
pub fn team_shape_skill() -> Result<EntityId> {
    EntityId::derive(
        crate::entity_id::derived_domains::BOOTSTRAP_SKILL,
        &[TEAM_SHAPE_SKILL_NAME.as_bytes()],
    )
}

/// The skill's lessons, in the order the SKILL.md teaches them. The planner
/// puts the ones that fired into the spawn receipt's `why`.
pub const TEAM_SHAPE_LESSONS: [&str; 6] = [
    "solo first: when one agent already succeeds often, adding agents tends to hurt",
    "a team must beat solo at equal budget, not at ten times the spend",
    "committee narrows ideas: strong for researching what exists, late on generative work",
    "vote judges between finished options; debate only on request",
    "market needs a referee signed before the work: a test, a holdout, a pinned judge",
    "width has no count cap; the budget is the cap, and the plan states it before launch",
];

/// Who decides (ARCH-0079 #patterns). `Solo` is the width-1 degenerate
/// shape the skill starts from; the rest are OF-540's skill patterns.
/// Whether a team converges on one answer or diverges into many is a
/// setting of the pattern, not a pattern of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinationPattern {
    Solo,
    CeoDecides,
    Committee,
    Vote,
    Market,
    Rotation,
}

impl CoordinationPattern {
    pub const ALL: [Self; 6] = [
        Self::Solo,
        Self::CeoDecides,
        Self::Committee,
        Self::Vote,
        Self::Market,
        Self::Rotation,
    ];

    /// Stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Solo => "solo",
            Self::CeoDecides => "ceo_decides",
            Self::Committee => "committee",
            Self::Vote => "vote",
            Self::Market => "market",
            Self::Rotation => "rotation",
        }
    }

    pub fn from_token(token: &str) -> crate::error::Result<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "solo" => Ok(Self::Solo),
            "ceo_decides" | "ceo" => Ok(Self::CeoDecides),
            "committee" | "council" => Ok(Self::Committee),
            "vote" => Ok(Self::Vote),
            "market" => Ok(Self::Market),
            "rotation" => Ok(Self::Rotation),
            _ => Err(super::widen_record::invalid("unknown coordination pattern")),
        }
    }

    /// The shape a bound pattern skill teaches.
    #[must_use]
    pub const fn from_team(pattern: TeamPattern) -> Self {
        match pattern {
            TeamPattern::CeoDecides => Self::CeoDecides,
            TeamPattern::Committee => Self::Committee,
            TeamPattern::Vote => Self::Vote,
            TeamPattern::Market => Self::Market,
            TeamPattern::Rotation => Self::Rotation,
        }
    }

    /// Whether this pattern runs more than one agent by construction.
    #[must_use]
    pub const fn is_team(self) -> bool {
        !matches!(self, Self::Solo)
    }

    /// The smallest width at which the pattern means anything.
    #[must_use]
    pub const fn min_width(self) -> u32 {
        match self {
            Self::Solo => 1,
            Self::CeoDecides | Self::Market => 2,
            Self::Committee | Self::Vote | Self::Rotation => 3,
        }
    }

    /// Whether the pattern can run at `width`: solo is exactly one agent, a
    /// team at least its floor. Width has no count cap.
    #[must_use]
    pub const fn admits_width(self, width: u32) -> bool {
        match self {
            Self::Solo => width == 1,
            _ => width >= self.min_width(),
        }
    }
}

/// A concrete team shape a plan commits to: a pattern at a width.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamShape {
    pub pattern: CoordinationPattern,
    pub width: u32,
}

impl TeamShape {
    pub const SOLO: Self = Self {
        pattern: CoordinationPattern::Solo,
        width: 1,
    };

    /// Stable wire token, `pattern` or `pattern:width` past solo.
    #[must_use]
    pub fn token(&self) -> String {
        if self.pattern == CoordinationPattern::Solo {
            self.pattern.as_str().to_owned()
        } else {
            format!("{}:{}", self.pattern.as_str(), self.width)
        }
    }
}
