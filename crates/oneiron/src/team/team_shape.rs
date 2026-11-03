use crate::team::TeamPattern;
use serde::{Deserialize, Serialize};

/// Who decides (ARCH-0079 #patterns). `Solo` is the width-1 degenerate
/// shape the skill starts from; the rest are OF-540's skill patterns.
/// Whether a team converges on one answer or diverges into many is a
/// setting of the pattern, not a pattern of its own.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
