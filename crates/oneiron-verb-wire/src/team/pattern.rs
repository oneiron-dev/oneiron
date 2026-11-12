//! Moved from `crates/oneiron/src/team/pattern.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// Who decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamPattern {
    /// The leader alone, after advice. The default.
    CeoDecides,
    /// A few members deliberate; the chair decides (Council Mode).
    Committee,
    /// Members vote first; debate only on request.
    Vote,
    /// A referee: a rule signed before the work.
    Market,
    /// Roles rotate by turn inside the leader's patch. Optional; starts untested.
    Rotation,
    /// One agent alone: the no-team control arm. Never started
    /// (`team_stamp` maps it to `None`); its receipts come from the
    /// solo close writer, never from `self.team.record`.
    Solo,
}

impl TeamPattern {
    /// The pinned wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CeoDecides => "ceo_decides",
            Self::Committee => "committee",
            Self::Vote => "vote",
            Self::Market => "market",
            Self::Rotation => "rotation",
            Self::Solo => "solo",
        }
    }

    /// The decider kind a receipt under this pattern must name.
    #[must_use]
    pub const fn decider_kind(self) -> &'static str {
        match self {
            Self::CeoDecides | Self::Rotation | Self::Solo => "leader",
            Self::Committee => "chair",
            Self::Vote => "vote",
            Self::Market => "referee",
        }
    }
}

/// Converge on one answer, or diverge into many: a setting of any pattern.
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
pub enum TeamAxis {
    Converge,
    Diverge,
}

/// The start a pattern skill writes for one planned team (DOOR-111): the
/// leader's briefing, one briefing per member the plan launches, and the
/// axis the team runs. The owner's launch freezes it under the intent, so a
/// replay launches this start and never asks the runner again.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PatternLaunchSpec {
    /// What the leader reads after the owner's prompt.
    pub leader_briefing: String,
    /// One briefing per member, in launch order: the plan's width less the
    /// leader.
    pub member_briefings: Vec<String>,
    pub axis: TeamAxis,
}
