//! Moved from `crates/oneiron/src/edit_distance/publisher/vocab.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_skill_attribution::types::AttributionVerdict;

/// The defect class an issue signature reports (ARCH-0056 §5 routing, §9 UP
/// rung 1).
///
/// Pinned to [`AttributionVerdict`] arm-for-arm and token-for-token via
/// [`IssueCategory::from_verdict`] — the attribution judge's verdict IS the
/// category, and the tests assert the two vocabularies cannot drift apart. It
/// is a distinct type only because `AttributionVerdict` carries skill-routing
/// semantics (which entity a verdict writes against) that the publisher's
/// wire vocabulary must not inherit.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum IssueCategory {
    /// The shipped artifact's own content was wrong.
    SkillDefect,
    /// The executor fumbled an artifact that was correct.
    ExecutionLapse,
    /// The artifact was missing content the attempt needed.
    Discovery,
    /// An external fact moved under an artifact that was right when made.
    Environment,
    /// The decider's taste moved; the artifact was not wrong.
    PreferenceShift,
    /// The judge could not attribute it: no label fit, or it was not sure.
    Unclear,
}

impl IssueCategory {
    /// Every arm — the closed enum made iterable, so a seventh category cannot
    /// be added without every site here seeing it.
    pub const ALL: [Self; 6] = [
        Self::SkillDefect,
        Self::ExecutionLapse,
        Self::Discovery,
        Self::Environment,
        Self::PreferenceShift,
        Self::Unclear,
    ];

    /// The pinned on-disk/wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SkillDefect => "skill_defect",
            Self::ExecutionLapse => "execution_lapse",
            Self::Discovery => "discovery",
            Self::Environment => "environment",
            Self::PreferenceShift => "preference_shift",
            Self::Unclear => "unclear",
        }
    }

    /// Parses a pinned token; `None` for one this engine never wrote.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|arm| arm.as_str() == value)
    }

    /// The category behind an attribution verdict — the no-fork bridge.
    #[must_use]
    pub const fn from_verdict(verdict: AttributionVerdict) -> Self {
        match verdict {
            AttributionVerdict::SkillDefect => Self::SkillDefect,
            AttributionVerdict::ExecutionLapse => Self::ExecutionLapse,
            AttributionVerdict::Discovery => Self::Discovery,
            AttributionVerdict::Environment => Self::Environment,
            AttributionVerdict::PreferenceShift => Self::PreferenceShift,
            AttributionVerdict::Unclear => Self::Unclear,
        }
    }
}
