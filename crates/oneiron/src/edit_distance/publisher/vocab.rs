//! Closed issue vocabulary: defect categories and count keys.

use crate::skill_attribution::AttributionVerdict;

/// The defect class an issue signature reports (ARCH-0056 §5 routing, §9 UP
/// rung 1).
///
/// Pinned to [`AttributionVerdict`] arm-for-arm and token-for-token via
/// [`IssueCategory::from_verdict`] — the attribution judge's verdict IS the
/// category, and the tests assert the two vocabularies cannot drift apart. It
/// is a distinct type only because `AttributionVerdict` carries skill-routing
/// semantics (which entity a verdict writes against) that the publisher's
/// wire vocabulary must not inherit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
}

impl IssueCategory {
    /// Every arm — the closed enum made iterable, so a sixth category cannot
    /// be added without every site here seeing it.
    pub const ALL: [Self; 5] = [
        Self::SkillDefect,
        Self::ExecutionLapse,
        Self::Discovery,
        Self::Environment,
        Self::PreferenceShift,
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
        }
    }
}

/// The closed set of count names a signature may carry.
///
/// Each arm is one-to-one with a landed [`ProposalOutcome`] fact, so the whole
/// vocabulary is derivable from judged receipts and nothing here needs a
/// consumer to invent a number. `ApprovedUntouched` has no arm on purpose: it
/// is `Judged - Amended - Rejected`, and a redundant count is a second place
/// for the two to disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CountKey {
    /// Judged outcomes behind this signature — the denominator.
    Judged,
    /// Of those, approved only after the human amended the body.
    Amended,
    /// Of those, rejected outright.
    Rejected,
}

impl CountKey {
    /// Every arm.
    pub const ALL: [Self; 3] = [Self::Judged, Self::Amended, Self::Rejected];

    /// The pinned on-disk/wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Judged => "judged",
            Self::Amended => "amended",
            Self::Rejected => "rejected",
        }
    }

    /// Parses a pinned token; `None` for one this engine never wrote.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|arm| arm.as_str() == value)
    }
}
