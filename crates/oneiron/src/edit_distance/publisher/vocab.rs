//! Closed issue vocabulary: defect categories and count keys.

use crate::skill_attribution::AttributionVerdict;

#[doc(hidden)]
pub use oneiron_verb_wire::edit_distance::publisher::vocab::IssueCategory;

/// The closed set of count names a signature may carry.
///
/// Each arm is one-to-one with a landed [`ProposalOutcome`](crate::identity_topology::ProposalOutcome) fact, so the whole
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
