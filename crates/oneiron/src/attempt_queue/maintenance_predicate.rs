//! Claim predicates used by queued maintenance proposals.

/// Predicate of a proposed heal for a failure-ladder case.
pub const COACH_HEAL_PROPOSAL_PREDICATE: &str = "coach.heal.proposal";

/// Predicate of a proposed heal for a blocked report.
pub const COACH_ISSUE_PROPOSAL_PREDICATE: &str = "coach.issue.proposal";

/// Predicate of a proposed resolution of a model finding's issue, for the owner to confirm
/// (OF-418 L3).
pub const COACH_ISSUE_RESOLUTION_PREDICATE: &str = "coach.issue.resolution";

/// Predicate of a proposed heal for a model finding's issue (OF-418 L3).
pub const COACH_DIAGNOSTIC_PROPOSAL_PREDICATE: &str = "coach.diagnostic.proposal";

pub(crate) const CONTENT_PREFIX: &str = "representation:";

/// The prefix of an approved representation's content ref, for the served
/// sink's content resolver (FIX 1469).
pub(crate) const REPRESENTATION_CONTENT_PREFIX: &str = CONTENT_PREFIX;
