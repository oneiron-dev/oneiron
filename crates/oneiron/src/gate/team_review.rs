//! Predicate of an owner-reviewed team deliverable.

/// The predicate of the review a submit writes: whether the team's output,
/// as pinned, is accepted. The Gate's default manifest declares it critical,
/// so the review waits for the owner.
pub(crate) const TEAM_DELIVERABLE_REVIEW_PREDICATE: &str = "team.deliverable.acceptance";
