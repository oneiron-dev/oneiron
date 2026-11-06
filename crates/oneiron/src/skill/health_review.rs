//! Agent-health reviewer skill, policy-file and receipt identifiers.

/// The reviewer skill: its revision's `policy.json` seeds the T1 dials, and
/// an owner's outcome on a card scores that revision.
pub(crate) const AGENT_HEALTH_REVIEW_SKILL_ID: &str = "agent-health-review";

/// The package file that carries a revision's seeds: one number per dial key.
pub(crate) const REVIEWER_POLICY_FILE: &str = "policy.json";

/// A reviewer receipt id's prefix: `health_review:` and 64 hex. The replay
/// judge reads such a receipt through [`Vault::health_review_receipt`].
pub const HEALTH_REVIEW_RECEIPT_PREFIX: &str = "health_review:";
