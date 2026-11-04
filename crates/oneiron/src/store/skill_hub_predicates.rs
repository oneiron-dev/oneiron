//! The claim predicates the skill hub attaches. The skill hub (`skill_hub`)
//! writes and reads these claims; the store's archive import screens them.

/// Claim predicate for mutable hub aliases attached to canonical skill identity.
pub const PREDICATE_SKILL_HUB_PROVENANCE: &str = "skill.hub_provenance";

/// Claim predicate for scanner receipts attached to a canonical content hash.
pub const PREDICATE_SKILL_SCAN_VERDICT: &str = "skill.scan_verdict";
