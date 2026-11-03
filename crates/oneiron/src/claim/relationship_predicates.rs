//! Claim predicates and label bounds for member-to-person relationships.

/// CLAIM predicate binding a grant's `member_ref` to a PERSON entity.
///
/// Deliberately NOT in `CLAIM_PREDICATE_REGISTRY`: the registry is the
/// crate-owned STRUCTURAL schema list, and the generic claim door already
/// accepts a well-formed non-structural predicate. Registering these two would
/// claim a validator seat neither of them needs.
pub const PREDICATE_RELATIONSHIP_PERSON_REF: &str = "core.relationship.person_ref";

/// CLAIM predicate labelling a PERSON entity with a relationship word.
pub const PREDICATE_RELATIONSHIP_LABEL: &str = "core.relationship.label";

/// Maximum byte length of a relationship label.
///
/// The label grammar is ASCII-only, so this bounds the character count too.
pub const MAX_RELATIONSHIP_LABEL_BYTES: usize = 64;
