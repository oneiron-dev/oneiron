//! Moved from `crates/oneiron/src/federation/relationships.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;

/// Trust class a relationship label resolves to.
///
/// The word lists are FIXED: there is no Unicode folding and no synonym model,
/// so an unrecognized but well-formed label lands on [`Self::Unlabeled`] rather
/// than being guessed into a class.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
pub enum RelationshipTrustClass {
    /// Partner-grade closeness.
    Intimate,
    /// Blood or household family.
    Family,
    /// Chosen personal closeness.
    Friend,
    /// Work relationships inside one's own org.
    Professional,
    /// Commercial counterparties.
    Client,
    /// Bound to a person, but with no label in the fixed table.
    Unlabeled,
}

/// Resolved label context for a member bound to a PERSON.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct MemberRelationshipContext {
    /// PERSON entity the member is bound to.
    pub person: EntityId,
    /// Winning label, stored verbatim.
    pub label: String,
    /// CLAIM entity the winning label came from.
    pub label_claim: EntityId,
    /// Trust class [`relationship_trust_class`] maps `label` to.
    pub trust_class: RelationshipTrustClass,
}

/// Relationship state of a federation grant's `member_ref`.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub enum MemberRelationship {
    /// Bound to a person carrying a valid label.
    Labeled(MemberRelationshipContext),
    /// Bound to a person with no valid label claim.
    Unlabeled {
        /// PERSON entity the member is bound to.
        person: EntityId,
    },
    /// No valid person binding.
    Unbound,
}
