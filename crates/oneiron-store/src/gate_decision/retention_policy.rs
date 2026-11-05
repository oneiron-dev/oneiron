//! Append-time decision ancestry and retention-policy values.

/// The manifest chooses how child scope rows compose with their ancestors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateRetentionPrecedence {
    NestedNarrowing,
    MostSpecific,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateRetentionOverrideCeiling {
    Vault,
    Parent,
}
