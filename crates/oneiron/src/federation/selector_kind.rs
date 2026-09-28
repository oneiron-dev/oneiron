//! Replication vocabulary keyed on declared classification and family, never byte ranges.

use std::collections::BTreeSet;

use crate::registry::{
    EntityClassification, EntityTypeRegistryEntry, TypeByteFamily, entity_type_registry_entry,
    family_matches,
};

/// A classification or one family within it. The historical type name does
/// not imply a numeric range: a relocated kind keeps exactly the same scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SelectorRange {
    Semantic,
    Core,
    Maintenance,
    Family(TypeByteFamily),
}

impl SelectorRange {
    /// Resolves a registry identity without consulting its storage byte or zone.
    #[must_use]
    pub fn for_entry(entry: &EntityTypeRegistryEntry) -> Option<Self> {
        if entry.classification == EntityClassification::Semantic && entry.family.is_none() {
            return Some(Self::Semantic);
        }
        let family = entry.family?;
        family_matches(entry, family).then_some(Self::Family(family))
    }

    /// Whether a scope includes another scope. Families are disjoint atoms;
    /// a classification is their union. This also defines the pact lattice.
    #[must_use]
    pub fn includes(self, other: Self) -> bool {
        if self == other {
            return true;
        }
        match (self, other) {
            (Self::Core, Self::Family(family)) => {
                family.classification() == EntityClassification::Core
            }
            (Self::Maintenance, Self::Family(family)) => {
                family.classification() == EntityClassification::Maintenance
            }
            _ => false,
        }
    }

    /// Sorts, deduplicates and removes redundant family scopes.
    #[must_use]
    pub fn normalize(mut bands: Vec<Self>) -> Vec<Self> {
        bands.sort_unstable();
        bands.dedup();
        let all = bands.clone();
        bands.retain(|band| !all.iter().any(|wide| wide != band && wide.includes(*band)));
        bands
    }

    /// Stable classification/family spelling, shared by pact and sync codecs.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Semantic => "semantic",
            Self::Core => "core",
            Self::Maintenance => "maintenance",
            Self::Family(TypeByteFamily::Conversation) => "core/conversation",
            Self::Family(TypeByteFamily::People) => "core/people",
            Self::Family(TypeByteFamily::World) => "core/world",
            Self::Family(TypeByteFamily::Content) => "core/content",
            Self::Family(TypeByteFamily::AgentsAndSurfacing) => "core/agents_and_surfacing",
            Self::Family(TypeByteFamily::CoreOverflow) => "core/core_overflow",
            Self::Family(TypeByteFamily::AuthorityPolicyCustody) => {
                "maintenance/authority_policy_custody"
            }
            Self::Family(TypeByteFamily::AuditObservability) => "maintenance/audit_observability",
            Self::Family(TypeByteFamily::OutboundCommunicationConsent) => {
                "maintenance/outbound_communication_consent"
            }
            Self::Family(TypeByteFamily::RegistriesDerived) => "maintenance/registries_derived",
            Self::Family(TypeByteFamily::Productivity) => "pack/productivity",
            Self::Family(TypeByteFamily::Code) => "pack/code",
            Self::Family(TypeByteFamily::Documents) => "pack/documents",
            Self::Family(TypeByteFamily::Companion) => "pack/companion",
            Self::Family(TypeByteFamily::PackOverflow) => "pack/pack_overflow",
        }
    }

    /// Decodes the shared vocabulary. Retired byte-range names fail closed.
    #[must_use]
    pub fn from_wire_name(value: &str) -> Option<Self> {
        match value {
            "semantic" => Some(Self::Semantic),
            "core" => Some(Self::Core),
            "maintenance" => Some(Self::Maintenance),
            "core/conversation" => Some(Self::Family(TypeByteFamily::Conversation)),
            "core/people" => Some(Self::Family(TypeByteFamily::People)),
            "core/world" => Some(Self::Family(TypeByteFamily::World)),
            "core/content" => Some(Self::Family(TypeByteFamily::Content)),
            "core/agents_and_surfacing" => Some(Self::Family(TypeByteFamily::AgentsAndSurfacing)),
            "core/core_overflow" => Some(Self::Family(TypeByteFamily::CoreOverflow)),
            "maintenance/authority_policy_custody" => {
                Some(Self::Family(TypeByteFamily::AuthorityPolicyCustody))
            }
            "maintenance/audit_observability" => {
                Some(Self::Family(TypeByteFamily::AuditObservability))
            }
            "maintenance/outbound_communication_consent" => {
                Some(Self::Family(TypeByteFamily::OutboundCommunicationConsent))
            }
            "maintenance/registries_derived" => {
                Some(Self::Family(TypeByteFamily::RegistriesDerived))
            }
            "pack/productivity" => Some(Self::Family(TypeByteFamily::Productivity)),
            "pack/code" => Some(Self::Family(TypeByteFamily::Code)),
            "pack/documents" => Some(Self::Family(TypeByteFamily::Documents)),
            "pack/companion" => Some(Self::Family(TypeByteFamily::Companion)),
            "pack/pack_overflow" => Some(Self::Family(TypeByteFamily::PackOverflow)),
            _ => None,
        }
    }
}

/// The band axis of the pact lattice: a classification includes its families,
/// and a set naming every family of a classification covers the classification.
impl super::scope::ScopeAtom for SelectorRange {
    fn includes(&self, other: &Self) -> bool {
        SelectorRange::includes(*self, *other)
    }

    fn covered_by(&self, wide: &BTreeSet<Self>) -> bool {
        if wide
            .iter()
            .any(|band| SelectorRange::includes(*band, *self))
        {
            return true;
        }
        let classification = match self {
            Self::Core => EntityClassification::Core,
            Self::Maintenance => EntityClassification::Maintenance,
            Self::Semantic | Self::Family(_) => return false,
        };
        crate::registry::TYPE_BYTE_FAMILIES
            .iter()
            .filter(|entry| entry.family.classification() == classification)
            .all(|entry| {
                wide.iter()
                    .any(|band| SelectorRange::includes(*band, Self::Family(entry.family)))
            })
    }
}

/// Resolves a type byte through its registry row. Unknown and experimental
/// bytes have no replication identity and are never admitted by a range cut.
#[must_use]
pub fn selector_range_of(type_byte: u8) -> Option<SelectorRange> {
    entity_type_registry_entry(type_byte).and_then(SelectorRange::for_entry)
}

#[cfg(test)]
mod tests;
