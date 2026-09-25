//! Byte-space v3.1 family allocation, independent of kind behavior.

use super::{ENTITY_TYPE_REGISTRY, EntityClassification, EntityTypeRegistryEntry, TypeByteZone};

/// Stable kind family. A spill keeps its family even when its byte is in overflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TypeByteFamily {
    Conversation,
    People,
    World,
    Content,
    AgentsAndSurfacing,
    CoreOverflow,
    AuthorityPolicyCustody,
    AuditObservability,
    OutboundCommunicationConsent,
    RegistriesDerived,
    Productivity,
    Code,
    Documents,
    Companion,
    PackOverflow,
}

/// One canonical family allocation range. Overflow ranges reserve capacity,
/// not a new behavior for the kinds that spill into them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeByteFamilyEntry {
    pub family: TypeByteFamily,
    pub name: &'static str,
    pub zone: TypeByteZone,
    pub start: u8,
    pub end: u8,
}

/// ARCH-0058 §2a allocation table. It is never a replication routing table.
pub const TYPE_BYTE_FAMILIES: &[TypeByteFamilyEntry] = &[
    TypeByteFamilyEntry {
        family: TypeByteFamily::Conversation,
        name: "conversation",
        zone: TypeByteZone::Core,
        start: 1,
        end: 9,
    },
    TypeByteFamilyEntry {
        family: TypeByteFamily::People,
        name: "people",
        zone: TypeByteZone::Core,
        start: 10,
        end: 19,
    },
    TypeByteFamilyEntry {
        family: TypeByteFamily::World,
        name: "world",
        zone: TypeByteZone::Core,
        start: 20,
        end: 29,
    },
    TypeByteFamilyEntry {
        family: TypeByteFamily::Content,
        name: "content",
        zone: TypeByteZone::Core,
        start: 30,
        end: 39,
    },
    TypeByteFamilyEntry {
        family: TypeByteFamily::AgentsAndSurfacing,
        name: "agents and surfacing",
        zone: TypeByteZone::Core,
        start: 40,
        end: 49,
    },
    TypeByteFamilyEntry {
        family: TypeByteFamily::CoreOverflow,
        name: "overflow",
        zone: TypeByteZone::Core,
        start: 50,
        end: 63,
    },
    TypeByteFamilyEntry {
        family: TypeByteFamily::AuthorityPolicyCustody,
        name: "authority, policy, custody",
        zone: TypeByteZone::System,
        start: 64,
        end: 71,
    },
    TypeByteFamilyEntry {
        family: TypeByteFamily::AuditObservability,
        name: "audit and observability",
        zone: TypeByteZone::System,
        start: 72,
        end: 79,
    },
    TypeByteFamilyEntry {
        family: TypeByteFamily::OutboundCommunicationConsent,
        name: "outbound communication and consent",
        zone: TypeByteZone::System,
        start: 80,
        end: 89,
    },
    TypeByteFamilyEntry {
        family: TypeByteFamily::RegistriesDerived,
        name: "registries and derived",
        zone: TypeByteZone::System,
        start: 90,
        end: 99,
    },
    TypeByteFamilyEntry {
        family: TypeByteFamily::Productivity,
        name: "productivity",
        zone: TypeByteZone::CompiledProduct,
        start: 100,
        end: 104,
    },
    TypeByteFamilyEntry {
        family: TypeByteFamily::Code,
        name: "code",
        zone: TypeByteZone::CompiledProduct,
        start: 105,
        end: 109,
    },
    TypeByteFamilyEntry {
        family: TypeByteFamily::Documents,
        name: "documents",
        zone: TypeByteZone::CompiledProduct,
        start: 110,
        end: 114,
    },
    TypeByteFamilyEntry {
        family: TypeByteFamily::Companion,
        name: "companion",
        zone: TypeByteZone::CompiledProduct,
        start: 115,
        end: 119,
    },
    TypeByteFamilyEntry {
        family: TypeByteFamily::PackOverflow,
        name: "overflow",
        zone: TypeByteZone::CompiledProduct,
        start: 120,
        end: 125,
    },
];

impl TypeByteFamily {
    /// Allocation metadata for this family.
    #[must_use]
    pub fn allocation(self) -> &'static TypeByteFamilyEntry {
        TYPE_BYTE_FAMILIES
            .iter()
            .find(|entry| entry.family == self)
            .expect("every family has an allocation row")
    }

    pub(crate) fn code(self) -> u8 {
        u8::try_from(
            TYPE_BYTE_FAMILIES
                .iter()
                .position(|entry| entry.family == self)
                .expect("family allocation exists")
                + 1,
        )
        .expect("fifteen family codes")
    }

    pub(crate) fn from_code(code: u8) -> Option<Self> {
        TYPE_BYTE_FAMILIES
            .get(usize::from(code).checked_sub(1)?)
            .map(|entry| entry.family)
    }

    /// Classification of kinds in this family, independent of their bytes.
    #[must_use]
    pub const fn classification(self) -> EntityClassification {
        match self {
            Self::Conversation => EntityClassification::Core,
            Self::People => EntityClassification::Core,
            Self::World => EntityClassification::Core,
            Self::Content => EntityClassification::Core,
            Self::AgentsAndSurfacing => EntityClassification::Core,
            Self::CoreOverflow => EntityClassification::Core,
            Self::AuthorityPolicyCustody => EntityClassification::Maintenance,
            Self::AuditObservability => EntityClassification::Maintenance,
            Self::OutboundCommunicationConsent => EntityClassification::Maintenance,
            Self::RegistriesDerived => EntityClassification::Maintenance,
            Self::Productivity => EntityClassification::Pack,
            Self::Code => EntityClassification::Pack,
            Self::Documents => EntityClassification::Pack,
            Self::Companion => EntityClassification::Pack,
            Self::PackOverflow => EntityClassification::Pack,
        }
    }
}

/// Looks up a registered kind's declared family. Never infers it from a byte range.
#[must_use]
pub fn family_of(type_byte: u8) -> Option<TypeByteFamily> {
    super::entity_type_registry_entry(type_byte).and_then(|entry| entry.family)
}

/// Chooses the lowest free byte in a family, then its zone's overflow range.
/// `occupied` includes vault-scoped reservations. Static kinds and canon reserves
/// are always occupied, so omitting them cannot accidentally allocate over them.
/// System families have no overflow range; exhaustion returns `None`.
#[must_use]
pub fn allocate_type_byte(family: TypeByteFamily, occupied: &[u8]) -> Option<u8> {
    let family_row = family.allocation();
    let free = |byte: &u8| {
        !occupied.contains(byte)
            && !ENTITY_TYPE_REGISTRY
                .iter()
                .any(|entry| entry.type_byte == *byte)
            && ![
                super::type_bytes::ENTITY_TYPE_SUSPICIOUS_WAKE,
                super::type_bytes::ENTITY_TYPE_CLAIM_CLASS_DESCRIPTOR,
                super::type_bytes::ENTITY_TYPE_SKILL_HUB,
            ]
            .contains(byte)
    };
    (family_row.start..=family_row.end).find(free).or_else(|| {
        let overflow = match family_row.zone {
            TypeByteZone::Core => TypeByteFamily::CoreOverflow,
            TypeByteZone::CompiledProduct => TypeByteFamily::PackOverflow,
            _ => return None,
        }
        .allocation();
        (overflow.start..=overflow.end).find(free)
    })
}

/// Checks the declared family and classification, never the byte position.
pub(crate) fn family_matches(entry: &EntityTypeRegistryEntry, family: TypeByteFamily) -> bool {
    entry.family == Some(family) && entry.classification == family.classification()
}

#[cfg(test)]
mod tests;
