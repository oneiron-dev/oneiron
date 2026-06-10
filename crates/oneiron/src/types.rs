use std::collections::HashMap;
use std::path::PathBuf;

use uuid::Uuid;

pub(crate) const ENTITY_ID_LEN: usize = 16;
pub(crate) const EDGE_KEY_LEN: usize = 33;
pub(crate) const EDGE_VALUE_STRUCTURAL_LEN: usize = 12;
pub(crate) const EDGE_VALUE_SEMANTIC_LEN: usize = 24;
pub(crate) const EDGE_VALUE_SEMANTIC_PROVENANCED_LEN: usize = 26;

/// Byte 0 is the ARCH-0003 semantic CLAIM type byte, not a StructuralKind.
pub const ENTITY_TYPE_CLAIM: u8 = 0;
pub const ENTITY_TYPE_TURN: u8 = 1;
pub const ENTITY_TYPE_SESSION: u8 = 2;
pub const ENTITY_TYPE_MESSAGE: u8 = 3;
pub const ENTITY_TYPE_PERSON: u8 = 4;
pub const ENTITY_TYPE_RELATIONSHIP: u8 = 5;
pub const ENTITY_TYPE_EVENT: u8 = 6;
pub const ENTITY_TYPE_SKILL: u8 = 7;
pub const ENTITY_TYPE_SUMMARY: u8 = 8;
pub const ENTITY_TYPE_PLACE: u8 = 9;
pub const ENTITY_TYPE_ASSET_TEXT: u8 = 10;
pub const ENTITY_TYPE_CONVERSATION: u8 = 11;
pub const ENTITY_TYPE_ORG: u8 = 12;
pub const ENTITY_TYPE_FACET: u8 = 13;
pub const ENTITY_TYPE_WORLD: u8 = 14;
pub const ENTITY_TYPE_ASSET: u8 = 15;
pub const ENTITY_TYPE_NOTIFICATION: u8 = 16;
pub const ENTITY_TYPE_TASK_LIST: u8 = 80;
pub const ENTITY_TYPE_TASK: u8 = 81;
pub const ENTITY_TYPE_MACHINE: u8 = 82;
pub const ENTITY_TYPE_REDACTION_AUDIT: u8 = 120;

/// Registry classification mirroring the contracts.ts §1
/// `EntityClassification` enum: `"semantic" | "core" | "pack" | "maintenance"`.
///
/// CLAIM (byte 0) is the single SEMANTIC type (ARCH-0003) and deliberately
/// NOT a StructuralKind; core and pack kinds ARE StructuralKinds; maintenance
/// records (REDACTION_AUDIT) are engine-authored audit records, also not
/// StructuralKinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntityClassification {
    /// `"semantic"` — CLAIM, the single subject·predicate·value type.
    Semantic,
    /// `"core"` — universal CORE StructuralKinds (TURN … NOTIFICATION).
    Core,
    /// `"pack"` — pack-registered StructuralKinds (TASK_LIST / TASK / MACHINE
    /// today; other pack kinds get bytes at pack registration).
    Pack,
    /// `"maintenance"` — system/maintenance records (REDACTION_AUDIT).
    Maintenance,
}

/// The LOCKED type-byte band allocation from contracts.ts §1 `typeByteBands`.
///
/// Storage ABI: every u8 type byte falls in exactly one band; packs register
/// kinds against their declared band and never collide with CORE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeByteBand {
    /// Byte `0` — "Semantic core": CLAIM's semantic type byte, not a
    /// StructuralKind.
    Semantic,
    /// Bytes `1–63` — "CORE StructuralKinds" (universal kinds, ARCH-0002
    /// registry authority).
    Core,
    /// Bytes `64–79` — "Companion pack (Eiri)".
    Companion,
    /// Bytes `80–99` — "Productivity pack (cross-product)" (TASK_LIST=80,
    /// TASK=81, MACHINE=82; NOTE assigned at pack registration).
    Productivity,
    /// Bytes `100–119` — "CRM pack".
    Crm,
    /// Bytes `120–255` — "Induced / dynamic / maintenance"
    /// (REDACTION_AUDIT=120, runtime-induced and tenant-custom kinds).
    InducedDynamicMaintenance,
}

/// The single semantic type byte (CLAIM) — the entirety of the `0` band.
pub const TYPE_BYTE_SEMANTIC: u8 = 0;
/// First byte of the CORE StructuralKinds band (`1–63`).
pub const TYPE_BYTE_BAND_CORE_START: u8 = 1;
/// Last byte of the CORE StructuralKinds band (`1–63`).
pub const TYPE_BYTE_BAND_CORE_END: u8 = 63;
/// First byte of the companion pack band (`64–79`).
pub const TYPE_BYTE_BAND_COMPANION_START: u8 = 64;
/// Last byte of the companion pack band (`64–79`).
pub const TYPE_BYTE_BAND_COMPANION_END: u8 = 79;
/// First byte of the productivity pack band (`80–99`).
pub const TYPE_BYTE_BAND_PRODUCTIVITY_START: u8 = 80;
/// Last byte of the productivity pack band (`80–99`).
pub const TYPE_BYTE_BAND_PRODUCTIVITY_END: u8 = 99;
/// First byte of the CRM pack band (`100–119`).
pub const TYPE_BYTE_BAND_CRM_START: u8 = 100;
/// Last byte of the CRM pack band (`100–119`).
pub const TYPE_BYTE_BAND_CRM_END: u8 = 119;
/// First byte of the open-ended induced/dynamic/maintenance band (`120+`).
pub const TYPE_BYTE_BAND_MAINTENANCE_START: u8 = 120;

/// Maps a type byte to its LOCKED band. Total over all 256 bytes.
///
/// Band membership is pure namespace allocation: an unregistered byte still
/// has a band, but is rejected by [`validate_entity_type`] on every write
/// path until a pack registers it (registration mechanism deferred post-M2).
#[must_use]
pub const fn band_of(type_byte: u8) -> TypeByteBand {
    match type_byte {
        TYPE_BYTE_SEMANTIC => TypeByteBand::Semantic,
        TYPE_BYTE_BAND_CORE_START..=TYPE_BYTE_BAND_CORE_END => TypeByteBand::Core,
        TYPE_BYTE_BAND_COMPANION_START..=TYPE_BYTE_BAND_COMPANION_END => TypeByteBand::Companion,
        TYPE_BYTE_BAND_PRODUCTIVITY_START..=TYPE_BYTE_BAND_PRODUCTIVITY_END => {
            TypeByteBand::Productivity
        }
        TYPE_BYTE_BAND_CRM_START..=TYPE_BYTE_BAND_CRM_END => TypeByteBand::Crm,
        TYPE_BYTE_BAND_MAINTENANCE_START..=u8::MAX => TypeByteBand::InducedDynamicMaintenance,
    }
}

/// Returns whether `type_byte` is a REGISTERED StructuralKind.
///
/// Per contracts.ts §1: byte 0 (CLAIM) is the semantic type and deliberately
/// NOT a StructuralKind; maintenance records (REDACTION_AUDIT = 120) are not
/// StructuralKinds either. Only registered `core` and `pack` kinds qualify.
/// Unregistered bytes return `false` here AND remain rejected by
/// [`validate_entity_type`] on every write path (unchanged behavior).
#[must_use]
pub fn is_structural_kind(type_byte: u8) -> bool {
    matches!(
        entity_type_registry_entry(type_byte).map(|entry| entry.classification),
        Some(EntityClassification::Core | EntityClassification::Pack)
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntityTypeRegistryEntry {
    pub kind: &'static str,
    pub type_byte: u8,
    pub short_id_prefix: Option<&'static str>,
    /// contracts.ts §1 classification for this kind.
    pub classification: EntityClassification,
    /// The LOCKED type-byte band this kind is allocated within. Always equal
    /// to `band_of(self.type_byte)` (pinned by spec test).
    pub band: TypeByteBand,
}

pub const ENTITY_TYPE_REGISTRY: &[EntityTypeRegistryEntry] = &[
    EntityTypeRegistryEntry {
        kind: "CLAIM",
        type_byte: ENTITY_TYPE_CLAIM,
        short_id_prefix: Some("cl"),
        classification: EntityClassification::Semantic,
        band: TypeByteBand::Semantic,
    },
    EntityTypeRegistryEntry {
        kind: "TURN",
        type_byte: ENTITY_TYPE_TURN,
        short_id_prefix: Some("tn"),
        classification: EntityClassification::Core,
        band: TypeByteBand::Core,
    },
    EntityTypeRegistryEntry {
        kind: "SESSION",
        type_byte: ENTITY_TYPE_SESSION,
        short_id_prefix: Some("ss"),
        classification: EntityClassification::Core,
        band: TypeByteBand::Core,
    },
    EntityTypeRegistryEntry {
        kind: "MESSAGE",
        type_byte: ENTITY_TYPE_MESSAGE,
        short_id_prefix: Some("ms"),
        classification: EntityClassification::Core,
        band: TypeByteBand::Core,
    },
    EntityTypeRegistryEntry {
        kind: "PERSON",
        type_byte: ENTITY_TYPE_PERSON,
        short_id_prefix: Some("pr"),
        classification: EntityClassification::Core,
        band: TypeByteBand::Core,
    },
    EntityTypeRegistryEntry {
        kind: "RELATIONSHIP",
        type_byte: ENTITY_TYPE_RELATIONSHIP,
        short_id_prefix: Some("rl"),
        classification: EntityClassification::Core,
        band: TypeByteBand::Core,
    },
    EntityTypeRegistryEntry {
        kind: "EVENT",
        type_byte: ENTITY_TYPE_EVENT,
        short_id_prefix: Some("ev"),
        classification: EntityClassification::Core,
        band: TypeByteBand::Core,
    },
    EntityTypeRegistryEntry {
        kind: "SKILL",
        type_byte: ENTITY_TYPE_SKILL,
        short_id_prefix: Some("sk"),
        classification: EntityClassification::Core,
        band: TypeByteBand::Core,
    },
    EntityTypeRegistryEntry {
        kind: "SUMMARY",
        type_byte: ENTITY_TYPE_SUMMARY,
        short_id_prefix: Some("sm"),
        classification: EntityClassification::Core,
        band: TypeByteBand::Core,
    },
    EntityTypeRegistryEntry {
        kind: "PLACE",
        type_byte: ENTITY_TYPE_PLACE,
        short_id_prefix: Some("pl"),
        classification: EntityClassification::Core,
        band: TypeByteBand::Core,
    },
    EntityTypeRegistryEntry {
        kind: "ASSET_TEXT",
        type_byte: ENTITY_TYPE_ASSET_TEXT,
        short_id_prefix: Some("tx"),
        classification: EntityClassification::Core,
        band: TypeByteBand::Core,
    },
    EntityTypeRegistryEntry {
        kind: "CONVERSATION",
        type_byte: ENTITY_TYPE_CONVERSATION,
        short_id_prefix: Some("cv"),
        classification: EntityClassification::Core,
        band: TypeByteBand::Core,
    },
    EntityTypeRegistryEntry {
        kind: "ORG",
        type_byte: ENTITY_TYPE_ORG,
        short_id_prefix: Some("og"),
        classification: EntityClassification::Core,
        band: TypeByteBand::Core,
    },
    EntityTypeRegistryEntry {
        kind: "FACET",
        type_byte: ENTITY_TYPE_FACET,
        short_id_prefix: Some("fc"),
        classification: EntityClassification::Core,
        band: TypeByteBand::Core,
    },
    EntityTypeRegistryEntry {
        kind: "WORLD",
        type_byte: ENTITY_TYPE_WORLD,
        short_id_prefix: Some("wd"),
        classification: EntityClassification::Core,
        band: TypeByteBand::Core,
    },
    EntityTypeRegistryEntry {
        kind: "ASSET",
        type_byte: ENTITY_TYPE_ASSET,
        short_id_prefix: Some("as"),
        classification: EntityClassification::Core,
        band: TypeByteBand::Core,
    },
    EntityTypeRegistryEntry {
        kind: "NOTIFICATION",
        type_byte: ENTITY_TYPE_NOTIFICATION,
        short_id_prefix: Some("nt"),
        classification: EntityClassification::Core,
        band: TypeByteBand::Core,
    },
    EntityTypeRegistryEntry {
        kind: "TASK_LIST",
        type_byte: ENTITY_TYPE_TASK_LIST,
        short_id_prefix: Some("tl"),
        classification: EntityClassification::Pack,
        band: TypeByteBand::Productivity,
    },
    EntityTypeRegistryEntry {
        kind: "TASK",
        type_byte: ENTITY_TYPE_TASK,
        short_id_prefix: Some("tk"),
        classification: EntityClassification::Pack,
        band: TypeByteBand::Productivity,
    },
    EntityTypeRegistryEntry {
        kind: "MACHINE",
        type_byte: ENTITY_TYPE_MACHINE,
        short_id_prefix: Some("mc"),
        classification: EntityClassification::Pack,
        band: TypeByteBand::Productivity,
    },
    EntityTypeRegistryEntry {
        kind: "REDACTION_AUDIT",
        type_byte: ENTITY_TYPE_REDACTION_AUDIT,
        short_id_prefix: None,
        classification: EntityClassification::Maintenance,
        band: TypeByteBand::InducedDynamicMaintenance,
    },
];

/// A time-ordered entity identifier backed by UUIDv7 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntityId([u8; ENTITY_ID_LEN]);

impl EntityId {
    /// Creates a new identifier using the current UUIDv7 timestamp.
    #[must_use]
    pub fn now() -> Self {
        Self(Uuid::now_v7().into_bytes())
    }

    /// Creates an identifier from raw bytes, rejecting reserved sentinel IDs.
    ///
    /// The all-zero, all-`0xFF`, and known `[entity_type, 0xFF×15]` short-id
    /// counter sentinel patterns are reserved at the public `EntityId` layer.
    /// Other byte patterns remain valid IDs even if other LMDB indexes use
    /// similar-looking internal sentinel keys.
    pub fn from_bytes(bytes: [u8; 16]) -> crate::error::Result<Self> {
        if is_reserved_entity_id_bytes(&bytes) {
            return Err(crate::error::Error::InvalidKey);
        }
        Ok(Self(bytes))
    }

    /// Creates an identifier from raw bytes without validating sentinel patterns.
    ///
    /// Reserved for internal construction where the caller already knows the
    /// bytes are either valid entity IDs or intentional sentinel values.
    #[cfg(test)]
    pub(crate) fn from_bytes_unchecked(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the raw identifier bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Returns the lowercase hex-encoded string (32 chars).
    pub fn to_hex(&self) -> String {
        bytes_to_hex_lower(&self.0)
    }

    /// Parses a 32-char hex string (case-insensitive) into an EntityId.
    pub fn from_hex(s: &str) -> crate::error::Result<Self> {
        if s.len() != 32 {
            return Err(crate::error::Error::InvalidKey);
        }
        let mut bytes = [0u8; 16];
        for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
            let hi = hex_nibble(chunk[0]).ok_or(crate::error::Error::InvalidKey)?;
            let lo = hex_nibble(chunk[1]).ok_or(crate::error::Error::InvalidKey)?;
            bytes[i] = (hi << 4) | lo;
        }
        Self::from_bytes(bytes)
    }
}

/// Parses a `&[u8]` slice into an `EntityId`, returning
/// `Error::CorruptedIndex(context)` if the length is wrong, or
/// `Error::InvalidKey` if the bytes match a reserved sentinel pattern (used
/// by short_id counters and similar internal rows that must not be hydrated
/// as live entities). Used by index readers (HNSW neighbor keys, vector keys,
/// short_id reverse values) where a malformed key is on-disk corruption.
///
/// **Note:** callers needing contextual `CorruptedIndex` for diagnostics
/// should `.map_err` the `InvalidKey` variant. The HNSW read path does
/// this; `maintain.rs::recompute_short_id_hashes` handles both variants.
pub(crate) fn parse_entity_id(
    bytes: &[u8],
    context: &'static str,
) -> crate::error::Result<EntityId> {
    if bytes.len() != ENTITY_ID_LEN {
        return Err(crate::error::Error::CorruptedIndex(context));
    }
    let mut arr = [0u8; ENTITY_ID_LEN];
    arr.copy_from_slice(bytes);
    if is_reserved_entity_id_bytes(&arr) {
        return Err(crate::error::Error::InvalidKey);
    }
    Ok(EntityId(arr))
}

fn is_reserved_entity_id_bytes(bytes: &[u8; ENTITY_ID_LEN]) -> bool {
    if *bytes == [0x00; ENTITY_ID_LEN] || *bytes == [0xFF; ENTITY_ID_LEN] {
        return true;
    }

    bytes[1..].iter().all(|&b| b == 0xFF) && short_id_prefix(bytes[0]).is_ok()
}

/// Lowercase hex-encodes an arbitrary byte slice. Shared with the
/// analyzer manifest hasher so every hex rendering in the crate goes
/// through one implementation.
pub(crate) fn bytes_to_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Converts an ASCII hex character to its nibble value.
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Returns the short ID prefix for an entity type byte.
///
/// Returns an error for unknown entity type IDs and registered maintenance
/// types with no short-ID prefix.
pub fn short_id_prefix(entity_type: u8) -> crate::error::Result<&'static str> {
    entity_type_registry_entry(entity_type)
        .and_then(|entry| entry.short_id_prefix)
        .ok_or(crate::error::Error::InvalidEntityType(entity_type))
}

#[must_use]
pub fn entity_type_registry_entry(entity_type: u8) -> Option<&'static EntityTypeRegistryEntry> {
    ENTITY_TYPE_REGISTRY
        .iter()
        .find(|entry| entry.type_byte == entity_type)
}

pub(crate) fn validate_entity_type(entity_type: u8) -> crate::error::Result<()> {
    entity_type_registry_entry(entity_type)
        .map(|_| ())
        .ok_or(crate::error::Error::InvalidEntityType(entity_type))
}

/// Relationship kind used by graph edges.
///
/// Storage ABI: these discriminants are pinned to the ARCH-0034 `edgeKinds`
/// registry. They are encoded into `edges_out`/`edges_in` keys and EdgeRef/CRDT
/// edge-key refs; vaults written with the pre-M0-1 order need the M0-4
/// schema-version migration (ONE-1081) before those bytes are read under this
/// ordering.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EdgeKind {
    /// Entity belongs to another entity.
    BelongsTo = 4,
    /// Entity participates in another entity.
    ParticipatesIn = 13,
    /// Entity is attached to another entity.
    Attached = 14,
    /// Entity was authored by another entity.
    AuthoredBy = 0,
    /// Entity mentions another entity.
    Mentions = 9,
    /// Entity is about another entity.
    About = 10,
    /// Entity supports another entity.
    Supports = 11,
    /// Entity opposes another entity.
    Opposes = 12,
    /// Entity is a claim of another entity.
    ClaimOf = 5,
    /// Entity is scoped to another entity.
    ScopedTo = 1,
    /// Entity supersedes another entity.
    Supersedes = 3,
    /// Entity is derived from another entity.
    DerivedFrom = 8,
    /// Entity is part of another entity.
    PartOf = 2,
    /// Person is employed by an organization.
    EmployedBy = 15,
    /// Person has a behavioral facet.
    HasFacet = 16,
    /// Person exists in a world context.
    InWorld = 18,
    /// Claim is scoped to a facet.
    FacetOf = 17,
    /// Relationship is set in a world context.
    SetIn = 19,
    /// Task is a child of another task (tree hierarchy).
    /// Never traversed by PPR (contract `lambda: null`, "Not traversed.");
    /// read via the dedicated `subtree` / `ancestors` tree APIs.
    ChildOf = 6,
    /// Task is assigned to a machine for execution.
    /// Never traversed by PPR (contract `lambda: null`, "Not traversed.").
    AssignedTo = 7,
}

impl EdgeKind {
    /// Returns the default STORED edge weight for this edge kind (the legacy
    /// `pprWeight` prior of the contract's `edgeKinds` table).
    ///
    /// This is NOT the PPR traversal multiplier: per-kind traversal budgets
    /// are the λ_τ table (`ppr::lambda_for_kind`), which deliberately differs
    /// from this prior for the five world-model kinds, and `ChildOf` /
    /// `AssignedTo` are never traversed by PPR regardless of the weight
    /// stored on their edges.
    pub fn default_weight(self) -> f32 {
        match self {
            Self::BelongsTo => 1.0,
            Self::ParticipatesIn => 1.0,
            Self::Attached => 0.8,
            Self::AuthoredBy => 0.9,
            Self::Mentions => 0.6,
            Self::About => 0.5,
            Self::Supports => 1.0,
            Self::Opposes => 0.0,
            Self::ClaimOf => 1.0,
            Self::ScopedTo => 0.7,
            Self::Supersedes => 0.3,
            Self::DerivedFrom => 0.2,
            Self::PartOf => 0.8,
            Self::EmployedBy => 0.8,
            Self::HasFacet => 0.7,
            Self::InWorld => 0.7,
            Self::FacetOf => 0.7,
            Self::SetIn => 0.7,
            Self::ChildOf => 1.0,
            Self::AssignedTo => 0.8,
        }
    }

    /// Converts a raw discriminant into an edge kind.
    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::AuthoredBy),
            1 => Some(Self::ScopedTo),
            2 => Some(Self::PartOf),
            3 => Some(Self::Supersedes),
            4 => Some(Self::BelongsTo),
            5 => Some(Self::ClaimOf),
            6 => Some(Self::ChildOf),
            7 => Some(Self::AssignedTo),
            8 => Some(Self::DerivedFrom),
            9 => Some(Self::Mentions),
            10 => Some(Self::About),
            11 => Some(Self::Supports),
            12 => Some(Self::Opposes),
            13 => Some(Self::ParticipatesIn),
            14 => Some(Self::Attached),
            15 => Some(Self::EmployedBy),
            16 => Some(Self::HasFacet),
            17 => Some(Self::FacetOf),
            18 => Some(Self::InWorld),
            19 => Some(Self::SetIn),
            _ => None,
        }
    }
}

/// Storage layout class for an edge value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeValueLayout {
    Structural,
    SemanticBare,
    SemanticProvenanced,
}

impl EdgeValueLayout {
    #[must_use]
    pub const fn bytes(self) -> usize {
        match self {
            Self::Structural => EDGE_VALUE_STRUCTURAL_LEN,
            Self::SemanticBare => EDGE_VALUE_SEMANTIC_LEN,
            Self::SemanticProvenanced => EDGE_VALUE_SEMANTIC_PROVENANCED_LEN,
        }
    }

    fn from_len(len: usize) -> Option<Self> {
        match len {
            EDGE_VALUE_STRUCTURAL_LEN => Some(Self::Structural),
            EDGE_VALUE_SEMANTIC_LEN => Some(Self::SemanticBare),
            EDGE_VALUE_SEMANTIC_PROVENANCED_LEN => Some(Self::SemanticProvenanced),
            _ => None,
        }
    }
}

/// Hot confirmation flag cached on a 26-byte semantic-provenanced edge.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeConfirmationStatus {
    Proposed = 0,
    Confirmed = 1,
    Disputed = 2,
    Retracted = 3,
}

impl EdgeConfirmationStatus {
    fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Proposed),
            1 => Some(Self::Confirmed),
            2 => Some(Self::Disputed),
            3 => Some(Self::Retracted),
            _ => None,
        }
    }
}

/// Hot actor-class flag cached on a 26-byte semantic-provenanced edge.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeActorClass {
    Human = 0,
    Agent = 1,
    System = 2,
}

impl EdgeActorClass {
    fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Human),
            1 => Some(Self::Agent),
            2 => Some(Self::System),
            _ => None,
        }
    }
}

/// Two hot provenance flags derived from the `edge.provenance` Claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdgeProvenanceFlags {
    pub confirmation_status: EdgeConfirmationStatus,
    pub actor_class: EdgeActorClass,
}

/// Decoded fixed-width edge value fields.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DecodedEdgeValue {
    pub layout: EdgeValueLayout,
    pub weight: f32,
    pub created_at: u64,
    pub vad: Option<Vad>,
    pub provenance: Option<EdgeProvenanceFlags>,
}

/// Selects the value layout for writes. Reads dispatch on value length.
pub(crate) fn edge_value_layout_for_kind(
    kind: EdgeKind,
    has_provenance_claim: bool,
) -> EdgeValueLayout {
    match kind {
        EdgeKind::AuthoredBy
        | EdgeKind::ScopedTo
        | EdgeKind::PartOf
        | EdgeKind::Supersedes
        | EdgeKind::BelongsTo
        | EdgeKind::ClaimOf
        | EdgeKind::ChildOf
        | EdgeKind::AssignedTo
        | EdgeKind::DerivedFrom => EdgeValueLayout::Structural,
        EdgeKind::Mentions
        | EdgeKind::About
        | EdgeKind::Supports
        | EdgeKind::Opposes
        | EdgeKind::ParticipatesIn
        | EdgeKind::Attached
        | EdgeKind::EmployedBy
        | EdgeKind::HasFacet
        | EdgeKind::FacetOf
        | EdgeKind::InWorld
        | EdgeKind::SetIn => {
            if has_provenance_claim {
                EdgeValueLayout::SemanticProvenanced
            } else {
                EdgeValueLayout::SemanticBare
            }
        }
    }
}

/// Bi-temporal interval represented as UNIX timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeRange {
    /// Inclusive start timestamp.
    pub start: u64,
    /// Inclusive end timestamp.
    pub end: u64,
}

/// HNSW configuration values.
///
/// The distance metric and index structure are fixed by the storage contract
/// and persisted as compatibility tags, not exposed as runtime tuning knobs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HnswConfig {
    /// Maximum neighbors per node in layer 0.
    pub m_max_0: usize,
    /// Beam width used during graph construction.
    pub ef_construction: usize,
    /// Beam width used during search. Search-time only; not part of persisted
    /// HNSW compatibility metadata.
    pub ef_search: usize,
}

impl Default for HnswConfig {
    fn default() -> Self {
        Self {
            m_max_0: 64,
            ef_construction: 200,
            ef_search: 128,
        }
    }
}

/// Vault runtime configuration.
///
/// The struct is `#[non_exhaustive]`, so downstream callers cannot build it
/// with a struct literal. Use one of the presets (`VaultConfig::device()`
/// or `VaultConfig::server()`, or `VaultConfig::default()` which aliases
/// `device()`) and mutate fields as needed:
///
/// ```
/// # use oneiron::VaultConfig;
/// let mut cfg = VaultConfig::default();
/// cfg.dimensions = 768;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VaultConfig {
    /// Embedding vector dimension.
    pub dimensions: usize,
    /// Embedding model identifier used for vector compatibility checks.
    ///
    /// `None` is allowed only for genuinely vector-less vaults. Once vector
    /// or HNSW data exists, opening the vault requires `Some` with the same
    /// model identifier stored on disk, and vector writes require a stamped
    /// model identity before the first vector is committed.
    pub embedding_model: Option<String>,
    /// LMDB map size in bytes.
    pub map_size: usize,
    /// Maximum LMDB reader slots.
    pub max_readers: u32,
    /// HNSW tuning configuration.
    pub hnsw: HnswConfig,
    /// Text analyzer configuration (plan ONE-317 §2.3).
    pub text_analyzer: TextAnalyzerConfig,
    /// Roots probed at open time for per-language dictionaries
    /// (`<path>/ja/system.dic`, `<path>/ko/system.dic`,
    /// `<path>/zh/jieba.dict.utf8`). First-found wins per-language; missing
    /// dicts silently downgrade the affected language to Portable mode.
    ///
    /// **Security.** Every path here is opened and (for Sudachi/jieba)
    /// read in full at `Vault::open`. Callers MUST only include paths they
    /// trust — e.g. the iOS app bundle's `Resources/` directory, or a
    /// packager-controlled cache directory. Do NOT pass user-uploaded
    /// directories, network mounts, or world-writable locations: a hostile
    /// dict file can drive Sudachi / jieba / Lindera into unexpected
    /// behavior, and the dict-bytes hash is then baked into the LMDB
    /// analyzer manifest, silently pinning the vault to that dict.
    pub dict_search_paths: Vec<PathBuf>,
    /// Skip the text-index manifest handshake at [`crate::Vault::open`] so the
    /// caller can reach [`crate::MaintenanceBuilder::clear_text_index`]
    /// after a dict swap or BM25 field-schema change. Without this escape
    /// hatch, [`crate::Error::IncompatibleAnalyzer`] and
    /// [`crate::Error::Bm25FieldSchemaChanged`] trap the user before any
    /// `Vault` exists to call `.maintain()` on.
    ///
    /// Only use this to immediately run `clear_text_index`. On a populated
    /// vault, [`crate::Vault::open`] marks the text index untrusted and
    /// [`crate::Vault::search_text`] (and the pipeline / context_pack
    /// callers that go through the same internal trust gate)
    /// returns [`crate::Error::CorruptedIndex`] until the clear commits.
    pub skip_text_index_manifest_check: bool,
}

/// Text analyzer configuration. Kept minimal in v1 — the full analyzer
/// manifest (normalization policy, per-channel schema, lang modes) is
/// computed from dict discovery at open time and stored in the vault's
/// on-disk manifest. Fields here cover caller-controllable knobs only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TextAnalyzerConfig {}

/// Per-call overrides for `BatchBuilder::text`. Reserved; v1 ignores all
/// fields but the struct is public so downstream can adopt without a
/// minor-version bump later.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TextIndexOptions {
    /// Explicit language hint for this batch of text fields. Overrides
    /// `whichlang` detection on Latin/Cyrillic/Greek runs and the
    /// DualHanFallback decision on Han runs. Unambiguous-script runs
    /// (Hiragana, Katakana, Hangul, Hebrew, Thai, Lao, Khmer, Myanmar)
    /// route by their own script class regardless of this hint — the
    /// script is the stronger signal.
    pub language_hint: Option<crate::analyzer::LanguageHint>,
}

impl Default for VaultConfig {
    /// Aliases `VaultConfig::device()` — the common default. Call
    /// `VaultConfig::server()` explicitly if you want the server preset.
    fn default() -> Self {
        Self::device()
    }
}

impl VaultConfig {
    /// Returns a device-optimized preset.
    #[must_use]
    pub fn device() -> Self {
        Self {
            dimensions: 1024,
            embedding_model: None,
            map_size: 1 << 30,
            max_readers: 126,
            hnsw: HnswConfig::default(),
            text_analyzer: TextAnalyzerConfig::default(),
            dict_search_paths: Vec::new(),
            skip_text_index_manifest_check: false,
        }
    }

    /// Returns a server-optimized preset.
    #[must_use]
    pub fn server() -> Self {
        Self {
            dimensions: 4096,
            embedding_model: None,
            map_size: 1 << 33,
            max_readers: 126,
            hnsw: HnswConfig::default(),
            text_analyzer: TextAnalyzerConfig::default(),
            dict_search_paths: Vec::new(),
            skip_text_index_manifest_check: false,
        }
    }
}

/// A scored entity result.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScoredEntity {
    /// Entity identifier.
    pub id: EntityId,
    /// Ranking score.
    pub score: f32,
}

/// Retrieval signal type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Signal {
    Vector,
    Text,
    Phonetic,
    Temporal,
    Ppr,
}

/// Temporal query precision controls sigmoid width for temporal scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TemporalGranularity {
    Exact,
    Hour,
    Day,
    Week,
    Month,
    Season,
    Year,
    Vague,
}

impl TemporalGranularity {
    /// Returns the scoring sigma in seconds for this granularity.
    pub fn sigma_secs(self) -> u64 {
        match self {
            Self::Exact => 3_600,
            Self::Hour => 14_400,
            Self::Day => 86_400,
            Self::Week => 604_800,
            Self::Month => 2_592_000,
            Self::Season => 7_776_000,
            Self::Year => 15_552_000,
            Self::Vague => 31_536_000,
        }
    }
}

/// Temporal anchor intent for bitemporal scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum TemporalAnchorMode {
    Occurred,
    Learned,
    Both,
    #[default]
    Auto,
}

/// Output serialization format for context packing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum PackFormat {
    #[default]
    Json,
    Yaml,
    Toon,
    Markdown,
    Plaintext,
}

/// Field selection profile for context packing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum FieldProfile {
    Minimal,
    #[default]
    Standard,
    Full,
}

/// Hydrated entity with decoded fields, edges, and provenance.
#[derive(Debug, Clone)]
pub struct ContextEntity {
    pub id: EntityId,
    pub short_id: String,
    pub content_hash: u8,
    pub entity_type: u8,
    pub score: f32,
    pub fields: Option<HashMap<String, serde_json::Value>>,
    pub edges: Option<Vec<EdgeInfo>>,
    pub vector: Option<Vec<f32>>,
}

/// Edge info for hydrated context entities.
#[derive(Debug, Clone)]
pub struct EdgeInfo {
    pub kind: EdgeKind,
    pub target: EntityId,
    pub target_short_id: Option<String>,
    pub weight: f32,
    pub created_at: u64,
    pub vad: Option<Vad>,
    pub provenance: Option<EdgeProvenanceFlags>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Vad {
    pub valence: f32,
    pub arousal: f32,
    pub dominance: f32,
}

/// VAD coordinate rejected during validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VadComponent {
    Valence,
    Arousal,
    Dominance,
}

impl Vad {
    pub const NEUTRAL: Self = Self {
        valence: 0.0,
        arousal: 0.0,
        dominance: 0.0,
    };

    pub fn is_finite(&self) -> bool {
        self.non_finite_component().is_none()
    }

    pub fn is_in_range(&self) -> bool {
        self.out_of_range_component().is_none()
    }

    pub(crate) fn invalid_component(&self) -> Option<(VadComponent, f32)> {
        self.non_finite_component()
            .or_else(|| self.out_of_range_component())
    }

    fn non_finite_component(&self) -> Option<(VadComponent, f32)> {
        if !self.valence.is_finite() {
            return Some((VadComponent::Valence, self.valence));
        }
        if !self.arousal.is_finite() {
            return Some((VadComponent::Arousal, self.arousal));
        }
        if !self.dominance.is_finite() {
            return Some((VadComponent::Dominance, self.dominance));
        }
        None
    }

    fn out_of_range_component(&self) -> Option<(VadComponent, f32)> {
        if !(-1.0..=1.0).contains(&self.valence) {
            return Some((VadComponent::Valence, self.valence));
        }
        if !(0.0..=1.0).contains(&self.arousal) {
            return Some((VadComponent::Arousal, self.arousal));
        }
        if !(0.0..=1.0).contains(&self.dominance) {
            return Some((VadComponent::Dominance, self.dominance));
        }
        None
    }
}

fn read_f32_le(value: &[u8], offset: usize) -> crate::error::Result<f32> {
    let bytes = value
        .get(offset..offset + 4)
        .and_then(|b| b.try_into().ok())
        .ok_or(crate::error::Error::CorruptedIndex("edge value"))?;
    Ok(f32::from_le_bytes(bytes))
}

fn read_u64_le(value: &[u8], offset: usize) -> crate::error::Result<u64> {
    let bytes = value
        .get(offset..offset + 8)
        .and_then(|b| b.try_into().ok())
        .ok_or(crate::error::Error::CorruptedIndex("edge value"))?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_vad(value: &[u8]) -> crate::error::Result<Vad> {
    Ok(Vad {
        valence: read_f32_le(value, 12)?,
        arousal: read_f32_le(value, 16)?,
        dominance: read_f32_le(value, 20)?,
    })
}

pub(crate) fn decode_edge_value(value: &[u8]) -> crate::error::Result<DecodedEdgeValue> {
    let layout = EdgeValueLayout::from_len(value.len())
        .ok_or(crate::error::Error::CorruptedIndex("edge value"))?;
    let weight = read_f32_le(value, 0)?;
    if !weight.is_finite() {
        return Err(crate::error::Error::CorruptedIndex("edge value"));
    }
    let created_at = read_u64_le(value, 4)?;
    let vad = match layout {
        EdgeValueLayout::Structural => None,
        EdgeValueLayout::SemanticBare | EdgeValueLayout::SemanticProvenanced => {
            let vad = read_vad(value)?;
            if !vad.is_finite() || !vad.is_in_range() {
                return Err(crate::error::Error::CorruptedIndex("edge value"));
            }
            Some(vad)
        }
    };
    let provenance = match layout {
        EdgeValueLayout::SemanticProvenanced => {
            let confirmation_status = EdgeConfirmationStatus::try_from_u8(value[24])
                .ok_or(crate::error::Error::CorruptedIndex("edge value"))?;
            let actor_class = EdgeActorClass::try_from_u8(value[25])
                .ok_or(crate::error::Error::CorruptedIndex("edge value"))?;
            Some(EdgeProvenanceFlags {
                confirmation_status,
                actor_class,
            })
        }
        EdgeValueLayout::Structural | EdgeValueLayout::SemanticBare => None,
    };

    Ok(DecodedEdgeValue {
        layout,
        weight,
        created_at,
        vad,
        provenance,
    })
}

pub(crate) fn decode_edge_value_for_kind(
    kind: EdgeKind,
    value: &[u8],
) -> crate::error::Result<DecodedEdgeValue> {
    let decoded = decode_edge_value(value)?;
    let legal = match edge_value_layout_for_kind(kind, false) {
        EdgeValueLayout::Structural => decoded.layout == EdgeValueLayout::Structural,
        EdgeValueLayout::SemanticBare | EdgeValueLayout::SemanticProvenanced => matches!(
            decoded.layout,
            EdgeValueLayout::SemanticBare | EdgeValueLayout::SemanticProvenanced
        ),
    };

    if !legal {
        return Err(crate::error::Error::CorruptedIndex("edge value"));
    }

    Ok(decoded)
}

pub(crate) fn encode_edge_value(
    kind: EdgeKind,
    weight: f32,
    created_at: u64,
    vad: Vad,
    provenance: Option<EdgeProvenanceFlags>,
) -> crate::error::Result<Vec<u8>> {
    if !weight.is_finite() {
        return Err(crate::error::Error::InvalidEdgeWeight { value: weight });
    }
    if let Some((component, value)) = vad.invalid_component() {
        return Err(crate::error::Error::InvalidVad { component, value });
    }
    if provenance.is_some()
        && edge_value_layout_for_kind(kind, false) == EdgeValueLayout::Structural
    {
        return Err(crate::error::Error::InvariantViolation(
            "structural edges do not carry provenance hot flags",
        ));
    }
    if vad != Vad::NEUTRAL && edge_value_layout_for_kind(kind, false) == EdgeValueLayout::Structural
    {
        return Err(crate::error::Error::InvariantViolation(
            "structural edges do not carry VAD",
        ));
    }

    let layout = edge_value_layout_for_kind(kind, provenance.is_some());
    let mut value = vec![0_u8; layout.bytes()];
    value[0..4].copy_from_slice(&weight.to_le_bytes());
    value[4..12].copy_from_slice(&created_at.to_le_bytes());

    match layout {
        EdgeValueLayout::Structural => {}
        EdgeValueLayout::SemanticBare | EdgeValueLayout::SemanticProvenanced => {
            value[12..16].copy_from_slice(&vad.valence.to_le_bytes());
            value[16..20].copy_from_slice(&vad.arousal.to_le_bytes());
            value[20..24].copy_from_slice(&vad.dominance.to_le_bytes());
        }
    }

    if let Some(flags) = provenance {
        value[24] = flags.confirmation_status as u8;
        value[25] = flags.actor_class as u8;
    }

    Ok(value)
}

/// Stats about the context pack query.
#[derive(Debug, Clone)]
pub struct PackStats {
    pub candidates_considered: usize,
    pub signals_used: Vec<Signal>,
    pub query_time_us: u64,
    pub entities_hydrated: usize,
    pub neighbors_hydrated: usize,
}

/// A fully hydrated context pack ready for serialization or programmatic use.
#[derive(Debug, Clone)]
pub struct ContextPack {
    pub results: Vec<ContextEntity>,
    pub neighbors: Vec<ContextEntity>,
    pub stats: PackStats,
}

/// Token budget allocation across entity types.
#[derive(Debug, Clone, Copy)]
pub struct TokenAllocation {
    pub claims: f32,
    pub turns: f32,
    pub summaries: f32,
    pub other: f32,
}

impl Default for TokenAllocation {
    fn default() -> Self {
        Self {
            claims: 0.45,
            turns: 0.10,
            summaries: 0.25,
            other: 0.20,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_id_hex_round_trip() {
        let id = EntityId::now();
        let hex = id.to_hex();
        assert_eq!(hex.len(), 32);
        let recovered = EntityId::from_hex(&hex).unwrap();
        assert_eq!(id, recovered);
    }

    #[test]
    fn entity_id_from_hex_rejects_invalid() {
        assert!(EntityId::from_hex("too_short").is_err());
        assert!(EntityId::from_hex("gggggggggggggggggggggggggggggggg").is_err());
    }
}
