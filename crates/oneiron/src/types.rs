use std::collections::{BTreeMap, HashMap};
use std::io::Cursor;
use std::path::PathBuf;

use rmpv::Value;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};

#[path = "companion.rs"]
pub mod companion;
pub use companion::{
    COMPANION_RECORD_BODY_KEYS, COMPANION_RECORD_SCHEMA_VERSION, COMPANION_REGISTER_PACK_ID,
    COMPANION_REGISTER_SHORT_ID_PREFIX, COMPANION_TASK_JOB_KIND, COMPANION_TASK_PAYLOAD_KEYS,
    COMPANION_TASK_PAYLOAD_SCHEMA_VERSION, ClaimCompanionTask, ClaimCompanionTaskOutcome,
    CompanionExportClassification, CompanionExpression, CompanionExpressionRegister,
    CompanionProvenance, CompanionQueue, CompanionRecord, CompanionRecordKey, CompanionRecordKind,
    CompanionRegister, CompanionScope, CompanionScopeResolution, CompanionScopeResolutionSource,
    CompanionSubject, CompanionTask, CompanionTaskKind, CompanionTaskStatus, CompleteCompanionTask,
    CompleteCompanionTaskOutcome, ENTITY_TYPE_COMPANION_REGISTER, EndCompanionRelationship,
    EndCompanionRelationshipOutcome, EnqueueCompanionTask, EnqueueCompanionTaskOutcome,
    FailCompanionTask, FailCompanionTaskOutcome, RetryCompanionTask, RetryCompanionTaskOutcome,
    companion_value_from_json, companion_value_to_json, decode_companion_record_body,
    decode_companion_task_payload, encode_companion_record_body, encode_companion_task_payload,
};

#[path = "psych_profile.rs"]
pub mod psych_profile;
pub use psych_profile::{
    PSYCH_PROFILE_BODY_KEYS, PSYCH_PROFILE_SCHEMA_VERSION, PsychProfile, PsychProfileConfidence,
    PsychProfileSnapshotStatus, PsychProfileStaleReason, PsychProfileState,
    decode_psych_profile_body, encode_psych_profile_body,
};

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
/// OF-334 AgentDefinition entity (AGENT-1, ONE-1443). A saved, host-agnostic
/// composition record (skills / connectors / code-mode MCPs / model tier /
/// scope / optional prompt) with structural CRUD and an update gate — SKILL's
/// shape, so it is a CORE StructuralKind. Short-ID prefix `ag`.
pub const ENTITY_TYPE_AGENT_DEF: u8 = 17;
pub const ENTITY_TYPE_TASK_LIST: u8 = 80;
pub const ENTITY_TYPE_TASK: u8 = 81;
pub const ENTITY_TYPE_MACHINE: u8 = 82;
pub const ENTITY_TYPE_CODE_ARTIFACT: u8 = 83;
pub const ENTITY_TYPE_CODE_SYMBOL: u8 = 84;
/// OF-368 D1 (ARTL-1) versioned blob artifact for foreign binary (office)
/// files. Rides the OF-320 artifact model: append-only version chain in
/// `vault_meta`, content-addressed ASSET bytes, `blob.version` LEDGER claim
/// per version. A blob artifact is not a code artifact — kind = shape
/// (DEC-0005 §7), so CODE_ARTIFACT (83) reuse was rejected.
pub const ENTITY_TYPE_BLOB_ARTIFACT: u8 = 85;
pub const ENTITY_TYPE_REDACTION_AUDIT: u8 = 120;
/// MODEL substrate entity (ONE-1138, ratified): engine-authored maintenance
/// kind — "written when a substrate first appears in a write path". Public
/// puts are rejected with `MaintenanceKindNotWritable`. Short-ID prefix
/// `mo` is RESERVED. MACHINE (82) reuse was REJECTED — kind = shape
/// (DEC-0005 §7): a model substrate is not a device.
pub const ENTITY_TYPE_MODEL: u8 = 121;
/// AUTHORITY_LOG entry (ONE-1324). Engine-authored maintenance kind for the
/// fold-verified vault authority roster; public puts are rejected with
/// `MaintenanceKindNotWritable`.
pub const ENTITY_TYPE_AUTHORITY_LOG: u8 = 122;
/// DEC-0005 PolicyManifestV1 entity. Engine-authored maintenance kind used by
/// the Gate resolver; public puts are rejected with
/// `MaintenanceKindNotWritable`.
pub const ENTITY_TYPE_POLICY_MANIFEST: u8 = 123;
/// FED-001 FederationGrant entity. Engine-authored maintenance kind for
/// shared-vault membership records.
pub const ENTITY_TYPE_FEDERATION_GRANT: u8 = 124;
// Byte 125 is reserved for future CONNECTION_RECORD maintenance records.
// Byte 126 is reserved for future DIAGNOSTIC maintenance records.
// Byte 127 is reserved for future FEDERATION_KEY_ENVELOPE maintenance records.
// These bytes are intentionally unregistered until those substrates land, so
// they remain rejected with `InvalidEntityType` on write paths.
/// EIRI-004 AccessGrant entity. Engine-authored maintenance kind for scoped
/// companion control-plane access records.
pub const ENTITY_TYPE_ACCESS_GRANT: u8 = 128;
/// AEI-006 PsychProfile snapshot entity. Engine-authored maintenance kind for
/// derived profile mirror snapshots keyed by source revision ids.
pub const ENTITY_TYPE_PSYCH_PROFILE: u8 = 129;
// Byte 130 is reserved for future SUSPICIOUS_WAKE maintenance records.
// It is intentionally unregistered until that substrate lands, so it remains
// rejected with `InvalidEntityType` on write paths.
/// OF-347 ChannelIdentity entity. Engine-authored maintenance kind for
/// vault-resident agent/channel addressability records.
pub const ENTITY_TYPE_CHANNEL_IDENTITY: u8 = 131;
/// OF-347 CounterpartyContact entity. Engine-authored maintenance kind for
/// per-(identity, counterparty) contact and consent records.
pub const ENTITY_TYPE_COUNTERPARTY_CONTACT: u8 = 132;
/// OF-367 StandingOutboundGrant entity. Engine-authored maintenance kind for
/// ask-card and bundle-approval outbound consent grants.
pub const ENTITY_TYPE_OUTBOUND_GRANT: u8 = 133;
/// OF-325 PersonaSnapshotExport entity. Engine-authored maintenance kind
/// recording each consent-gated persona snapshot export (mode A artifact);
/// projects into the receipt family as a Share receipt carrying the
/// persona_compile_stamp.
pub const ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT: u8 = 134;

pub(crate) const TASK_BODY_ROLE_KEY: &str = "role";

/// Pinned TASK role byte for the productivity pack.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskRole {
    Task = 1,
    Goal = 2,
    Milestone = 3,
    Habit = 4,
    HabitCheckin = 5,
}

impl TaskRole {
    pub const ALL: [Self; 5] = [
        Self::Task,
        Self::Goal,
        Self::Milestone,
        Self::Habit,
        Self::HabitCheckin,
    ];

    #[must_use]
    pub const fn role_byte(self) -> u8 {
        match self {
            Self::Task => 1,
            Self::Goal => 2,
            Self::Milestone => 3,
            Self::Habit => 4,
            Self::HabitCheckin => 5,
        }
    }

    #[must_use]
    pub const fn from_role_byte(role: u8) -> Option<Self> {
        match role {
            1 => Some(Self::Task),
            2 => Some(Self::Goal),
            3 => Some(Self::Milestone),
            4 => Some(Self::Habit),
            5 => Some(Self::HabitCheckin),
            _ => None,
        }
    }
}

#[cfg(test)]
pub(crate) fn task_body_for_test(role: TaskRole) -> Vec<u8> {
    let value = Value::Map(vec![(
        Value::from(TASK_BODY_ROLE_KEY),
        Value::from(role.role_byte()),
    )]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &value)
        .expect("writing MessagePack TASK body to Vec cannot fail");
    bytes
}

pub(crate) fn task_role_from_body_bytes(bytes: &[u8]) -> crate::error::Result<TaskRole> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| crate::error::Error::InvalidTaskBody("body is not valid MessagePack"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(crate::error::Error::InvalidTaskBody(
            "trailing bytes after body map",
        ));
    }
    let entries = value.as_map().ok_or(crate::error::Error::InvalidTaskBody(
        "body must be a MessagePack map",
    ))?;
    let mut role = None;
    for (key, value) in entries {
        let key = key.as_str().ok_or(crate::error::Error::InvalidTaskBody(
            "body keys must be strings",
        ))?;
        if key != TASK_BODY_ROLE_KEY {
            continue;
        }
        if role.is_some() {
            return Err(crate::error::Error::InvalidTaskBody(
                "duplicate task role key",
            ));
        }
        let role_byte = value
            .as_u64()
            .and_then(|raw| u8::try_from(raw).ok())
            .ok_or(crate::error::Error::InvalidTaskBody(
                "task role must be a byte",
            ))?;
        role = Some(
            TaskRole::from_role_byte(role_byte)
                .ok_or(crate::error::Error::InvalidTaskBody("unknown task role"))?,
        );
    }
    role.ok_or(crate::error::Error::InvalidTaskBody("missing task role"))
}

/// Registry classification mirroring the contracts.ts §1
/// `EntityClassification` enum: `"semantic" | "core" | "pack" | "maintenance"`.
///
/// CLAIM (byte 0) is the single SEMANTIC type (ARCH-0003) and deliberately
/// NOT a StructuralKind; core and pack kinds ARE StructuralKinds; maintenance
/// records (REDACTION_AUDIT=120, MODEL=121, AUTHORITY_LOG=122,
/// POLICY_MANIFEST=123, FEDERATION_GRANT=124, CONNECTION_RECORD=125 reserved,
/// DIAGNOSTIC=126 reserved, FEDERATION_KEY_ENVELOPE=127 reserved,
/// ACCESS_GRANT=128, PSYCH_PROFILE=129, SUSPICIOUS_WAKE=130 reserved) are
/// engine-authored records or reserved maintenance substrates, also not
/// StructuralKinds. CHANNEL_IDENTITY=131 and COUNTERPARTY_CONTACT=132 are
/// engine-authored maintenance kinds for OF-347; OUTBOUND_GRANT=133 is the
/// OF-367 standing consent-grant substrate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntityClassification {
    /// `"semantic"` — CLAIM, the single subject·predicate·value type.
    Semantic,
    /// `"core"` — universal CORE StructuralKinds (TURN … NOTIFICATION).
    Core,
    /// `"pack"` — pack-registered StructuralKinds (TASK_LIST / TASK /
    /// MACHINE / CODE_ARTIFACT today; other pack kinds get bytes at pack
    /// registration).
    Pack,
    /// `"maintenance"` — system/maintenance records.
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
    /// TASK=81, MACHINE=82, CODE_ARTIFACT=83; NOTE assigned at pack
    /// registration).
    Productivity,
    /// Bytes `100–119` — "CRM pack".
    Crm,
    /// Bytes `120–255` — "Induced / dynamic / maintenance"
    /// (REDACTION_AUDIT=120, MODEL=121, AUTHORITY_LOG=122 reserved,
    /// POLICY_MANIFEST=123, FEDERATION_GRANT=124, CONNECTION_RECORD=125
    /// reserved, DIAGNOSTIC=126 reserved, FEDERATION_KEY_ENVELOPE=127
    /// reserved, ACCESS_GRANT=128, PSYCH_PROFILE=129, SUSPICIOUS_WAKE=130
    /// reserved, CHANNEL_IDENTITY=131, COUNTERPARTY_CONTACT=132,
    /// OUTBOUND_GRANT=133, runtime-induced and tenant-custom kinds).
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
/// has a band, but is rejected by `validate_entity_type` on every write
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
/// NOT a StructuralKind; maintenance records (REDACTION_AUDIT = 120,
/// MODEL = 121, AUTHORITY_LOG = 122, POLICY_MANIFEST = 123,
/// FEDERATION_GRANT = 124, CONNECTION_RECORD = 125 reserved,
/// DIAGNOSTIC = 126 reserved, FEDERATION_KEY_ENVELOPE = 127 reserved,
/// ACCESS_GRANT = 128, PSYCH_PROFILE = 129, SUSPICIOUS_WAKE = 130 reserved,
/// CHANNEL_IDENTITY = 131, COUNTERPARTY_CONTACT = 132, OUTBOUND_GRANT = 133)
/// are not StructuralKinds either. The reserved bytes are unregistered.
/// Only registered `core` and `pack` kinds qualify. Unregistered bytes return
/// `false` here AND remain rejected by `validate_entity_type` on every write
/// path (unchanged behavior).
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuralKindRegistration {
    pub type_byte: u8,
    pub short_id_prefix: String,
    pub band: TypeByteBand,
    pub pack: String,
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
        kind: "AGENT_DEF",
        type_byte: ENTITY_TYPE_AGENT_DEF,
        short_id_prefix: Some("ag"),
        classification: EntityClassification::Core,
        band: TypeByteBand::Core,
    },
    EntityTypeRegistryEntry {
        kind: "COMPANION_REGISTER",
        type_byte: ENTITY_TYPE_COMPANION_REGISTER,
        short_id_prefix: Some(COMPANION_REGISTER_SHORT_ID_PREFIX),
        classification: EntityClassification::Pack,
        band: TypeByteBand::Companion,
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
        kind: "CODE_ARTIFACT",
        type_byte: ENTITY_TYPE_CODE_ARTIFACT,
        short_id_prefix: Some("cd"),
        classification: EntityClassification::Pack,
        band: TypeByteBand::Productivity,
    },
    EntityTypeRegistryEntry {
        kind: "CODE_SYMBOL",
        type_byte: ENTITY_TYPE_CODE_SYMBOL,
        short_id_prefix: Some("cs"),
        classification: EntityClassification::Pack,
        band: TypeByteBand::Productivity,
    },
    EntityTypeRegistryEntry {
        kind: "BLOB_ARTIFACT",
        type_byte: ENTITY_TYPE_BLOB_ARTIFACT,
        short_id_prefix: Some("ba"),
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
    EntityTypeRegistryEntry {
        kind: "MODEL",
        type_byte: ENTITY_TYPE_MODEL,
        short_id_prefix: Some("mo"),
        classification: EntityClassification::Maintenance,
        band: TypeByteBand::InducedDynamicMaintenance,
    },
    EntityTypeRegistryEntry {
        kind: "AUTHORITY_LOG",
        type_byte: ENTITY_TYPE_AUTHORITY_LOG,
        short_id_prefix: None,
        classification: EntityClassification::Maintenance,
        band: TypeByteBand::InducedDynamicMaintenance,
    },
    EntityTypeRegistryEntry {
        kind: "POLICY_MANIFEST",
        type_byte: ENTITY_TYPE_POLICY_MANIFEST,
        short_id_prefix: None,
        classification: EntityClassification::Maintenance,
        band: TypeByteBand::InducedDynamicMaintenance,
    },
    EntityTypeRegistryEntry {
        kind: "FEDERATION_GRANT",
        type_byte: ENTITY_TYPE_FEDERATION_GRANT,
        short_id_prefix: None,
        classification: EntityClassification::Maintenance,
        band: TypeByteBand::InducedDynamicMaintenance,
    },
    // Byte 125 CONNECTION_RECORD, byte 126 DIAGNOSTIC, and byte 127
    // FEDERATION_KEY_ENVELOPE are reserved and intentionally unregistered.
    EntityTypeRegistryEntry {
        kind: "ACCESS_GRANT",
        type_byte: ENTITY_TYPE_ACCESS_GRANT,
        short_id_prefix: None,
        classification: EntityClassification::Maintenance,
        band: TypeByteBand::InducedDynamicMaintenance,
    },
    EntityTypeRegistryEntry {
        kind: "PSYCH_PROFILE",
        type_byte: ENTITY_TYPE_PSYCH_PROFILE,
        short_id_prefix: None,
        classification: EntityClassification::Maintenance,
        band: TypeByteBand::InducedDynamicMaintenance,
    },
    // Byte 130 SUSPICIOUS_WAKE is reserved and intentionally unregistered.
    EntityTypeRegistryEntry {
        kind: "CHANNEL_IDENTITY",
        type_byte: ENTITY_TYPE_CHANNEL_IDENTITY,
        short_id_prefix: None,
        classification: EntityClassification::Maintenance,
        band: TypeByteBand::InducedDynamicMaintenance,
    },
    EntityTypeRegistryEntry {
        kind: "COUNTERPARTY_CONTACT",
        type_byte: ENTITY_TYPE_COUNTERPARTY_CONTACT,
        short_id_prefix: None,
        classification: EntityClassification::Maintenance,
        band: TypeByteBand::InducedDynamicMaintenance,
    },
    EntityTypeRegistryEntry {
        kind: "OUTBOUND_GRANT",
        type_byte: ENTITY_TYPE_OUTBOUND_GRANT,
        short_id_prefix: None,
        classification: EntityClassification::Maintenance,
        band: TypeByteBand::InducedDynamicMaintenance,
    },
    EntityTypeRegistryEntry {
        kind: "PERSONA_SNAPSHOT_EXPORT",
        type_byte: ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT,
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
    /// The all-zero, all-`0xFF`, and `[entity_type, 0xFF×15]` patterns are
    /// reserved at the public `EntityId` layer. The latter were the pre-ABI-v3
    /// short-id counter sentinel rows (counters now live in `vault_meta`, see
    /// `store::SHORT_ID_COUNTER_KEY_PREFIX`); the reservation is kept so the
    /// legacy patterns can never be hydrated as live entity IDs.
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
        let (chunks, rem) = s.as_bytes().as_chunks::<2>();
        debug_assert!(rem.is_empty());
        for (i, &[hi_byte, lo_byte]) in chunks.iter().enumerate() {
            let hi = hex_nibble(hi_byte).ok_or(crate::error::Error::InvalidKey)?;
            let lo = hex_nibble(lo_byte).ok_or(crate::error::Error::InvalidKey)?;
            bytes[i] = (hi << 4) | lo;
        }
        Self::from_bytes(bytes)
    }
}

/// First leading byte reserved for received foreign world ids.
///
/// Locally authored WORLD ids remain outside this range. Keeping the foreign
/// range distinct lets outbound federation selectors require [`LocalWorldId`]
/// while the inbound/re-federation path can fail closed when raw wire bytes
/// name a received foreign world.
pub const FOREIGN_WORLD_ID_RANGE_START_BYTE: u8 = 0xF0;

/// Returns whether `id` is in the received-foreign WORLD id range.
#[must_use]
pub fn is_foreign_world_id_range(id: EntityId) -> bool {
    id.0[0] >= FOREIGN_WORLD_ID_RANGE_START_BYTE
}

/// WORLD id proven eligible for local outbound sharing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LocalWorldId(EntityId);

impl LocalWorldId {
    /// Creates a local WORLD id wrapper, rejecting the foreign range.
    pub fn from_entity_id(id: EntityId) -> crate::error::Result<Self> {
        if is_foreign_world_id_range(id) {
            return Err(crate::error::Error::InvalidKey);
        }
        Ok(Self(id))
    }

    /// Returns the raw entity id.
    #[must_use]
    pub const fn entity_id(self) -> EntityId {
        self.0
    }
}

impl TryFrom<EntityId> for LocalWorldId {
    type Error = crate::error::Error;

    fn try_from(value: EntityId) -> crate::error::Result<Self> {
        Self::from_entity_id(value)
    }
}

/// WORLD id received from a foreign vault.
///
/// This type intentionally does not convert into [`LocalWorldId`], which keeps
/// A->B->C re-share out of outbound selector construction.
///
/// ```compile_fail
/// use oneiron::sync::SyncSelectorWorld;
/// use oneiron::types::{EntityId, ForeignWorldId};
///
/// let foreign = ForeignWorldId::from_entity_id(
///     EntityId::from_bytes([0xF1; 16]).unwrap(),
/// )
/// .unwrap();
/// let _cannot_reshare = SyncSelectorWorld::World(foreign);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ForeignWorldId(EntityId);

impl ForeignWorldId {
    /// Creates a foreign WORLD id wrapper, accepting only the foreign range.
    pub fn from_entity_id(id: EntityId) -> crate::error::Result<Self> {
        if !is_foreign_world_id_range(id) {
            return Err(crate::error::Error::InvalidKey);
        }
        Ok(Self(id))
    }

    /// Returns the raw entity id.
    #[must_use]
    pub const fn entity_id(self) -> EntityId {
        self.0
    }
}

impl TryFrom<EntityId> for ForeignWorldId {
    type Error = crate::error::Error;

    fn try_from(value: EntityId) -> crate::error::Result<Self> {
        Self::from_entity_id(value)
    }
}

/// Parses a `&[u8]` slice into an `EntityId`, returning
/// `Error::CorruptedIndex(context)` if the length is wrong, or
/// `Error::InvalidKey` if the bytes match a reserved sentinel pattern
/// (legacy short_id counter rows and similar internal patterns that must not
/// be hydrated as live entities). Used by index readers (HNSW neighbor keys,
/// vector keys, `short_ids_reverse` keys, `short_ids` forward values) where a
/// malformed key is on-disk corruption.
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

/// Actor metadata required by [`WriteEnvelope`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteActor {
    entity_ref: EntityId,
    actor_class: EdgeActorClass,
}

impl WriteActor {
    /// Creates a write actor from an entity id plus its caller-asserted class.
    #[must_use]
    pub const fn new(entity_ref: EntityId, actor_class: EdgeActorClass) -> Self {
        Self {
            entity_ref,
            actor_class,
        }
    }

    /// Actor entity reference stamped into candidate writes.
    #[must_use]
    pub const fn entity_ref(self) -> EntityId {
        self.entity_ref
    }

    /// Actor class stamped into candidate writes and supplied to the Gate evaluator.
    #[must_use]
    pub const fn actor_class(self) -> EdgeActorClass {
        self.actor_class
    }
}

/// Opaque provenance payload carried by a [`WriteEnvelope`].
#[derive(Debug, Clone, PartialEq)]
pub struct WriteProvenance {
    value: Value,
}

impl WriteProvenance {
    /// Creates a provenance payload, rejecting an absent (`nil`) value.
    pub fn new(value: Value) -> crate::error::Result<Self> {
        if matches!(value, Value::Nil) {
            return Err(crate::error::Error::InvalidClaimBody(
                "write envelope missing provenance",
            ));
        }

        Ok(Self { value })
    }

    /// Returns the opaque provenance value.
    #[must_use]
    pub fn value(&self) -> &Value {
        &self.value
    }
}

/// Required metadata for writing a [`ClaimCandidate`].
#[derive(Debug, Clone, PartialEq)]
pub struct WriteEnvelope {
    actor: WriteActor,
    source: ClaimSource,
    provenance: WriteProvenance,
    approval: ClaimApprovalStatus,
}

impl WriteEnvelope {
    /// Creates an envelope from already-validated typed fields.
    #[must_use]
    pub fn new(
        actor: WriteActor,
        source: ClaimSource,
        provenance: WriteProvenance,
        approval: ClaimApprovalStatus,
    ) -> Self {
        Self {
            actor,
            source,
            provenance,
            approval,
        }
    }

    /// Creates an envelope from caller-bound optional fields.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidClaimBody`] when any required envelope
    /// axis is absent.
    pub fn try_new(
        actor: Option<WriteActor>,
        source: Option<ClaimSource>,
        provenance: Option<WriteProvenance>,
        approval: Option<ClaimApprovalStatus>,
    ) -> crate::error::Result<Self> {
        let actor = actor.ok_or(crate::error::Error::InvalidClaimBody(
            "write envelope missing actor",
        ))?;
        let source = source.ok_or(crate::error::Error::InvalidClaimBody(
            "write envelope missing source",
        ))?;
        let provenance = provenance.ok_or(crate::error::Error::InvalidClaimBody(
            "write envelope missing provenance",
        ))?;
        let approval = approval.ok_or(crate::error::Error::InvalidClaimBody(
            "write envelope missing approval",
        ))?;

        Ok(Self::new(actor, source, provenance, approval))
    }

    /// Actor stamped into candidate writes.
    #[must_use]
    pub const fn actor(&self) -> WriteActor {
        self.actor
    }

    /// Provenance source stamped into candidate writes.
    #[must_use]
    pub const fn source(&self) -> ClaimSource {
        self.source
    }

    /// Opaque provenance payload stamped into candidate writes.
    #[must_use]
    pub fn provenance(&self) -> &WriteProvenance {
        &self.provenance
    }

    /// Explicit approval state stamped into candidate writes.
    #[must_use]
    pub const fn approval(&self) -> ClaimApprovalStatus {
        self.approval
    }
}

/// Caller-emitted claim data before write-path envelope stamping.
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimCandidate {
    predicate: String,
    subject: ClaimSubject,
    value: Value,
    confidence: f32,
    salience: Option<f32>,
    evidence: Option<Value>,
    valid_from: Option<u64>,
    valid_to: Option<u64>,
    world: Option<EntityId>,
    scope: Option<Value>,
    stale: bool,
}

impl ClaimCandidate {
    /// Creates candidate claim data. Metadata axes are supplied by
    /// [`WriteEnvelope`] at write time.
    #[must_use]
    pub fn new(
        predicate: impl Into<String>,
        subject: ClaimSubject,
        value: Value,
        confidence: f32,
    ) -> Self {
        Self {
            predicate: predicate.into(),
            subject,
            value,
            confidence,
            salience: None,
            evidence: None,
            valid_from: None,
            valid_to: None,
            world: None,
            scope: None,
            stale: false,
        }
    }

    /// Adds candidate-local salience.
    #[must_use]
    pub fn with_salience(mut self, salience: f32) -> Self {
        self.salience = Some(salience);
        self
    }

    /// Adds candidate-local evidence; the envelope keeps its own provenance stamp.
    #[must_use]
    pub fn with_evidence(mut self, evidence: Value) -> Self {
        self.evidence = Some(evidence);
        self
    }

    /// Adds an optional validity window.
    #[must_use]
    pub fn with_validity(mut self, valid_from: Option<u64>, valid_to: Option<u64>) -> Self {
        self.valid_from = valid_from;
        self.valid_to = valid_to;
        self
    }

    /// Adds an optional world scope.
    #[must_use]
    pub fn with_world(mut self, world: EntityId) -> Self {
        self.world = Some(world);
        self
    }

    /// Adds an optional opaque scope value.
    #[must_use]
    pub fn with_scope(mut self, scope: Value) -> Self {
        self.scope = Some(scope);
        self
    }

    /// Marks the candidate as stale derived data.
    #[must_use]
    pub fn with_stale(mut self, stale: bool) -> Self {
        self.stale = stale;
        self
    }

    pub(crate) const fn subject(&self) -> ClaimSubject {
        self.subject
    }

    pub(crate) fn value_str(&self) -> Option<&str> {
        self.value.as_str()
    }

    pub(crate) fn into_claim_body(self, envelope: &WriteEnvelope) -> ClaimBody {
        let mut body = ClaimBody::new(
            self.predicate,
            self.subject,
            self.value,
            self.confidence,
            envelope.approval(),
            ClaimLifecycleStatus::Active,
        );
        body.salience = self.salience;
        body.evidence = Some(write_envelope_evidence(envelope, self.evidence));
        body.valid_from = self.valid_from;
        body.valid_to = self.valid_to;
        body.source = Some(envelope.source());
        body.world = self.world;
        body.scope = self.scope;
        body.stale = self.stale;
        body
    }
}

pub(crate) const WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY: &str = "actor_entity_ref";
pub(crate) const WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY: &str = "actor_class";
pub(crate) const WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY: &str = "provenance";
pub(crate) const WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY: &str = "candidate_evidence";

pub(crate) fn write_envelope_evidence(
    envelope: &WriteEnvelope,
    candidate_evidence: Option<Value>,
) -> Value {
    let actor = envelope.actor();
    let mut entries = vec![
        (
            Value::from(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY),
            Value::Binary(actor.entity_ref().as_bytes().to_vec()),
        ),
        (
            Value::from(WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY),
            Value::from(actor.actor_class() as u8),
        ),
        (
            Value::from(WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY),
            envelope.provenance().value().clone(),
        ),
    ];

    if let Some(candidate_evidence) = candidate_evidence {
        entries.push((
            Value::from(WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY),
            candidate_evidence,
        ));
    }

    Value::Map(entries)
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

#[must_use]
pub(crate) fn static_short_id_prefix_collision(short_id_prefix: &str) -> bool {
    ENTITY_TYPE_REGISTRY
        .iter()
        .filter_map(|entry| entry.short_id_prefix)
        .any(|prefix| prefix == short_id_prefix)
}

pub(crate) fn validate_entity_type(entity_type: u8) -> crate::error::Result<()> {
    entity_type_registry_entry(entity_type)
        .map(|_| ())
        .ok_or(crate::error::Error::InvalidEntityType(entity_type))
}

/// First byte of the induced / dynamic / maintenance type-byte band
/// (contracts.ts `typeByteBands` row `120+`). Registered kinds in this band
/// (REDACTION_AUDIT = 120, MODEL = 121, AUTHORITY_LOG = 122,
/// POLICY_MANIFEST = 123, FEDERATION_GRANT = 124, CONNECTION_RECORD = 125
/// reserved, DIAGNOSTIC = 126 reserved, FEDERATION_KEY_ENVELOPE = 127
/// reserved, ACCESS_GRANT = 128, PSYCH_PROFILE = 129, SUSPICIOUS_WAKE = 130
/// reserved, CHANNEL_IDENTITY = 131, COUNTERPARTY_CONTACT = 132,
/// OUTBOUND_GRANT = 133) are engine-authored maintenance records or reserved
/// maintenance substrates.
/// Reserved bytes are not registered yet.
pub(crate) const MAINTENANCE_TYPE_BYTE_BAND_START: u8 = 120;

/// Validates an entity type byte for PUBLIC write paths (D5).
///
/// Genuinely unknown bytes fail with [`Error::InvalidEntityType`]; registered
/// maintenance-band kinds (type byte ≥ 120: REDACTION_AUDIT, MODEL,
/// POLICY_MANIFEST, FEDERATION_GRANT, ACCESS_GRANT, PSYCH_PROFILE,
/// CHANNEL_IDENTITY, COUNTERPARTY_CONTACT, OUTBOUND_GRANT) fail with the distinct
/// [`Error::MaintenanceKindNotWritable`]. Reserved-unregistered
/// maintenance bytes (AUTHORITY_LOG = 122, CONNECTION_RECORD = 125,
/// DIAGNOSTIC = 126, FEDERATION_KEY_ENVELOPE = 127, SUSPICIOUS_WAKE = 130)
/// still fail with [`Error::InvalidEntityType`] so API-boundary error codes
/// never conflate "unknown byte" with "reserved maintenance kind".
/// Engine-internal writers (the REDACTION_AUDIT receipt writer, the MODEL
/// get-or-create door in `vault.rs`, policy-manifest resolver fixtures,
/// federation-grant substrate writers, and PsychProfile snapshot writer)
/// bypass this gate.
///
/// [`Error::InvalidEntityType`]: crate::error::Error::InvalidEntityType
/// [`Error::MaintenanceKindNotWritable`]: crate::error::Error::MaintenanceKindNotWritable
pub(crate) fn validate_public_entity_type(entity_type: u8) -> crate::error::Result<()> {
    validate_entity_type(entity_type)?;
    if entity_type >= MAINTENANCE_TYPE_BYTE_BAND_START {
        return Err(crate::error::Error::MaintenanceKindNotWritable(entity_type));
    }
    Ok(())
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
    /// Returns the default STORED edge weight for this edge kind — the
    /// LITERAL `pprWeight` column of the contract's `edgeKinds` table
    /// (oneiron-docs `site/src/data/oneiron-contracts.ts`, ARCH-0019 PPR
    /// edge-kinds priors). `None` mirrors the contract's `pprWeight: null`
    /// rows exactly: `child_of` and `assigned_to` carry no stored-weight
    /// prior, so callers writing such edges must choose a weight explicitly.
    ///
    /// This is NOT the PPR traversal multiplier: per-kind traversal budgets
    /// are the λ_τ table (`ppr::lambda_for_kind`), which deliberately differs
    /// from this prior for the five world-model kinds, and `ChildOf` /
    /// `AssignedTo` are never traversed by PPR regardless of the weight
    /// stored on their edges.
    pub const fn default_weight(self) -> Option<f32> {
        match self {
            Self::BelongsTo => Some(1.0),
            Self::ParticipatesIn => Some(1.0),
            Self::Attached => Some(0.8),
            Self::AuthoredBy => Some(0.9),
            Self::Mentions => Some(0.6),
            Self::About => Some(0.5),
            Self::Supports => Some(1.0),
            Self::Opposes => Some(0.0),
            Self::ClaimOf => Some(1.0),
            Self::ScopedTo => Some(0.7),
            Self::Supersedes => Some(0.3),
            Self::DerivedFrom => Some(0.2),
            Self::PartOf => Some(0.8),
            Self::EmployedBy => Some(0.8),
            Self::HasFacet => Some(0.7),
            Self::InWorld => Some(0.7),
            Self::FacetOf => Some(0.7),
            Self::SetIn => Some(0.7),
            Self::ChildOf => None,
            Self::AssignedTo => None,
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
    pub(crate) fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Human),
            1 => Some(Self::Agent),
            2 => Some(Self::System),
            _ => None,
        }
    }

    /// Actor-class key used by Gate `actor_ceilings` policy rows.
    #[must_use]
    pub const fn gate_actor_class(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Agent => "agent",
            Self::System => "system",
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

const TEMPORAL_SECONDS_PER_DAY: u64 = 86_400;
const TEMPORAL_RECENT_DAYS: u64 = 7;

/// Accepted natural-language temporal retrieval hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TemporalExpression {
    Recent,
    Yesterday,
    LastWeek,
    LastMonth,
    LastYear,
}

impl TemporalExpression {
    /// Parses a standalone temporal expression. The accepted grammar is
    /// deliberately small: `recent`, `yesterday`, `last week`, `last month`,
    /// and `last year`.
    pub fn parse(expression: &str) -> std::result::Result<Self, TemporalExpressionParseError> {
        let normalized = normalize_temporal_expression(expression);
        if normalized.is_empty() {
            return Err(TemporalExpressionParseError::Empty);
        }

        match normalized.as_str() {
            "recent" => Ok(Self::Recent),
            "yesterday" => Ok(Self::Yesterday),
            "last week" => Ok(Self::LastWeek),
            "last month" => Ok(Self::LastMonth),
            "last year" => Ok(Self::LastYear),
            _ => Err(TemporalExpressionParseError::Unsupported {
                expression: normalized,
            }),
        }
    }

    /// Resolves this expression to inclusive UTC Unix-second retrieval bounds
    /// from a caller-supplied clock.
    #[must_use]
    pub fn resolve(self, now: u64) -> TimeRange {
        match self {
            Self::Recent => TimeRange {
                start: now.saturating_sub(TEMPORAL_RECENT_DAYS * TEMPORAL_SECONDS_PER_DAY),
                end: now,
            },
            Self::Yesterday => {
                let today_start = utc_day_start(now);
                TimeRange {
                    start: today_start.saturating_sub(TEMPORAL_SECONDS_PER_DAY),
                    end: today_start.saturating_sub(1),
                }
            }
            Self::LastWeek => {
                let today_start = utc_day_start(now);
                TimeRange {
                    start: today_start.saturating_sub(7 * TEMPORAL_SECONDS_PER_DAY),
                    end: today_start.saturating_sub(1),
                }
            }
            Self::LastMonth => previous_calendar_month_range(now),
            Self::LastYear => previous_calendar_year_range(now),
        }
    }
}

/// Typed parse failure for temporal retrieval hints.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TemporalExpressionParseError {
    #[error("empty temporal expression")]
    Empty,
    #[error("unsupported temporal expression: {expression}")]
    Unsupported { expression: String },
    #[error("ambiguous temporal expression in query")]
    Ambiguous,
}

/// Parses a standalone temporal expression and resolves it to inclusive UTC
/// Unix-second bounds from `now`.
pub fn parse_temporal_expression(
    expression: &str,
    now: u64,
) -> std::result::Result<TimeRange, TemporalExpressionParseError> {
    Ok(TemporalExpression::parse(expression)?.resolve(now))
}

/// Extracts one accepted temporal hint from a larger retrieval query.
///
/// Queries without temporal hint words return `Ok(None)`. Queries containing
/// an unsupported temporal-looking phrase, or more than one temporal hint,
/// fail closed with a typed parse error.
pub fn temporal_expression_from_query(
    query: &str,
) -> std::result::Result<Option<TemporalExpression>, TemporalExpressionParseError> {
    let tokens = temporal_query_tokens(query);
    let mut found = None;
    let mut index = 0;

    while index < tokens.len() {
        let parsed = match tokens[index].as_str() {
            "recent" => Some(TemporalExpression::Recent),
            "yesterday" => Some(TemporalExpression::Yesterday),
            "today" | "tomorrow" | "tonight" => {
                return Err(TemporalExpressionParseError::Unsupported {
                    expression: tokens[index].clone(),
                });
            }
            "next" | "this" => match tokens.get(index + 1).map(String::as_str) {
                Some(next) if is_temporal_unit_token(next) || is_weekday_token(next) => {
                    return Err(TemporalExpressionParseError::Unsupported {
                        expression: format!("{} {next}", tokens[index]),
                    });
                }
                _ => None,
            },
            "last" => match tokens.get(index + 1).map(String::as_str) {
                None => None,
                Some("week") => {
                    index += 1;
                    Some(TemporalExpression::LastWeek)
                }
                Some("month") => {
                    index += 1;
                    Some(TemporalExpression::LastMonth)
                }
                Some("year") => {
                    index += 1;
                    Some(TemporalExpression::LastYear)
                }
                Some(next) if is_temporal_unit_token(next) || is_weekday_token(next) => {
                    return Err(TemporalExpressionParseError::Unsupported {
                        expression: format!("last {next}"),
                    });
                }
                Some(_) => {
                    if let Some(expression) = unsupported_last_quantity_expression(&tokens, index) {
                        return Err(TemporalExpressionParseError::Unsupported { expression });
                    }
                    None
                }
            },
            _ => None,
        };

        if let Some(expression) = parsed
            && found.replace(expression).is_some()
        {
            return Err(TemporalExpressionParseError::Ambiguous);
        }
        index += 1;
    }

    Ok(found)
}

fn normalize_temporal_expression(expression: &str) -> String {
    temporal_query_tokens(expression).join(" ")
}

fn temporal_query_tokens(value: &str) -> Vec<String> {
    value
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn is_temporal_unit_token(token: &str) -> bool {
    matches!(
        token,
        "day"
            | "days"
            | "hour"
            | "hours"
            | "minute"
            | "minutes"
            | "second"
            | "seconds"
            | "week"
            | "weeks"
            | "month"
            | "months"
            | "year"
            | "years"
            | "quarter"
            | "quarters"
    )
}

fn is_temporal_quantity_token(token: &str) -> bool {
    token.bytes().all(|byte| byte.is_ascii_digit())
        || matches!(
            token,
            "zero"
                | "a"
                | "an"
                | "one"
                | "two"
                | "three"
                | "four"
                | "five"
                | "six"
                | "seven"
                | "eight"
                | "nine"
                | "ten"
                | "eleven"
                | "twelve"
                | "thirteen"
                | "fourteen"
                | "fifteen"
                | "sixteen"
                | "seventeen"
                | "eighteen"
                | "nineteen"
                | "twenty"
                | "thirty"
                | "forty"
                | "fifty"
                | "sixty"
                | "seventy"
                | "eighty"
                | "ninety"
                | "hundred"
                | "thousand"
                | "dozen"
                | "half"
                | "couple"
                | "few"
                | "several"
                | "many"
        )
}

fn unsupported_last_quantity_expression(tokens: &[String], last_index: usize) -> Option<String> {
    let mut index = last_index + 1;
    let mut saw_quantity = false;

    while let Some(token) = tokens.get(index).map(String::as_str) {
        if token == "of" && saw_quantity {
            index += 1;
            continue;
        }

        if is_temporal_quantity_token(token) {
            saw_quantity = true;
            index += 1;
            continue;
        }

        if saw_quantity && (is_temporal_unit_token(token) || is_weekday_token(token)) {
            return Some(tokens[last_index..=index].join(" "));
        }

        return None;
    }

    None
}

fn is_weekday_token(token: &str) -> bool {
    matches!(
        token,
        "monday" | "tuesday" | "wednesday" | "thursday" | "friday" | "saturday" | "sunday"
    )
}

fn utc_day_start(timestamp: u64) -> u64 {
    timestamp - timestamp % TEMPORAL_SECONDS_PER_DAY
}

fn previous_calendar_month_range(now: u64) -> TimeRange {
    let (year, month, _) = civil_from_unix_days(unix_days_from_timestamp(now));
    let current_month_start = unix_seconds_from_civil(year, month, 1);
    let (previous_year, previous_month) = if month == 1 {
        (year - 1, 12)
    } else {
        (year, month - 1)
    };
    TimeRange {
        start: unix_seconds_from_civil_saturating(previous_year, previous_month, 1),
        end: current_month_start.saturating_sub(1),
    }
}

fn previous_calendar_year_range(now: u64) -> TimeRange {
    let (year, _, _) = civil_from_unix_days(unix_days_from_timestamp(now));
    let current_year_start = unix_seconds_from_civil(year, 1, 1);
    TimeRange {
        start: unix_seconds_from_civil_saturating(year - 1, 1, 1),
        end: current_year_start.saturating_sub(1),
    }
}

fn unix_seconds_from_civil_saturating(year: i32, month: u32, day: u32) -> u64 {
    let days = unix_days_from_civil(year, month, day);
    if days <= 0 {
        0
    } else {
        (days as u64).saturating_mul(TEMPORAL_SECONDS_PER_DAY)
    }
}

fn unix_seconds_from_civil(year: i32, month: u32, day: u32) -> u64 {
    let days = unix_days_from_civil(year, month, day);
    assert!(
        days >= 0,
        "temporal UTC conversion is only defined for Unix epoch and later dates"
    );
    if days == 0 {
        0
    } else {
        (days as u64).saturating_mul(TEMPORAL_SECONDS_PER_DAY)
    }
}

fn unix_days_from_timestamp(timestamp: u64) -> i64 {
    i64::try_from(timestamp / TEMPORAL_SECONDS_PER_DAY)
        .expect("temporal UTC conversion supports Unix days representable as i64")
}

fn civil_from_unix_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + i64::from(m <= 2);
    let year = i32::try_from(year)
        .expect("temporal UTC conversion supports civil years representable as i32");
    (year, m as u32, d as u32)
}

fn unix_days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let mut year = i64::from(year);
    let month = i64::from(month);
    let day = i64::from(day);

    year -= i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * adjusted_month + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
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

/// Scoring-only BM25F rank profile (ARCH-0031 §bm25f, ARCH-0019 D3).
///
/// Selects the BM25 scoring formula — [`Bm25Formula::Okapi`] (default) vs
/// [`Bm25Formula::Plus`]`{ delta }` — and overrides per-channel `weight`
/// / `b` for the four v1 analyzer channels (`Surface`, `Stem`,
/// `NormalizedOverlay`, `CjkNgram`). `k1` stays pinned at the contract's
/// global `1.2` and is not configurable.
///
/// The profile is applied at query time only. It never participates in
/// the on-disk analyzer manifest or the BM25F field-schema hash, so
/// changing it never requires a reindex (ARCH-0031: "Weights are
/// scoring-only — changing them doesn't require reindex").
///
/// A channel override with `weight == 0.0` excludes that channel from
/// scoring entirely. Overrides accumulate; the last override per channel
/// wins. Validation is fail-closed at the point of use
/// ([`crate::Vault::search_text_with_profile`] /
/// [`crate::PipelineBuilder::rank_profile`]): non-finite or negative
/// weights, `b` outside `[0.0, 1.0]`, a non-finite or non-positive
/// BM25+ `delta`, and overrides on reserved channels (`Shingle`,
/// `Synonym`, `Phonetic` — never emitted in v1) are rejected with
/// [`crate::Error::InvalidRankProfile`].
///
/// [`Bm25Formula::Okapi`]: crate::Bm25Formula::Okapi
/// [`Bm25Formula::Plus`]: crate::Bm25Formula::Plus
#[derive(Debug, Clone, PartialEq)]
#[must_use = "a rank profile only affects scoring when passed to a query"]
pub struct Bm25RankProfile {
    formula: crate::bm25::Bm25Formula,
    weight_overrides: Vec<(crate::analyzer::AnalyzerChannel, f64)>,
    b_overrides: Vec<(crate::analyzer::AnalyzerChannel, f64)>,
}

impl Default for Bm25RankProfile {
    /// The contract default profile: Okapi formula, no channel overrides
    /// (Surface 1.00/0.75, Stem 0.35/0.65, NormalizedOverlay 0.55/0.00,
    /// CjkNgram 0.45/0.30 per the ARCH-0031 channel table).
    fn default() -> Self {
        Self {
            formula: crate::bm25::Bm25Formula::Okapi,
            weight_overrides: Vec::new(),
            b_overrides: Vec::new(),
        }
    }
}

impl Bm25RankProfile {
    /// Selects the BM25 scoring formula. `Okapi` is the contract default;
    /// `Plus { delta }` is the BM25+ option (`delta` must be finite and
    /// `> 0.0`; the contract opt-in value is `delta: 1.0`).
    pub fn with_formula(mut self, formula: crate::bm25::Bm25Formula) -> Self {
        self.formula = formula;
        self
    }

    /// Overrides the scoring weight of one of the four v1 channels.
    /// `0.0` excludes the channel from scoring. Must be finite and
    /// `>= 0.0`; validated fail-closed at query time.
    pub fn with_channel_weight(
        mut self,
        channel: crate::analyzer::AnalyzerChannel,
        weight: f64,
    ) -> Self {
        self.weight_overrides.push((channel, weight));
        self
    }

    /// Overrides the BM25 length-norm `b` of one of the four v1 channels.
    /// Must be finite and within `[0.0, 1.0]`; validated fail-closed at
    /// query time. Note `NormalizedOverlay` scores under the `NoNorm`
    /// length policy, so its `b` is inert by contract.
    pub fn with_channel_b(mut self, channel: crate::analyzer::AnalyzerChannel, b: f64) -> Self {
        self.b_overrides.push((channel, b));
        self
    }

    /// Validates the profile and lowers it onto the internal scoring
    /// config. Fail-closed: any invalid parameter is a typed
    /// [`Error::InvalidRankProfile`], never a clamp or a silent skip.
    pub(crate) fn to_bm25_config(&self) -> Result<crate::bm25::Bm25Config, crate::error::Error> {
        use crate::analyzer::AnalyzerChannel;
        use crate::bm25::{Bm25Config, Bm25Formula};
        use crate::error::Error;

        fn scored_slot(
            channel: AnalyzerChannel,
            parameter: &'static str,
        ) -> Result<usize, crate::error::Error> {
            // Only the four v1 channels are scoreable; reserved channels
            // are never emitted, so an override there is a caller bug.
            if !AnalyzerChannel::ALL_V1.contains(&channel) {
                return Err(Error::InvalidRankProfile {
                    parameter,
                    value: f64::from(channel.field_id()),
                });
            }
            Ok(channel.field_id() as usize)
        }

        if let Bm25Formula::Plus { delta } = self.formula
            && (!delta.is_finite() || delta <= 0.0)
        {
            return Err(Error::InvalidRankProfile {
                parameter: "formula.delta",
                value: delta,
            });
        }

        let mut config = Bm25Config {
            formula: self.formula,
            ..Bm25Config::default()
        };

        for &(channel, weight) in &self.weight_overrides {
            let slot = scored_slot(channel, "weight.reserved_channel")?;
            if !weight.is_finite() || weight < 0.0 {
                return Err(Error::InvalidRankProfile {
                    parameter: "channel.weight",
                    value: weight,
                });
            }
            config.fields[slot].weight = weight;
        }

        for &(channel, b) in &self.b_overrides {
            let slot = scored_slot(channel, "b.reserved_channel")?;
            if !b.is_finite() || !(0.0..=1.0).contains(&b) {
                return Err(Error::InvalidRankProfile {
                    parameter: "channel.b",
                    value: b,
                });
            }
            config.fields[slot].b = b;
        }

        Ok(config)
    }
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
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

    pub fn validate(&self) -> crate::error::Result<()> {
        if let Some((component, value)) = self.invalid_component() {
            return Err(crate::error::Error::InvalidVad { component, value });
        }
        Ok(())
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

/// Source that produced a turn/message VAD annotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VadAnnotationSource {
    ModelInference,
    UserSelfReport,
}

impl VadAnnotationSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ModelInference => "model_inference",
            Self::UserSelfReport => "user_self_report",
        }
    }
}

/// Persisted VAD metadata attached to a TURN or MESSAGE entity.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct VadAnnotation {
    pub vad: Vad,
    pub source: VadAnnotationSource,
    pub annotated_at: u64,
}

impl VadAnnotation {
    pub fn new(
        vad: Vad,
        source: VadAnnotationSource,
        annotated_at: u64,
    ) -> crate::error::Result<Self> {
        vad.validate()?;
        Ok(Self {
            vad,
            source,
            annotated_at,
        })
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

/// Fully parsed strict edge row shared by fail-closed graph readers.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct StrictEdgeRecord {
    pub source: EntityId,
    pub kind: EdgeKind,
    pub target: EntityId,
    pub decoded: DecodedEdgeValue,
}

impl StrictEdgeRecord {
    pub(crate) fn into_edge_info(self) -> EdgeInfo {
        EdgeInfo {
            kind: self.kind,
            target: self.target,
            target_short_id: None,
            weight: self.decoded.weight,
            created_at: self.decoded.created_at,
            vad: self.decoded.vad,
            provenance: self.decoded.provenance,
        }
    }
}

/// Parses one `edges_out` / `edges_in` row fail-closed.
///
/// A key that is not `EDGE_KEY_LEN` bytes, an unknown edge-kind byte,
/// a reserved/invalid source or peer id, or a value that does not decode as
/// a valid layout for the kind (12/24/26 B per ARCH-0034) is normalized to
/// `Error::CorruptedIndex("edge record")`.
pub(crate) fn parse_strict_edge_record(
    key: &[u8],
    value: &[u8],
) -> crate::error::Result<StrictEdgeRecord> {
    let (source, kind, target) = parse_strict_edge_record_key(key)?;
    let decoded = decode_edge_value_for_kind(kind, value).map_err(|_| edge_record_error())?;

    Ok(StrictEdgeRecord {
        source,
        kind,
        target,
        decoded,
    })
}

pub(crate) fn parse_strict_edge_record_key(
    key: &[u8],
) -> crate::error::Result<(EntityId, EdgeKind, EntityId)> {
    if key.len() != EDGE_KEY_LEN {
        return Err(edge_record_error());
    }

    let source = EntityId::from_bytes(
        key[..ENTITY_ID_LEN]
            .try_into()
            .map_err(|_| edge_record_error())?,
    )
    .map_err(|_| edge_record_error())?;
    let kind = EdgeKind::try_from_u8(key[ENTITY_ID_LEN]).ok_or_else(edge_record_error)?;
    let target = EntityId::from_bytes(
        key[ENTITY_ID_LEN + 1..EDGE_KEY_LEN]
            .try_into()
            .map_err(|_| edge_record_error())?,
    )
    .map_err(|_| edge_record_error())?;

    Ok((source, kind, target))
}

fn edge_record_error() -> crate::error::Error {
    crate::error::Error::CorruptedIndex("edge record")
}

/// Validates a stored edge weight against the contract-pinned range.
///
/// Contract: edge `weight` ∈ \[0, 1\] (oneiron-docs
/// `site/src/data/oneiron-contracts.ts` `edgeKinds` — every non-null
/// `pprWeight` prior lives in this closed interval, and the weight gloss pins
/// the stored range). NaN, ±infinity, and finite values outside \[0, 1\] are
/// rejected with the typed [`Error::InvalidEdgeWeight`] on EVERY write path
/// (public batch ops and sync replay materialization alike); the read path is
/// unchanged.
///
/// [`Error::InvalidEdgeWeight`]: crate::error::Error::InvalidEdgeWeight
pub(crate) fn validate_edge_weight(weight: f32) -> crate::error::Result<()> {
    if !(0.0..=1.0).contains(&weight) {
        return Err(crate::error::Error::InvalidEdgeWeight { value: weight });
    }
    Ok(())
}

pub(crate) fn encode_edge_value(
    kind: EdgeKind,
    weight: f32,
    created_at: u64,
    vad: Vad,
    provenance: Option<EdgeProvenanceFlags>,
) -> crate::error::Result<Vec<u8>> {
    validate_edge_weight(weight)?;
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
    /// Candidates assigned the low gravity signal because they had vector
    /// similarity above the cosine-ghost threshold and no BM25 text channel
    /// presence.
    pub cosine_ghosts_dampened: usize,
    /// CLAIM records silently excluded by the D19 read-path status gate
    /// (ARCH-0003: surface only `appr ∈ {auto, approved}` ∧ `life = active`
    /// ∧ `stale = false`) or by the fail-closed type-0 body decode, across
    /// the pipeline stage and pack hydration (results + neighbors). A claim
    /// suppressed in both stages counts once per stage.
    pub claims_suppressed: usize,
    /// Token accounting populated by serialization/projection paths.
    ///
    /// Raw `ContextPackBuilder::run()` results are not serialized and leave
    /// this as `PackTokenStats::default()`. Use serialized/projection builder
    /// paths when exact output-token accounting is required.
    pub tokens: PackTokenStats,
    pub items_truncated: PackItemAccounting,
    pub items_dropped: PackItemAccounting,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PackTokenStats {
    /// Stable tokenizer identifier used for every count in this struct.
    ///
    /// Empty when stats came from an unserialized raw pack.
    pub tokenizer_id: String,
    /// Exact token count of the final serialized context-pack bytes.
    ///
    /// This includes format envelope, separators, and serialized stats when
    /// they are emitted.
    pub total_tokens: usize,
    /// Per-section row-token accounting.
    ///
    /// Section counts are computed from the row-level accounting text used by
    /// budget allocation. They intentionally exclude format envelope and
    /// separators, so their sum is not expected to equal `total_tokens`.
    pub sections: Vec<PackSectionTokenStats>,
    /// Per-item row-token accounting.
    ///
    /// Item counts use the same row-level basis as `sections`, not exact
    /// emitted substrings for each output format.
    pub items: Vec<PackItemTokenStats>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackSectionTokenStats {
    /// Logical section name, for example `results`, `neighbors`, or `merged`.
    pub section: String,
    /// Row-level token count for this section.
    pub tokens: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackItemTokenStats {
    /// Logical section containing this item.
    pub section: String,
    /// Serialized short reference for the item, including the content-hash suffix.
    pub id: String,
    /// Entity type byte used for the serialized row group.
    pub entity_type: u8,
    /// Row-level token count for this item.
    pub tokens: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackItemAccountingReason {
    ItemBudget,
    TokenBudget,
}

impl PackItemAccountingReason {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ItemBudget => "item_budget",
            Self::TokenBudget => "token_budget",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackItemAccounting {
    pub count: usize,
    pub reason: PackItemAccountingReason,
}

impl PackItemAccounting {
    #[must_use]
    pub fn item_budget() -> Self {
        Self {
            count: 0,
            reason: PackItemAccountingReason::ItemBudget,
        }
    }

    #[must_use]
    pub fn token_budget() -> Self {
        Self {
            count: 0,
            reason: PackItemAccountingReason::TokenBudget,
        }
    }
}

/// Machine-readable reason an otherwise successful context-pack query surfaced
/// no entities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmptyReason {
    FilterMatchedNone,
    NoData,
    AllActivated,
    BelowThreshold,
}

/// Stable deletion reason surfaced by short-id hydrate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HydratedShortIdDeletionReason {
    UserDelete,
    UserHardDelete,
    GdprDelete,
    PolicyDelete,
}

/// Where hydrate found deletion evidence for a short-id row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HydratedShortIdDeletionSource {
    Tombstone,
    PendingTombstone,
    DanglingShortId,
}

/// Deletion metadata returned when a short-id row resolves to deleted state.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HydratedShortIdDeletion {
    pub source: HydratedShortIdDeletionSource,
    pub reason: Option<HydratedShortIdDeletionReason>,
    pub deleted_at: Option<u64>,
    pub request_id: Option<String>,
    pub hard: bool,
}

/// Renderer-facing lifecycle state for one record in a memory timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryTimelineRecordState {
    /// The record exists and is not closed by the supersession graph.
    Live,
    /// The record exists and has been superseded by at least one newer record.
    Superseded,
    /// The record exists as explicitly retracted claim history.
    Retracted,
    /// The record exists only as a deletion shell with tombstone metadata.
    Deleted,
    /// The graph still references an entity id whose record is absent locally.
    Missing,
}

/// One node in a bitemporal supersession timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryTimelineRecord {
    pub id: EntityId,
    pub state: MemoryTimelineRecordState,
    pub entity_type: Option<u8>,
    pub occurred_start: Option<u64>,
    pub occurred_end: Option<u64>,
    pub learned_at: Option<u64>,
    pub body_bytes: Option<usize>,
    pub deletion: Option<HydratedShortIdDeletion>,
    pub supersedes: Vec<EntityId>,
    pub superseded_by: Vec<EntityId>,
}

/// Stable, ordered supersession-chain data for one anchor entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryTimeline {
    pub anchor: EntityId,
    pub records: Vec<MemoryTimelineRecord>,
}

/// Human-readable memory verbs exposed by API surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedMemoryVerb {
    Remember,
    Supersede,
    Retract,
    Delete,
    HardDelete,
}

impl NamedMemoryVerb {
    /// Parses a public route verb, accepting stable aliases while resolving to
    /// one canonical typed operation family.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "remember" | "put" | "put_entity" => Some(Self::Remember),
            "supersede" | "replace" | "revise" | "supersede_claim" => Some(Self::Supersede),
            "retract" | "withdraw" | "retract_claim" => Some(Self::Retract),
            "delete" | "forget" | "soft_delete" | "user_delete" => Some(Self::Delete),
            "hard_delete" | "erase" | "purge" | "user_hard_delete" => Some(Self::HardDelete),
            _ => None,
        }
    }

    pub const fn canonical_name(self) -> &'static str {
        match self {
            Self::Remember => "remember",
            Self::Supersede => "supersede",
            Self::Retract => "retract",
            Self::Delete => "delete",
            Self::HardDelete => "hard_delete",
        }
    }

    pub const fn operation_kind(self) -> MemoryOperationKind {
        match self {
            Self::Remember => MemoryOperationKind::PutEntity,
            Self::Supersede => MemoryOperationKind::SupersedeClaim,
            Self::Retract => MemoryOperationKind::RetractClaim,
            Self::Delete | Self::HardDelete => MemoryOperationKind::DeleteEntity,
        }
    }
}

/// Typed operation family selected by a named memory verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryOperationKind {
    PutEntity,
    SupersedeClaim,
    RetractClaim,
    DeleteEntity,
}

/// Structured context for an empty context-pack response.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmptyContext {
    pub reason: EmptyReason,
    pub total_in_scope: usize,
    pub hint: String,
}

/// A fully hydrated context pack ready for serialization or programmatic use.
#[derive(Debug, Clone)]
pub struct ContextPack {
    pub results: Vec<ContextEntity>,
    pub neighbors: Vec<ContextEntity>,
    pub stats: PackStats,
    pub empty: Option<EmptyContext>,
}

pub const EIRI_CONTEXT_VERSION_V4: &str = "v4";

/// Stable Eiri Context v4 memory-board slot names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EiriMemoryBoardSlot {
    Claims,
    Turns,
    Summaries,
    Facets,
    Companions,
    Other,
}

impl EiriMemoryBoardSlot {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claims => "claims",
            Self::Turns => "turns",
            Self::Summaries => "summaries",
            Self::Facets => "facets",
            Self::Companions => "companions",
            Self::Other => "other",
        }
    }

    #[must_use]
    pub const fn sort_rank(self) -> u8 {
        match self {
            Self::Claims => 0,
            Self::Turns => 1,
            Self::Summaries => 2,
            Self::Facets => 3,
            Self::Companions => 4,
            Self::Other => 5,
        }
    }
}

/// Source section for one memory-board row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EiriMemoryBoardSource {
    Result,
    Neighbor,
}

impl EiriMemoryBoardSource {
    #[must_use]
    pub const fn sort_rank(self) -> u8 {
        match self {
            Self::Result => 0,
            Self::Neighbor => 1,
        }
    }
}

/// Per-slot row caps for an Eiri Context v4 memory board.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EiriMemoryBoardBudget {
    pub claims: usize,
    pub turns: usize,
    pub summaries: usize,
    pub facets: usize,
    pub companions: usize,
    pub other: usize,
}

impl EiriMemoryBoardBudget {
    #[must_use]
    pub const fn new(
        claims: usize,
        turns: usize,
        summaries: usize,
        facets: usize,
        companions: usize,
        other: usize,
    ) -> Self {
        Self {
            claims,
            turns,
            summaries,
            facets,
            companions,
            other,
        }
    }

    #[must_use]
    pub const fn get(self, slot: EiriMemoryBoardSlot) -> usize {
        match slot {
            EiriMemoryBoardSlot::Claims => self.claims,
            EiriMemoryBoardSlot::Turns => self.turns,
            EiriMemoryBoardSlot::Summaries => self.summaries,
            EiriMemoryBoardSlot::Facets => self.facets,
            EiriMemoryBoardSlot::Companions => self.companions,
            EiriMemoryBoardSlot::Other => self.other,
        }
    }

    pub fn increment(&mut self, slot: EiriMemoryBoardSlot) {
        let counter = match slot {
            EiriMemoryBoardSlot::Claims => &mut self.claims,
            EiriMemoryBoardSlot::Turns => &mut self.turns,
            EiriMemoryBoardSlot::Summaries => &mut self.summaries,
            EiriMemoryBoardSlot::Facets => &mut self.facets,
            EiriMemoryBoardSlot::Companions => &mut self.companions,
            EiriMemoryBoardSlot::Other => &mut self.other,
        };
        *counter = counter.saturating_add(1);
    }
}

/// Companion scope that influenced Eiri Context v4 assembly.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EiriCompanionAssembly {
    pub caller: Option<String>,
    pub scope: Option<String>,
    pub scope_source: Option<String>,
    pub person_ref: Option<String>,
    pub persona_ref: Option<String>,
    pub expression: Option<String>,
}

/// One stable row in the Eiri Context v4 memory board.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EiriMemoryBoardRow {
    pub row_index: usize,
    pub slot: EiriMemoryBoardSlot,
    pub source: EiriMemoryBoardSource,
    pub id: String,
    pub short_id: String,
    pub content_hash: String,
    pub entity_type: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_ref: Option<String>,
    pub score: f32,
}

/// Deterministic Eiri Context v4 memory-board envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EiriMemoryBoard {
    pub version: String,
    pub budget: EiriMemoryBoardBudget,
    pub rows: Vec<EiriMemoryBoardRow>,
    pub companion: Option<EiriCompanionAssembly>,
}

/// Session-scoped RAG cursor returned by Eiri Context v4 surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EiriSessionRagState {
    pub session_id: String,
    pub revision: u64,
    pub query_count: u64,
    pub last_retrieval_run_id: Option<String>,
    pub last_result_ids: Vec<String>,
}

impl EiriSessionRagState {
    #[must_use]
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            revision: 0,
            query_count: 0,
            last_retrieval_run_id: None,
            last_result_ids: Vec::new(),
        }
    }
}

impl Default for EiriSessionRagState {
    fn default() -> Self {
        Self::new("default")
    }
}

/// Read-only ambient context returned by the companion resume endpoint.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SessionContext {
    pub api_version: String,
    pub counts: BTreeMap<String, u64>,
    pub last_activity: Option<u64>,
    #[serde(default)]
    pub rag_state: EiriSessionRagState,
}

/// Pending notification surfaced during companion resume hydration.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct NotificationItem {
    pub id: String,
    pub learned_at: u64,
    pub body: serde_json::Value,
}

/// Existing work item that still needs caller-side processing.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct UnprocessedItem {
    pub id: String,
    pub entity_type: u8,
    pub learned_at: u64,
    pub body: serde_json::Value,
}

/// Token meter snapshot included in every companion resume bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResumeBudget {
    pub tokens_used: u64,
    pub tokens_limit: u64,
    pub tokens_remaining: u64,
}

impl ResumeBudget {
    #[must_use]
    pub fn from_meter(tokens_used: u64, tokens_limit: u64) -> Self {
        Self {
            tokens_used,
            tokens_limit,
            tokens_remaining: tokens_limit.saturating_sub(tokens_used),
        }
    }
}

/// Single-call companion hydration bundle.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ResumeBundle {
    pub session: SessionContext,
    pub notifications: Vec<NotificationItem>,
    pub unprocessed: Vec<UnprocessedItem>,
    pub budget: ResumeBudget,
}

impl ResumeBundle {
    #[must_use]
    pub fn new(
        session: SessionContext,
        notifications: Vec<NotificationItem>,
        unprocessed: Vec<UnprocessedItem>,
        budget: ResumeBudget,
    ) -> Self {
        Self {
            session,
            notifications,
            unprocessed,
            budget,
        }
    }
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

/// Item budget for context-pack retrieval before the final global truncation.
///
/// Primary entity budgets are enforced per retrieval kind after query filters
/// and before `limit` truncation. `selected_edges` caps edge-walk neighbor
/// selection; it is not an entity type byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextPackRetrievalBudget {
    pub claims: usize,
    pub turns: usize,
    pub summaries: usize,
    pub facets: usize,
    pub other: usize,
    pub selected_edges: usize,
}

impl ContextPackRetrievalBudget {
    #[must_use]
    pub const fn new(
        claims: usize,
        turns: usize,
        summaries: usize,
        facets: usize,
        other: usize,
        selected_edges: usize,
    ) -> Self {
        Self {
            claims,
            turns,
            summaries,
            facets,
            other,
            selected_edges,
        }
    }

    #[must_use]
    pub fn from_limit(
        result_limit: usize,
        allocation: TokenAllocation,
        selected_edges: usize,
    ) -> Self {
        let split_other = allocation.other / 2.0;
        let weights = [
            allocation.claims,
            allocation.turns,
            allocation.summaries,
            split_other,
            split_other,
        ];
        let mut budgets = allocate_context_pack_item_budgets(result_limit, weights);
        if result_limit > 0 {
            for (budget, weight) in budgets.iter_mut().zip(weights) {
                if *budget == 0 && weight.is_finite() && weight > 0.0 {
                    *budget = 1;
                }
            }
        }
        Self {
            claims: budgets[0],
            turns: budgets[1],
            summaries: budgets[2],
            facets: budgets[3],
            other: budgets[4],
            selected_edges,
        }
    }
}

fn allocate_context_pack_item_budgets(limit: usize, weights: [f32; 5]) -> [usize; 5] {
    if limit == 0 {
        return [0; 5];
    }

    let mut sanitized = [0.0_f32; 5];
    for (index, weight) in weights.into_iter().enumerate() {
        if weight.is_finite() && weight > 0.0 {
            sanitized[index] = weight;
        }
    }

    let total_weight: f32 = sanitized.iter().sum();
    if total_weight <= 0.0 {
        let base = limit / sanitized.len();
        let mut budgets = [base; 5];
        for budget in budgets.iter_mut().take(limit % sanitized.len()) {
            *budget = budget.saturating_add(1);
        }
        return budgets;
    }

    let mut budgets = [0_usize; 5];
    let mut remainders = [(0_usize, 0.0_f32); 5];
    let mut allocated = 0_usize;
    for (index, weight) in sanitized.iter().copied().enumerate() {
        if weight <= 0.0 {
            continue;
        }
        let exact = (limit as f32) * (weight / total_weight);
        let whole = exact.floor() as usize;
        budgets[index] = whole;
        remainders[index] = (index, exact - whole as f32);
        allocated = allocated.saturating_add(whole);
    }

    let mut leftover = limit.saturating_sub(allocated);
    remainders.sort_unstable_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    for (index, _) in remainders {
        if leftover == 0 {
            break;
        }
        if sanitized[index] > 0.0 {
            budgets[index] = budgets[index].saturating_add(1);
            leftover -= 1;
        }
    }
    budgets
}

#[cfg(test)]
mod tests {
    use super::*;

    const FROZEN_NOW: u64 = 1_710_504_000; // 2024-03-15T12:00:00Z

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

    #[test]
    fn strict_edge_record_parser_decodes_key_and_value() {
        let source = EntityId::from_bytes([0x11; ENTITY_ID_LEN]).unwrap();
        let target = EntityId::from_bytes([0x22; ENTITY_ID_LEN]).unwrap();
        let kind = EdgeKind::Supports;
        let mut key = [0_u8; EDGE_KEY_LEN];
        key[..ENTITY_ID_LEN].copy_from_slice(source.as_bytes());
        key[ENTITY_ID_LEN] = kind as u8;
        key[ENTITY_ID_LEN + 1..].copy_from_slice(target.as_bytes());
        let value = encode_edge_value(kind, 0.75, 42, Vad::NEUTRAL, None).unwrap();

        let record = parse_strict_edge_record(&key, &value).unwrap();
        assert_eq!(record.source, source);
        assert_eq!(record.kind, kind);
        assert_eq!(record.target, target);
        assert_eq!(record.decoded.weight, 0.75);
        assert_eq!(record.decoded.created_at, 42);

        let info = record.into_edge_info();
        assert_eq!(info.kind, kind);
        assert_eq!(info.target, target);
        assert_eq!(info.target_short_id, None);
        assert_eq!(info.weight, 0.75);
        assert_eq!(info.created_at, 42);
    }

    #[test]
    fn strict_edge_record_parser_normalizes_corruption_errors() {
        let source = EntityId::from_bytes([0x11; ENTITY_ID_LEN]).unwrap();
        let target = EntityId::from_bytes([0x22; ENTITY_ID_LEN]).unwrap();
        let mut key = [0_u8; EDGE_KEY_LEN];
        key[..ENTITY_ID_LEN].copy_from_slice(source.as_bytes());
        key[ENTITY_ID_LEN] = EdgeKind::Supports as u8;
        key[ENTITY_ID_LEN + 1..].copy_from_slice(target.as_bytes());

        let truncated_value = [0_u8; EDGE_VALUE_STRUCTURAL_LEN - 1];
        let err = parse_strict_edge_record(&key, &truncated_value)
            .expect_err("truncated edge value must fail closed");
        assert!(matches!(
            err,
            crate::error::Error::CorruptedIndex("edge record")
        ));

        key[ENTITY_ID_LEN + 1..].fill(0xFF);
        let value = encode_edge_value(EdgeKind::Supports, 0.5, 1, Vad::NEUTRAL, None).unwrap();
        let err = parse_strict_edge_record(&key, &value)
            .expect_err("reserved target id must fail closed");
        assert!(matches!(
            err,
            crate::error::Error::CorruptedIndex("edge record")
        ));
    }

    #[test]
    fn task_role_from_body_bytes_rejects_malformed_bodies() {
        fn encode(value: &Value) -> Vec<u8> {
            let mut bytes = Vec::new();
            rmpv::encode::write_value(&mut bytes, value).expect("encode msgpack test body");
            bytes
        }

        let role_byte = TaskRole::Task.role_byte();

        // A map carrying two "role" entries: decoders that resolve first-vs-last
        // key differently must not silently disagree; this is rejected outright.
        let duplicate_role = encode(&Value::Map(vec![
            (Value::from(TASK_BODY_ROLE_KEY), Value::from(role_byte)),
            (Value::from(TASK_BODY_ROLE_KEY), Value::from(role_byte)),
        ]));
        match task_role_from_body_bytes(&duplicate_role) {
            Err(crate::error::Error::InvalidTaskBody(msg)) => {
                assert_eq!(msg, "duplicate task role key");
            }
            other => panic!("expected duplicate-role-key rejection, got {other:?}"),
        }

        let non_map = encode(&Value::from(role_byte));
        match task_role_from_body_bytes(&non_map) {
            Err(crate::error::Error::InvalidTaskBody(msg)) => {
                assert_eq!(msg, "body must be a MessagePack map");
            }
            other => panic!("expected non-map rejection, got {other:?}"),
        }

        let non_string_key = encode(&Value::Map(vec![(
            Value::from(1_u64),
            Value::from(role_byte),
        )]));
        match task_role_from_body_bytes(&non_string_key) {
            Err(crate::error::Error::InvalidTaskBody(msg)) => {
                assert_eq!(msg, "body keys must be strings");
            }
            other => panic!("expected non-string-key rejection, got {other:?}"),
        }
    }

    #[test]
    fn local_world_id_rejects_foreign_range() {
        let local = EntityId::from_bytes([0xEF; 16]).unwrap();
        let foreign = EntityId::from_bytes([FOREIGN_WORLD_ID_RANGE_START_BYTE; 16]).unwrap();

        assert_eq!(
            LocalWorldId::from_entity_id(local).unwrap().entity_id(),
            local
        );
        assert!(LocalWorldId::from_entity_id(foreign).is_err());
    }

    #[test]
    fn foreign_world_id_accepts_only_foreign_range() {
        let local = EntityId::from_bytes([0xEF; 16]).unwrap();
        let foreign = EntityId::from_bytes([0xF1; 16]).unwrap();

        assert_eq!(
            ForeignWorldId::from_entity_id(foreign).unwrap().entity_id(),
            foreign
        );
        assert!(ForeignWorldId::from_entity_id(local).is_err());
    }

    #[test]
    fn temporal_expression_parser_resolves_supported_forms_from_frozen_clock() {
        assert_eq!(
            parse_temporal_expression("recent", FROZEN_NOW).unwrap(),
            TimeRange {
                start: 1_709_899_200,
                end: FROZEN_NOW,
            }
        );
        assert_eq!(
            parse_temporal_expression("yesterday", FROZEN_NOW).unwrap(),
            TimeRange {
                start: 1_710_374_400,
                end: 1_710_460_799,
            }
        );
        assert_eq!(
            parse_temporal_expression("last week", FROZEN_NOW).unwrap(),
            TimeRange {
                start: 1_709_856_000,
                end: 1_710_460_799,
            }
        );
        assert_eq!(
            parse_temporal_expression("last month", FROZEN_NOW).unwrap(),
            TimeRange {
                start: 1_706_745_600,
                end: 1_709_251_199,
            }
        );
        assert_eq!(
            parse_temporal_expression("last year", FROZEN_NOW).unwrap(),
            TimeRange {
                start: 1_672_531_200,
                end: 1_704_067_199,
            }
        );
    }

    #[test]
    fn temporal_expression_query_parser_rejects_unsupported_last_forms() {
        assert!(matches!(
            temporal_expression_from_query("notes from last friday"),
            Err(TemporalExpressionParseError::Unsupported { expression })
                if expression == "last friday"
        ));
        assert!(matches!(
            temporal_expression_from_query("notes from last 2 weeks"),
            Err(TemporalExpressionParseError::Unsupported { expression })
                if expression == "last 2 weeks"
        ));
        assert!(matches!(
            temporal_expression_from_query("notes from last 24 hours"),
            Err(TemporalExpressionParseError::Unsupported { expression })
                if expression == "last 24 hours"
        ));
        assert!(matches!(
            temporal_expression_from_query("notes from last 30 minutes"),
            Err(TemporalExpressionParseError::Unsupported { expression })
                if expression == "last 30 minutes"
        ));
        assert!(matches!(
            temporal_expression_from_query("notes from last eleven weeks"),
            Err(TemporalExpressionParseError::Unsupported { expression })
                if expression == "last eleven weeks"
        ));
        assert!(matches!(
            temporal_expression_from_query("notes from last twenty four hours"),
            Err(TemporalExpressionParseError::Unsupported { expression })
                if expression == "last twenty four hours"
        ));
        assert!(matches!(
            temporal_expression_from_query("notes from last two weeks"),
            Err(TemporalExpressionParseError::Unsupported { expression })
                if expression == "last two weeks"
        ));
        assert!(matches!(
            temporal_expression_from_query("notes from last few days"),
            Err(TemporalExpressionParseError::Unsupported { expression })
                if expression == "last few days"
        ));
        assert!(matches!(
            temporal_expression_from_query("notes from last couple of months"),
            Err(TemporalExpressionParseError::Unsupported { expression })
                if expression == "last couple of months"
        ));
    }

    #[test]
    fn temporal_expression_query_parser_ignores_non_temporal_last_nouns() {
        for query in ["last commit", "my last note", "last update", "show me last"] {
            assert_eq!(
                temporal_expression_from_query(query).unwrap(),
                None,
                "{query}"
            );
        }
    }

    #[test]
    fn temporal_expression_query_parser_rejects_multiple_hints() {
        assert!(matches!(
            temporal_expression_from_query("recent notes from yesterday"),
            Err(TemporalExpressionParseError::Ambiguous)
        ));
    }

    #[test]
    fn temporal_expression_query_parser_rejects_unsupported_non_last_forms() {
        assert!(matches!(
            temporal_expression_from_query("notes from tomorrow"),
            Err(TemporalExpressionParseError::Unsupported { expression })
                if expression == "tomorrow"
        ));
        assert!(matches!(
            temporal_expression_from_query("notes from next week"),
            Err(TemporalExpressionParseError::Unsupported { expression })
                if expression == "next week"
        ));
        assert!(matches!(
            temporal_expression_from_query("notes from this month"),
            Err(TemporalExpressionParseError::Unsupported { expression })
                if expression == "this month"
        ));
        assert_eq!(temporal_expression_from_query("next steps").unwrap(), None);
    }

    #[test]
    fn unix_seconds_from_civil_keeps_epoch_boundary_at_zero() {
        assert_eq!(unix_seconds_from_civil(1970, 1, 1), 0);
        assert_eq!(unix_seconds_from_civil(1970, 1, 2), 86_400);
    }

    #[test]
    #[should_panic(expected = "only defined for Unix epoch and later dates")]
    fn unix_seconds_from_civil_rejects_pre_epoch_dates() {
        let _ = unix_seconds_from_civil(1969, 12, 31);
    }

    #[test]
    fn temporal_expression_calendar_ranges_saturate_at_epoch_boundary() {
        assert_eq!(
            parse_temporal_expression("last month", 0).unwrap(),
            TimeRange { start: 0, end: 0 }
        );
        assert_eq!(
            parse_temporal_expression("last year", 0).unwrap(),
            TimeRange { start: 0, end: 0 }
        );
        assert_eq!(
            parse_temporal_expression("last month", 15 * TEMPORAL_SECONDS_PER_DAY).unwrap(),
            TimeRange { start: 0, end: 0 }
        );
        assert_eq!(
            parse_temporal_expression("last year", 15 * TEMPORAL_SECONDS_PER_DAY).unwrap(),
            TimeRange { start: 0, end: 0 }
        );
    }

    #[test]
    #[should_panic(expected = "civil years representable as i32")]
    fn temporal_expression_rejects_extreme_timestamp_without_wrapping() {
        let _ = parse_temporal_expression("last month", u64::MAX);
    }

    #[test]
    fn context_pack_retrieval_budget_default_token_allocation_splits_other_weight() {
        let budget = ContextPackRetrievalBudget::from_limit(20, TokenAllocation::default(), 7);

        assert_eq!(budget.claims, 9);
        assert_eq!(budget.turns, 2);
        assert_eq!(budget.summaries, 5);
        assert_eq!(budget.facets, 2);
        assert_eq!(budget.other, 2);
        assert_eq!(budget.selected_edges, 7);
    }

    #[test]
    fn context_pack_retrieval_budget_default_small_limit_keeps_positive_buckets_eligible() {
        let budget = ContextPackRetrievalBudget::from_limit(3, TokenAllocation::default(), 0);

        assert!(budget.claims > 0);
        assert!(budget.turns > 0);
        assert!(budget.summaries > 0);
        assert!(budget.facets > 0);
        assert!(budget.other > 0);
    }
}
