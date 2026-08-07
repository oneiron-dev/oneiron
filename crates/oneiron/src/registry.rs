//! Entity-type registry: type bytes, bands, classification, the registry array + lookups/validators.

use crate::companion::{COMPANION_REGISTER_SHORT_ID_PREFIX, ENTITY_TYPE_COMPANION_REGISTER};

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
/// ARCH-0032 NOTE primitive (OF-330, ONE-1377): the cross-product
/// working-thought entity, landed with the single `opinion/take` kind so an
/// actor can record an attributed opinion BESIDE a neutral ARCH-0003 CLAIM
/// instead of editing it. Pack-registered in the productivity band; bodies ride
/// the pinned `crate::note::NOTE_BODY_KEYS` ABI.
///
/// The byte is deliberately SPLIT from canon: 86 is engine reality today, while
/// BYTE-SPACE REDESIGN v3 assigns NOTE 106 and ONE-1754 executes that
/// persisted re-key as one atomic v3 map. No engine constant here names 106.
pub const ENTITY_TYPE_NOTE: u8 = 86;
/// ARCH-0069 S1/S2 secret custody (SECRET-01, ONE-1919): the `SecretCustodyRecord`
/// is the secret VALUE's home — plaintext bytes at rest under the vault DEK
/// plane, never claims / CRDT / export / logs. Maintenance classification in
/// the Companion band.
/// Byte 77 minted under the byte-space v3 rider (re-pick within 77–99 on a
/// spine conflict; registrations are not re-keys). Replication of this byte
/// is fail-closed until ONE-1865's per-credential dial replaces the interim
/// sync/selector.rs exclusion.
pub const ENTITY_TYPE_SECRET_CUSTODY: u8 = 77;
/// ARCH-0055 identity-topology ledger event (ONE-1743, owner-ruled seat;
/// byte pinned by the byte-space v3 canon row shipping in the docs lane).
/// Engine-authored maintenance record written ONLY by the identity-topology
/// apply/undo door; public puts are rejected with
/// `MaintenanceKindNotWritable` (D5/MODEL pattern) regardless of the byte's
/// band, and sync ingest rides the ARCH-0023b fail-closed single-writer
/// stream class.
pub const ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT: u8 = 76;
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
/// OF-277 connector-key registry record (GOV-01, ONE-1416). Engine-authored
/// maintenance kind carrying effector budgets (sends / spend / rate) and the
/// charter slots for one outbound connector key; public puts are rejected
/// with `MaintenanceKindNotWritable` (structural "no anonymous connectors").
/// Short-ID prefix `ck`.
pub const ENTITY_TYPE_CONNECTOR_KEY: u8 = 135;
/// ARCH-0035 communication projector record. Engine-authored maintenance
/// kind for source events, consent transitions, ruling receipts, and the
/// rebuildable contact-view cache.
pub const ENTITY_TYPE_COMM_RECORD: u8 = 136;
/// ONE-1741 SKILL_CONTENT_ANCHOR entity. Engine-authored maintenance kind: a
/// deterministic per-content-hash anchor that owns `skill.scan_verdict`
/// reserved claims, so scan verdicts key on the immortal content bytes rather
/// than any submitting SKILL holder (which can depart). Its 16-byte id is
/// derived from the 32-byte content hash (see
/// `skill_hub::skill_content_anchor_entity_id`), never `EntityId::now()`, so
/// two nodes ingesting the same bytes converge on one anchor. Public puts of
/// this byte are rejected with `MaintenanceKindNotWritable`.
pub const ENTITY_TYPE_SKILL_CONTENT_ANCHOR: u8 = 138;

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
/// OF-367 standing consent-grant substrate; CONNECTOR_KEY=135 is the OF-277
/// connector-key registry substrate; COMM_RECORD=136 is the ARCH-0035
/// communication projection substrate.
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
    /// OUTBOUND_GRANT=133, CONNECTOR_KEY=135, COMM_RECORD=136, runtime-induced and
    /// tenant-custom kinds).
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
/// CHANNEL_IDENTITY = 131, COUNTERPARTY_CONTACT = 132, OUTBOUND_GRANT = 133,
/// CONNECTOR_KEY = 135, COMM_RECORD = 136) are not StructuralKinds either. The reserved bytes
/// are unregistered. Only registered `core` and `pack` kinds qualify.
/// Unregistered bytes return `false` here AND remain rejected by
/// `validate_entity_type` on every write path (unchanged behavior).
#[must_use]
pub fn is_structural_kind(type_byte: u8) -> bool {
    matches!(
        entity_type_registry_entry(type_byte).map(|entry| entry.classification),
        Some(EntityClassification::Core | EntityClassification::Pack)
    )
}

/// Entity kinds the engine refuses to delete on every door (targeted, batch, or
/// replayed tombstone). `POLICY_MANIFEST` and `AUTHORITY_LOG` are authority-bearing
/// control-plane records; `SKILL_CONTENT_ANCHOR` (ONE-1741) is the immortal subject
/// that content-global scan verdicts hang off — deleting it would strand every
/// verdict for those content bytes. `IDENTITY_TOPOLOGY_EVENT` (ARCH-0055, type 76)
/// is the engine-authored merge/split ledger: dropping an event while its shell
/// edges survive would orphan the redirect (undo returns `EntityNotFound` and the
/// shell wedges), and the family's only reversal is an appended counter-event, never
/// a row deletion. The deletion/batch engine consults this neutral
/// registry predicate instead of naming the protected kinds itself, so the protected
/// set stays owned by the registry and cannot drift between delete doors.
#[must_use]
pub(crate) fn is_delete_protected_engine_record(entity_type: u8) -> bool {
    matches!(
        entity_type,
        ENTITY_TYPE_POLICY_MANIFEST
            | ENTITY_TYPE_AUTHORITY_LOG
            | ENTITY_TYPE_SKILL_CONTENT_ANCHOR
            | ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT
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
    // Maintenance-classified by owner ruling despite sitting in the 64–79
    // band (byte-space v3 canon row rides the docs lane): classification —
    // not band — drives the public-write rejection.
    EntityTypeRegistryEntry {
        kind: "IDENTITY_TOPOLOGY_EVENT",
        type_byte: ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
        short_id_prefix: None,
        classification: EntityClassification::Maintenance,
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
        kind: "NOTE",
        type_byte: ENTITY_TYPE_NOTE,
        short_id_prefix: Some("no"),
        classification: EntityClassification::Pack,
        band: TypeByteBand::Productivity,
    },
    EntityTypeRegistryEntry {
        kind: "SECRET_CUSTODY",
        type_byte: ENTITY_TYPE_SECRET_CUSTODY,
        short_id_prefix: None,
        classification: EntityClassification::Maintenance,
        band: TypeByteBand::Companion,
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
    EntityTypeRegistryEntry {
        kind: "CONNECTOR_KEY",
        type_byte: ENTITY_TYPE_CONNECTOR_KEY,
        short_id_prefix: Some("ck"),
        classification: EntityClassification::Maintenance,
        band: TypeByteBand::InducedDynamicMaintenance,
    },
    EntityTypeRegistryEntry {
        kind: "COMM_RECORD",
        type_byte: ENTITY_TYPE_COMM_RECORD,
        short_id_prefix: None,
        classification: EntityClassification::Maintenance,
        band: TypeByteBand::InducedDynamicMaintenance,
    },
    EntityTypeRegistryEntry {
        kind: "SKILL_CONTENT_ANCHOR",
        type_byte: ENTITY_TYPE_SKILL_CONTENT_ANCHOR,
        short_id_prefix: None,
        classification: EntityClassification::Maintenance,
        band: TypeByteBand::InducedDynamicMaintenance,
    },
];

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

/// Validates an entity type byte for PUBLIC write paths (D5).
///
/// Genuinely unknown bytes fail with [`Error::InvalidEntityType`]; every
/// REGISTERED `Maintenance`-classified kind fails with the distinct
/// [`Error::MaintenanceKindNotWritable`] — the maintenance band (≥ 120:
/// REDACTION_AUDIT, MODEL, POLICY_MANIFEST, FEDERATION_GRANT, ACCESS_GRANT,
/// PSYCH_PROFILE, CHANNEL_IDENTITY, COUNTERPARTY_CONTACT, OUTBOUND_GRANT,
/// PERSONA_SNAPSHOT_EXPORT, CONNECTOR_KEY, COMM_RECORD, SKILL_CONTENT_ANCHOR)
/// plus the classification-routed IDENTITY_TOPOLOGY_EVENT (76): the
/// classification, not the band, is what makes a kind engine-authored.
/// Reserved-unregistered maintenance bytes (CONNECTION_RECORD = 125,
/// DIAGNOSTIC = 126, FEDERATION_KEY_ENVELOPE = 127, SUSPICIOUS_WAKE = 130)
/// still fail with [`Error::InvalidEntityType`] so API-boundary error codes
/// never conflate "unknown byte" with "reserved maintenance kind".
/// Engine-internal writers (the REDACTION_AUDIT receipt writer, the MODEL
/// get-or-create door in `vault.rs`, policy-manifest resolver fixtures,
/// federation-grant substrate writers, the PsychProfile snapshot writer, and
/// the identity-topology apply/undo door) bypass this gate via
/// `allow_maintenance`.
///
/// [`Error::InvalidEntityType`]: crate::error::Error::InvalidEntityType
/// [`Error::MaintenanceKindNotWritable`]: crate::error::Error::MaintenanceKindNotWritable
pub(crate) fn validate_public_entity_type(entity_type: u8) -> crate::error::Result<()> {
    let entry = entity_type_registry_entry(entity_type)
        .ok_or(crate::error::Error::InvalidEntityType(entity_type))?;
    if entry.classification == EntityClassification::Maintenance {
        return Err(crate::error::Error::MaintenanceKindNotWritable(entity_type));
    }
    Ok(())
}
