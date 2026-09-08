//! Registry rows: the `ENTITY_TYPE_REGISTRY` table and its lookups.

use crate::companion::{COMPANION_REGISTER_SHORT_ID_PREFIX, ENTITY_TYPE_COMPANION_REGISTER};

use super::namespaces::ID_NAMESPACE_REGISTRY;
use super::type_bytes::{
    ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT,
    ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_BLOB_ARTIFACT, ENTITY_TYPE_CHANNEL_IDENTITY,
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_CODE_ARTIFACT, ENTITY_TYPE_CODE_SYMBOL, ENTITY_TYPE_COMM_RECORD,
    ENTITY_TYPE_CONNECTOR_KEY, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_COUNTERPARTY_CONTACT,
    ENTITY_TYPE_DIAGNOSTIC, ENTITY_TYPE_EVENT, ENTITY_TYPE_FACET, ENTITY_TYPE_FEDERATION_GRANT,
    ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT, ENTITY_TYPE_MACHINE, ENTITY_TYPE_MESSAGE,
    ENTITY_TYPE_MODEL, ENTITY_TYPE_NOTE, ENTITY_TYPE_NOTIFICATION, ENTITY_TYPE_ORG,
    ENTITY_TYPE_OUTBOUND_GRANT, ENTITY_TYPE_PERSON, ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT,
    ENTITY_TYPE_PLACE, ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_PSYCH_PROFILE,
    ENTITY_TYPE_REDACTION_AUDIT, ENTITY_TYPE_RELATIONSHIP, ENTITY_TYPE_SECRET_CUSTODY,
    ENTITY_TYPE_SESSION, ENTITY_TYPE_SKILL, ENTITY_TYPE_SKILL_CONTENT_ANCHOR, ENTITY_TYPE_SUMMARY,
    ENTITY_TYPE_TASK, ENTITY_TYPE_TASK_LIST, ENTITY_TYPE_TURN, ENTITY_TYPE_WORLD,
};
use super::zones::{EntityClassification, TypeByteZone};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntityTypeRegistryEntry {
    pub kind: &'static str,
    pub type_byte: u8,
    pub short_id_prefix: Option<&'static str>,
    /// Presentation prefixes this kind ANSWERS TO but never MINTS (ONE-1930).
    ///
    /// A prefix retires here when the canonical spelling changes: `short_id_prefix`
    /// is the one form new short ids are minted with, and every entry in this
    /// list still resolves to the same kind so already-published references keep
    /// working. Declaring the old form beside the new one is what keeps parsers
    /// from carrying their own hardcoded synonym tables.
    ///
    /// Empty on every row today: the four board-facing re-keys this field exists
    /// for (`cl→c`, `pr→p`, `sk→s`, `wd→w`) are held behind a canon change in
    /// `oneiron-docs` `site/src/data/oneiron-contracts.ts`, which
    /// `tests/byte_space_v3_conformance.rs` pins the engine to. When canon moves,
    /// those four rows gain their old spelling here and nothing else changes.
    ///
    /// INVARIANTS (pinned by `short_id_prefixes_are_globally_unique`): a legacy
    /// prefix is never also a canonical prefix, and no two rows share one.
    pub legacy_short_id_prefixes: &'static [&'static str],
    /// contracts.ts §1 classification for this kind.
    pub classification: EntityClassification,
    /// The v3 type-byte zone this kind is allocated within. Always equal to
    /// `zone_of(self.type_byte)` (pinned by spec test).
    pub zone: TypeByteZone,
}

impl EntityTypeRegistryEntry {
    /// Returns whether `prefix` names this kind — canonically or as a declared
    /// legacy spelling.
    #[must_use]
    pub fn answers_to_prefix(&self, prefix: &str) -> bool {
        self.short_id_prefix == Some(prefix) || self.legacy_short_id_prefixes.contains(&prefix)
    }
}

pub const ENTITY_TYPE_REGISTRY: &[EntityTypeRegistryEntry] = &[
    EntityTypeRegistryEntry {
        kind: "CLAIM",
        type_byte: ENTITY_TYPE_CLAIM,
        short_id_prefix: Some("cl"),
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Semantic,
        zone: TypeByteZone::Semantic,
    },
    EntityTypeRegistryEntry {
        kind: "TURN",
        type_byte: ENTITY_TYPE_TURN,
        short_id_prefix: Some("tn"),
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Core,
        zone: TypeByteZone::Core,
    },
    EntityTypeRegistryEntry {
        kind: "SESSION",
        type_byte: ENTITY_TYPE_SESSION,
        short_id_prefix: Some("ss"),
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Core,
        zone: TypeByteZone::Core,
    },
    EntityTypeRegistryEntry {
        kind: "MESSAGE",
        type_byte: ENTITY_TYPE_MESSAGE,
        short_id_prefix: Some("ms"),
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Core,
        zone: TypeByteZone::Core,
    },
    EntityTypeRegistryEntry {
        kind: "PERSON",
        type_byte: ENTITY_TYPE_PERSON,
        short_id_prefix: Some("pr"),
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Core,
        zone: TypeByteZone::Core,
    },
    EntityTypeRegistryEntry {
        kind: "RELATIONSHIP",
        type_byte: ENTITY_TYPE_RELATIONSHIP,
        short_id_prefix: Some("rl"),
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Core,
        zone: TypeByteZone::Core,
    },
    EntityTypeRegistryEntry {
        kind: "EVENT",
        type_byte: ENTITY_TYPE_EVENT,
        short_id_prefix: Some("ev"),
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Core,
        zone: TypeByteZone::Core,
    },
    EntityTypeRegistryEntry {
        kind: "SKILL",
        type_byte: ENTITY_TYPE_SKILL,
        short_id_prefix: Some("sk"),
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Core,
        zone: TypeByteZone::Core,
    },
    EntityTypeRegistryEntry {
        kind: "SUMMARY",
        type_byte: ENTITY_TYPE_SUMMARY,
        short_id_prefix: Some("sm"),
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Core,
        zone: TypeByteZone::Core,
    },
    EntityTypeRegistryEntry {
        kind: "PLACE",
        type_byte: ENTITY_TYPE_PLACE,
        short_id_prefix: Some("pl"),
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Core,
        zone: TypeByteZone::Core,
    },
    EntityTypeRegistryEntry {
        kind: "ASSET_TEXT",
        type_byte: ENTITY_TYPE_ASSET_TEXT,
        short_id_prefix: Some("tx"),
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Core,
        zone: TypeByteZone::Core,
    },
    EntityTypeRegistryEntry {
        kind: "CONVERSATION",
        type_byte: ENTITY_TYPE_CONVERSATION,
        short_id_prefix: Some("cv"),
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Core,
        zone: TypeByteZone::Core,
    },
    EntityTypeRegistryEntry {
        kind: "ORG",
        type_byte: ENTITY_TYPE_ORG,
        short_id_prefix: Some("og"),
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Core,
        zone: TypeByteZone::Core,
    },
    EntityTypeRegistryEntry {
        kind: "FACET",
        type_byte: ENTITY_TYPE_FACET,
        short_id_prefix: Some("fc"),
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Core,
        zone: TypeByteZone::Core,
    },
    EntityTypeRegistryEntry {
        kind: "WORLD",
        type_byte: ENTITY_TYPE_WORLD,
        short_id_prefix: Some("wd"),
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Core,
        zone: TypeByteZone::Core,
    },
    EntityTypeRegistryEntry {
        kind: "ASSET",
        type_byte: ENTITY_TYPE_ASSET,
        short_id_prefix: Some("as"),
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Core,
        zone: TypeByteZone::Core,
    },
    EntityTypeRegistryEntry {
        kind: "NOTIFICATION",
        type_byte: ENTITY_TYPE_NOTIFICATION,
        short_id_prefix: Some("nt"),
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Core,
        zone: TypeByteZone::Core,
    },
    EntityTypeRegistryEntry {
        kind: "AGENT_DEF",
        type_byte: ENTITY_TYPE_AGENT_DEF,
        short_id_prefix: Some("ag"),
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Core,
        zone: TypeByteZone::Core,
    },
    EntityTypeRegistryEntry {
        kind: "COMPANION_REGISTER",
        type_byte: ENTITY_TYPE_COMPANION_REGISTER,
        short_id_prefix: Some(COMPANION_REGISTER_SHORT_ID_PREFIX),
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Pack,
        zone: TypeByteZone::System,
    },
    // The system zone holds both engine-authored and publicly writable kinds:
    // classification — not zone position — drives the public-write rejection.
    // COMPANION_REGISTER above and this row are the two live proofs.
    EntityTypeRegistryEntry {
        kind: "IDENTITY_TOPOLOGY_EVENT",
        type_byte: ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
        short_id_prefix: None,
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Maintenance,
        zone: TypeByteZone::System,
    },
    EntityTypeRegistryEntry {
        kind: "TASK_LIST",
        type_byte: ENTITY_TYPE_TASK_LIST,
        short_id_prefix: Some("tl"),
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Pack,
        zone: TypeByteZone::CompiledProduct,
    },
    EntityTypeRegistryEntry {
        kind: "TASK",
        type_byte: ENTITY_TYPE_TASK,
        short_id_prefix: Some("tk"),
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Pack,
        zone: TypeByteZone::CompiledProduct,
    },
    EntityTypeRegistryEntry {
        kind: "MACHINE",
        type_byte: ENTITY_TYPE_MACHINE,
        short_id_prefix: Some("mc"),
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Pack,
        zone: TypeByteZone::CompiledProduct,
    },
    EntityTypeRegistryEntry {
        kind: "CODE_ARTIFACT",
        type_byte: ENTITY_TYPE_CODE_ARTIFACT,
        short_id_prefix: Some("cd"),
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Pack,
        zone: TypeByteZone::CompiledProduct,
    },
    EntityTypeRegistryEntry {
        kind: "CODE_SYMBOL",
        type_byte: ENTITY_TYPE_CODE_SYMBOL,
        short_id_prefix: Some("cs"),
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Pack,
        zone: TypeByteZone::CompiledProduct,
    },
    EntityTypeRegistryEntry {
        kind: "BLOB_ARTIFACT",
        type_byte: ENTITY_TYPE_BLOB_ARTIFACT,
        short_id_prefix: Some("ba"),
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Pack,
        zone: TypeByteZone::CompiledProduct,
    },
    EntityTypeRegistryEntry {
        kind: "NOTE",
        type_byte: ENTITY_TYPE_NOTE,
        short_id_prefix: Some("no"),
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Pack,
        zone: TypeByteZone::CompiledProduct,
    },
    EntityTypeRegistryEntry {
        kind: "SECRET_CUSTODY",
        type_byte: ENTITY_TYPE_SECRET_CUSTODY,
        short_id_prefix: None,
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Maintenance,
        zone: TypeByteZone::System,
    },
    EntityTypeRegistryEntry {
        kind: "REDACTION_AUDIT",
        type_byte: ENTITY_TYPE_REDACTION_AUDIT,
        short_id_prefix: None,
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Maintenance,
        zone: TypeByteZone::System,
    },
    EntityTypeRegistryEntry {
        kind: "MODEL",
        type_byte: ENTITY_TYPE_MODEL,
        short_id_prefix: Some("mo"),
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Maintenance,
        zone: TypeByteZone::System,
    },
    EntityTypeRegistryEntry {
        kind: "AUTHORITY_LOG",
        type_byte: ENTITY_TYPE_AUTHORITY_LOG,
        short_id_prefix: None,
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Maintenance,
        zone: TypeByteZone::System,
    },
    EntityTypeRegistryEntry {
        kind: "POLICY_MANIFEST",
        type_byte: ENTITY_TYPE_POLICY_MANIFEST,
        short_id_prefix: None,
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Maintenance,
        zone: TypeByteZone::System,
    },
    EntityTypeRegistryEntry {
        kind: "FEDERATION_GRANT",
        type_byte: ENTITY_TYPE_FEDERATION_GRANT,
        short_id_prefix: None,
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Maintenance,
        zone: TypeByteZone::System,
    },
    EntityTypeRegistryEntry {
        kind: "DIAGNOSTIC",
        type_byte: ENTITY_TYPE_DIAGNOSTIC,
        short_id_prefix: None,
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Maintenance,
        zone: TypeByteZone::System,
    },
    // Byte 125 CONNECTION_RECORD and byte 127 FEDERATION_KEY_ENVELOPE are
    // reserved and intentionally unregistered.
    //
    // DIAGNOSTIC is NOT among them any more: this comment used to read "byte
    // 126 DIAGNOSTIC", a pre-migration leftover that named a dev-only
    // experimental byte. Byte-space v3 ratified the move to byte 69, which is
    // registered above (ONE-1394) — nothing may re-claim 126 for it.
    EntityTypeRegistryEntry {
        kind: "ACCESS_GRANT",
        type_byte: ENTITY_TYPE_ACCESS_GRANT,
        short_id_prefix: None,
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Maintenance,
        zone: TypeByteZone::System,
    },
    EntityTypeRegistryEntry {
        kind: "PSYCH_PROFILE",
        type_byte: ENTITY_TYPE_PSYCH_PROFILE,
        short_id_prefix: None,
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Maintenance,
        zone: TypeByteZone::System,
    },
    // Byte 130 SUSPICIOUS_WAKE is reserved and intentionally unregistered.
    EntityTypeRegistryEntry {
        kind: "CHANNEL_IDENTITY",
        type_byte: ENTITY_TYPE_CHANNEL_IDENTITY,
        short_id_prefix: None,
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Maintenance,
        zone: TypeByteZone::System,
    },
    EntityTypeRegistryEntry {
        kind: "COUNTERPARTY_CONTACT",
        type_byte: ENTITY_TYPE_COUNTERPARTY_CONTACT,
        short_id_prefix: None,
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Maintenance,
        zone: TypeByteZone::System,
    },
    EntityTypeRegistryEntry {
        kind: "OUTBOUND_GRANT",
        type_byte: ENTITY_TYPE_OUTBOUND_GRANT,
        short_id_prefix: None,
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Maintenance,
        zone: TypeByteZone::System,
    },
    EntityTypeRegistryEntry {
        kind: "PERSONA_SNAPSHOT_EXPORT",
        type_byte: ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT,
        short_id_prefix: None,
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Maintenance,
        zone: TypeByteZone::System,
    },
    EntityTypeRegistryEntry {
        kind: "CONNECTOR_KEY",
        type_byte: ENTITY_TYPE_CONNECTOR_KEY,
        short_id_prefix: Some("ck"),
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Maintenance,
        zone: TypeByteZone::System,
    },
    EntityTypeRegistryEntry {
        kind: "COMM_RECORD",
        type_byte: ENTITY_TYPE_COMM_RECORD,
        short_id_prefix: None,
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Maintenance,
        zone: TypeByteZone::System,
    },
    EntityTypeRegistryEntry {
        kind: "SKILL_CONTENT_ANCHOR",
        type_byte: ENTITY_TYPE_SKILL_CONTENT_ANCHOR,
        short_id_prefix: None,
        legacy_short_id_prefixes: &[],
        classification: EntityClassification::Maintenance,
        zone: TypeByteZone::System,
    },
];

#[must_use]
pub fn entity_type_registry_entry(entity_type: u8) -> Option<&'static EntityTypeRegistryEntry> {
    ENTITY_TYPE_REGISTRY
        .iter()
        .find(|entry| entry.type_byte == entity_type)
}

/// Returns whether `type_byte` is a REGISTERED StructuralKind.
///
/// Per contracts.ts §1: byte 0 (CLAIM) is the semantic type and deliberately
/// NOT a StructuralKind, and the engine-authored system records in 64–99 are
/// not StructuralKinds either. Only registered `core` and `pack` kinds
/// qualify. Unregistered bytes return `false` here AND remain rejected by
/// `validate_entity_type` on every write path.
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

/// Returns the short ID prefix for an entity type byte.
///
/// Returns an error for unknown entity type IDs and registered maintenance
/// types with no short-ID prefix.
pub fn short_id_prefix(entity_type: u8) -> crate::error::Result<&'static str> {
    entity_type_registry_entry(entity_type)
        .and_then(|entry| entry.short_id_prefix)
        .ok_or(crate::error::Error::InvalidEntityType(entity_type))
}

/// Whether `short_id_prefix` is already spoken for by a STATIC declaration.
///
/// A dynamic pack registration must lose to every static claim on the prefix,
/// not just the canonical ones: taking a retired spelling would make old
/// references resolve to the new pack, and taking `vt` would shadow the vault
/// namespace. All three tables answer here so a caller cannot consult one and
/// miss the others.
#[must_use]
pub(crate) fn static_short_id_prefix_collision(short_id_prefix: &str) -> bool {
    ENTITY_TYPE_REGISTRY
        .iter()
        .any(|entry| entry.answers_to_prefix(short_id_prefix))
        || ID_NAMESPACE_REGISTRY
            .iter()
            .any(|entry| entry.prefix == short_id_prefix)
}
