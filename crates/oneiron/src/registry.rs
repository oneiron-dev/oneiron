//! Entity-type registry: type bytes, v3 zones, classification, the registry array + lookups/validators.

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
pub const ENTITY_TYPE_TASK_LIST: u8 = 100;
pub const ENTITY_TYPE_TASK: u8 = 101;
pub const ENTITY_TYPE_MACHINE: u8 = 102;
pub const ENTITY_TYPE_CODE_ARTIFACT: u8 = 103;
pub const ENTITY_TYPE_CODE_SYMBOL: u8 = 104;
/// OF-368 D1 (ARTL-1) versioned blob artifact for foreign binary (office)
/// files. Rides the OF-320 artifact model: append-only version chain in
/// `vault_meta`, content-addressed ASSET bytes, `blob.version` LEDGER claim
/// per version. A blob artifact is not a code artifact — kind = shape
/// (DEC-0005 §7), so CODE_ARTIFACT reuse was rejected.
pub const ENTITY_TYPE_BLOB_ARTIFACT: u8 = 105;
/// ARCH-0032 NOTE primitive (OF-330, ONE-1377): the cross-product
/// working-thought entity, landed with the single `opinion/take` kind so an
/// actor can record an attributed opinion BESIDE a neutral ARCH-0003 CLAIM
/// instead of editing it. Pack-registered in the compiled-product zone; bodies
/// ride the pinned `crate::note::NOTE_BODY_KEYS` ABI.
pub const ENTITY_TYPE_NOTE: u8 = 106;
/// ARCH-0069 S1/S2 secret custody (SECRET-01, ONE-1919): the `SecretCustodyRecord`
/// is the secret VALUE's home — plaintext bytes at rest under the vault DEK
/// plane, never claims / CRDT / export / logs. Maintenance classification in
/// the system zone.
/// Byte 77 minted under the byte-space v3 rider; already at its canon byte, so
/// ONE-1754's re-key has nothing to move for it. Replication of this byte is
/// fail-closed until ONE-1865's per-credential dial replaces the interim
/// sync/selector.rs exclusion.
pub const ENTITY_TYPE_SECRET_CUSTODY: u8 = 77;
/// ARCH-0055 identity-topology ledger event (ONE-1743, owner-ruled seat;
/// byte pinned by the byte-space v3 canon row shipping in the docs lane).
/// Engine-authored maintenance record written ONLY by the identity-topology
/// apply/undo door; public puts are rejected with
/// `MaintenanceKindNotWritable` (D5/MODEL pattern) regardless of the byte's
/// zone, and sync ingest rides the ARCH-0023b fail-closed single-writer
/// stream class.
pub const ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT: u8 = 76;
pub const ENTITY_TYPE_REDACTION_AUDIT: u8 = 64;
/// MODEL substrate entity (ONE-1138, ratified): engine-authored maintenance
/// kind — "written when a substrate first appears in a write path". Public
/// puts are rejected with `MaintenanceKindNotWritable`. Short-ID prefix
/// `mo` is RESERVED. MACHINE reuse was REJECTED — kind = shape
/// (DEC-0005 §7): a model substrate is not a device.
pub const ENTITY_TYPE_MODEL: u8 = 65;
/// AUTHORITY_LOG entry (ONE-1324). Engine-authored maintenance kind for the
/// fold-verified vault authority roster; public puts are rejected with
/// `MaintenanceKindNotWritable`.
pub const ENTITY_TYPE_AUTHORITY_LOG: u8 = 66;
/// DEC-0005 PolicyManifestV1 entity. Engine-authored maintenance kind used by
/// the Gate resolver; public puts are rejected with
/// `MaintenanceKindNotWritable`.
pub const ENTITY_TYPE_POLICY_MANIFEST: u8 = 67;
/// FED-001 FederationGrant entity. Engine-authored maintenance kind for
/// shared-vault membership records.
pub const ENTITY_TYPE_FEDERATION_GRANT: u8 = 68;
// Byte 69 DIAGNOSTIC, byte 72 SUSPICIOUS_WAKE, byte 74 CLAIM_CLASS_DESCRIPTOR
// and byte 75 SKILL_HUB are canon-reserved system bytes with no engine
// substrate yet. They stay deliberately unregistered — present in the canon
// conformance census as reserves, rejected with `InvalidEntityType` on every
// write path — rather than disappearing from the record.
/// OF-277 connector-key registry record (GOV-01, ONE-1416). Engine-authored
/// maintenance kind carrying effector budgets (sends / spend / rate) and the
/// charter slots for one outbound connector key; public puts are rejected
/// with `MaintenanceKindNotWritable` (structural "no anonymous connectors").
/// Short-ID prefix `ck`.
pub const ENTITY_TYPE_CONNECTOR_KEY: u8 = 70;
/// AEI-006 PsychProfile snapshot entity. Engine-authored maintenance kind for
/// derived profile mirror snapshots keyed by source revision ids.
pub const ENTITY_TYPE_PSYCH_PROFILE: u8 = 71;
/// EIRI-004 AccessGrant entity. Engine-authored maintenance kind for scoped
/// companion control-plane access records.
pub const ENTITY_TYPE_ACCESS_GRANT: u8 = 73;
/// OF-347 ChannelIdentity entity. Engine-authored maintenance kind for
/// vault-resident agent/channel addressability records.
pub const ENTITY_TYPE_CHANNEL_IDENTITY: u8 = 79;
/// OF-347 CounterpartyContact entity. Engine-authored maintenance kind for
/// per-(identity, counterparty) contact and consent records.
pub const ENTITY_TYPE_COUNTERPARTY_CONTACT: u8 = 80;
/// OF-367 StandingOutboundGrant entity. Engine-authored maintenance kind for
/// ask-card and bundle-approval outbound consent grants.
pub const ENTITY_TYPE_OUTBOUND_GRANT: u8 = 81;
/// OF-325 PersonaSnapshotExport entity. Engine-authored maintenance kind
/// recording each consent-gated persona snapshot export (mode A artifact);
/// projects into the receipt family as a Share receipt carrying the
/// persona_compile_stamp.
pub const ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT: u8 = 82;
/// ARCH-0035 communication projector record. Engine-authored maintenance
/// kind for source events, consent transitions, ruling receipts, and the
/// rebuildable contact-view cache.
pub const ENTITY_TYPE_COMM_RECORD: u8 = 83;
/// ONE-1741 SKILL_CONTENT_ANCHOR entity. Engine-authored maintenance kind: a
/// deterministic per-content-hash anchor that owns `skill.scan_verdict`
/// reserved claims, so scan verdicts key on the immortal content bytes rather
/// than any submitting SKILL holder (which can depart). Its 16-byte id is
/// derived from the 32-byte content hash (see
/// `skill_hub::skill_content_anchor_entity_id`), never `EntityId::now()`, so
/// two nodes ingesting the same bytes converge on one anchor. Public puts of
/// this byte are rejected with `MaintenanceKindNotWritable`.
pub const ENTITY_TYPE_SKILL_CONTENT_ANCHOR: u8 = 84;

/// Registry classification mirroring the contracts.ts §1
/// `EntityClassification` enum: `"semantic" | "core" | "pack" | "maintenance"`.
///
/// CLAIM (byte 0) is the single SEMANTIC type (ARCH-0003) and deliberately
/// NOT a StructuralKind; core and pack kinds ARE StructuralKinds; the system
/// zone's engine-authored records (REDACTION_AUDIT … SKILL_CONTENT_ANCHOR) are
/// not StructuralKinds either. Classification, not zone position, is what makes
/// a kind engine-authored: COMPANION_REGISTER sits inside the same 64–99 zone
/// and stays publicly writable because it is classified `Pack`.
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

/// The v3 type-byte ZONE map — the sole allocation authority, mirroring
/// contracts.ts §1 `typeByteBands`. The high bit is the engine/pack boundary:
/// the engine half is 0–127, the pack half 128–255.
///
/// Storage ABI: every u8 falls in exactly one zone. Zone membership is pure
/// namespace allocation — an unregistered byte still has a zone but is
/// rejected by [`validate_entity_type`] on every write path.
///
/// This is NOT the sync-selector / federation-scope vocabulary. That is a
/// separate, deliberately frozen wire type
/// ([`crate::sync::selector::SelectorRange`]); allocation decisions read this
/// enum and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeByteZone {
    /// Byte `0` — CLAIM's semantic type byte, not a StructuralKind.
    Semantic,
    /// Bytes `1–63` — universal CORE StructuralKinds. LOCKED, UNTOUCHED.
    Core,
    /// Bytes `64–99` — system kinds. Engine-authored maintenance records plus
    /// the classification-routed exceptions that stay publicly writable.
    System,
    /// Bytes `100–125` — compiled-in product packs. The ONLY zone a dynamic
    /// `register_structural_kind` may allocate within in production.
    CompiledProduct,
    /// Bytes `126–127` — engine-half experimental. Development mode only.
    EngineExperimental,
    /// Bytes `128–247` — PackByteMap per-vault local handles. NEVER statically
    /// allocated; rejected outright until the first runtime-installed-pack
    /// ticket ships the per-vault name → handle map.
    PackHandle,
    /// Bytes `248–254` — pack-half experimental. Development mode only.
    PackExperimental,
    /// Byte `255` — reserved sentinel. Always rejected, in every mode.
    Sentinel,
}

/// The single semantic type byte (CLAIM) — the entirety of the `0` zone.
pub const TYPE_BYTE_SEMANTIC: u8 = 0;
/// First byte of the CORE StructuralKinds zone (`1–63`).
pub const TYPE_BYTE_ZONE_CORE_START: u8 = 1;
/// Last byte of the CORE StructuralKinds zone (`1–63`).
pub const TYPE_BYTE_ZONE_CORE_END: u8 = 63;
/// First byte of the system-kind zone (`64–99`).
pub const TYPE_BYTE_ZONE_SYSTEM_START: u8 = 64;
/// Last byte of the system-kind zone (`64–99`).
pub const TYPE_BYTE_ZONE_SYSTEM_END: u8 = 99;
/// First byte of the compiled-in product-pack zone (`100–125`).
pub const TYPE_BYTE_ZONE_COMPILED_PRODUCT_START: u8 = 100;
/// Last byte of the compiled-in product-pack zone (`100–125`).
pub const TYPE_BYTE_ZONE_COMPILED_PRODUCT_END: u8 = 125;
/// First byte of the engine-half experimental zone (`126–127`).
pub const TYPE_BYTE_ZONE_ENGINE_EXPERIMENTAL_START: u8 = 126;
/// Last byte of the engine-half experimental zone (`126–127`).
pub const TYPE_BYTE_ZONE_ENGINE_EXPERIMENTAL_END: u8 = 127;
/// Maps a type byte to its v3 zone. Total over all 256 bytes.
///
/// The pack half's edges are spelled as literals HERE and nowhere else. Byte
/// 128 is not an allocation, but `pub const TYPE_BYTE_…: u8 = 128;` is
/// indistinguishable from one at a glance and is exactly the shape the
/// `byte_space_v3_has_no_static_pack_half_allocations` census forbids without
/// exemption — so the engine half keeps its named edges and the pack half's
/// live inside the match that IS the allocation table. Totality is still the
/// compiler's: this match has no wildcard arm.
#[must_use]
pub const fn zone_of(type_byte: u8) -> TypeByteZone {
    match type_byte {
        TYPE_BYTE_SEMANTIC => TypeByteZone::Semantic,
        TYPE_BYTE_ZONE_CORE_START..=TYPE_BYTE_ZONE_CORE_END => TypeByteZone::Core,
        TYPE_BYTE_ZONE_SYSTEM_START..=TYPE_BYTE_ZONE_SYSTEM_END => TypeByteZone::System,
        TYPE_BYTE_ZONE_COMPILED_PRODUCT_START..=TYPE_BYTE_ZONE_COMPILED_PRODUCT_END => {
            TypeByteZone::CompiledProduct
        }
        TYPE_BYTE_ZONE_ENGINE_EXPERIMENTAL_START..=TYPE_BYTE_ZONE_ENGINE_EXPERIMENTAL_END => {
            TypeByteZone::EngineExperimental
        }
        128..=247 => TypeByteZone::PackHandle,
        248..=254 => TypeByteZone::PackExperimental,
        255 => TypeByteZone::Sentinel,
    }
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

/// What an id-namespace prefix names.
///
/// The entity registry can only describe things that HAVE a type byte. `vt`
/// names vaults, and a vault is not an entity — it is the container entities
/// live in. Minting a VAULT type byte to make `vt` expressible would put a
/// false row in the storage ABI, so the namespace registry carries the
/// non-entity prefixes instead and the entity registry stays honest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdNamespaceTarget {
    /// A registered entity kind, named by its type byte.
    EntityType(u8),
    /// A vault, addressed by its 32-byte `authority::AuthorityVaultId`.
    Vault,
}

/// One presentation-id namespace: the prefix and what it resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdNamespaceRegistryEntry {
    pub target: IdNamespaceTarget,
    pub prefix: &'static str,
}

/// Canonical prefix for the vault id namespace.
pub const VAULT_ID_NAMESPACE_PREFIX: &str = "vt";

/// Presentation-id namespaces that are NOT backed by an entity type.
///
/// Entity-backed namespaces are not duplicated here — [`id_namespace_for_prefix`]
/// derives them from [`ENTITY_TYPE_REGISTRY`], so a prefix has exactly one
/// definition site and the two tables cannot drift apart.
pub const ID_NAMESPACE_REGISTRY: &[IdNamespaceRegistryEntry] = &[IdNamespaceRegistryEntry {
    target: IdNamespaceTarget::Vault,
    prefix: VAULT_ID_NAMESPACE_PREFIX,
}];

/// Resolves a presentation-id prefix to its namespace.
///
/// Entity kinds answer to their canonical prefix AND to any declared legacy
/// spelling; non-entity namespaces answer only to their canonical prefix
/// (nothing has retired one yet). Returns `None` for a prefix no registry
/// declares — that is the unknown-prefix RESOLUTION failure, and the layer
/// above may still admit the id through an exact alias row.
/// The returned entry always carries the CANONICAL spelling, so a caller
/// resolving a retired prefix learns the current one in the same lookup.
#[must_use]
pub fn id_namespace_for_prefix(prefix: &str) -> Option<IdNamespaceRegistryEntry> {
    if let Some(entry) = ENTITY_TYPE_REGISTRY
        .iter()
        .find(|entry| entry.answers_to_prefix(prefix))
        // A kind with no canonical prefix has no presentation namespace at all,
        // retired spellings or not — total by construction, no panic path.
        && let Some(canonical) = entry.short_id_prefix
    {
        return Some(IdNamespaceRegistryEntry {
            target: IdNamespaceTarget::EntityType(entry.type_byte),
            prefix: canonical,
        });
    }
    ID_NAMESPACE_REGISTRY
        .iter()
        .find(|entry| entry.prefix == prefix)
        .copied()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuralKindRegistration {
    pub type_byte: u8,
    pub short_id_prefix: String,
    pub zone: TypeByteZone,
    pub pack: String,
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
    // Byte 125 CONNECTION_RECORD, byte 126 DIAGNOSTIC, and byte 127
    // FEDERATION_KEY_ENVELOPE are reserved and intentionally unregistered.
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

/// Zone-aware static entity-type validation. ONE rule, two entry points — the
/// crate's [`validate_entity_type`] is a thin delegate that passes
/// `cfg!(debug_assertions)`, so production and development can never drift.
///
/// Registration-sensitivity is confined to the engine zones 0–125: a byte
/// there passes only if a static kind claims it (dynamic vault registrations
/// are layered on top by `Store::validate_entity_type`). Everything above is
/// decided by the zone alone, so no registry row — static or persisted — can
/// widen it:
///
/// * `128–247` (PackHandle) ALWAYS fails. PackByteMap is deliberately not
///   built here, so a stale persisted registration naming one of these bytes
///   cannot make a write pass.
/// * `126–127` and `248–254` are the two experimental zones: admitted only
///   under `dev`.
/// * `255` is the sentinel and fails in BOTH modes.
pub(crate) fn validate_entity_type_for_mode(
    entity_type: u8,
    dev: bool,
) -> crate::error::Result<()> {
    let invalid = || crate::error::Error::InvalidEntityType(entity_type);
    match zone_of(entity_type) {
        TypeByteZone::Semantic
        | TypeByteZone::Core
        | TypeByteZone::System
        | TypeByteZone::CompiledProduct => entity_type_registry_entry(entity_type)
            .map(|_| ())
            .ok_or_else(invalid),
        TypeByteZone::EngineExperimental | TypeByteZone::PackExperimental => {
            if dev {
                Ok(())
            } else {
                Err(invalid())
            }
        }
        TypeByteZone::PackHandle | TypeByteZone::Sentinel => Err(invalid()),
    }
}

pub(crate) fn validate_entity_type(entity_type: u8) -> crate::error::Result<()> {
    validate_entity_type_for_mode(entity_type, cfg!(debug_assertions))
}

/// Validates an entity type byte for PUBLIC write paths (D5).
///
/// Genuinely unknown bytes fail with [`Error::InvalidEntityType`]; every
/// REGISTERED `Maintenance`-classified kind fails with the distinct
/// [`Error::MaintenanceKindNotWritable`] — every engine-authored record in the
/// v3 system zone (REDACTION_AUDIT, MODEL, AUTHORITY_LOG, POLICY_MANIFEST,
/// FEDERATION_GRANT, CONNECTOR_KEY, PSYCH_PROFILE, ACCESS_GRANT,
/// IDENTITY_TOPOLOGY_EVENT, SECRET_CUSTODY, CHANNEL_IDENTITY,
/// COUNTERPARTY_CONTACT, OUTBOUND_GRANT, PERSONA_SNAPSHOT_EXPORT, COMM_RECORD,
/// SKILL_CONTENT_ANCHOR). Classification, not zone position, is what makes a
/// kind engine-authored — COMPANION_REGISTER shares the zone and stays
/// publicly writable. The canon-reserved system bytes with no engine substrate
/// (DIAGNOSTIC = 69, SUSPICIOUS_WAKE = 72, CLAIM_CLASS_DESCRIPTOR = 74,
/// SKILL_HUB = 75) still fail with [`Error::InvalidEntityType`] so
/// API-boundary error codes never conflate "unknown byte" with "reserved
/// system kind".
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
