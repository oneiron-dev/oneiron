//! Entity-type registry: type bytes, v3 zones, classification, the registry array + lookups/validators.

mod namespaces;
mod registry_table;
mod type_bytes;
mod validation;
mod zones;

pub use self::namespaces::{
    ID_NAMESPACE_REGISTRY, IdNamespaceRegistryEntry, IdNamespaceTarget, StructuralKindRegistration,
    VAULT_ID_NAMESPACE_PREFIX, id_namespace_for_prefix,
};
pub use self::registry_table::{
    ENTITY_TYPE_REGISTRY, EntityTypeRegistryEntry, entity_type_registry_entry, is_structural_kind,
    short_id_prefix,
};
pub use self::type_bytes::{
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
pub use self::zones::{
    EntityClassification, TYPE_BYTE_SEMANTIC, TYPE_BYTE_ZONE_COMPILED_PRODUCT_END,
    TYPE_BYTE_ZONE_COMPILED_PRODUCT_START, TYPE_BYTE_ZONE_CORE_END, TYPE_BYTE_ZONE_CORE_START,
    TYPE_BYTE_ZONE_ENGINE_EXPERIMENTAL_END, TYPE_BYTE_ZONE_ENGINE_EXPERIMENTAL_START,
    TYPE_BYTE_ZONE_SYSTEM_END, TYPE_BYTE_ZONE_SYSTEM_START, TypeByteZone, zone_of,
};

pub(crate) use self::registry_table::{
    is_delete_protected_engine_record, static_short_id_prefix_collision,
};
pub(crate) use self::validation::{validate_entity_type, validate_public_entity_type};
// Only the `#[cfg(test)]` type-registry suite names this door; the crate's own
// `validate_entity_type` delegate calls it inside `validation.rs` directly.
#[cfg(test)]
pub(crate) use self::validation::validate_entity_type_for_mode;
