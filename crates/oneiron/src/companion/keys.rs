//! Pinned on-disk constants for companion records and task payloads.

/// Dedicated companion-register structural kind byte.
///
/// Pinned by canon, not by arithmetic on a band start. The pre-v3 value was
/// byte 64, which byte-space v3 hands to REDACTION_AUDIT; the v3 allocation
/// table originally gave COMPANION_REGISTER no destination at all. The
/// canon-first resolution (oneiron-contracts `systemBandAllocation`, 2026-08-08)
/// puts it at 78 — the first free byte in the system zone after
/// SECRET_CUSTODY=77 — and ONE-1754 re-keys 64 → 78 inside its one atomic map.
/// Classification stays `Pack`: the kind remains publicly writable even though
/// it now sits in the system zone, because classification and not zone
/// position decides that. The registration is still lazy per vault.
pub const ENTITY_TYPE_COMPANION_REGISTER: u8 = 78;

/// Short-id prefix for companion-register rows.
pub const COMPANION_REGISTER_SHORT_ID_PREFIX: &str = "cr";

/// Pack id recorded in the vault-scoped structural-kind registry.
pub const COMPANION_REGISTER_PACK_ID: &str = "oneiron-companion-register";

/// Current companion record body schema version.
pub const COMPANION_RECORD_SCHEMA_VERSION: u64 = 2;

pub(super) const COMPANION_RECORD_SCHEMA_VERSION_V1: u64 = 1;

/// Pinned on-disk MessagePack key set for companion record bodies.
pub const COMPANION_RECORD_BODY_KEYS: [&str; 9] = [
    "schema_version",
    "kind",
    "scope",
    "subject",
    "value",
    "provenance",
    "lifecycle",
    "export",
    "lifecycle_events",
];

pub(super) const KEY_SCHEMA_VERSION: &str = COMPANION_RECORD_BODY_KEYS[0];

pub(super) const KEY_KIND: &str = COMPANION_RECORD_BODY_KEYS[1];

pub(super) const KEY_SCOPE: &str = COMPANION_RECORD_BODY_KEYS[2];

pub(super) const KEY_SUBJECT: &str = COMPANION_RECORD_BODY_KEYS[3];

pub(super) const KEY_VALUE: &str = COMPANION_RECORD_BODY_KEYS[4];

pub(super) const KEY_PROVENANCE: &str = COMPANION_RECORD_BODY_KEYS[5];

pub(super) const KEY_LIFECYCLE: &str = COMPANION_RECORD_BODY_KEYS[6];

pub(super) const KEY_EXPORT: &str = COMPANION_RECORD_BODY_KEYS[7];

pub(super) const KEY_LIFECYCLE_EVENTS: &str = COMPANION_RECORD_BODY_KEYS[8];

pub(super) const SCOPE_KEYS: [&str; 3] = ["kind", "person_ref", "vault_id"];

pub(super) const SUBJECT_KEYS: [&str; 3] = ["kind", "persona_ref", "relationship_ref"];

pub(super) const RELATIONSHIP_REF_KEYS: [&str; 2] = ["source_ref", "target_ref"];

pub(super) const PROVENANCE_KEYS: [&str; 5] =
    ["actor_ref", "actor_class", "source", "approval", "value"];

pub(super) const LIFECYCLE_EVENT_KEYS: [&str; 2] = ["kind", "at"];

/// Generic AttemptQueue kind used by all durable companion background tasks.
pub const COMPANION_TASK_ATTEMPT_KIND: &str = "companion_task";

/// Current companion task payload schema version.
pub const COMPANION_TASK_PAYLOAD_SCHEMA_VERSION: u64 = 1;

/// Pinned on-disk MessagePack key set for companion task payloads.
pub const COMPANION_TASK_PAYLOAD_KEYS: [&str; 4] = ["schema_version", "task", "scope", "subject"];

pub(super) const ERR_INVALID_COMPANION_TASK_PAYLOAD: &str = "invalid companion task payload";

pub(super) const KEY_TASK_SCHEMA_VERSION: &str = COMPANION_TASK_PAYLOAD_KEYS[0];

pub(super) const KEY_TASK: &str = COMPANION_TASK_PAYLOAD_KEYS[1];

pub(super) const KEY_TASK_SCOPE: &str = COMPANION_TASK_PAYLOAD_KEYS[2];

pub(super) const KEY_TASK_SUBJECT: &str = COMPANION_TASK_PAYLOAD_KEYS[3];
