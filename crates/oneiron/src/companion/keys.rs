//! Retired register discriminator and durable companion task payload keys.

pub use oneiron_contracts::companion::{
    COMPANION_REGISTER_SHORT_ID_PREFIX, ENTITY_TYPE_COMPANION_REGISTER,
};

pub(super) const SCOPE_KEYS: [&str; 3] = ["kind", "person_ref", "vault_id"];

pub(super) const SUBJECT_KEYS: [&str; 3] = ["kind", "persona_ref", "relationship_ref"];

pub(super) const RELATIONSHIP_REF_KEYS: [&str; 2] = ["source_ref", "target_ref"];

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
