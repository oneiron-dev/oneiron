//! Companion task queue and PERSON/FACET persona compilation.
//!
//! Old persona/relationship-shaped FACET bodies and the retired register type
//! are classified here solely so every storage, sync and export door refuses
//! them. Scenario masks remain ordinary FACET rows.

mod codec;
mod keys;
mod model;
mod persona;
mod queue;
mod vault;

/// The retired identity carrier is never a PERSON baseline or scenario mask.
/// Byte 115 is closed outright; legacy persona/relationship bodies hidden on
/// FACET are equally non-portable at every storage and sync outlet.
pub(crate) fn is_retired_identity_carrier(kind: u8, data: &[u8]) -> bool {
    kind == ENTITY_TYPE_COMPANION_REGISTER
        || (kind == crate::registry::ENTITY_TYPE_FACET && is_identity_facet_body(data))
}

pub(crate) fn is_identity_facet_body(data: &[u8]) -> bool {
    let Ok(rmpv::Value::Map(entries)) = rmpv::decode::read_value(&mut &data[..]) else {
        return false;
    };
    entries.iter().any(|(k, v)| {
        k.as_str() == Some("kind") && matches!(v.as_str(), Some("persona" | "relationship"))
    })
}

pub use self::codec::{companion_value_from_json, companion_value_to_json};
pub use self::keys::{
    COMPANION_REGISTER_SHORT_ID_PREFIX, COMPANION_TASK_ATTEMPT_KIND, COMPANION_TASK_PAYLOAD_KEYS,
    COMPANION_TASK_PAYLOAD_SCHEMA_VERSION, ENTITY_TYPE_COMPANION_REGISTER,
};
pub use self::model::{
    CompanionExpression, CompanionRecordKey, CompanionRecordKind, CompanionScope, CompanionSubject,
};
pub use self::persona::{CompiledPersona, PERSONA_CHANGE_PREDICATE, PersonaChange, PersonaMadeBy};
pub(crate) use self::persona::{body_fields as persona_body_fields, validated_persona_baseline};
pub use self::queue::{
    ClaimCompanionTask, ClaimCompanionTaskOutcome, CompanionQueue, CompanionTask,
    CompanionTaskKind, CompanionTaskStatus, CompleteCompanionTask, CompleteCompanionTaskOutcome,
    EnqueueCompanionTask, EnqueueCompanionTaskOutcome, FailCompanionTask, FailCompanionTaskOutcome,
    RetryCompanionTask, RetryCompanionTaskOutcome, decode_companion_task_payload,
    encode_companion_task_payload,
};

#[cfg(test)]
pub(crate) mod tests;

// The flat companion.rs module used to provide these names to the sibling test
// module through `use super::*`: its own private crate/std import header, and
// every companion-internal item the tests name bare. After the directory split
// the seam re-imports both so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::keys::*;
#[cfg(test)]
use crate::attempt_queue::{ClaimAttempt, ClaimOutcome};
#[cfg(test)]
use crate::error::Result;
