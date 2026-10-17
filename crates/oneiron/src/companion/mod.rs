//! Companion task queue and PERSON/FACET persona compilation.
//!
//! PERSON holds baseline and evolved identity; a FACET is an explicit scenario
//! mask. A FACET body shaped as a persona or relationship is refused at write
//! admission, on both the local and the sync door.

mod codec;
mod keys;
mod model;
mod persona;
mod queue;
mod vault;

/// A FACET body naming `kind` `persona` or `relationship` carries identity,
/// which belongs on PERSON. Both write-admission refusals share this shape test.
pub(crate) fn is_identity_facet_body(data: &[u8]) -> bool {
    let Ok(rmpv::Value::Map(entries)) = rmpv::decode::read_value(&mut &data[..]) else {
        return false;
    };
    entries.iter().any(|(k, v)| {
        k.as_str() == Some("kind") && matches!(v.as_str(), Some("persona" | "relationship"))
    })
}

pub use self::keys::{
    COMPANION_TASK_ATTEMPT_KIND, COMPANION_TASK_PAYLOAD_KEYS, COMPANION_TASK_PAYLOAD_SCHEMA_VERSION,
};
pub use self::model::{
    CompanionExpression, CompanionScope, CompanionSubject, CompanionSubjectKind, CompanionTaskKey,
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
