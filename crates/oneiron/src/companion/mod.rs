//! Companion relationship/persona record substrate.
//!
//! This module is intentionally storage-agnostic: it defines the typed record
//! shape, canonical MessagePack body encoding, and a small register used by
//! callers/tests before later API or vault wiring.

mod codec;
mod keys;
mod model;
mod queue;
mod register;
mod store;
mod vault;

pub use self::codec::{
    companion_value_from_json, companion_value_to_json, decode_companion_record_body,
    encode_companion_record_body,
};
pub use self::keys::{
    COMPANION_RECORD_BODY_KEYS, COMPANION_RECORD_SCHEMA_VERSION, COMPANION_REGISTER_PACK_ID,
    COMPANION_REGISTER_SHORT_ID_PREFIX, COMPANION_TASK_ATTEMPT_KIND, COMPANION_TASK_PAYLOAD_KEYS,
    COMPANION_TASK_PAYLOAD_SCHEMA_VERSION, ENTITY_TYPE_COMPANION_REGISTER,
};
pub use self::model::{
    CompanionExportClassification, CompanionExpression, CompanionLifecycleEvent,
    CompanionLifecycleEventKind, CompanionProvenance, CompanionRecord, CompanionRecordKey,
    CompanionRecordKind, CompanionScope, CompanionSubject,
};
pub use self::queue::{
    ClaimCompanionTask, ClaimCompanionTaskOutcome, CompanionQueue, CompanionTask,
    CompanionTaskKind, CompanionTaskStatus, CompleteCompanionTask, CompleteCompanionTaskOutcome,
    EndCompanionRelationship, EndCompanionRelationshipOutcome, EnqueueCompanionTask,
    EnqueueCompanionTaskOutcome, FailCompanionTask, FailCompanionTaskOutcome, RetryCompanionTask,
    RetryCompanionTaskOutcome, decode_companion_task_payload, encode_companion_task_payload,
};
pub use self::register::{
    CompanionExpressionRegister, CompanionRegister, CompanionScopeResolution,
    CompanionScopeResolutionSource,
};
pub(crate) use self::store::companion_record_key_lookup_in_txn;

#[cfg(test)]
mod tests;

// The flat companion.rs module used to provide these names to the sibling test
// module through `use super::*`: its own private crate/std import header, and
// every companion-internal item the tests name bare. After the directory split
// the seam re-imports both so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::{codec::*, keys::*};
#[cfg(test)]
use crate::attempt_queue::{ClaimAttempt, ClaimOutcome};
#[cfg(test)]
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
#[cfg(test)]
use crate::edge::EdgeActorClass;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::write_envelope::WriteEnvelope;
#[cfg(test)]
use rmpv::Value;
