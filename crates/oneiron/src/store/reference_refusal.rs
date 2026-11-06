//! Core half of `store::reference_refusal`: its store-layer items live in `oneiron_store::reference_refusal` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::reference_refusal::*;

use crate::entity_id::EntityId;
use crate::store::receipt_row::{ReceiptKind, ReceiptRecord};
use std::collections::BTreeMap;
// Stable reasons recorded by reference-refusal receipts.

use oneiron_contracts::memory::{MEMORY_CODE_INVENTED_REFERENCE, MEMORY_CODE_NOT_FOUND};
use serde::{Deserialize, Serialize};

/// The receipt the record at `id` carries: its outcome, at `at`, for
/// `reason`. A creation status carries its own trace, never `reason`.
/// `facts` are as [`stamped_facts`] gives them: a refusal's actor is its
/// writer's stamp token, which the receipt stores as its actor (FIX 11040).
pub(crate) fn reference_refusal_receipt(
    id: &EntityId,
    facts: &ReferenceRefusalFacts,
    reason: RefusalReason,
    at: u64,
) -> ReceiptRecord {
    // A creation status names no actor id: it records what the writer's
    // reply asserted, and names nothing an actor's erase must reach.
    let (trace, actor) = match facts.outcome {
        ReferenceOutcome::CreationNotProven => (TRACE_CREATION_NOT_PROVEN, None),
        ReferenceOutcome::Refused | ReferenceOutcome::Unlinked => {
            (reason.as_str(), Some(facts.actor.to_hex()))
        }
    };
    let fields = BTreeMap::from([
        (
            FIELD_ACTOR_CLASS.to_owned(),
            actor_class_name(facts.actor_class).to_owned(),
        ),
        (FIELD_ROW.to_owned(), facts.row.to_owned()),
        (FIELD_FIELD.to_owned(), facts.field.clone()),
    ]);
    ReceiptRecord {
        receipt_id: receipt_id(id),
        receipt_kind: ReceiptKind::ReferenceRefusal,
        occurred_at: at,
        actor,
        on_behalf_of: None,
        outcome: facts.outcome.as_str().to_owned(),
        job_ref: None,
        trigger_ref: None,
        policy_trace: vec![trace.to_owned()],
        fields,
    }
}

/// Whether `receipt` is the reference-refusal record `id` carries: its own
/// id, the outcome `refused` or `unlinked` with a hex actor (its writer's
/// stamp token) and one typed reason, or `creation_not_proven` with no actor and its one trace, and
/// exactly the refusal facts, each in its bounded shape, so no carrier can
/// smuggle an attempt's content into the audit family.
pub(crate) fn binds(id: &EntityId, receipt: &ReceiptRecord) -> bool {
    let field = |name: &str| receipt.fields.get(name).map(String::as_str);
    let hex_actor = receipt.actor.as_deref().is_some_and(|actor| {
        EntityId::from_hex(actor).is_ok_and(|parsed| parsed.to_hex() == actor)
    });
    let traced = match receipt.outcome.as_str() {
        OUTCOME_REFUSED | OUTCOME_UNLINKED => {
            hex_actor
                && matches!(
                    receipt.policy_trace.as_slice(),
                    [reason] if RefusalReason::parse(reason).is_some()
                )
        }
        OUTCOME_CREATION_NOT_PROVEN => {
            receipt.actor.is_none()
                && matches!(
                    receipt.policy_trace.as_slice(),
                    [trace] if trace == TRACE_CREATION_NOT_PROVEN
                )
        }
        _ => false,
    };
    receipt.receipt_kind == ReceiptKind::ReferenceRefusal
        && receipt.receipt_id == receipt_id(id)
        && traced
        && receipt.on_behalf_of.is_none()
        && receipt.job_ref.is_none()
        && receipt.trigger_ref.is_none()
        && matches!(field(FIELD_ACTOR_CLASS), Some("human" | "agent" | "system"))
        && field(FIELD_ROW).is_some_and(|row| {
            !row.is_empty()
                && row.len() <= MAX_ROW_BYTES
                && row.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || byte == b'.'
                        || byte == b'_'
                })
        })
        && field(FIELD_FIELD).is_some_and(|pointer| {
            pointer.starts_with('/')
                && pointer.len() <= MAX_FIELD_BYTES
                && pointer.bytes().all(|byte| byte.is_ascii_graphic())
        })
        && receipt.fields.len() == REFUSAL_FIELDS.len()
        && receipt
            .fields
            .keys()
            .all(|key| REFUSAL_FIELDS.contains(&key.as_str()))
}
