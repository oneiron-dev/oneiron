//! Reference-refusal receipts (OF-063): a write was refused because a record
//! ref it named does not resolve for its writer.
//!
//! The refusal is receipted where it happens, on its own write, before the
//! caller hears it; the refused write never ran. The receipt names the actor,
//! the actor's class, the verb row, the field pointer and the time, as its own
//! RECEIPT_RECORD. It never holds the ref, the rejected value or any other
//! content of the attempt: the audit family keeps only that a write was
//! refused, by whom, through which row and at which field.

use std::collections::BTreeMap;

use super::{ReceiptKind, ReceiptRecord};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

const OUTCOME_REFUSED: &str = "refused";
/// The one reason every reference refusal carries: the typed facade code.
const REASON: &str = crate::memory::MEMORY_CODE_INVENTED_REFERENCE;
const FIELD_ACTOR_CLASS: &str = "actor_class";
const FIELD_ROW: &str = "row";
const FIELD_FIELD: &str = "field";
/// Every field a reference-refusal receipt holds.
const REFUSAL_FIELDS: [&str; 3] = [FIELD_ACTOR_CLASS, FIELD_ROW, FIELD_FIELD];
const MAX_ROW_BYTES: usize = 128;
const MAX_FIELD_BYTES: usize = 256;

/// What one reference refusal records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReferenceRefusalFacts {
    /// The writer the refusal answered.
    pub(crate) actor: EntityId,
    /// The writer's class.
    pub(crate) actor_class: crate::EdgeActorClass,
    /// The verb-table row the write came through.
    pub(crate) row: &'static str,
    /// The JSON pointer of the slot whose ref did not resolve.
    pub(crate) field: String,
}

/// The receipt id of the reference-refusal record stored at `id`.
fn receipt_id(id: &EntityId) -> String {
    format!("reference_refusal:{}", id.to_hex())
}

const fn actor_class_name(class: crate::EdgeActorClass) -> &'static str {
    match class {
        crate::EdgeActorClass::Human => "human",
        crate::EdgeActorClass::Agent => "agent",
        crate::EdgeActorClass::System => "system",
    }
}

/// The receipt the record at `id` carries: `refused`, at `at`.
pub(super) fn reference_refusal_receipt(
    id: &EntityId,
    facts: &ReferenceRefusalFacts,
    at: u64,
) -> ReceiptRecord {
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
        actor: Some(facts.actor.to_hex()),
        on_behalf_of: None,
        outcome: OUTCOME_REFUSED.to_owned(),
        job_ref: None,
        trigger_ref: None,
        policy_trace: vec![REASON.to_owned()],
        fields,
    }
}

/// Whether `receipt` is the reference-refusal record `id` carries: its own
/// id, a hex actor, the outcome `refused`, the one reason, and exactly the
/// refusal facts, each in its bounded shape, so no carrier can smuggle an
/// attempt's content into the audit family.
pub(super) fn binds(id: &EntityId, receipt: &ReceiptRecord) -> bool {
    let field = |name: &str| receipt.fields.get(name).map(String::as_str);
    receipt.receipt_kind == ReceiptKind::ReferenceRefusal
        && receipt.receipt_id == receipt_id(id)
        && receipt.outcome == OUTCOME_REFUSED
        && receipt.actor.as_deref().is_some_and(|actor| {
            EntityId::from_hex(actor).is_ok_and(|parsed| parsed.to_hex() == actor)
        })
        && receipt.on_behalf_of.is_none()
        && receipt.job_ref.is_none()
        && receipt.trigger_ref.is_none()
        && matches!(receipt.policy_trace.as_slice(), [reason] if reason == REASON)
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

/// Receipts `facts` as one reference refusal, on its own grouped write. The
/// refused write staged nothing, so nothing else rides this write, and the
/// caller hears the refusal only once it commits.
pub(crate) fn record_reference_refusal(vault: &Vault, facts: &ReferenceRefusalFacts) -> Result<()> {
    vault.store.write_in_group(|txn| {
        // The id first: the floor `recorded_at_in_txn` persists covers it.
        let id = vault.store.clock.entity_id()?;
        let at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        super::record::put_reference_refusal_in_txn(vault, txn, id, facts, at)
    })
}
