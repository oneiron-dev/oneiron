//! Content-free reference-refusal facts and their receipt projection.

use crate::entity_id::EntityId;
use crate::store::receipt_row::{ReceiptKind, ReceiptRecord};
use std::collections::BTreeMap;

// Stable reasons recorded by reference-refusal receipts.

use serde::{Deserialize, Serialize};

use oneiron_contracts::memory::{MEMORY_CODE_INVENTED_REFERENCE, MEMORY_CODE_NOT_FOUND};

/// Why a write or an answer was refused (OF-063, Engine 10-18): the one
/// reason the refusal's reference-refusal receipt records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RefusalReason {
    /// A record it named does not resolve for its writer: invented,
    /// missing, or one the writer may not read.
    #[serde(rename = "INVENTED_REFERENCE")]
    InventedReference,
    /// The gate, the door's authority or the write's own checks refused it.
    #[serde(rename = "GATE_REFUSED")]
    GateRefused,
}

impl RefusalReason {
    /// The stable form, as the receipt records it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InventedReference => MEMORY_CODE_INVENTED_REFERENCE,
            Self::GateRefused => "GATE_REFUSED",
        }
    }

    /// Parses the stable form.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        [Self::InventedReference, Self::GateRefused]
            .into_iter()
            .find(|reason| reason.as_str() == value)
    }

    /// The reason a refused claim element's error gives (the one policy
    /// hook for it): a record it named that does not resolve is an invented
    /// reference, and every other refusal the gate's or its door's.
    pub(crate) fn of_code(code: &str) -> Self {
        if code == MEMORY_CODE_INVENTED_REFERENCE || code == MEMORY_CODE_NOT_FOUND {
            Self::InventedReference
        } else {
            Self::GateRefused
        }
    }
}

const OUTCOME_REFUSED: &str = "refused";
const OUTCOME_UNLINKED: &str = "unlinked";
const OUTCOME_CREATION_NOT_PROVEN: &str = "creation_not_proven";
/// The one trace a creation-status record carries: the record is real and
/// readable, but its birth does not prove its writer made it (FIX 1211). It
/// is neither an invented reference nor a gate refusal.
const TRACE_CREATION_NOT_PROVEN: &str = "CREATION_NOT_PROVEN";
const FIELD_ACTOR_CLASS: &str = "actor_class";
const FIELD_ROW: &str = "row";
const FIELD_FIELD: &str = "field";
/// Every field a reference-refusal receipt holds.
const REFUSAL_FIELDS: [&str; 3] = [FIELD_ACTOR_CLASS, FIELD_ROW, FIELD_FIELD];
const MAX_ROW_BYTES: usize = 128;
const MAX_FIELD_BYTES: usize = 256;

/// What became of the write that named an unresolved ref.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReferenceOutcome {
    /// A typed ref slot: the write was refused and never ran.
    Refused,
    /// A prose link: the text is kept as written, the link unlinked.
    ///
    /// This records the AI's attempt, not a landed message: the receipt is
    /// written before the engine call, on its own grouped write, so it stands
    /// even when that write then fails (a gate refusal, a cap). A reader of
    /// the audit family must not read it as proof the text landed.
    Unlinked,
    /// A landed reply said it created a record its writer reads, and the
    /// record's birth does not prove that writer made it (FIX 1211). The
    /// reply stands; the record is shown as not proven created.
    CreationNotProven,
}

impl ReferenceOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Refused => OUTCOME_REFUSED,
            Self::Unlinked => OUTCOME_UNLINKED,
            Self::CreationNotProven => OUTCOME_CREATION_NOT_PROVEN,
        }
    }
}

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
    /// What became of the write.
    pub(crate) outcome: ReferenceOutcome,
}

/// The receipt id of the reference-refusal record stored at `id`.
pub(crate) fn receipt_id(id: &EntityId) -> String {
    format!("reference_refusal:{}", id.to_hex())
}

const fn actor_class_name(class: crate::EdgeActorClass) -> &'static str {
    match class {
        crate::EdgeActorClass::Human => "human",
        crate::EdgeActorClass::Agent => "agent",
        crate::EdgeActorClass::System => "system",
    }
}

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
