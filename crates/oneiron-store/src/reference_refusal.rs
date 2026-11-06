//! Content-free reference-refusal facts and their receipt projection.

use crate::receipt_row::ReceiptKind;
use oneiron_contracts::entity_id::EntityId;
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
    pub fn of_code(code: &str) -> Self {
        if code == MEMORY_CODE_INVENTED_REFERENCE || code == MEMORY_CODE_NOT_FOUND {
            Self::InventedReference
        } else {
            Self::GateRefused
        }
    }
}

pub const OUTCOME_REFUSED: &str = "refused";
pub const OUTCOME_UNLINKED: &str = "unlinked";
pub const OUTCOME_CREATION_NOT_PROVEN: &str = "creation_not_proven";
/// The one trace a creation-status record carries: the record is real and
/// readable, but its birth does not prove its writer made it (FIX 1211). It
/// is neither an invented reference nor a gate refusal.
pub const TRACE_CREATION_NOT_PROVEN: &str = "CREATION_NOT_PROVEN";
pub const FIELD_ACTOR_CLASS: &str = "actor_class";
pub const FIELD_ROW: &str = "row";
pub const FIELD_FIELD: &str = "field";
/// Every field a reference-refusal receipt holds.
pub const REFUSAL_FIELDS: [&str; 3] = [FIELD_ACTOR_CLASS, FIELD_ROW, FIELD_FIELD];
pub const MAX_ROW_BYTES: usize = 128;
pub const MAX_FIELD_BYTES: usize = 256;

/// What became of the write that named an unresolved ref.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceOutcome {
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
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Refused => OUTCOME_REFUSED,
            Self::Unlinked => OUTCOME_UNLINKED,
            Self::CreationNotProven => OUTCOME_CREATION_NOT_PROVEN,
        }
    }
}

/// What one reference refusal records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceRefusalFacts {
    /// The writer the refusal answered.
    pub actor: EntityId,
    /// The writer's class.
    pub actor_class: oneiron_base::edge::EdgeActorClass,
    /// The verb-table row the write came through.
    pub row: &'static str,
    /// The JSON pointer of the slot whose ref did not resolve.
    pub field: String,
    /// What became of the write.
    pub outcome: ReferenceOutcome,
}

/// The receipt id of the reference-refusal record stored at `id`.
pub fn receipt_id(id: &EntityId) -> String {
    format!("reference_refusal:{}", id.to_hex())
}

pub const fn actor_class_name(class: oneiron_base::edge::EdgeActorClass) -> &'static str {
    match class {
        oneiron_base::edge::EdgeActorClass::Human => "human",
        oneiron_base::edge::EdgeActorClass::Agent => "agent",
        oneiron_base::edge::EdgeActorClass::System => "system",
    }
}
