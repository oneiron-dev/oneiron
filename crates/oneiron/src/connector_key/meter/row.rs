//! Effector budget row identity: the source (key budget row or compiled
//! charter cap) and the ordinal a usage row, a match, a debit, a ladder
//! event or an exhaustion names, and the key that owns it.
//! Entry: `EffectorBudgetRowId`. Defines its own items.

use serde::{Deserialize, Serialize};

use super::*;

#[doc(hidden)]
pub(crate) use oneiron_records::connector_key::meter::row::{
    EFFECTOR_BUDGET_ROW_KEY_LEN, EFFECTOR_BUDGET_ROW_TAG_CHARTER, EFFECTOR_BUDGET_ROW_TAG_KEY,
};
#[doc(hidden)]
pub use oneiron_records::connector_key::meter::row::{
    EffectorBudgetLocation, EffectorBudgetRowId, EffectorBudgetRowSource,
};

/// A ladder threshold one effector budget row crossed in a charge, for the
/// host's one steering queue (same contract as `BudgetAdmission.ladder_events`
/// in the LLM meter, whose own rows it never joins).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectorBudgetLadderEvent {
    /// The row of the emitting key that fired the event: a dispatch matching
    /// several rows can cross the same threshold on more than one.
    pub row: EffectorBudgetRowId,
    pub threshold: BudgetThreshold,
    pub steering: Option<BudgetSteeringSignal>,
}

/// Thresholds first emitted by one confirmed outbound settlement, under
/// the key whose rows fired, including co-actor and catalog-pool keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectorBudgetSettlementEvents {
    pub key_ref: EntityId,
    pub ladder_events: Vec<EffectorBudgetLadderEvent>,
}

/// Suspension and refusal reason for an exhausted budget row: the owning key
/// and the row, so a pool row reads as the catalog key's, never the
/// per-grant key's (FIX 3760).
pub(crate) fn budget_exhausted_reason(location: &EffectorBudgetLocation) -> String {
    let key = location.key_ref.to_hex();
    let index = location.row.index;
    match location.row.source {
        EffectorBudgetRowSource::Key => format!("budget_exhausted:key:{key}:row:{index}"),
        EffectorBudgetRowSource::Charter => {
            format!("budget_exhausted:key:{key}:charter_row:{index}")
        }
    }
}

/// The ordinal of a row at `offset` in its source's list.
pub(super) fn row_ordinal(offset: usize) -> u64 {
    // usize is at most 64 bits on every supported target.
    offset as u64
}
