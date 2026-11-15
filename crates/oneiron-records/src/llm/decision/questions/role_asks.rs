//! Moved from `crates/oneiron/src/llm/decision/questions/role_asks.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_wake_contract::llm::decision::types::TypedDecision;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;

/// One unit's person ask: the unit (an artifact unit's artifact), the declined decision it
/// went up from (its receipt names the question, principal and ask) and, once its holder's
/// answer landed on the unit, that answer's claim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuestionUnitAsk {
    /// The ask's arrival number.
    pub seq: u64,
    #[serde(with = "oneiron_store::model_decision::codec::entity")]
    pub unit: EntityId,
    /// The unit's source hash when it was asked.
    pub frontier: [u8; 32],
    pub source_kind: u8,
    /// The ladder's abstention that queued the ask, with its receipt.
    pub declined: TypedDecision,
    /// The `judgment.answer` claim the holder's answer landed as; none while the ask waits.
    #[serde(with = "oneiron_store::model_decision::codec::optional_entity")]
    pub applied: Option<EntityId>,
    /// The artifact unit the ask is for, as its caller named it (a sheet row, a paragraph,
    /// a folder file); none for a graph unit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_unit: Option<serde_json::Value>,
}
