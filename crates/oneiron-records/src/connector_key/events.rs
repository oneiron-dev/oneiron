//! Moved from `crates/oneiron/src/connector_key/events.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value as Json;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorEvent {
    pub event_id: String,
    pub connector: String,
    pub event_kind: String,
    pub predicate: String,
    pub payload: Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorWakeStatus {
    Enqueued,
    KeyInactive,
    BudgetExhausted,
    /// A full count-bound budget window paces the wake (FIX 8686): the
    /// event waits, uncharged, and is admitted again once the window opens.
    Deferred,
    /// A paced wake reached its deadline before its window let it in
    /// (FIX 8753): nothing was charged and no agent woke.
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorWakeDecision {
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
    pub subscription: EntityId,
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
    pub agent: EntityId,
    pub status: ConnectorWakeStatus,
    pub attempt_id: Option<[u8; 16]>,
    pub event_hash: String,
    /// A deferred wake's due instant, Unix seconds: when its window opens
    /// and it is admitted again (FIX 8686).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paced_until: Option<u64>,
}

pub fn invalid() -> Error {
    Error::InvalidConfig("invalid connector event subscription".into())
}

pub fn valid_ref(value: &str) -> bool {
    !value.trim().is_empty() && value == value.trim() && value.len() <= 256 && !value.contains('\0')
}
