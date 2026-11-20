//! Moved from `crates/oneiron/src/phone_line/mod.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::federation::Scope;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The owner's explicit setting. A missing setting is off; enabling it grants no reads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhoneLineConfig {
    pub enabled: bool,
    pub share_scope: Scope,
}

/// The actual identity, receiving agent and channel actor the owner configured.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhoneLineState {
    pub identity_ref: EntityId,
    pub agent_ref: EntityId,
    pub bridge_actor: EntityId,
    pub owner_actor: EntityId,
    pub enabled: bool,
    /// Consent data only, enforced beside an answering reader's actual credential.
    pub share_scope: Scope,
    pub updated_at: u64,
}

/// Untrusted provider metadata, never a recognized person or an instruction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhoneLineArrival {
    pub call_id: String,
    pub caller: Option<String>,
}

/// Quarantined arrival metadata behind an opaque reference in the existing inbox queue.
/// There is no recording, transcript, answered-call or provider-identity claim here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhoneLineArrivalRecord {
    pub identity_ref: EntityId,
    pub agent_ref: EntityId,
    pub bridge_actor: EntityId,
    pub share_scope: Scope,
    pub arrival: PhoneLineArrival,
    pub received_at: u64,
    pub payload_ref: String,
    pub correlation_id: String,
    pub attempt_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PhoneLineArrivalReceipt {
    pub record: PhoneLineArrivalRecord,
    pub replayed: bool,
}
