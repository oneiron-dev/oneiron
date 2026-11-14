//! Moved from `crates/oneiron/src/campaign/enrollment/held.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
/// The last observed hold and its approved redrive, not evidence that a send happened.
pub struct CampaignEnrollmentHeldCall {
    pub call_ref: EntityId,
    pub consequence_ref: EntityId,
    pub call_seq: u64,
    pub campaign_ref: EntityId,
    pub program_ref: EntityId,
    pub step_ref: EntityId,
    pub member_ref: EntityId,
    pub owner_actor: EntityId,
    pub frozen_event_ref: EntityId,
    pub attempt_ref: String,
    pub approval_digest: String,
    pub approval_actor: Option<EntityId>,
    pub envelope_hash: String,
    pub held_at_ms: u64,
    pub owner_ask_seq: Option<u64>,
    pub approved_redrive: Option<String>,
}
