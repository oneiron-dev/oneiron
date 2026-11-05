//! Native identity frozen beside one campaign leg's transport envelope.

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::gate::CampaignLegFacts;

/// The facts a ledger row cannot recover from its consequence and call
/// sequence alone. This is native frozen data, not a consent proof.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FrozenCampaignLeg {
    query_ref: EntityId,
    campaign_ref: EntityId,
    entity_ref: EntityId,
    epoch: u64,
    program_ref: EntityId,
    step_ref: EntityId,
    payload_digest: [u8; 32],
    sender_ref: EntityId,
}

impl FrozenCampaignLeg {
    pub(super) fn new(target: &CampaignLegFacts, sender_ref: EntityId) -> Self {
        Self {
            query_ref: target.query_ref,
            campaign_ref: target.campaign_ref,
            entity_ref: target.entity_ref,
            epoch: target.epoch,
            program_ref: target.program_ref,
            step_ref: target.step_ref,
            payload_digest: target.payload_digest,
            sender_ref,
        }
    }
}
