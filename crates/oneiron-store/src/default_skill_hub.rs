//! The first-party library skill hub every vault opens with: its stable id
//! and the offline seed of its pinned Git record. The skill hub
//! (`skill_hub::default_hub`) imports from it and lets the owner repoint it;
//! the vault open path seeds it.
use crate::write_envelope::skill_source::HubSyncPolicy;
use crate::write_envelope::skill_source::SkillHubKind;
use crate::write_envelope::skill_source::SkillHubRecord;
use crate::write_envelope::skill_source::SkillHubTrustTier;
use crate::write_envelope::skill_source::encode_skill_hub_record;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::entity_id::derived_domains::FIRST_PARTY_SKILL_HUB;
use oneiron_contracts::temporal::TimeRange;

pub const HUB_ENDPOINT: &str = "https://github.com/oneiron-dev/oneiron-hub.git";

/// Stable identity of the first-party library hub in every vault.
pub fn default_skill_hub_id() -> Result<EntityId> {
    EntityId::derive(FIRST_PARTY_SKILL_HUB, &[])
}
