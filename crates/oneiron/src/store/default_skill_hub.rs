//! The first-party library skill hub every vault opens with: its stable id
//! and the offline seed of its pinned Git record. The skill hub
//! (`skill_hub::default_hub`) imports from it and lets the owner repoint it;
//! the vault open path seeds it.
use crate::entity_id::derived_domains::FIRST_PARTY_SKILL_HUB;
use crate::write_envelope::skill_source::{
    HubSyncPolicy, SkillHubKind, SkillHubRecord, SkillHubTrustTier, encode_skill_hub_record,
};
use crate::{EntityId, Vault, error::Result, temporal::TimeRange};

const HUB_ENDPOINT: &str = "https://github.com/oneiron-dev/oneiron-hub.git";

/// Stable identity of the first-party library hub in every vault.
pub fn default_skill_hub_id() -> Result<EntityId> {
    EntityId::derive(FIRST_PARTY_SKILL_HUB, &[])
}

pub(crate) fn seed_default_skill_hub(vault: &Vault) -> Result<()> {
    let id = default_skill_hub_id()?;
    let mut txn = vault.store.env.write_txn()?;
    // Reopens never revert an owner's endpoint, trust, or policy changes. Nor
    // does an erased default come back without an explicit restore decision.
    if crate::ports::EntityStoreRead::port_entity_present(&vault.store, &txn, &id)?
        || vault.local_hard_delete_marker_exists_in_txn(&txn, &id)?
    {
        return Ok(());
    }
    let row = SkillHubRecord::new(
        SkillHubKind::Git,
        HUB_ENDPOINT,
        SkillHubTrustTier::Verified,
        HubSyncPolicy::PinnedCommit,
    )?;
    crate::batch::apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        &mut txn,
        vec![crate::batch::BatchOp::Put {
            id,
            entity_type: crate::registry::ENTITY_TYPE_SKILL_HUB,
            occurred: TimeRange { start: 0, end: 0 },
            learned_at: 0,
            row_version: None,
            data: encode_skill_hub_record(&row)?,
            allow_maintenance: true,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }],
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        true,
        true,
    )?;
    txn.commit()?;
    Ok(())
}
