//! First-party library source: offline seeding, immutable Git ref, explicit import.

use super::{
    GitEndpointSkillHubAdapter, HubPin, HubRef, HubSyncPolicy, SkillHubKind, SkillHubRecord,
    SkillHubTrustTier, encode_skill_hub_record,
};
use crate::{EntityId, Vault, error::Result, temporal::TimeRange};

/// Released oneiron-hub revision. Moving this pin requires a reviewed engine update;
/// a floating branch or network lookup must never change an opened vault's source.
const HUB_COMMIT: &str = "0614806577995b66f9a7b7638a581761c274076e";
const HUB_ENDPOINT: &str = "https://github.com/oneiron-dev/oneiron-hub.git";
const HUB_ID_NAMESPACE: &[u8] = b"oneiron/first-party-skill-hub/v1";

/// Stable identity of the first-party library hub in every vault.
pub fn default_skill_hub_id() -> Result<EntityId> {
    let hash = blake3::hash(HUB_ID_NAMESPACE);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    EntityId::from_bytes(bytes)
}

/// Immutable revision used for imports from the shipped library.
#[must_use]
pub const fn default_skill_hub_commit() -> &'static str {
    HUB_COMMIT
}

pub(crate) fn seed_default_skill_hub(vault: &Vault) -> Result<()> {
    let id = default_skill_hub_id()?;
    let mut txn = vault.store.env.write_txn()?;
    // Reopens never revert an owner's endpoint, trust, or policy changes. Nor
    // does an erased default come back without an explicit restore decision.
    if vault.store.entities.get(&txn, id.as_bytes())?.is_some()
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

impl Vault {
    /// Reads a configured hub without granting it activation authority.
    pub fn skill_hub_record(&self, id: &EntityId) -> Result<SkillHubRecord> {
        let txn = self.store.env.read_txn()?;
        self.hub_record_in_txn(&txn, id)
    }

    /// Fetches a library skill from the shipped commit through the ordinary Git
    /// adapter and import/scanner doors. No network access occurs during open.
    /// An owner may change the configured endpoint, but cannot change the commit
    /// pinned by this door; a source that lacks it fails closed.
    pub fn import_default_hub_skill(
        &self,
        subtree: &str,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        self.import_default_hub_skill_at_commit(subtree, HUB_COMMIT, occurred, learned_at)
    }

    fn import_default_hub_skill_at_commit(
        &self,
        subtree: &str,
        commit: &str,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        let id = default_skill_hub_id()?;
        let row = self.skill_hub_record(&id)?;
        if row.kind != SkillHubKind::Git || row.sync_policy != HubSyncPolicy::PinnedCommit {
            return Err(crate::error::Error::InvalidConfig(
                "default skill hub requires pinned Git configuration".to_owned(),
            ));
        }
        let adapter = GitEndpointSkillHubAdapter::new(id, &row.endpoint, commit)?;
        let reference = HubRef::new(id, subtree, HubPin::Commit(commit.to_owned()))?;
        self.import_skill_from_adapter(&adapter, &reference, occurred, learned_at)
    }
}

#[cfg(test)]
mod tests;
