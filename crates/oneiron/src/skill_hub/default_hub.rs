//! First-party library source: offline seeding, immutable Git ref, explicit import.

use super::{
    ForeignSkillPublisher, GitEndpointSkillHubAdapter, HubPin, HubRef, HubSyncPolicy, SkillHubKind,
    SkillHubRecord, SkillHubTrustTier, encode_skill_hub_record,
};
use crate::entity_id::derived_domains::FIRST_PARTY_SKILL_HUB;
use crate::{EntityId, Vault, error::Result, temporal::TimeRange};

/// Released oneiron-hub revision. Moving this pin requires a reviewed engine update;
/// a floating branch or network lookup must never change an opened vault's source.
const HUB_COMMIT: &str = "72e737009fb798db8380613db7f8c28bdbdb953f";
const HUB_ENDPOINT: &str = "https://github.com/oneiron-dev/oneiron-hub.git";
/// The model catalog has no authority; its exact file tree is pinned alongside the hub revision.
pub(crate) const MODEL_PACK_SUBTREE: &str = "packs/model-catalog";
pub(crate) const MODEL_PACK_NAME: &str = "oneiron.models";
pub(crate) const MODEL_PACK_HASH: &str =
    "9bb13193a0b203d2e04c43ca203051aba0c1c54963309c38bd03482eb9dc8d11";

/// Stable identity of the first-party library hub in every vault.
pub fn default_skill_hub_id() -> Result<EntityId> {
    EntityId::derive(FIRST_PARTY_SKILL_HUB, &[])
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
    if crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &txn, &id)?.is_some()
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

    /// Fetch the shipped model data through the pinned Git transport and pack source door.
    /// The caller must still qualify and explicitly install the pack.
    pub fn fetch_default_model_pack(
        &self,
        publisher: &ForeignSkillPublisher,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<(EntityId, HubRef)> {
        let id = default_skill_hub_id()?;
        let row = self.skill_hub_record(&id)?;
        if row.kind != SkillHubKind::Git || row.sync_policy != HubSyncPolicy::PinnedCommit {
            return Err(crate::error::Error::InvalidConfig(
                "default model pack requires pinned Git configuration".to_owned(),
            ));
        }
        let adapter = GitEndpointSkillHubAdapter::new(id, &row.endpoint, HUB_COMMIT)?;
        let reference = HubRef::new(id, MODEL_PACK_SUBTREE, HubPin::Commit(HUB_COMMIT.into()))?;
        let (source_id, pinned) =
            self.fetch_pack_from_adapter(&adapter, &reference, publisher, occurred, learned_at)?;
        let source = self.get_pack_source(&source_id)?.ok_or_else(|| {
            crate::error::Error::InvalidConfig("fetched model pack is missing".into())
        })?;
        if source.manifest().name != MODEL_PACK_NAME
            || source.content_hash().to_hex() != MODEL_PACK_HASH
        {
            return Err(crate::error::Error::InvalidConfig(
                "pinned model pack content drift".into(),
            ));
        }
        Ok((source_id, pinned))
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

    /// Re-imports a deleted or locally retired library skill from the pinned
    /// first-party commit. Unchanged imports are left alone; a restore births
    /// a new Candidate rather than reviving the old entity or its authority.
    pub fn restore_default_hub_skill(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        subtree: &str,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        self.restore_default_hub_skill_at_commit(owner, subtree, HUB_COMMIT, occurred, learned_at)
    }

    fn restore_default_hub_skill_at_commit(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        subtree: &str,
        commit: &str,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        use super::SkillHubAdapter;
        let id = default_skill_hub_id()?;
        self.check_restore_owner_in_txn(&self.store.env.read_txn()?, owner)?;
        let row = self.skill_hub_record(&id)?;
        if row.kind != SkillHubKind::Git || row.sync_policy != HubSyncPolicy::PinnedCommit {
            return Err(crate::error::Error::InvalidConfig(
                "default skill hub requires pinned Git configuration".to_owned(),
            ));
        }
        let adapter = GitEndpointSkillHubAdapter::new(id, &row.endpoint, commit)?;
        let source = HubRef::new(id, subtree, HubPin::Commit(commit.to_owned()))?;
        let package = adapter.fetch_package(&source)?;
        let hash = package.content_hash()?;
        // A no-op restore makes no advisory request. Recheck after the
        // network work inside the write transaction before minting an ID.
        let existing = {
            let txn = self.store.env.read_txn()?;
            self.check_restore_owner_in_txn(&txn, owner)?;
            if self.hub_record_in_txn(&txn, &id)? != row {
                return Err(crate::error::Error::InvalidConfig(
                    "default skill hub configuration changed during fetch".to_owned(),
                ));
            }
            self.default_skill_present_in_txn(&txn, &source, hash, &package.record.skill_id)?
        };
        if let Some(entity) = existing {
            return Ok(entity);
        }
        let coordinates = super::osv::dependency_inventory(&package)?;
        let (_, _, scans) =
            self.dependency_advisories(hash, &coordinates, &super::osv::OsvDevClient, learned_at)?;
        let mut txn = self.store.env.write_txn()?;
        self.check_restore_owner_in_txn(&txn, owner)?;
        if self.hub_record_in_txn(&txn, &id)? != row {
            return Err(crate::error::Error::InvalidConfig(
                "default skill hub configuration changed during fetch".to_owned(),
            ));
        }
        if let Some(entity) =
            self.default_skill_present_in_txn(&txn, &source, hash, &package.record.skill_id)?
        {
            return Ok(entity);
        }
        let entity = self.restore_default_skill_in_txn(
            &mut txn,
            owner,
            &source,
            &package,
            self.store.clock.entity_id()?,
            occurred,
            learned_at,
        )?;
        for scan in &scans {
            self.ingest_skill_scan_verdict_in_txn(
                &mut txn, &entity, hash, scan, occurred, learned_at,
            )?;
        }
        txn.commit()?;
        Ok(entity)
    }
}

#[cfg(test)]
mod tests;
