//! The shipped catalog is read from an installed, pinned first-party hub pack.
use super::{CatalogSeed, invalid};
use crate::{
    Vault,
    entity_id::EntityId,
    error::Result,
    skill_hub::{
        HubSyncPolicy, MODEL_PACK_HASH, MODEL_PACK_NAME, MODEL_PACK_SUBTREE, default_skill_hub_id,
    },
};
use std::collections::BTreeSet;

impl CatalogSeed {
    /// Only an installed first-party source with the released tree hash is accepted.
    /// Fetching or staging a pack alone never gives its rows routing authority.
    pub fn from_installed_pack(vault: &Vault) -> Result<Self> {
        let receipt = vault
            .installed_pack(MODEL_PACK_NAME)?
            .ok_or_else(|| invalid("model catalog pack is not installed"))?;
        let hub = default_skill_hub_id()?;
        if receipt.hub_id != hub.to_hex()
            || receipt.hub_ref != MODEL_PACK_SUBTREE
            || receipt.content_hash != MODEL_PACK_HASH
            || vault.skill_hub_record(&hub)?.sync_policy != HubSyncPolicy::PinnedCommit
        {
            return Err(invalid("model catalog is not the pinned first-party pack"));
        }
        let id = EntityId::from_hex(&receipt.source_id)?;
        let source = vault
            .get_pack_source(&id)?
            .ok_or_else(|| invalid("installed model catalog source is missing"))?;
        if source.manifest().name != MODEL_PACK_NAME
            || source.content_hash().to_hex() != receipt.content_hash
        {
            return Err(invalid("installed model catalog hash differs"));
        }
        let files = source.files();
        if files.len() != 2 {
            return Err(invalid("model catalog has unexpected source facets"));
        }
        let bytes = files
            .iter()
            .find(|file| file.path == "knowledge/catalog.json")
            .ok_or_else(|| invalid("model catalog data file missing"))?;
        let seed = Self::from_json(&bytes.content)?;
        let vendors: BTreeSet<_> = seed
            .rows
            .iter()
            .map(|row| row.catalog.model.provider())
            .collect();
        if seed.rows.len() < 40 || vendors.len() < 40 {
            return Err(invalid("model catalog must have at least 40 vendors"));
        }
        Ok(seed)
    }
}

impl Vault {
    /// Import only the installed pack's validated model rows; role bindings remain separate.
    pub fn seed_installed_model_catalog(&self) -> Result<()> {
        self.seed_model_catalog(&CatalogSeed::from_installed_pack(self)?)
    }
}
