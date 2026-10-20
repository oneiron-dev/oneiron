//! The shipped catalog is read from an installed first-party hub pack. Its
//! authority is the install receipt's content hash and that hash's scan
//! evidence; which revision installs is the catalog ref's sync policy, which
//! is vault data. Installing the pack activates its rows for inference admission.
use super::{CatalogSeed, invalid};
use crate::{
    Vault,
    entity_id::EntityId,
    error::Result,
    skill_hub::{
        HubPin, HubSyncPolicy, MODEL_PACK_NAME, MODEL_PACK_SUBTREE, default_skill_hub_id,
        pack_catalog::PackInstallStatus, skill_scan_verdicts_for_content_hash_in_store,
    },
};
use std::collections::BTreeSet;

impl CatalogSeed {
    /// Only an installed first-party source with scan evidence is accepted.
    /// Fetching or staging a pack alone never gives its rows routing authority.
    pub fn from_installed_pack(vault: &Vault) -> Result<Self> {
        let txn = vault.store.env.read_txn()?;
        Self::from_installed_pack_in_txn(vault, &txn)
    }

    pub(crate) fn from_installed_pack_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Self> {
        let receipt = vault
            .installed_pack_in_txn(txn, MODEL_PACK_NAME)?
            .ok_or_else(|| invalid("model catalog pack is not installed"))?;
        let hub = default_skill_hub_id()?;
        if receipt.hub_id != hub.to_hex()
            || receipt.hub_ref != MODEL_PACK_SUBTREE
            || receipt.status != PackInstallStatus::Active
        {
            return Err(invalid(
                "model catalog is not the installed first-party pack",
            ));
        }
        // The ref's own policy judges drift: a frozen ref accepts one hash.
        if let Some(tracked) = vault.hub_ref_sync_in_txn(txn, &hub, MODEL_PACK_SUBTREE)?
            && tracked.sync_policy == HubSyncPolicy::ContentHashFrozen
            && tracked.hub_ref.pin != HubPin::ContentHash(receipt.content_hash.clone())
        {
            return Err(invalid(
                "model catalog drifted from its frozen content hash",
            ));
        }
        let id = EntityId::from_hex(&receipt.source_id)?;
        let source = vault
            .pack_source_in_txn(txn, &id)?
            .ok_or_else(|| invalid("installed model catalog source is missing"))?;
        if source.manifest().name != MODEL_PACK_NAME
            || source.content_hash().to_hex() != receipt.content_hash
        {
            return Err(invalid("installed model catalog hash differs"));
        }
        // Knowledge-only bytes enter the same hash-bound scan ledger as skills
        // at the hub fetch door. Verdicts stay signals on the install ask; only
        // bytes that never reached that ledger are refused here.
        if skill_scan_verdicts_for_content_hash_in_store(&vault.store, txn, source.content_hash())?
            .is_empty()
        {
            return Err(invalid("installed model catalog has no scan evidence"));
        }
        let files = source.files();
        if files.len() != 2 {
            return Err(invalid("model catalog has unexpected source facets"));
        }
        let bytes = files
            .iter()
            .find(|file| file.path == "knowledge/catalog.json")
            .ok_or_else(|| invalid("model catalog data file missing"))?;
        let mut seed = Self::from_json(&bytes.content)?;
        let vendors: BTreeSet<_> = seed
            .rows
            .iter()
            .map(|row| row.catalog.model.provider())
            .collect();
        if seed.rows.len() < 40 || vendors.len() < 40 {
            return Err(invalid("model catalog must have at least 40 vendors"));
        }
        // Each row the pack ships is read from its installed source, and from
        // nothing the pack's own bytes claim (FIX 5760).
        for row in &mut seed.rows {
            row.source_rows = Some(vec![id]);
        }
        Ok(seed)
    }
}

impl Vault {
    /// Import only the installed pack's validated model rows; role bindings remain separate.
    pub fn seed_installed_model_catalog(&self) -> Result<()> {
        self.seed_model_catalog(&CatalogSeed::from_installed_pack(self)?)
    }

    /// Install-time activation, in the install's own transaction: the new
    /// pack's rows enter the registry that inference admission reads. A row
    /// the prior pack shipped and nobody edited follows the new pack.
    pub(crate) fn activate_installed_model_catalog_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        prior: Option<&CatalogSeed>,
    ) -> Result<()> {
        let seed = CatalogSeed::from_installed_pack_in_txn(self, txn)?;
        self.refresh_model_catalog_in_txn(txn, &seed, prior)
    }
}
