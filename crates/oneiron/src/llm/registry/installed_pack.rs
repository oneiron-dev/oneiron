//! The shipped catalog is read from an installed first-party hub pack. Its
//! authority is the install receipt's content hash and that hash's scan
//! evidence; which revision installs is the catalog ref's sync policy, which
//! is vault data. Installing the pack activates its rows for inference admission.
use super::{CatalogSeed, invalid};
use crate::{
    Vault,
    entity_id::EntityId,
    error::Result,
    side_table::{self, LegacyJson, SideTable, SideTableDbs},
    skill_hub::{
        HubPin, HubSyncPolicy, MODEL_PACK_NAME, MODEL_PACK_SUBTREE, default_skill_hub_id,
        pack_catalog::{PackInstallReceipt, PackInstallStatus},
        skill_scan_verdicts_for_content_hash_in_store,
    },
};
use heed::RoTxn;
use std::collections::BTreeSet;

/// The currency of a legacy pre-9534 stored copy of a first-party
/// installed-pack row whose catalog cost names no currency key: the
/// published pack's existing contract, which quotes its list prices in US
/// dollars (Engine ruling on FIX 9534, narrowed by FIX 11778). It is read
/// for those stored copies alone: pack bytes and new rows never read it,
/// and a row whose cost says `"currency": null` stays unknown.
const PACK_LIST_PRICE_CURRENCY: &str = "USD";

/// The model pack's install receipt, read for the source it names.
const PACK_RECEIPT: SideTable<String, PackInstallReceipt, LegacyJson> =
    SideTable::new(&side_table::SKILL_HUB_PACK_INSTALL);

/// [`PACK_LIST_PRICE_CURRENCY`] on `row`'s catalog cost when it names no
/// currency; one that names any, `null` included, keeps it. Read only for
/// legacy pre-9534 stored pack-copies (FIX 11778), never for pack bytes.
fn with_pack_row_currency(row: &mut serde_json::Value) {
    if let Some(cost) = row
        .pointer_mut("/catalog/cost")
        .and_then(serde_json::Value::as_object_mut)
    {
        cost.entry("currency")
            .or_insert_with(|| PACK_LIST_PRICE_CURRENCY.into());
    }
}

/// A stored registry row's bytes under the pack's currency contract, when
/// the row is a legacy pre-9534 copy of a row of the pack installed from
/// `pack`: its source rows name that pack's source (Engine ruling on FIX
/// 9534, narrowed by FIX 11778), the installed one or the one an install is
/// replacing, and its catalog cost names no `currency` key. `None` for any
/// other row, which reads as it is stored: explicit `null` or any code
/// reads as-is.
pub(super) fn stored_pack_row(bytes: &[u8], pack: EntityId) -> Option<Vec<u8>> {
    let mut row: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let copied = row
        .get("source_rows")?
        .as_array()?
        .iter()
        .any(|id| id.as_str().and_then(|hex| EntityId::from_hex(hex).ok()) == Some(pack));
    if !copied {
        return None;
    }
    let missing = row
        .pointer("/catalog/cost")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|cost| !cost.contains_key("currency"));
    if !missing {
        return None;
    }
    with_pack_row_currency(&mut row);
    serde_json::to_vec(&row).ok()
}

/// The source the installed model pack was installed from, as its receipt
/// names it; `None` with no model pack installed.
pub(super) fn installed_pack_source(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
) -> Result<Option<EntityId>> {
    PACK_RECEIPT
        .get(dbs, txn, &MODEL_PACK_NAME.to_owned())?
        .filter(|receipt| receipt.pack_name == MODEL_PACK_NAME)
        .map(|receipt| EntityId::from_hex(&receipt.source_id))
        .transpose()
}

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
        // Further source facets beside the catalog data install too (FIX
        // 9921); the hash, scan and receipt checks above bind every file.
        let files = source.files();
        let bytes = files
            .iter()
            .find(|file| file.path == "knowledge/catalog.json")
            .ok_or_else(|| invalid("model catalog data file missing"))?;
        let mut seed = Self::from_json(&bytes.content)?;
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
        // The new receipt no longer names the prior pack's source, so a row
        // copied from that pack is stored under its currency contract before
        // the refresh reads it, and reads as stored after (FIX 9534).
        if let Some(prior) = prior {
            let packs: BTreeSet<EntityId> = prior
                .rows
                .iter()
                .filter_map(|row| row.source_rows.as_deref())
                .flatten()
                .copied()
                .collect();
            super::REGISTRY_ROW.keep_pack_rows(&self.store, txn, &packs)?;
        }
        self.refresh_model_catalog_in_txn(txn, &seed, prior)
    }
}
