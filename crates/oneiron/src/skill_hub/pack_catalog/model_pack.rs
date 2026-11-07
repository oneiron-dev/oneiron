//! Model packs at the hub door (FIX 5365, MODEL PACKS = A). A pack of kind
//! `model` carries data only: its roles, variants, changelog and bench
//! evidence in [`MODEL_PACK_FILE`]. Its authority is the install receipt's
//! content hash and that hash's scan evidence, the checks the first-party
//! model catalog's rows meet (`CatalogSeed::from_installed_pack`); no new
//! key signs it. Packs from any admitted hub publisher install the same way.
use heed::RoTxn;
use oneiron_store::settings::model_pack::{ModelPack, ModelPackId};

use super::{PackInstallReceipt, PackInstallStatus, PackKind, PackManifest, admission, invalid};
use crate::error::{Error, ErrorKind, Result};
use crate::skill_hub::{
    HubFile, HubPin, HubSyncPolicy, skill_scan_verdicts_for_content_hash_in_store,
};
use crate::{EntityId, Vault};

/// Where a model pack keeps its data.
pub const MODEL_PACK_FILE: &str = "knowledge/model-pack.json";

/// The PACK.md fields that declare runtime powers. An engine call (CALLS,
/// FIX 5365): a model pack is data, so it declares none of them and no
/// adapter, and its files are PACK.md and `knowledge/` data alone.
pub(super) const MODEL_PACK_RUNTIME_FIELDS: [&str; 10] = [
    "predicates",
    "kinds",
    "grants",
    "effects",
    "wakes",
    "hooks",
    "organs",
    "lenses",
    "migrations",
    "setup",
];

/// An installed model pack: the receipt it installed under and its data,
/// read from the exact source that receipt names.
#[derive(Debug, Clone, PartialEq)]
pub struct InstalledModelPack {
    pub receipt: PackInstallReceipt,
    pub pack: ModelPack,
}

/// The source's model pack: its data file, read under its manifest's name
/// and version. A source of kind `model` without one, or whose data does not
/// read, is refused.
pub(super) fn read_source_model_pack(
    manifest: &PackManifest,
    files: &[HubFile],
) -> Result<ModelPack> {
    let file = files
        .iter()
        .find(|file| file.path == MODEL_PACK_FILE)
        .ok_or_else(|| invalid("a model pack requires knowledge/model-pack.json"))?;
    let id = ModelPackId::new(manifest.name.clone())
        .map_err(|_| invalid("a model pack's name is not a pack id"))?;
    ModelPack::parse(id, manifest.version.clone(), &file.content)
        .map_err(|error| Error::InvalidConfig(format!("pack source: model pack: {error}")))
}

impl Vault {
    /// Every Active model pack installed, in pack name order, each read
    /// from the source its receipt names. A pack that fails a check its
    /// receipt binds (a frozen ref's drift, the source's name, kind or
    /// content hash, its scan evidence, its data) is not admitted and is
    /// left out, so no route follows it.
    pub(crate) fn installed_model_packs_in_txn(
        &self,
        txn: &RoTxn<'_>,
    ) -> Result<Vec<InstalledModelPack>> {
        let mut packs = Vec::new();
        for entry in admission::PACK_INSTALL.iter_from(&self.store, txn, &[])? {
            let (name, receipt) = entry.map_err(|error| {
                if error.kind() == ErrorKind::SideTableRow {
                    invalid("pack install catalog corrupt")
                } else {
                    error
                }
            })?;
            if receipt.kind != PackKind::Model || receipt.status != PackInstallStatus::Active {
                continue;
            }
            if let Some(pack) = self.admit_installed_model_pack_in_txn(txn, &name, receipt)? {
                packs.push(pack);
            }
        }
        Ok(packs)
    }

    /// `receipt`'s pack, when it meets every check the first-party model
    /// catalog meets; `None` when one fails.
    fn admit_installed_model_pack_in_txn(
        &self,
        txn: &RoTxn<'_>,
        name: &str,
        receipt: PackInstallReceipt,
    ) -> Result<Option<InstalledModelPack>> {
        if receipt.pack_name != name {
            return Ok(None);
        }
        let (Ok(hub), Ok(source_id)) = (
            EntityId::from_hex(&receipt.hub_id),
            EntityId::from_hex(&receipt.source_id),
        ) else {
            return Ok(None);
        };
        // The ref's own policy judges drift: a frozen ref accepts one hash.
        if let Some(tracked) = self.hub_ref_sync_in_txn(txn, &hub, &receipt.hub_ref)?
            && tracked.sync_policy == HubSyncPolicy::ContentHashFrozen
            && tracked.hub_ref.pin != HubPin::ContentHash(receipt.content_hash.clone())
        {
            return Ok(None);
        }
        let Some(source) = self.pack_source_in_txn(txn, &source_id)? else {
            return Ok(None);
        };
        if source.manifest().name != name
            || source.manifest().kind != PackKind::Model
            || source.content_hash().to_hex() != receipt.content_hash
        {
            return Ok(None);
        }
        // Bytes that never reached the hub door's scan ledger are refused.
        if skill_scan_verdicts_for_content_hash_in_store(&self.store, txn, source.content_hash())?
            .is_empty()
        {
            return Ok(None);
        }
        let Ok(pack) = read_source_model_pack(source.manifest(), source.files()) else {
            return Ok(None);
        };
        Ok(Some(InstalledModelPack { receipt, pack }))
    }
}
