//! A table of setting defaults as pack data (design pass 34, section 3.2; row L1): a pack of kind
//! `capability` may carry one table in [`SETTING_DEFAULTS_FILE`], a JSON object from catalogue
//! key to default. It is a lane's preset for the engine's settings: installing the pack proposes
//! each default to the owner, and an update proposes again; nothing in force moves until his yes
//! (`crate::setting::propose_installed_pack_defaults_in_txn`).
//!
//! A pack holds no widening power, but a table still asks the owner to change what the vault
//! reads, so it rides the same sources as a verb-class table (RULING L8-57-TABLE-SOURCE = A): the
//! packs the owner put and the packs installed from an admitted hub after its scan. The vault's
//! `local` pack, which a resident agent writes, never carries one: its source is refused at the
//! put, and no `local` or agent-authored install is read.
use heed::RoTxn;

use super::{
    LOCAL_PACK_NAME, PackInstallReceipt, PackInstallStatus, PackKind, PackManifest, PackSource,
    admission, invalid,
};
use crate::error::{ErrorKind, Result};
use crate::skill_hub::{HubFile, skill_scan_verdict_stands_in_store};
use crate::{EntityId, Vault};

/// Where a pack keeps its table of setting defaults.
pub const SETTING_DEFAULTS_FILE: &str = "knowledge/setting-defaults.json";

/// A pack's table of setting defaults as its source carries it: each catalogue key once, with its
/// default as JSON, in key order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackSettingDefaults {
    pub defaults: Vec<(String, serde_json::Value)>,
}

/// The source's table of setting defaults, when it carries one. A table in the `local` pack or in
/// a pack of another kind than `capability`, one that is not a JSON object, and one with a key
/// this build does not know or a value the key refuses, refuse the source.
pub(super) fn read_source_setting_defaults(
    manifest: &PackManifest,
    files: &[HubFile],
) -> Result<Option<PackSettingDefaults>> {
    let Some(file) = files.iter().find(|file| file.path == SETTING_DEFAULTS_FILE) else {
        return Ok(None);
    };
    if manifest.name == LOCAL_PACK_NAME {
        return Err(invalid(
            "the local pack carries no setting defaults: a resident agent writes it",
        ));
    }
    if manifest.kind != PackKind::Capability {
        return Err(invalid(
            "a table of setting defaults rides a capability pack",
        ));
    }
    let table: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(&file.content)
        .map_err(|_| {
        invalid("a table of setting defaults is one JSON object of setting keys")
    })?;
    let defaults: Vec<(String, serde_json::Value)> = table.into_iter().collect();
    crate::setting::pack_defaults_from_json(&defaults)?;
    Ok(Some(PackSettingDefaults { defaults }))
}

impl Vault {
    /// The source of `pack`'s Active install, where that install may carry presets
    /// ([`install_may_carry_presets`]), read in `txn` from the source its receipt names. `None`
    /// with no such install, or one whose source is gone, does not match its receipt's name, kind
    /// and content hash, or has no scan verdict standing on its bytes. A catalog row that does
    /// not read fails the read.
    pub(crate) fn preset_source_in_txn(
        &self,
        txn: &RoTxn<'_>,
        pack: &str,
    ) -> Result<Option<PackSource>> {
        let receipt = admission::PACK_INSTALL
            .get(&self.store, txn, &pack.to_owned())
            .map_err(|error| {
                if error.kind() == ErrorKind::SideTableRow {
                    invalid("pack install catalog corrupt")
                } else {
                    error
                }
            })?;
        let Some(receipt) = receipt.filter(|receipt| install_may_carry_presets(pack, receipt))
        else {
            return Ok(None);
        };
        let Ok(source_id) = EntityId::from_hex(&receipt.source_id) else {
            return Ok(None);
        };
        let Some(source) = self.pack_source_in_txn(txn, &source_id)? else {
            return Ok(None);
        };
        if source.manifest().name != pack
            || source.manifest().kind != receipt.kind
            || source.content_hash().to_hex() != receipt.content_hash
            || !skill_scan_verdict_stands_in_store(&self.store, txn, source.content_hash())?
        {
            return Ok(None);
        }
        Ok(Some(source))
    }

    /// The table of setting defaults of `pack`'s Active install, where that install may carry
    /// one ([`Vault::preset_source_in_txn`]). `None` otherwise.
    pub(crate) fn installed_setting_defaults_in_txn(
        &self,
        txn: &RoTxn<'_>,
        pack: &str,
    ) -> Result<Option<PackSettingDefaults>> {
        Ok(self
            .preset_source_in_txn(txn, pack)?
            .and_then(|source| source.setting_defaults().cloned()))
    }
}

/// Whether the install `receipt` under `name` may carry presets, a table of setting defaults or
/// a line preset: Active, a capability pack, and neither the `local` pack nor an agent-authored
/// install.
pub(super) fn install_may_carry_presets(name: &str, receipt: &PackInstallReceipt) -> bool {
    receipt.status == PackInstallStatus::Active
        && receipt.kind == PackKind::Capability
        && receipt.pack_name == name
        && name != LOCAL_PACK_NAME
        && receipt.agent_author.is_none()
}
