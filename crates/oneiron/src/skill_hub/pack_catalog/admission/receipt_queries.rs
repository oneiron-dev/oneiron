//! Pack receipt inventory and source-validated lookup queries.

use super::*;

impl Vault {
    /// Each pack name whose install receipt selects a script, with the source
    /// it selects, every one of them: a restore asks `installed_script_pack`
    /// about each.
    pub(crate) fn script_pack_selections(&self) -> Result<Vec<(String, EntityId)>> {
        let txn = self.store.env.read_txn()?;
        let mut selections = Vec::new();
        for entry in PACK_INSTALL.iter_from(&self.store, &txn, &[])? {
            let (name, receipt) = entry.map_err(|error| {
                if error.kind() == crate::error::ErrorKind::SideTableRow {
                    invalid("pack install catalog corrupt")
                } else {
                    error
                }
            })?;
            if matches!(receipt.adapter, Some(PackAdapter::Script(_))) {
                selections.push((name, EntityId::from_hex(&receipt.source_id)?));
            }
        }
        Ok(selections)
    }
    /// Active installations only, verified against their still-live exact source.
    /// A Candidate never enters the section/board projection.
    pub fn installed_packs(&self) -> Result<Vec<PackInstallReceipt>> {
        let txn = self.store.env.read_txn()?;
        let mut rows = Vec::new();
        for entry in PACK_INSTALL.iter_from(&self.store, &txn, &[])? {
            let (name, _) = entry.map_err(|error| {
                if error.kind() == crate::error::ErrorKind::SideTableRow {
                    invalid("pack install catalog corrupt")
                } else {
                    error
                }
            })?;
            // The lens uses the same snapshot to distinguish a deleted source
            // (not live) from a malformed receipt or a drifting live source.
            let Some(receipt) = self.mounted_pack_in_txn(&txn, &name)? else {
                continue;
            };
            let source_id = EntityId::from_hex(&receipt.source_id)?;
            let source = self
                .pack_source_in_txn(&txn, &source_id)?
                .ok_or_else(|| invalid("installed pack source missing"))?;
            if receipt.sections != source.sections() || receipt.status != PackInstallStatus::Active
            {
                return Err(invalid("installed pack sections disagree with source"));
            }
            rows.push(receipt);
        }
        Ok(rows)
    }
    /// Claim-family state for one Active pack section, limited to the pack's
    /// own declared predicates. Hosts must still scope each returned id before
    /// serving any row; this is an inventory door, not read authority.
    pub fn pack_section_claim_ids(
        &self,
        pack_name: &str,
        section_id: &str,
    ) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        let pack = self
            .installed_pack_in_txn(&txn, pack_name)?
            .ok_or_else(|| invalid("pack section is not installed"))?;
        if !pack.sections.iter().any(|section| {
            section.section_id == section_id
                && section.state_family.family == "claim"
                && section.state_family.version == 1
                && section.authority_lane.0 == "read"
        }) {
            return Err(invalid("pack section has no claim reader"));
        }
        let mut ids = Vec::new();
        for predicate in &pack.predicates {
            for (id, _) in self.claims_with_predicate_in_txn(&txn, predicate)? {
                ids.push(id);
            }
        }
        ids.sort_by_key(|id| *id.as_bytes());
        ids.dedup();
        Ok(ids)
    }
    pub fn candidate_pack(&self, source: &PackSource) -> Result<Option<PackInstallReceipt>> {
        let txn = self.store.env.read_txn()?;
        PACK_CANDIDATE
            .get(&self.store, &txn, &candidate_key(source))
            .map_err(|error| {
                if error.kind() == crate::error::ErrorKind::SideTableRow {
                    invalid("candidate receipt corrupt")
                } else {
                    error
                }
            })
    }
    pub fn installed_pack(&self, name: &str) -> Result<Option<PackInstallReceipt>> {
        let txn = self.store.env.read_txn()?;
        self.installed_pack_in_txn(&txn, name)
    }
    pub fn pack_for_predicate(&self, name: &str) -> Result<Option<PackInstallReceipt>> {
        let txn = self.store.env.read_txn()?;
        let Some(pack) = PACK_PREDICATE.get(&self.store, &txn, &name.to_owned())? else {
            return Ok(None);
        };
        let installed = self
            .installed_pack_in_txn(&txn, &pack)?
            .ok_or_else(|| invalid("pack predicate has no installation"))?;
        if !installed.predicates.iter().any(|p| p == name) {
            return Err(invalid("pack predicate catalog disagrees"));
        }
        Ok(Some(installed))
    }
    /// A script run compares the exact selected receipt in its own writer
    /// transaction; Candidates are never runnable installations.
    pub(crate) fn installed_pack_for_script_in_txn(
        &self,
        txn: &RoTxn<'_>,
        name: &str,
    ) -> Result<Option<PackInstallReceipt>> {
        self.installed_pack_in_txn(txn, name)
    }

    /// A lens treats a deleted source as an absent installation. Parse the
    /// receipt first so a malformed catalog still fails closed, and use one
    /// snapshot for both this deletion check and normal source validation.
    pub(crate) fn mounted_pack_in_txn(
        &self,
        txn: &RoTxn<'_>,
        name: &str,
    ) -> Result<Option<PackInstallReceipt>> {
        let Some(receipt) = PACK_INSTALL
            .get(&self.store, txn, &name.to_owned())
            .map_err(|error| {
                if error.kind() == crate::error::ErrorKind::SideTableRow {
                    invalid("pack install catalog corrupt")
                } else {
                    error
                }
            })?
        else {
            return Ok(None);
        };
        if receipt.pack_name != name {
            return Err(invalid("pack install name mismatch"));
        }
        let source_id = EntityId::from_hex(&receipt.source_id)?;
        if !crate::vault::live_entity_row_in_txn(&self.store, txn, &source_id)?.is_live() {
            return Ok(None);
        }
        self.installed_pack_in_txn(txn, name)
    }
    pub(crate) fn installed_pack_in_txn(
        &self,
        txn: &RoTxn<'_>,
        name: &str,
    ) -> Result<Option<PackInstallReceipt>> {
        PACK_INSTALL
            .get(&self.store, txn, &name.to_owned())?
            .map(|receipt| {
                if receipt.pack_name != name {
                    return Err(invalid("pack install name mismatch"));
                }
                let source_id = EntityId::from_hex(&receipt.source_id)?;
                let source = self
                    .pack_source_in_txn(txn, &source_id)?
                    .ok_or_else(|| invalid("installed source is unavailable"))?;
                if source.manifest.name != name
                    || source.content_hash().to_hex() != receipt.content_hash
                    || source.manifest.kind != receipt.kind
                    || source.manifest.adapter != receipt.adapter
                {
                    return Err(invalid("installed source identity drift"));
                }
                validate_installed_qualification(&source, &receipt)?;
                Ok(receipt)
            })
            .transpose()
    }
}
