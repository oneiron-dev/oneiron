//! Engine-embedded connector source and local first-open installation.
//! A bootstrap receipt describes requested powers; it never mints a grant or a wake.

use super::qualify::{validate_installed_qualification, validate_qualification};
use super::{
    PackAdapter, PackCandidateReason, PackInstallReceipt, PackInstallStatus, PackKind,
    PackQualifier, PackSource, admission,
};
use crate::side_table::{self, Raw, SideTable};
use crate::skill_hub::HubFile;
use crate::{EntityId, TimeRange, Vault, error::Result};

/// Marker (engine version string) that the built-in connector packs have been seeded.
const SEEDED: SideTable<(), String, Raw> = SideTable::new(&side_table::SKILL_HUB_PACK_BUILTIN_SEED);
const PACKS: [(&str, &str); 4] = [
    (
        "slack",
        include_str!("../../../../../packs/builtin/slack/PACK.md"),
    ),
    (
        "line",
        include_str!("../../../../../packs/builtin/line/PACK.md"),
    ),
    (
        "email",
        include_str!("../../../../../packs/builtin/email/PACK.md"),
    ),
    (
        "linkedin",
        include_str!("../../../../../packs/builtin/linkedin/PACK.md"),
    ),
];

fn engine_hub_id() -> Result<EntityId> {
    EntityId::derive(
        crate::entity_id::derived_domains::BUILTIN_CONNECTOR_PACK_HUB,
        &[],
    )
}

/// The publisher an engine-seeded receipt names.
const ENGINE_PUBLISHER: &str = "oneiron-engine";

pub(crate) fn seed_builtin_packs(vault: &Vault) -> Result<()> {
    super::local::seed_local_pack(vault)?;
    let version = env!("CARGO_PKG_VERSION").to_owned();
    let rtxn = vault.store.env.read_txn()?;
    // Built-in packs version with the engine: a new engine reseeds them.
    if SEEDED.get(&vault.store, &rtxn, &())?.as_ref() == Some(&version) {
        return Ok(());
    }
    drop(rtxn);
    // Match the bootstrap skills: malformed policy remains open for owner repair.
    if crate::gate::resolve_policy_manifest(&vault.store, &vault.store.env.read_txn()?)?
        .diagnostics()
        .loaded_manifest_forces_fail_closed()
    {
        return Ok(());
    }
    let mut txn = vault.store.env.write_txn()?;
    if SEEDED.get(&vault.store, &txn, &())?.as_ref() == Some(&version) {
        return Ok(());
    }
    for (name, markdown) in PACKS {
        let source = PackSource::from_files(vec![HubFile::new("PACK.md", markdown.as_bytes())])?;
        if source.manifest.name != format!("oneiron.{name}")
            || source.manifest.kind != PackKind::Connector
            || source.manifest.adapter != Some(PackAdapter::Builtin(name.to_owned()))
        {
            return Err(super::invalid(
                "embedded adapter manifest disagrees with build",
            ));
        }
        // A prior locally installed pack owns its name. Never overwrite an owner's
        // installation (including one imported before this bootstrap pass); an
        // engine-seeded receipt follows the engine's own source.
        if let Some(installed) =
            admission::PACK_INSTALL.get(&vault.store, &txn, &source.manifest.name)?
            && (installed.publisher != ENGINE_PUBLISHER
                || installed.content_hash == source.content_hash().to_hex())
        {
            continue;
        }
        // A prior source or tombstone at the deterministic hash owns this ID.
        // Do not relabel a foreign import as engine-born or resurrect erasure.
        let source_id = source.entity_id()?;
        let deletion =
            crate::ports::TombstoneStoreRead::port_deletion_state(&vault.store, &txn, &source_id)?;
        if crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &txn, &source_id)?.is_some()
            || deletion.deleted
            || deletion.stale
        {
            continue;
        }
        vault.stage_pack_source_in_txn(&mut txn, &source, TimeRange { start: 0, end: 0 }, 0)?;
        let receipt = PackInstallReceipt {
            source_id: source_id.to_hex(),
            pack_name: source.manifest.name.clone(),
            content_hash: source.content_hash().to_hex(),
            kind: source.manifest.kind,
            adapter: source.manifest.adapter.clone(),
            engine_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            status: PackInstallStatus::Candidate,
            candidate_reason: Some(PackCandidateReason::QualificationRequired),
            hub_id: engine_hub_id()?.to_hex(),
            hub_ref: format!("built-in:{name}"),
            pin_type: "engine_version".to_owned(),
            pin_value: env!("CARGO_PKG_VERSION").to_owned(),
            publisher: ENGINE_PUBLISHER.to_owned(),
            permissions: admission::pack_permissions(&source, None)?,
            qualification_report_hash: None,
            connector_qualification: None,
            runtime: None,
            sections: source.sections().to_vec(),
            predicates: source.manifest.predicates.iter().cloned().collect(),
            kinds: source.manifest.kinds.iter().cloned().collect(),
            skills: Vec::new(),
            installed_at: 0,
        };
        admission::PACK_CANDIDATE.put(&vault.store, &mut txn, &receipt.content_hash, &receipt)?;
    }
    SEEDED.put(&vault.store, &mut txn, &(), &version)?;
    txn.commit()?;
    Ok(())
}

impl Vault {
    /// Bootstrap never trusts an engine-built connector merely because it is
    /// first-party. Its real isolated adapter must clear the same probes as a
    /// hub pack before the receipt enters the Active installation catalog.
    pub fn qualify_builtin_connector_pack(
        &self,
        channel: &str,
        qualifier: &dyn PackQualifier,
    ) -> Result<PackInstallReceipt> {
        let (_, markdown) = PACKS
            .iter()
            .find(|(name, _)| *name == channel)
            .ok_or_else(|| super::invalid("unknown built-in connector pack"))?;
        let source = PackSource::from_files(vec![HubFile::new("PACK.md", markdown.as_bytes())])?;
        let hash = source.content_hash().to_hex();
        let (candidate, installed) = {
            let txn = self.store.env.read_txn()?;
            (
                admission::PACK_CANDIDATE.get(&self.store, &txn, &hash)?,
                admission::PACK_INSTALL.get(&self.store, &txn, &source.manifest.name)?,
            )
        };
        let mut receipt = candidate
            .as_ref()
            .or(installed.as_ref())
            .cloned()
            .ok_or_else(|| super::invalid("built-in connector source is not seeded"))?;
        if receipt.publisher != ENGINE_PUBLISHER
            || receipt.content_hash != hash
            || receipt.engine_version.is_none()
            || installed
                .as_ref()
                .is_some_and(|prior| prior.publisher != ENGINE_PUBLISHER)
        {
            return Err(super::invalid(
                "built-in connector was replaced by an owner installation",
            ));
        }
        let qualification = qualifier.qualify(&source)?;
        validate_qualification(&source, &qualification)?;
        receipt.status = PackInstallStatus::Active;
        receipt.candidate_reason = None;
        receipt.qualification_report_hash = Some(qualification.report_hash.clone());
        receipt.connector_qualification = qualification
            .connector
            .as_ref()
            .map(|connector| connector.receipt().clone());
        receipt.runtime = qualification.runtime;
        receipt.engine_version = Some(env!("CARGO_PKG_VERSION").to_owned());
        receipt.pin_value = env!("CARGO_PKG_VERSION").to_owned();
        receipt.installed_at = crate::unix_seconds_now();
        self.with_write_txn_grouped(|txn| {
            if admission::PACK_CANDIDATE.get(&self.store, txn, &hash)? != candidate
                || admission::PACK_INSTALL.get(&self.store, txn, &source.manifest.name)?
                    != installed
                || self.pack_source_in_txn(txn, &source.entity_id()?)?.as_ref() != Some(&source)
            {
                return Err(super::invalid(
                    "built-in connector changed during qualification",
                ));
            }
            validate_installed_qualification(&source, &receipt)?;
            admission::PACK_INSTALL.put(&self.store, txn, &receipt.pack_name, &receipt)?;
            admission::PACK_CANDIDATE.delete(&self.store, txn, &hash)?;
            Ok(receipt.clone())
        })
    }

    /// A built-in channel runs as its engine pack (OF-519): once the vault
    /// is seeded, a send on it needs `oneiron.<channel>` installed Active
    /// with the built-in adapter. An owner who removed or replaced the pack
    /// has no such channel. A channel no built-in pack names passes.
    pub fn require_builtin_channel_pack(&self, channel: &str) -> Result<()> {
        let Some((name, _)) = PACKS.iter().find(|(name, _)| *name == channel) else {
            return Ok(());
        };
        let txn = self.store.env.read_txn()?;
        if !SEEDED.contains(&self.store, &txn, &())? {
            return Ok(());
        }
        match self.installed_pack_in_txn(&txn, &format!("oneiron.{name}"))? {
            Some(receipt)
                if receipt.status == PackInstallStatus::Active
                    && receipt.adapter == Some(PackAdapter::Builtin((*name).to_owned()))
                    && receipt.engine_version.as_deref() == Some(env!("CARGO_PKG_VERSION")) =>
            {
                Ok(())
            }
            _ => Err(super::invalid(
                "the channel's built-in pack is not installed",
            )),
        }
    }
}

#[cfg(test)]
mod tests;
