//! Engine-embedded connector source and local first-open installation.
//! A bootstrap receipt describes requested powers; it never mints a grant or a wake.

use super::qualify::{validate_installed_qualification, validate_qualification};
use super::{
    PackAdapter, PackCandidateReason, PackInstallReceipt, PackInstallStatus, PackKind,
    PackQualifier, PackSource, SetupCheckQualifier, admission,
};
use crate::side_table::{self, Raw, SideTable};
use crate::skill_hub::{HubFile, HubPin, HubRef};
use crate::{EntityId, TimeRange, Vault, error::Result};

/// Marker (engine version string) that the built-in connector packs have been seeded.
const SEEDED: SideTable<(), String, Raw> = SideTable::new(&side_table::SKILL_HUB_PACK_BUILTIN_SEED);
const PACKS: [(&str, &str); 6] = [
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
    (
        "browser",
        include_str!("../../../../../packs/builtin/browser/PACK.md"),
    ),
    (
        "native_mail",
        include_str!("../../../../../packs/builtin/native_mail/PACK.md"),
    ),
];
/// Each built-in pack's guided setup skill (OF-378), at the folder its
/// PACK.md `setup` names. It ships in the same exact source, so the owner
/// reads it while the connector is still a Candidate.
const SETUP_SKILLS: [(&str, &str); 5] = [
    (
        "slack",
        include_str!("../../../../../packs/builtin/slack/skills/setup/SKILL.md"),
    ),
    (
        "line",
        include_str!("../../../../../packs/builtin/line/skills/setup/SKILL.md"),
    ),
    (
        "email",
        include_str!("../../../../../packs/builtin/email/skills/setup/SKILL.md"),
    ),
    (
        "linkedin",
        include_str!("../../../../../packs/builtin/linkedin/skills/setup/SKILL.md"),
    ),
    (
        "browser",
        include_str!("../../../../../packs/builtin/browser/skills/setup/SKILL.md"),
    ),
];
const SETUP_SKILL_PATH: &str = "skills/setup/SKILL.md";

/// One built-in pack's exact source: its PACK.md and its setup skill.
fn builtin_source(name: &str, markdown: &str) -> Result<PackSource> {
    let mut files = vec![HubFile::new("PACK.md", markdown.as_bytes())];
    if let Some((_, skill)) = SETUP_SKILLS.iter().find(|(channel, _)| *channel == name) {
        files.push(HubFile::new(SETUP_SKILL_PATH, skill.as_bytes()));
    }
    PackSource::from_files(files)
}

/// A built-in channel's exact embedded source.
pub(super) fn embedded_builtin_source(channel: &str) -> Result<PackSource> {
    let (name, markdown) = PACKS
        .iter()
        .find(|(name, _)| *name == channel)
        .ok_or_else(|| super::invalid("unknown built-in connector pack"))?;
    builtin_source(name, markdown)
}

/// The engine hub ref a built-in source's bundled skills are imported under,
/// pinned to that exact source.
fn builtin_hub_ref(name: &str, source: &PackSource) -> Result<HubRef> {
    HubRef::new(
        engine_hub_id()?,
        format!("built-in:{name}"),
        HubPin::ContentHash(source.content_hash().to_hex()),
    )
}

fn engine_hub_id() -> Result<EntityId> {
    EntityId::derive(
        crate::entity_id::derived_domains::BUILTIN_CONNECTOR_PACK_HUB,
        &[],
    )
}

/// The publisher an engine-seeded receipt names.
const ENGINE_PUBLISHER: &str = "oneiron-engine";

/// A removed engine-seeded built-in goes back to the Candidate it was seeded
/// as, and qualifies again on its checked setup.
pub(super) fn reseeded_candidate(removed: &PackInstallReceipt) -> Option<PackInstallReceipt> {
    let Some(PackAdapter::Builtin(channel)) = removed.adapter.as_ref() else {
        return None;
    };
    if removed.publisher != ENGINE_PUBLISHER
        || !PACKS.iter().any(|(name, _)| *name == channel.as_str())
    {
        return None;
    }
    let mut candidate = removed.clone();
    candidate.status = PackInstallStatus::Candidate;
    candidate.candidate_reason = Some(PackCandidateReason::QualificationRequired);
    candidate.qualification_report_hash = None;
    candidate.connector_qualification = None;
    candidate.runtime = None;
    Some(candidate)
}

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
        let source = builtin_source(name, markdown)?;
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
        // The setup skill imports the ordinary bundled way and is held
        // Candidate with its pack until the connector qualifies.
        let skills = vault.admit_pack_skills_in_txn(
            &mut txn,
            &source,
            &builtin_hub_ref(name, &source)?,
            None,
            Some(PackCandidateReason::QualificationRequired),
            crate::unix_seconds_now(),
        )?;
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
            skills: skills.iter().map(EntityId::to_hex).collect(),
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
    /// first-party. The exact embedded source must pass a qualifier before
    /// the receipt enters the Active installation catalog: its checked setup
    /// connection ([`SetupCheckQualifier`]) or a probe suite.
    pub fn qualify_builtin_connector_pack(
        &self,
        channel: &str,
        qualifier: &dyn PackQualifier,
    ) -> Result<PackInstallReceipt> {
        let source = embedded_builtin_source(channel)?;
        let hub = builtin_hub_ref(channel, &source)?;
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
            // The held setup skill installs with its now-qualified pack.
            let at = crate::unix_seconds_now();
            let skills = self.admit_pack_skills_in_txn(txn, &source, &hub, None, None, at)?;
            if let Some(prior) = installed.as_ref() {
                self.supersede_pack_skills_in_txn(txn, prior, &skills, at)?;
            }
            receipt.skills = skills.iter().map(EntityId::to_hex).collect();
            admission::PACK_INSTALL.put(&self.store, txn, &receipt.pack_name, &receipt)?;
            admission::PACK_CANDIDATE.delete(&self.store, txn, &hash)?;
            Ok(receipt.clone())
        })
    }

    /// A built-in whose setup check just turned Verified qualifies in the
    /// same flow (Engine ruling 10-17). Only the engine-seeded receipt of the
    /// exact embedded source moves, and only while the runtime gate would
    /// refuse it: a Candidate, or a receipt an older engine qualified. A pack
    /// with several connections waits until every one is checked. Returns
    /// whether the pack is now Active.
    pub(crate) fn qualify_builtin_on_checked_setup(
        &self,
        pack: &str,
        content_hash: &str,
    ) -> Result<bool> {
        let Some(channel) = pack.strip_prefix("oneiron.") else {
            return Ok(false);
        };
        if !PACKS.iter().any(|(name, _)| *name == channel) {
            return Ok(false);
        }
        let source = embedded_builtin_source(channel)?;
        let Some(setup) = source.manifest().setup.as_ref() else {
            return Ok(false);
        };
        if source.content_hash().to_hex() != content_hash {
            return Ok(false);
        }
        let receipt = {
            let txn = self.store.env.read_txn()?;
            match admission::PACK_CANDIDATE.get(&self.store, &txn, &content_hash.to_owned())? {
                Some(candidate) => Some(candidate),
                None => self
                    .installed_pack_in_txn(&txn, pack)?
                    .filter(|installed| installed.content_hash == content_hash),
            }
        };
        let Some(receipt) = receipt else {
            return Ok(false);
        };
        let current = receipt.status == PackInstallStatus::Active
            && receipt.engine_version.as_deref() == Some(env!("CARGO_PKG_VERSION"));
        if receipt.publisher != ENGINE_PUBLISHER
            || receipt.adapter != Some(PackAdapter::Builtin(channel.to_owned()))
            || current
        {
            return Ok(false);
        }
        for connection in &setup.connections {
            if self
                .require_candidate_pack_connection_verified(pack, content_hash, &connection.id)
                .is_err()
            {
                return Ok(false);
            }
        }
        self.qualify_builtin_connector_pack(channel, &SetupCheckQualifier { vault: self })?;
        Ok(true)
    }

    /// A built-in channel runs as its engine pack (OF-519): once the vault
    /// is seeded, a send or an inbound event on it needs a pack serving the
    /// channel installed Active with the built-in adapter. An owner who
    /// removed or replaced the pack has no such channel. A channel no
    /// built-in pack names passes.
    pub fn require_builtin_channel_pack(&self, channel: &str) -> Result<()> {
        let txn = self.store.env.read_txn()?;
        self.require_builtin_channel_pack_in_txn(&txn, channel)
    }

    /// [`Self::require_builtin_channel_pack`] in the caller's snapshot.
    /// Email has two built-in packs: delegated Gmail (`email`) and the
    /// native mailbox (`native_mail`); either one Active serves it.
    pub(crate) fn require_builtin_channel_pack_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        channel: &str,
    ) -> Result<()> {
        let serves = |name: &str| name == channel || (channel == "email" && name == "native_mail");
        if !PACKS.iter().any(|(name, _)| serves(name)) {
            return Ok(());
        }
        if !SEEDED.contains(&self.store, txn, &())? {
            return Ok(());
        }
        for (name, _) in PACKS.iter().filter(|(name, _)| serves(name)) {
            if let Some(receipt) = self.installed_pack_in_txn(txn, &format!("oneiron.{name}"))?
                && receipt.status == PackInstallStatus::Active
                && receipt.adapter == Some(PackAdapter::Builtin((*name).to_owned()))
                && receipt.engine_version.as_deref() == Some(env!("CARGO_PKG_VERSION"))
            {
                return Ok(());
            }
        }
        Err(super::invalid(
            "the channel's built-in pack is not installed",
        ))
    }
}

#[cfg(test)]
mod tests;
