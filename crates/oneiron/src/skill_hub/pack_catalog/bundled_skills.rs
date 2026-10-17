//! Bundled skills traverse the same pinned hub import, scanner and provenance doors.
use super::{PackInstallReceipt, PackSource, admission::PACK_INSTALL, invalid};
use crate::side_table::{self, Raw, SideTable};
use crate::{
    Vault,
    entity_id::EntityId,
    error::Result,
    skill::{SkillContentHash, SkillLifecycle},
    skill_hub::{HubFile, HubPackage, HubPin, HubRef},
    temporal::TimeRange,
};
use std::collections::BTreeMap;

/// A bundled skill's provenance alias names the pack that minted it.
const PACK_SKILL_ALIAS: SideTable<(EntityId, [u8; 32]), String, Raw> =
    SideTable::new(&side_table::SKILL_HUB_PACK_SKILL_ALIAS);
/// A bundled skill the owner's removal of a pack retired, by that pack.
const PACK_SKILL_REMOVED: SideTable<EntityId, String, Raw> =
    SideTable::new(&side_table::SKILL_HUB_PACK_SKILL_REMOVED);

/// Exact per-skill source held until the pack install verdict commits.
pub(super) struct ImportedPackSkillSource {
    pub(super) entity: EntityId,
    pub(super) reference: HubRef,
    pub(super) hash: SkillContentHash,
}

/// Each `skills/<folder>/` of a pack as its own skill package, by folder.
pub(super) fn bundled_skill_packages(source: &PackSource) -> Result<Vec<(String, HubPackage)>> {
    let mut groups = BTreeMap::<String, Vec<HubFile>>::new();
    for file in &source.files {
        let Some(path) = file.path.strip_prefix("skills/") else {
            continue;
        };
        let (name, relative) = path
            .split_once('/')
            .ok_or_else(|| invalid("pack skill must have a folder"))?;
        groups
            .entry(name.to_owned())
            .or_default()
            .push(HubFile::new(relative, file.content.clone()));
    }
    groups
        .into_iter()
        .map(|(folder, files)| Ok((folder, super::super::folder::package_from_files(files)?)))
        .collect()
}

impl Vault {
    /// Imports each bundled skill of `source`. A `held` install (the pack
    /// lands Candidate) leaves a skill its own removal retired as it is; the
    /// install that turns the pack Active brings it back.
    pub(super) fn import_pack_skills_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        source: &PackSource,
        hub: &HubRef,
        held: bool,
        at: u64,
    ) -> Result<(Vec<EntityId>, Vec<ImportedPackSkillSource>)> {
        let mut ids = Vec::new();
        let mut skill_sources = Vec::new();
        for (folder, package) in bundled_skill_packages(source)? {
            let hash = package.content_hash()?;
            let skill_ref = pack_skill_hub_ref(hub, &folder, hash)?;
            let preferred_id = crate::codebase::entity_id_from_hash_material(
                b"oneiron.pack-skill.v1",
                &[hash.as_bytes()],
            )?;
            let id = self.import_skill_from_hub_in_txn(
                txn,
                &skill_ref,
                &package,
                preferred_id,
                TimeRange { start: at, end: at },
                at,
            )?;
            if !held {
                self.revive_removed_pack_skill_in_txn(txn, &id, &source.manifest.name, at)?;
            }
            // The final install/Candidate decision follows later in this same
            // transaction. Do not publish an intermediate Candidate receipt.
            skill_sources.push(ImportedPackSkillSource {
                entity: id,
                reference: skill_ref.clone(),
                hash,
            });
            PACK_SKILL_ALIAS.put(
                &self.store,
                txn,
                &pack_skill_alias_key(&id, &skill_ref)?,
                &source.manifest.name,
            )?;
            ids.push(id);
        }
        Ok((ids, skill_sources))
    }
    /// Replace only this pack's admitted prior revisions. Other pack owners
    /// retain a shared content holder until their own installation moves.
    pub(super) fn supersede_pack_skills_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        prior: &PackInstallReceipt,
        installed: &[EntityId],
        at: u64,
    ) -> Result<()> {
        let mut incoming = BTreeMap::new();
        for id in installed {
            let skill = self.read_skill_record_in_txn(txn, id)?;
            if incoming.insert(skill.skill_id, *id).is_some() {
                return Err(invalid("duplicate bundled skill identity"));
            }
        }
        for old_hex in &prior.skills {
            let old_id = EntityId::from_hex(old_hex)?;
            let old = self.read_skill_record_in_txn(txn, &old_id)?;
            let successor = incoming.get(&old.skill_id);
            if successor == Some(&old_id) || old.lifecycle_status != SkillLifecycle::Active {
                continue;
            }
            if !self.pack_skill_shared_in_txn(txn, &prior.pack_name, &old_id, old_hex)? {
                let next_id = successor.ok_or_else(|| {
                    invalid("dropping an active bundled skill requires an explicit retirement")
                })?;
                self.supersede_skill_record_in_txn(
                    txn,
                    &old_id,
                    next_id,
                    TimeRange { start: at, end: at },
                    at,
                )?;
            }
        }
        Ok(())
    }

    /// Whether a holder other than `pack_name` keeps the bundled skill
    /// `old_id` Active: a standalone or unmarked alias, or another mounted
    /// pack whose receipt still lists it.
    fn pack_skill_shared_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        pack_name: &str,
        old_id: &EntityId,
        old_hex: &str,
    ) -> Result<bool> {
        // Only aliases minted by this pack are its historical revisions.
        // Standalone and other-hub aliases are separate active owners.
        let mut shared = false;
        for (_, body, _) in self.active_claims_for_predicate_in_txn(
            txn,
            old_id,
            crate::skill_hub::PREDICATE_SKILL_HUB_PROVENANCE,
        )? {
            let value = crate::skill_hub::support::map_value(&body.value, "hubRef")
                .ok_or_else(|| invalid("bundled skill provenance missing hub ref"))?;
            let reference = HubRef::from_value(value)?;
            let marker = pack_skill_alias_key(old_id, &reference)?;
            match PACK_SKILL_ALIAS
                .get(&self.store, txn, &marker)
                .map_err(|error| {
                    if error.kind() == crate::error::ErrorKind::SideTableRow {
                        invalid("pack skill alias owner corrupt")
                    } else {
                        error
                    }
                })? {
                // A standalone or unmarked alias is a separate holder.
                None => shared = true,
                Some(owner) => {
                    // This marker describes where the alias was minted,
                    // not who owns the SKILL today. Only a live receipt
                    // still listing the old ID keeps the revision Active.
                    if owner != pack_name
                        && self
                            .mounted_pack_in_txn(txn, &owner)?
                            .is_some_and(|pack| pack.skills.iter().any(|skill| skill == old_hex))
                    {
                        shared = true;
                    }
                }
            }
        }
        for entry in PACK_INSTALL.iter_raw_from(&self.store, txn, &[])? {
            let (key, bytes) = entry?;
            if key == pack_name.as_bytes() {
                continue;
            }
            let other = PACK_INSTALL.decode_value(&bytes).map_err(|error| {
                if error.kind() == crate::error::ErrorKind::SideTableRow {
                    invalid("pack install catalog corrupt")
                } else {
                    error
                }
            })?;
            if self
                .mounted_pack_in_txn(txn, &other.pack_name)?
                .is_some_and(|pack| pack.skills.iter().any(|skill| skill == old_hex))
            {
                shared = true;
                break;
            }
        }
        Ok(shared)
    }

    /// Retires the bundled skills of the removed pack `removed` that no other
    /// holder keeps: each leaves Active for Quarantined, ratified by the
    /// owner's removal, and is marked as this pack's, so its next install of
    /// the same skill brings it back. Its revisions and evidence stay.
    pub(super) fn retire_pack_skills_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        removed: &PackInstallReceipt,
        at: u64,
    ) -> Result<()> {
        for hex in &removed.skills {
            let id = EntityId::from_hex(hex)?;
            let prior = self.read_skill_record_in_txn(txn, &id)?;
            if prior.lifecycle_status != SkillLifecycle::Active
                || self.pack_skill_shared_in_txn(txn, &removed.pack_name, &id, hex)?
            {
                continue;
            }
            let mut retired = prior.clone();
            retired.lifecycle_status = SkillLifecycle::Quarantined;
            retired.approval_status = crate::claim::ClaimApprovalStatus::Approved;
            self.write_pack_skill_state_in_txn(txn, &id, &prior, &retired, at)?;
            PACK_SKILL_REMOVED.put(&self.store, txn, &id, &removed.pack_name)?;
        }
        Ok(())
    }

    /// Brings back a skill `pack`'s own removal retired, as that pack installs
    /// it again. A skill another act quarantined stays as it is: arrival
    /// never revives a local decision.
    fn revive_removed_pack_skill_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        pack: &str,
        at: u64,
    ) -> Result<()> {
        if PACK_SKILL_REMOVED.get(&self.store, txn, id)?.as_deref() != Some(pack) {
            return Ok(());
        }
        PACK_SKILL_REMOVED.delete(&self.store, txn, id)?;
        let prior = self.read_skill_record_in_txn(txn, id)?;
        if prior.lifecycle_status != SkillLifecycle::Quarantined {
            return Ok(());
        }
        let mut revived = prior.clone();
        revived.lifecycle_status = SkillLifecycle::Active;
        self.write_pack_skill_state_in_txn(txn, id, &prior, &revived, at)
    }

    /// One lifecycle step of a bundled skill, through the ordinary update
    /// gate; its content never changes.
    fn write_pack_skill_state_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        prior: &crate::skill::SkillRecord,
        next: &crate::skill::SkillRecord,
        at: u64,
    ) -> Result<()> {
        crate::skill::validate_skill_update(prior, next)?;
        let data = crate::skill::encode_skill_record(next)?;
        self.apply_skill_record_body(txn, id, TimeRange { start: at, end: at }, at, data, false)
    }
}

fn pack_skill_alias_key(id: &EntityId, source: &HubRef) -> Result<(EntityId, [u8; 32])> {
    let encoded = serde_json::to_vec(&source.to_value()?)
        .map_err(|_| invalid("pack skill alias encoding failed"))?;
    Ok((*id, *blake3::hash(&encoded).as_bytes()))
}

/// Distinct skill provenance: the pack source ref itself may contain many
/// skills, while a hub provenance alias names exactly one skill entity.
pub(in crate::skill_hub) fn pack_skill_hub_ref(
    pack_ref: &HubRef,
    folder: &str,
    hash: crate::skill::SkillContentHash,
) -> Result<HubRef> {
    // Hash the structured, validated source ref and length-frame the folder:
    // both are independently bounded, but concatenating them could exceed
    // HubRef's 4096-byte ref_string limit after the owner approved the pack.
    let mut source = Vec::new();
    rmpv::encode::write_value(&mut source, &pack_ref.to_value()?)
        .map_err(|_| invalid("pack skill source ref encoding"))?;
    let mut alias = blake3::Hasher::new_derive_key("oneiron.pack-skill.provenance.v1");
    for part in [source.as_slice(), folder.as_bytes()] {
        alias.update(&(part.len() as u64).to_be_bytes());
        alias.update(part);
    }
    HubRef::new(
        pack_ref.hub_id,
        format!("pack-skill:{}", alias.finalize().to_hex()),
        HubPin::ContentHash(hash.to_hex()),
    )
}
