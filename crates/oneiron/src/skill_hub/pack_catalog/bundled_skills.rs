//! Bundled skills traverse the same pinned hub import, scanner and provenance doors.
use super::{PackInstallReceipt, PackSource, invalid};
use crate::{
    Vault,
    claim::ClaimApprovalStatus,
    entity_id::EntityId,
    error::Result,
    skill::SkillLifecycle,
    skill_hub::{ForeignSkillPublisher, HubFile, HubPin, HubRef},
    temporal::TimeRange,
};
use std::collections::BTreeMap;
impl Vault {
    pub(super) fn import_pack_skills_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        source: &PackSource,
        hub: &HubRef,
        publisher: &ForeignSkillPublisher,
        at: u64,
    ) -> Result<Vec<EntityId>> {
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
        let mut ids = Vec::new();
        for (folder, files) in groups {
            let package = super::super::folder::package_from_files(files)?;
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
            self.write_hub_import_receipt_in_txn(txn, &id, hash, &skill_ref, Some(publisher), at)?;
            self.store.vault_meta.put(
                txn,
                &pack_skill_alias_key(&id, &skill_ref)?,
                source.manifest.name.as_bytes(),
            )?;
            ids.push(id);
        }
        Ok(ids)
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
            // Only aliases minted by this pack are its historical revisions.
            // Standalone and other-hub aliases are separate active owners.
            let mut shared = false;
            for (_, body, _) in self.active_claims_for_predicate_in_txn(
                txn,
                &old_id,
                crate::skill_hub::PREDICATE_SKILL_HUB_PROVENANCE,
            )? {
                let value = crate::skill_hub::support::map_value(&body.value, "hubRef")
                    .ok_or_else(|| invalid("bundled skill provenance missing hub ref"))?;
                let reference = HubRef::from_value(value)?;
                let marker = pack_skill_alias_key(&old_id, &reference)?;
                match self.store.vault_meta.get(txn, &marker)? {
                    // A standalone or unmarked alias is a separate holder.
                    None => shared = true,
                    Some(owner) => {
                        let owner = std::str::from_utf8(&owner)
                            .map_err(|_| invalid("pack skill alias owner corrupt"))?;
                        // This marker describes where the alias was minted,
                        // not who owns the SKILL today. Only a live receipt
                        // still listing the old ID keeps the revision Active.
                        if owner != prior.pack_name
                            && self
                                .mounted_pack_in_txn(txn, owner)?
                                .is_some_and(|pack| pack.skills.contains(old_hex))
                        {
                            shared = true;
                        }
                    }
                }
            }
            for entry in self
                .store
                .vault_meta
                .prefix_iter(txn, b"pack.install.v1/")?
            {
                let (key, bytes) = entry?;
                if key.as_ref()
                    == [b"pack.install.v1/".as_slice(), prior.pack_name.as_bytes()].concat()
                {
                    continue;
                }
                let other: PackInstallReceipt = serde_json::from_slice(&bytes)
                    .map_err(|_| invalid("pack install catalog corrupt"))?;
                if self
                    .mounted_pack_in_txn(txn, &other.pack_name)?
                    .is_some_and(|pack| pack.skills.contains(old_hex))
                {
                    shared = true;
                    break;
                }
            }
            if !shared {
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
    pub(super) fn activate_pack_skills_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        ids: &[EntityId],
        at: u64,
    ) -> Result<()> {
        for id in ids {
            let mut record = self.read_skill_record_in_txn(txn, id)?;
            if record.lifecycle_status == SkillLifecycle::Candidate {
                if record.approval_status == ClaimApprovalStatus::Rejected
                    || self
                        .hub_admission_receipt_in_txn(txn, id)?
                        .is_some_and(|receipt| !receipt.accepted)
                {
                    return Err(invalid("locally rejected bundled skill cannot reactivate"));
                }
                // Installation is not human consent. The scanner may still
                // escalate `auto` if a verdict moves before this write.
                record.approval_status = ClaimApprovalStatus::Auto;
                record.lifecycle_status = SkillLifecycle::Active;
                let data = crate::skill::encode_skill_record(&record)?;
                let proof = super::super::HubAdmissionProof::post_fit(*id, &data);
                self.admit_hub_skill_record_in_txn(
                    txn,
                    TimeRange { start: at, end: at },
                    at,
                    data,
                    proof,
                )?;
            }
        }
        Ok(())
    }
}

fn pack_skill_alias_key(id: &EntityId, source: &HubRef) -> Result<Vec<u8>> {
    let mut key = b"pack.skill-alias.v1/".to_vec();
    key.extend_from_slice(id.as_bytes());
    let encoded = serde_json::to_vec(&source.to_value()?)
        .map_err(|_| invalid("pack skill alias encoding failed"))?;
    key.extend_from_slice(blake3::hash(&encoded).as_bytes());
    Ok(key)
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
