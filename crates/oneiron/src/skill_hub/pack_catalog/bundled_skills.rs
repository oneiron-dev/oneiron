//! Pack skills pass the existing archive scanner/Candidate door in the install transaction.
use super::{PackSource, invalid};
use crate::{
    Vault,
    claim::{ClaimApprovalStatus, ClaimSource},
    entity_id::EntityId,
    error::Result,
    skill::SkillLifecycle,
    skill_hub::{HubFile, HubPin, HubRef, SkillPackageFormat},
    temporal::TimeRange,
};
use std::collections::BTreeMap;
impl Vault {
    pub(super) fn import_pack_skills_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        source: &PackSource,
        hub: &HubRef,
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
            if let Some(id) = self.imported_skill_entity_for_content_hash_in_txn(txn, hash)? {
                let existing = self.stored_hub_package_in_txn(txn, &id)?;
                if existing.files != package.files {
                    return Err(invalid("pack skill source collision"));
                }
                self.append_hub_provenance_in_txn(
                    txn,
                    &id,
                    hash,
                    &skill_ref,
                    TimeRange { start: at, end: at },
                    at,
                )?;
                ids.push(id);
                continue;
            }
            let mut record = package.record;
            record.content_hash = Some(hash);
            record.source = ClaimSource::Imported;
            record.approval_status = ClaimApprovalStatus::Proposed;
            record.lifecycle_status = SkillLifecycle::Candidate;
            record.generated = false;
            record.human_authored = true;
            let id = crate::codebase::entity_id_from_hash_material(
                b"oneiron.pack-skill.v1",
                &[hash.as_bytes()],
            )?;
            if self.store.entities.get(txn, id.as_bytes())?.is_some() {
                return Err(invalid("pack skill id collision"));
            }
            self.import_archived_skill_in_txn(
                txn,
                &id,
                &record,
                (SkillPackageFormat::Folder, package.files),
                TimeRange { start: at, end: at },
                at,
            )?;
            self.append_hub_provenance_in_txn(
                txn,
                &id,
                hash,
                &skill_ref,
                TimeRange { start: at, end: at },
                at,
            )?;
            ids.push(id);
        }
        Ok(ids)
    }
}

/// Distinct skill provenance: the pack source ref itself may contain many
/// skills, while a hub provenance alias names exactly one skill entity.
pub(super) fn pack_skill_hub_ref(
    pack_ref: &HubRef,
    folder: &str,
    hash: crate::skill::SkillContentHash,
) -> Result<HubRef> {
    HubRef::new(
        pack_ref.hub_id,
        format!("{}/skills/{folder}", pack_ref.ref_string),
        HubPin::ContentHash(hash.to_hex()),
    )
}
