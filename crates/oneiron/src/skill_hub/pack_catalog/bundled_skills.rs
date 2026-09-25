//! Pack skills pass the existing archive scanner/Candidate door in the install transaction.
use super::{PackSource, invalid};
use crate::{
    Vault,
    claim::{ClaimApprovalStatus, ClaimSource},
    entity_id::EntityId,
    error::Result,
    skill::SkillLifecycle,
    skill_hub::{HubFile, SkillPackageFormat},
    temporal::TimeRange,
};
use std::collections::BTreeMap;
impl Vault {
    pub(super) fn import_pack_skills_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        source: &PackSource,
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
        for files in groups.into_values() {
            let package = super::super::folder::package_from_files(files)?;
            let hash = package.content_hash()?;
            if let Some(id) = self.imported_skill_entity_for_content_hash_in_txn(txn, hash)? {
                let existing = self.stored_hub_package_in_txn(txn, &id)?;
                if existing.files != package.files {
                    return Err(invalid("pack skill source collision"));
                }
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
            ids.push(id);
        }
        Ok(ids)
    }
}
