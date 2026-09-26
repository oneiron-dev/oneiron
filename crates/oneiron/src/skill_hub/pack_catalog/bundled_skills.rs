//! Bundled skills traverse the same pinned hub import, scanner and provenance doors.
use super::{PackSource, invalid};
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
            let skill_ref = HubRef::new(
                hub.hub_id,
                format!("{}/skills/{folder}", hub.ref_string.trim_end_matches('/')),
                HubPin::ContentHash(hash.to_hex()),
            )?;
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
            ids.push(id);
        }
        Ok(ids)
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
