//! Offline archive import is another Candidate birth, never an activation ticket.
use super::{HubFile, SkillPackageFormat, folder::package_from_source, package_codec::invalid};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::skill::{SkillLifecycle, SkillRecord};
use crate::{Vault, entity_id::EntityId, error::Result, temporal::TimeRange};

impl Vault {
    pub(crate) fn import_archived_skill_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        record: &SkillRecord,
        source: (SkillPackageFormat, Vec<HubFile>),
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        // Both formats derive capabilities from real source, never a manifest grant.
        // Native metadata can be independent of partial frontmatter, but grants no trust.
        let mut package = package_from_source(record, source.1, source.0)?;
        if record.content_hash != Some(package.content_hash()?)
            || record.skill_id != package.record.skill_id
            || record.desc != package.record.desc
            || record.version != package.record.version
            || record.source != ClaimSource::Imported
            || record.approval_status != ClaimApprovalStatus::Proposed
            || record.lifecycle_status != SkillLifecycle::Candidate
        {
            return Err(invalid("archive skill does not match its candidate folder"));
        }
        // Keep source metadata, dependencies and lineage, but not foreign authority.
        // The ordinary typed put validates the parent and all local lifecycle gates.
        package.record = record.clone();
        self.put_skill_record_in_txn(txn, id, record, occurred, learned_at)?;
        self.write_admitted_capability_surface_in_txn(txn, id, &package.capabilities)?;
        self.scan_and_ingest_on_import_in_txn(
            txn,
            id,
            package.content_hash()?,
            &package,
            occurred,
            learned_at,
        )?;
        self.persist_hub_package_in_txn(txn, id, &package)
    }
}
