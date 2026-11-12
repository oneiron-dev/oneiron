//! Candidate archive imports and exact owner restoration of existing engine seeds.
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
        let package = package_from_source(record, source.1, source.0)?;
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
        // The stored record is the package's: this record with the site notes
        // its tree gives (FIX 11958). The ordinary typed put validates the
        // parent and all local lifecycle gates.
        self.put_skill_record_in_txn(txn, id, &package.record, occurred, learned_at)?;
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

    /// Restores an existing census seed's native endpoint, not an imported birth.
    #[expect(
        clippy::too_many_arguments,
        reason = "native seed, archived carrier and source custody"
    )]
    pub(crate) fn restore_owner_seed_skill_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        seeds: &crate::vault::EngineSeedIdentities,
        bundle: &crate::batch::export::ExportSkillBundle,
        carrier: Option<&crate::batch::export::ExportEntity>,
        files: &dyn crate::batch::export::ArchiveFiles,
        secrets: crate::serialize::ExportSecrets,
        proof: super::HubAdmissionProof,
    ) -> Result<()> {
        let row = &bundle.entity;
        let id = EntityId::from_hex(&row.id)?;
        if row.entity_type != crate::registry::ENTITY_TYPE_SKILL
            || !seeds.census.skills.contains(&id)
            || crate::vault::live_entity_row_in_txn(&self.store, txn, &id)?.live_type()
                != Some(crate::registry::ENTITY_TYPE_SKILL)
        {
            return Err(invalid(
                "owner seed restore requires an existing census SKILL",
            ));
        }
        let data = row.body.to_bytes_in_with(files, secrets)?;
        if !proof.owner_seed_restore_binds(&id, &data) {
            return Err(invalid(
                "owner seed restore proof does not bind the archived body",
            ));
        }
        let record = crate::skill::decode_skill_record(&data)?;
        let format = bundle
            .source_format
            .ok_or_else(|| invalid("owner seed skill source format missing"))?;
        let tree = bundle
            .source_tree
            .as_ref()
            .ok_or_else(|| invalid("owner seed skill source tree missing"))?;
        let mut package =
            package_from_source(&record, tree.import_files_in_with(files, secrets)?, format)?;
        let hash = package.content_hash()?;
        if record.content_hash != Some(hash)
            || record.skill_id != package.record.skill_id
            || record.desc != package.record.desc
            || record.version != package.record.version
            || record.role != package.record.role
            || record.call != package.record.call
        {
            return Err(invalid(
                "owner seed skill does not match its archived source",
            ));
        }
        // A Native carrier can predate same-tree metadata edits. Check its
        // holder/tree, not equality with the newer native record in PACKAGE.
        let carrier_id = super::source_carrier::source_carrier_id(&id, &hash)?;
        let archived_carrier = carrier
            .map(|carrier| {
                let bytes = carrier.body.to_bytes_in_with(files, secrets)?;
                let (holder, carried) = super::source_carrier::decode_source_carrier(&bytes)?
                    .ok_or_else(|| invalid("archived seed source carrier missing"))?;
                if carrier.entity_type != crate::registry::ENTITY_TYPE_ASSET
                    || EntityId::from_hex(&carrier.id)? != carrier_id
                    || holder != id
                    || carried.content_hash()? != hash
                {
                    return Err(invalid("archived seed source carrier binding differs"));
                }
                Ok((carrier, bytes))
            })
            .transpose()?;
        // Parsing checks source and derives capabilities, not new native metadata.
        package.record = record;
        let occurred = TimeRange {
            start: row.occurred_start,
            end: row.occurred_end,
        };
        self.admit_hub_skill_record_in_txn(txn, occurred, row.learned_at, data, proof)?;
        self.write_admitted_capability_surface_in_txn(txn, &id, &package.capabilities)?;
        let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
        self.scan_and_ingest_on_import_in_txn(
            txn,
            &id,
            hash,
            &package,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )?;
        if let Some((carrier, bytes)) = archived_carrier
            && !crate::ports::EntityStoreRead::port_entity_present(&self.store, txn, &carrier_id)?
        {
            // Preserve the source vault's immutable custody bytes and stamps
            // before persistence can synthesize a carrier from newer metadata.
            self.batch_in()
                .put(
                    &carrier_id,
                    crate::registry::ENTITY_TYPE_ASSET,
                    TimeRange {
                        start: carrier.occurred_start,
                        end: carrier.occurred_end,
                    },
                    carrier.learned_at,
                    &bytes,
                )
                .apply(txn)?;
        }
        self.persist_hub_package_in_txn(txn, &id, &package)
    }
}
