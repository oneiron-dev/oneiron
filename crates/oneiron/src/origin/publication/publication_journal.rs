//! Journal access: repo identity, row scans, visible-ref rows, owner counts plus advance/receipt/validate helpers.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{
    GIT_WIRE_KEEP_REF_PREFIX, GitOid, GitRefName, GitWireCommitOutcome, GitWireRepo,
};

#[cfg(test)]
use super::publication_codec::OriginPublicationRow;
use super::publication_codec::{
    KEEP_OWNER, PUBLICATIONS, VISIBLE_REF, keep_owner_oid_scan_prefix, origin_keep_ref_name,
    visible_ref_key,
};
use super::publication_types::{
    ORIGIN_PUBLICATION_MAX_REQUIRED_OBJECTS, ORIGIN_PUBLICATION_MAX_ROWS, OriginCensusDisposition,
    OriginPublicationReceipt, OriginPublicationRecord, OriginPublicationRequest,
};
// ---------------------------------------------------------------------------
// Journal access
// ---------------------------------------------------------------------------

impl Vault {
    /// The repository identity publication rows are scoped to.
    ///
    /// The same derivation the LFS attachment plane already uses, so one served
    /// repository has ONE repo id across both origin planes.
    pub(super) fn origin_repo_id_for(&self, repo: &GitWireRepo) -> Result<EntityId> {
        crate::origin::lfs::lfs_repo_id(&repo.identity().as_hex())
    }

    pub(super) fn validate_origin_repo(&self, repo_id: EntityId, repo: &GitWireRepo) -> Result<()> {
        if self.origin_repo_id_for(repo)? != repo_id {
            return Err(Error::InvariantViolation(
                "origin publication repository identity does not match its handle",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn put_origin_publication_record(
        &self,
        record: &OriginPublicationRecord,
    ) -> Result<()> {
        self.with_write_txn(|wtxn| {
            PUBLICATIONS.put(
                &self.store,
                wtxn,
                &record.publication_id,
                &OriginPublicationRow::from_record(record),
            )?;
            Ok(())
        })
    }

    pub(in crate::origin) fn origin_publication_rows(
        &self,
        repo_id: Option<EntityId>,
    ) -> Result<Vec<OriginPublicationRecord>> {
        let rtxn = self.store.env.read_txn()?;
        let mut rows = Vec::new();
        let mut seen = 0_usize;
        for row in PUBLICATIONS.iter_from(&self.store, &rtxn, &[])? {
            seen += 1;
            if seen > ORIGIN_PUBLICATION_MAX_ROWS {
                return Err(Error::IndexOverflow("origin publication rows"));
            }
            let (_, row) = row?;
            let record = row.into_record()?;
            if repo_id.is_none_or(|scope| scope == record.repo_id) {
                rows.push(record);
            }
        }
        Ok(rows)
    }

    pub(super) fn origin_visible_ref_rows(&self, repo_id: &EntityId) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        let mut rows = Vec::new();
        for row in VISIBLE_REF.iter_from(&self.store, &rtxn, repo_id.as_bytes())? {
            if rows.len() >= ORIGIN_PUBLICATION_MAX_ROWS {
                return Err(Error::IndexOverflow("origin visible ref rows"));
            }
            let (_, publication_id) = row?;
            rows.push(publication_id);
        }
        Ok(rows)
    }

    /// Whether this repository's publication protocol has ever published this
    /// ref name.
    ///
    /// An O(1) ownership read, not an alternative advertisement authority.
    /// A missing row does not permit serving a raw ref. Even an owned ref must
    /// also survive [`Vault::published_origin_refs`] before it is advertised.
    pub(in crate::origin) fn origin_publication_manages_ref(
        &self,
        repo_id: EntityId,
        ref_name: &GitRefName,
    ) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        VISIBLE_REF.contains(&self.store, &rtxn, &visible_ref_key(&repo_id, ref_name))
    }

    /// How many logical owners still reference one object in one repository.
    pub(super) fn origin_keep_owner_count(&self, repo_id: &EntityId, oid: &GitOid) -> Result<u64> {
        let rtxn = self.store.env.read_txn()?;
        let prefix = keep_owner_oid_scan_prefix(repo_id, oid);
        let mut count = 0_u64;
        for row in KEEP_OWNER.iter_from(&self.store, &rtxn, &prefix)? {
            row?;
            count = count.saturating_add(1);
        }
        Ok(count)
    }
}

/// What one drive of the state machine did.
pub(super) struct OriginAdvance {
    pub(super) record: OriginPublicationRecord,
    pub(super) already_applied: bool,
    pub(super) wire: Option<GitWireCommitOutcome>,
    pub(super) disposition: OriginCensusDisposition,
}

pub(super) fn origin_receipt(
    record: OriginPublicationRecord,
    ref_was_already_applied: bool,
    wire: Option<GitWireCommitOutcome>,
) -> Result<OriginPublicationReceipt> {
    Ok(OriginPublicationReceipt {
        physical_keep_ref: origin_keep_ref_name(&record.new_oid)?,
        record,
        ref_was_already_applied,
        wire,
    })
}

/// Refuses a request the protocol must never turn into a durable row.
pub(super) fn validate_origin_publication_request(
    request: &OriginPublicationRequest,
) -> Result<()> {
    if request
        .ref_name
        .as_str()
        .starts_with(GIT_WIRE_KEEP_REF_PREFIX)
    {
        return Err(Error::InvariantViolation(
            "origin publication must not publish into the keep-ref namespace",
        ));
    }
    if request.required_objects.len() > ORIGIN_PUBLICATION_MAX_REQUIRED_OBJECTS
        || request.required_lfs_oids.len() > ORIGIN_PUBLICATION_MAX_REQUIRED_OBJECTS
    {
        return Err(Error::InvariantViolation(
            "origin publication requires an unbounded object set",
        ));
    }
    if request.occurred.end < request.occurred.start {
        return Err(Error::InvariantViolation(
            "origin publication occurred range is inverted",
        ));
    }
    Ok(())
}
