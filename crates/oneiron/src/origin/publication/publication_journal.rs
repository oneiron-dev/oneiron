//! Journal access: repo identity, row scans, visible-ref rows, owner counts plus advance/receipt/validate helpers.

use std::ops::ControlFlow;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{
    GIT_WIRE_KEEP_REF_PREFIX, GitOid, GitRefName, GitWire, GitWireCommitOutcome, GitWireRepo,
};
use crate::origin::scan_check::{OriginScan, ScanCount};

#[cfg(test)]
use super::publication_codec::OriginPublicationRow;
use super::publication_codec::{
    CAS_BACKFILL, CAS_INTENT, CasIntentKey, KEEP_OWNER, PUBLICATIONS, VISIBLE_REF,
    keep_owner_oid_scan_prefix, origin_keep_ref_name, visible_ref_key,
};
use super::publication_types::{
    ORIGIN_PUBLICATION_MAX_REQUIRED_OBJECTS, OriginCensusDisposition, OriginPublicationReceipt,
    OriginPublicationRecord, OriginPublicationRequest, OriginPublicationStatus,
};
// ---------------------------------------------------------------------------
// Journal access
// ---------------------------------------------------------------------------

/// CAS rows one write transaction of the open-time backfill writes.
const CAS_BACKFILL_BATCH: usize = 4096;

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
        self.with_write_txn_grouped(|wtxn| {
            PUBLICATIONS.put(
                &self.store,
                wtxn,
                &record.publication_id,
                &OriginPublicationRow::from_record(record),
            )?;
            Ok(())
        })
    }

    /// Visits the journal's rows in id order, for one repository or every
    /// one, until `visit` breaks. The journal is keyed by publication id, so
    /// the scan reads the whole vault's history; it never refuses for its
    /// length (rule 5): past its threshold row it raises an origin scan
    /// check and reads on. `visit` runs inside the scan's read transaction.
    pub(in crate::origin) fn visit_origin_publication_rows(
        &self,
        repo_id: Option<EntityId>,
        mut visit: impl FnMut(OriginPublicationRecord) -> ControlFlow<()>,
    ) -> Result<()> {
        let count = {
            let rtxn = self.store.env.read_txn()?;
            let mut count =
                ScanCount::start(&self.store, &rtxn, OriginScan::PublicationRows, None)?;
            for row in PUBLICATIONS.iter_from(&self.store, &rtxn, &[])? {
                count.row();
                let (_, row) = row?;
                let record = row.into_record()?;
                if repo_id.is_none_or(|scope| scope == record.repo_id) && visit(record).is_break() {
                    break;
                }
            }
            count
        };
        count.finish(self);
        Ok(())
    }

    /// Every journal row, for one repository or every one.
    pub(in crate::origin) fn origin_publication_rows(
        &self,
        repo_id: Option<EntityId>,
    ) -> Result<Vec<OriginPublicationRecord>> {
        let mut rows = Vec::new();
        self.visit_origin_publication_rows(repo_id, |record| {
            rows.push(record);
            ControlFlow::Continue(())
        })?;
        Ok(rows)
    }

    /// The first of one repository's journal rows that `matches`.
    pub(in crate::origin) fn find_origin_publication(
        &self,
        repo_id: EntityId,
        mut matches: impl FnMut(&OriginPublicationRecord) -> bool,
    ) -> Result<Option<OriginPublicationRecord>> {
        let mut found = None;
        self.visit_origin_publication_rows(Some(repo_id), |record| {
            if matches(&record) {
                found = Some(record);
                return ControlFlow::Break(());
            }
            ControlFlow::Continue(())
        })?;
        Ok(found)
    }

    /// The publication each of one repository's visible slots names: one
    /// per ref name its protocol published and has not seen deleted. Never
    /// refused for their number (rule 5); past the threshold row the scan
    /// raises an origin scan check.
    pub(in crate::origin) fn origin_visible_ref_rows(
        &self,
        repo_id: &EntityId,
    ) -> Result<Vec<EntityId>> {
        let mut rows = Vec::new();
        let count = {
            let rtxn = self.store.env.read_txn()?;
            let mut count = ScanCount::start(
                &self.store,
                &rtxn,
                OriginScan::VisibleRefRows,
                Some(*repo_id),
            )?;
            for row in VISIBLE_REF.iter_from(&self.store, &rtxn, repo_id.as_bytes())? {
                count.row();
                let (_, publication_id) = row?;
                rows.push(publication_id);
            }
            count
        };
        count.finish(self);
        Ok(rows)
    }

    /// Drops the visible slot of a ref name the repository no longer has.
    ///
    /// The slot names the last publication of a ref that is gone, so it has
    /// nothing left to advertise or keep: the projection hides it, and the
    /// census releases that publication's pins whether or not the slot is
    /// there. Dropping it keeps an advertisement walking live ref names, not
    /// every name the repository ever had. A slot whose ref exists stays.
    /// Callers hold the repository coordinator.
    pub(in crate::origin) fn retire_origin_visible_ref(
        &self,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        repo_id: EntityId,
        ref_name: &GitRefName,
    ) -> Result<()> {
        if git.read_ref(repo, ref_name)?.is_some() {
            return Ok(());
        }
        let key = visible_ref_key(&repo_id, ref_name);
        self.with_write_txn_grouped(|wtxn| {
            VISIBLE_REF.delete(&self.store, wtxn, &key)?;
            Ok(())
        })
    }

    /// Takes one Published row's CAS row and the backfill marker away: the
    /// state a vault written before Published rows kept their CAS row opens
    /// in.
    #[cfg(test)]
    pub(in crate::origin) fn forget_origin_cas_intent_for_test(
        &self,
        record: &OriginPublicationRecord,
    ) -> Result<()> {
        self.with_write_txn_grouped(|wtxn| {
            CAS_INTENT.delete(&self.store, wtxn, &CasIntentKey::new(record))?;
            CAS_BACKFILL.delete(&self.store, wtxn, &())?;
            Ok(())
        })
    }

    /// Gives every Published row the CAS row T2 now keeps, once per vault.
    ///
    /// A vault written before Published rows kept their CAS row admitted a
    /// publication only after reading its whole journal for a Published row
    /// with the same move. That row now answers in one read; this gives the
    /// older rows theirs, so no admission reads history again.
    pub(crate) fn backfill_origin_cas_intents_on_open(&self) -> Result<()> {
        let rows = {
            let rtxn = self.store.env.read_txn()?;
            if CAS_BACKFILL.contains(&self.store, &rtxn, &())? {
                return Ok(());
            }
            let mut rows = Vec::new();
            for row in PUBLICATIONS.iter_from(&self.store, &rtxn, &[])? {
                let (_, row) = row?;
                let record = row.into_record()?;
                if record.status != OriginPublicationStatus::Published {
                    continue;
                }
                let key = CasIntentKey::new(&record);
                if !CAS_INTENT.contains(&self.store, &rtxn, &key)? {
                    rows.push((key, record.publication_id));
                }
            }
            rows
        };
        // Admission refused a second Published row of one move, so each key
        // has one row to name.
        for batch in rows.chunks(CAS_BACKFILL_BATCH) {
            self.with_write_txn_grouped(|wtxn| {
                for (key, publication_id) in batch {
                    CAS_INTENT.put(&self.store, wtxn, key, publication_id)?;
                }
                Ok(())
            })?;
        }
        self.with_write_txn_grouped(|wtxn| {
            CAS_BACKFILL.put(&self.store, wtxn, &(), &())?;
            Ok(())
        })
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
