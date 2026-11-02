//! Journal access: repo identity, row scans, visible-ref rows, owner counts plus advance/receipt/validate helpers.

use std::ops::ControlFlow;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{
    GIT_WIRE_KEEP_REF_PREFIX, GitOid, GitRefExpectation, GitRefName, GitRefPublication, GitWire,
    GitWireCommitOutcome, GitWireRepo, lock_repository,
};
use crate::scan_check::{EngineScan, ScanCount};

#[cfg(test)]
use super::publication_codec::OriginPublicationRow;
use super::publication_codec::{
    CAS_BACKFILL, CAS_INTENT, CasIntentKey, KEEP_OWNER, PUBLICATIONS, VISIBLE_REF, keep_owner_key,
    keep_owner_oid_scan_prefix, origin_keep_ref_name, visible_ref_key,
};
use super::publication_types::{
    OriginCensusDisposition, OriginKeepRefKind, OriginPublicationAnswer, OriginPublicationReceipt,
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

    /// Names `record` in its ref's visible slot again while it is still
    /// `Published`: a re-drive that moved the ref back to its value
    /// advertises it again (FIX 10002). The caller holds the coordinator.
    pub(super) fn restore_origin_visible_slot(
        &self,
        record: &OriginPublicationRecord,
    ) -> Result<()> {
        self.with_write_txn_grouped(|wtxn| {
            let current = PUBLICATIONS
                .get(&self.store, wtxn, &record.publication_id)?
                .ok_or(Error::CorruptedIndex("origin publication disappeared"))?
                .into_record()?;
            if current.status != OriginPublicationStatus::Published {
                return Err(Error::ConcurrentWrite("origin publication changed"));
            }
            VISIBLE_REF.put(
                &self.store,
                wtxn,
                &visible_ref_key(&record.repo_id, &record.ref_name),
                &record.publication_id,
            )?;
            Ok(())
        })?;
        self.note_origin_ref_moved(record.ref_name.as_str());
        Ok(())
    }

    /// Starts the count of one publication's obligation walk against its
    /// scan row (rule 5, FIX 10001): every required Git and LFS object is
    /// pinned and proved one at a time, however many. The caller holds no
    /// read transaction.
    pub(super) fn start_obligation_count(&self, repo_id: &EntityId) -> Result<ScanCount> {
        let rtxn = self.store.env.read_txn()?;
        ScanCount::start(
            &self.store,
            &rtxn,
            EngineScan::OriginPublicationObligations,
            repo_id.as_bytes(),
        )
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
            let mut count = ScanCount::start(&self.store, &rtxn, EngineScan::PublicationRows, &[])?;
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
    #[cfg(test)]
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
    /// per ref name its protocol ever published. A deleted name keeps its
    /// slot, the one advertisement a re-drive or a recreation of its
    /// publication has. Never refused for their number (rule 5); past the
    /// threshold row the scan raises an origin scan check.
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
                EngineScan::VisibleRefRows,
                repo_id.as_bytes(),
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

    /// The publication that owns one move: a `Prepared` one making it, or
    /// the `Published` one that made it, whose CAS row names it for good. A
    /// refused move frees its row, so it has no owner.
    pub(in crate::origin) fn origin_move_owner(
        &self,
        repo_id: EntityId,
        ref_name: &GitRefName,
        expected_old_oid: Option<&GitOid>,
        new_oid: &GitOid,
    ) -> Result<Option<OriginPublicationRecord>> {
        let key = CasIntentKey::of_move(repo_id, ref_name, expected_old_oid, new_oid);
        let owner = {
            let rtxn = self.store.env.read_txn()?;
            CAS_INTENT.get(&self.store, &rtxn, &key)?
        };
        let Some(owner) = owner else {
            return Ok(None);
        };
        self.origin_publication(owner)
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
            let mut journaled = false;
            for row in PUBLICATIONS.iter_from(&self.store, &rtxn, &[])? {
                journaled = true;
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
            // An empty journal has nothing to give, and a vault that never
            // published takes no marker row for it.
            if !journaled {
                return Ok(());
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

    /// Whether a saved GitWire effect may move its refs, asked by GitWire at
    /// the effect itself so that no door to a saved effect re-applies one the
    /// origin no longer permits. A move an origin publication owns runs only
    /// under that publication's current authority; a move none owns is not the
    /// origin's to judge. A permitted Published owner whose name has no visible
    /// slot gets it back before the effect, so a recreated ref is visible the
    /// moment it exists and a crash cannot leave it hidden.
    pub(crate) fn admit_origin_ref_effect(
        &self,
        repo: &GitWireRepo,
        publications: &[GitRefPublication],
    ) -> Result<bool> {
        let repo_id = self.origin_repo_id_for(repo)?;
        for publication in publications {
            let Some(next) = publication.next() else {
                continue;
            };
            let expected = match publication.expected() {
                GitRefExpectation::Absent => None,
                GitRefExpectation::Value(oid) => Some(oid),
                GitRefExpectation::Any => continue,
            };
            let Some(owner) =
                self.origin_move_owner(repo_id, publication.name(), expected, next)?
            else {
                continue;
            };
            if self
                .origin_authority_refusal(repo, owner.publication_id)?
                .is_some()
            {
                return Ok(false);
            }
            if owner.status == OriginPublicationStatus::Published {
                let key = visible_ref_key(&owner.repo_id, &owner.ref_name);
                self.with_write_txn_grouped(|wtxn| {
                    if !VISIBLE_REF.contains(&self.store, wtxn, &key)? {
                        VISIBLE_REF.put(&self.store, wtxn, &key, &owner.publication_id)?;
                    }
                    Ok(())
                })?;
            }
        }
        Ok(true)
    }

    /// Retires a deleted name's visible slot while the ref is still absent.
    /// A read failure is not absence. No publication, CAS owner or Change row
    /// goes with it, so a later push at an old tip still finds its owner.
    pub(in crate::origin) fn retire_origin_visible_ref(
        &self,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        repo_id: EntityId,
        ref_name: &GitRefName,
    ) -> Result<()> {
        let _guard = lock_repository(repo.common_dir())?;
        if git.read_ref(repo, ref_name)?.is_some() {
            return Ok(());
        }
        self.with_write_txn_grouped(|wtxn| {
            VISIBLE_REF.delete(&self.store, wtxn, &visible_ref_key(&repo_id, ref_name))?;
            Ok(())
        })
        .inspect(|()| self.note_origin_ref_moved(ref_name.as_str()))
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

    /// Every logical owner of `kind` in one repository, as `(object, owner
    /// key)`. The scan is whole: it never refuses for its length (rule 5).
    pub(in crate::origin) fn origin_keep_owners_of_kind(
        &self,
        repo_id: EntityId,
        kind: OriginKeepRefKind,
    ) -> Result<Vec<(GitOid, String)>> {
        let (owners, count) = {
            let rtxn = self.store.env.read_txn()?;
            let mut count = ScanCount::start(
                &self.store,
                &rtxn,
                EngineScan::KeepOwnerRows,
                repo_id.as_bytes(),
            )?;
            let mut owners = Vec::new();
            for row in KEEP_OWNER.iter_from(&self.store, &rtxn, repo_id.as_bytes())? {
                count.row();
                let (key, _) = row?;
                if key.kind == kind.as_str() {
                    owners.push((GitOid::parse_hex(&key.oid)?, key.owner_key));
                }
            }
            (owners, count)
        };
        count.finish(self);
        Ok(owners)
    }

    /// Whether `owner_key` of `kind` still keeps one object in one
    /// repository.
    pub(in crate::origin) fn origin_keep_owner_held(
        &self,
        repo_id: EntityId,
        oid: &GitOid,
        kind: OriginKeepRefKind,
        owner_key: &str,
    ) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        let key = keep_owner_key(&repo_id, oid, kind, owner_key);
        KEEP_OWNER.contains(&self.store, &rtxn, &key)
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
        answer: OriginPublicationAnswer::Own,
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
    if request.occurred.end < request.occurred.start {
        return Err(Error::InvariantViolation(
            "origin publication occurred range is inverted",
        ));
    }
    Ok(())
}
