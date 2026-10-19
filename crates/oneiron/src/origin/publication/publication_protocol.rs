//! Public protocol surface: pin/unpin, publish_origin_ref, reconcile census driver, reads and advertisement projection.

use std::ops::ControlFlow;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{
    GitOid, GitRefName, GitWire, GitWireRepo, lock_repository, try_lock_repository,
};

use super::publication_codec::{
    KEEP_OWNER, PUBLICATIONS, keep_owner_key, origin_keep_ref_name, origin_publication_id,
};
use super::publication_journal::{origin_receipt, validate_origin_publication_request};
use super::publication_machine::OriginAdmission;
use super::publication_types::{
    OriginCensusDisposition, OriginCensusReport, OriginKeepRefKind, OriginPublicationAnswer,
    OriginPublicationReceipt, OriginPublicationRecord, OriginPublicationRequest,
    OriginPublicationStatus,
};
// ---------------------------------------------------------------------------
// The public protocol surface
// ---------------------------------------------------------------------------

impl Vault {
    /// Pins one git object behind a physical keep-ref and one logical owner.
    ///
    /// Crate-local inherent impl in the feature module: `vault.rs` is never
    /// edited to add a feature's entry points (the blob-artifact and vault-LFS
    /// precedent).
    ///
    /// The PHYSICAL root is written first and the LOGICAL owner second, so a
    /// crash between them leaves a keep-ref nobody claims — a safe leak the
    /// census removes. The other order would leave an owner row claiming a
    /// root that does not exist, and the object it thinks it is protecting
    /// could be collected out from under it.
    pub fn pin_origin_object(
        &self,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        kind: OriginKeepRefKind,
        owner_key: &str,
        oid: &GitOid,
        learned_at: u64,
    ) -> Result<GitRefName> {
        // Hold the same coordinator as retirement until BOTH the physical
        // root and its logical owner exist. Otherwise a concurrent last-owner
        // release could delete the root between these two writes.
        let _guard = lock_repository(repo.common_dir())?;
        let name = origin_keep_ref_name(oid)?;
        let outcome = git.write_keep_ref(repo, oid, learned_at)?;
        if !outcome.is_applied() {
            return Err(Error::InvariantViolation(
                "origin keep-ref could not be written",
            ));
        }
        let repo_id = self.origin_repo_id_for(repo)?;
        let key = keep_owner_key(&repo_id, oid, kind, owner_key);
        self.with_write_txn_grouped(|wtxn| {
            KEEP_OWNER.put(&self.store, wtxn, &key, &learned_at.to_le_bytes())?;
            Ok(())
        })?;
        Ok(name)
    }

    /// Releases one logical owner and, at zero owners, the physical root.
    ///
    /// The owner row goes first and the keep-ref second, for the same reason
    /// [`Vault::pin_origin_object`] writes them the other way round: an
    /// interrupted release leaves an unclaimed keep-ref, never a claim with no
    /// root. Deletion happens ONLY when no publication, change, conflict,
    /// recovery or snapshot owner still references the object.
    pub fn unpin_origin_object(
        &self,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        kind: OriginKeepRefKind,
        owner_key: &str,
        oid: &GitOid,
        learned_at: u64,
    ) -> Result<()> {
        // Serialize owner removal, the zero-owner proof and physical deletion
        // with pinning, including callers outside the receive-pack door.
        let _guard = lock_repository(repo.common_dir())?;
        let repo_id = self.origin_repo_id_for(repo)?;
        let key = keep_owner_key(&repo_id, oid, kind, owner_key);
        self.with_write_txn_grouped(|wtxn| {
            KEEP_OWNER.delete(&self.store, wtxn, &key)?;
            Ok(())
        })?;
        if self.origin_keep_owner_count(&repo_id, oid)? == 0
            && !git.delete_keep_ref(repo, oid, learned_at)?.is_applied()
        {
            return Err(Error::InvariantViolation(
                "origin keep-ref could not be deleted",
            ));
        }
        Ok(())
    }

    /// Writes the intent `request` names as its provenance, at
    /// `request.provenance_claim_id`, before the request is published. The
    /// engine builds the statement from the request
    /// ([`super::origin_publication_intent_claim`]); `repo.*` is engine-owned,
    /// so this is the one door that writes it.
    pub fn put_origin_publication_intent(&self, request: &OriginPublicationRequest) -> Result<()> {
        let body = super::origin_publication_intent_claim(request)?;
        self.with_write_txn_grouped(|wtxn| {
            // An erased intent is never named again (FIX 3877).
            let id = &request.provenance_claim_id;
            crate::origin::actor_erase::refuse_renaming_in_txn(self, wtxn, id, &body)?;
            self.put_reserved_claim_in_txn(
                wtxn,
                &request.provenance_claim_id,
                &body,
                request.occurred,
                request.learned_at,
            )
        })
    }

    /// Runs the whole publication protocol for one ref advance.
    ///
    /// An identical replay is idempotent: the publication id is derived from
    /// the advance itself, so a second call addresses the same row and writes
    /// no second claim.
    ///
    /// Terminal refusals never retry. Published replay uses the original CAS
    /// expectation and proves the live ref again before reporting success.
    /// The same move under another source resolves to the publication that
    /// made it when the ref carries its value (observed, never re-run), and
    /// is refused, naming them, when it needs objects that publication never
    /// certified.
    pub fn publish_origin_ref(
        &self,
        git: &GitWire<'_>,
        request: OriginPublicationRequest,
    ) -> Result<OriginPublicationReceipt> {
        validate_origin_publication_request(&request)?;
        self.validate_origin_repo(request.repo_id, &request.repo)?;
        let _guard = lock_repository(request.repo.common_dir())?;
        let publication_id = origin_publication_id(&request)?;
        self.require_origin_authority(&request.repo, publication_id)?;
        let existing = self.origin_publication(publication_id)?;
        if existing.as_ref().is_some_and(|record| {
            record.repo_id != request.repo_id
                || record.actor_id != request.actor_id
                || record.required_objects != request.required_objects
                || record.required_lfs_oids != request.required_lfs_oids
        }) {
            return Err(Error::InvariantViolation(
                "origin publication replay changed its availability or attribution",
            ));
        }
        let record = match existing {
            Some(record) if record.status == OriginPublicationStatus::Published => {
                return self.redrive_published_origin_ref(
                    git,
                    &request.repo,
                    record,
                    request.learned_at,
                );
            }
            Some(record) if record.status.is_terminal() => {
                return origin_receipt(record, false, None);
            }
            Some(record) => record,
            None => match self.admit_origin_publication(git, &request, publication_id)? {
                OriginAdmission::Staged(record) => record,
                OriginAdmission::Resolved(owner) => {
                    let mut receipt = origin_receipt(owner, true, None)?;
                    receipt.answer = OriginPublicationAnswer::ResolvedToOwner;
                    return Ok(receipt);
                }
            },
        };
        if record.status.is_terminal() {
            return origin_receipt(record, false, None);
        }
        let advance = self.advance_prepared_origin_publication(
            git,
            &request.repo,
            record,
            request.learned_at,
        )?;
        if advance.record.status == OriginPublicationStatus::Prepared {
            return Err(Error::ConcurrentWrite(
                "origin publication awaits readable objects",
            ));
        }
        origin_receipt(advance.record, advance.already_applied, advance.wire)
    }

    /// The post-crash census: exactly one durable disposition per partial
    /// state, and a leak sweep for the rows that already reached a terminal
    /// one.
    pub fn reconcile_origin_publications(
        &self,
        git: &GitWire<'_>,
        repo_id: EntityId,
        repo: &GitWireRepo,
        learned_at: u64,
    ) -> Result<OriginCensusReport> {
        self.validate_origin_repo(repo_id, repo)?;
        let _guard = lock_repository(repo.common_dir())?;
        self.reconcile_receive_pack_operations(repo.repo_root())?;
        let mut items = Vec::new();
        for publication_id in self.origin_publication_ids(Some(repo_id))? {
            let Some(record) = self.origin_publication(publication_id)? else {
                continue;
            };
            let disposition = if record.status == OriginPublicationStatus::Prepared {
                self.advance_prepared_origin_publication(git, repo, record, learned_at)?
                    .disposition
            } else {
                // Terminal already. The only thing left to do is the leak
                // sweep, and sweeping is not a state change.
                self.release_origin_publication_pin(git, repo, &record, learned_at)?;
                OriginCensusDisposition::NoChange
            };
            items.push((publication_id, disposition));
        }
        // The walk above reads origin rows only. A ref effect an earlier
        // attempt left prepared (a re-drive of a Published row, a staged or
        // batched publish) is its own GitWire row: finish it here too.
        git.recover_ref_effects(repo, learned_at)?;
        self.sweep_orphan_origin_publication_owners(git, repo_id, repo, learned_at)?;
        Ok(OriginCensusReport { items })
    }

    /// The durable record for one publication id.
    pub fn origin_publication(
        &self,
        publication_id: EntityId,
    ) -> Result<Option<OriginPublicationRecord>> {
        let rtxn = self.store.env.read_txn()?;
        self.origin_publication_in_txn(&rtxn, publication_id)
    }

    /// Reads a publication in the transaction that validates a checkout teardown.
    pub(crate) fn origin_publication_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        publication_id: EntityId,
    ) -> Result<Option<OriginPublicationRecord>> {
        let Some(row) = PUBLICATIONS.get(&self.store, txn, &publication_id)? else {
            return Ok(None);
        };
        row.into_record().map(Some)
    }

    /// Lists durable publication ids for read-only diagnostics, in every status.
    ///
    /// `None` includes every repository. The list is whole: the scan never
    /// refuses for its length, and past its threshold row it raises an
    /// [`ScanCheck`](crate::scan_check::ScanCheck).
    /// Use [`Vault::origin_publication`] to inspect a record. This list is not
    /// advertisement authority; only [`Vault::published_origin_refs`] proves
    /// that a ref may be served.
    pub fn origin_publication_ids(&self, repo_id: Option<EntityId>) -> Result<Vec<EntityId>> {
        let mut ids = Vec::new();
        self.visit_origin_publication_rows(repo_id, |record| {
            ids.push(record.publication_id);
            ControlFlow::Continue(())
        })?;
        Ok(ids)
    }

    /// THE advertisement projection, and the only one.
    ///
    /// A row survives here when its publication is `Published` AND the
    /// repository's live ref still carries exactly `new_oid`. Raw repository
    /// refs are never consulted as an authority: they are consulted only to
    /// DISPROVE a row this journal already claims. That asymmetry is the whole
    /// invariant — an unpublished ref cannot appear by existing, and a
    /// published one disappears the moment the repository disagrees.
    pub fn published_origin_refs(
        &self,
        git: &GitWire<'_>,
        repo_id: EntityId,
        repo: &GitWireRepo,
    ) -> Result<Vec<(GitRefName, GitOid)>> {
        self.validate_origin_repo(repo_id, repo)?;
        let _guard = lock_repository(repo.common_dir())?;
        self.project_published_origin_refs(git, repo_id, repo)
    }

    /// [`Vault::published_origin_refs`] for a reader that may not wait on the
    /// repository coordinator: it projects under the coordinator when it finds
    /// it free, and without it while a writer holds it.
    ///
    /// Without the coordinator the projection can only hide more, never show
    /// more. `Published` is terminal, a row's `Published` mark and its visible
    /// slot land in one transaction, and the live ref only disproves a row. So
    /// a projection overlapping a landing may hide that landing's ref until it
    /// is finalized, and can never advertise a ref/OID pair no publication
    /// claims.
    pub(crate) fn published_origin_refs_without_waiting(
        &self,
        git: &GitWire<'_>,
        repo_id: EntityId,
        repo: &GitWireRepo,
    ) -> Result<Vec<(GitRefName, GitOid)>> {
        self.validate_origin_repo(repo_id, repo)?;
        let _free = try_lock_repository(repo.common_dir())?;
        self.project_published_origin_refs(git, repo_id, repo)
    }

    fn project_published_origin_refs(
        &self,
        git: &GitWire<'_>,
        repo_id: EntityId,
        repo: &GitWireRepo,
    ) -> Result<Vec<(GitRefName, GitOid)>> {
        let mut advertised = Vec::new();
        for publication_id in self.origin_visible_ref_rows(&repo_id)? {
            let Some(record) = self.origin_publication(publication_id)? else {
                continue;
            };
            if record.repo_id != repo_id || record.status != OriginPublicationStatus::Published {
                continue;
            }
            if git.read_ref(repo, &record.ref_name)?.as_ref() != Some(&record.new_oid)
                || self
                    .origin_availability_failure(git, repo, &record)?
                    .is_some()
            {
                continue;
            }
            advertised.push((record.ref_name, record.new_oid));
        }
        advertised.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(advertised)
    }

    /// How many publications for one repository are still `Prepared`.
    pub fn prepared_origin_publication_count(&self, repo_id: EntityId) -> Result<u64> {
        let mut prepared = 0_u64;
        self.visit_origin_publication_rows(Some(repo_id), |record| {
            if record.status == OriginPublicationStatus::Prepared {
                prepared = prepared.saturating_add(1);
            }
            ControlFlow::Continue(())
        })?;
        Ok(prepared)
    }
}
