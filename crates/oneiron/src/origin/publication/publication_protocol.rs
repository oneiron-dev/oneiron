//! Public protocol surface: pin/unpin, publish_origin_ref, reconcile census driver, reads and advertisement projection.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitRefName, GitWire, GitWireRepo, lock_repository};

use super::publication_codec::{
    decode_publication_row, keep_owner_key, origin_keep_ref_name, origin_publication_id,
    publication_key,
};
use super::publication_journal::{origin_receipt, validate_origin_publication_request};
use super::publication_types::{
    OriginCensusDisposition, OriginCensusReport, OriginKeepRefKind, OriginPublicationReceipt,
    OriginPublicationRecord, OriginPublicationRequest, OriginPublicationStatus,
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
        self.with_write_txn(|wtxn| {
            self.store
                .vault_meta
                .put(wtxn, &key, &learned_at.to_le_bytes())?;
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
        self.with_write_txn(|wtxn| {
            self.store.vault_meta.delete(wtxn, &key)?;
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

    /// Runs the whole publication protocol for one ref advance.
    ///
    /// An identical replay is idempotent: the publication id is derived from
    /// the advance itself, so a second call addresses the same row and writes
    /// no second claim.
    ///
    /// Terminal refusals never retry. Published replay uses the original CAS
    /// expectation and proves the live ref again before reporting success.
    pub fn publish_origin_ref(
        &self,
        git: &GitWire<'_>,
        request: OriginPublicationRequest,
    ) -> Result<OriginPublicationReceipt> {
        validate_origin_publication_request(&request)?;
        self.validate_origin_repo(request.repo_id, &request.repo)?;
        let _guard = lock_repository(request.repo.common_dir())?;
        let publication_id = origin_publication_id(&request)?;
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
            None => self.stage_origin_publication(git, &request, publication_id)?,
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
        for record in self.origin_publication_rows(Some(repo_id))? {
            let publication_id = record.publication_id;
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
        self.sweep_orphan_origin_publication_owners(git, repo_id, repo, learned_at)?;
        Ok(OriginCensusReport { items })
    }

    /// The durable record for one publication id.
    pub fn origin_publication(
        &self,
        publication_id: EntityId,
    ) -> Result<Option<OriginPublicationRecord>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self
            .store
            .vault_meta
            .get(&rtxn, &publication_key(&publication_id))?
        else {
            return Ok(None);
        };
        decode_publication_row(&raw).map(Some)
    }

    /// Lists durable publication ids for read-only diagnostics, in every status.
    ///
    /// `None` includes every repository. The scan refuses after
    /// [`ORIGIN_PUBLICATION_MAX_ROWS`] rows rather than returning a partial list.
    /// Use [`Vault::origin_publication`] to inspect a record. This list is not
    /// advertisement authority; only [`Vault::published_origin_refs`] proves
    /// that a ref may be served.
    pub fn origin_publication_ids(&self, repo_id: Option<EntityId>) -> Result<Vec<EntityId>> {
        Ok(self
            .origin_publication_rows(repo_id)?
            .into_iter()
            .map(|record| record.publication_id)
            .collect())
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
        let prepared = self
            .origin_publication_rows(Some(repo_id))?
            .into_iter()
            .filter(|record| record.status == OriginPublicationStatus::Prepared)
            .count();
        u64::try_from(prepared)
            .map_err(|_| Error::ArithmeticOverflow("prepared origin publication count"))
    }
}
