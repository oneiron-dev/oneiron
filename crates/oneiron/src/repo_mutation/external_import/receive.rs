//! Where an outside import meets the door's own records (FIX 6871): its
//! exact base, resolved by the candidate matcher's one resolver before any
//! network effect, and the receive each send landed as, found among the
//! retained received refs and proved by the shared admitted-push check.
//!
//! Neither a shell exit, a source claim, an admission-only claim nor a
//! current ref proves a send: only a Published receive-pack publication of
//! exactly this store, ref, old and new tip by this importer does. Nothing
//! here matches, enqueues or promotes; the queue's one drain takes the
//! accepted ref from there.

use crate::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitRefName, GitWire, GitWireRepo, lock_repository};
use crate::merge_queue::MergeQueue;
use crate::Vault;

/// One exact ref update an import sends: `old` absent for the seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImportRefUpdate {
    pub(crate) name: GitRefName,
    pub(crate) old: Option<GitOid>,
    pub(crate) new: GitOid,
}

/// The door receive one update landed as: its receive-pack provenance and
/// its Published publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ImportReceive {
    pub(crate) provenance: EntityId,
    pub(crate) publication: EntityId,
}

impl Vault {
    /// Whether `base_revision` is the ONE tested revision of this store the
    /// commit `base` names exactly, as the candidate matcher resolves an
    /// accepted push's old tip: `Ok(())`, or the hold's reason code. A pure
    /// read before any fetch; never the current head, a text match or the
    /// request's own claim.
    ///
    /// # Errors
    /// A store or object store failure.
    pub(crate) fn external_import_base(
        &self,
        wire: &GitWire<'_>,
        repo: &GitWireRepo,
        base_revision: EntityId,
        base: &GitOid,
    ) -> Result<std::result::Result<(), String>> {
        let kinds = wire.object_info(repo, std::slice::from_ref(base))?;
        if kinds.get(base).map(String::as_str) != Some("commit") {
            return Ok(Err("base_commit_not_in_store".to_owned()));
        }
        let Ok(queue) = MergeQueue::open(self, repo.repo_ref().clone()) else {
            return Ok(Err("base_queue_unreadable".to_owned()));
        };
        let Some(candidates) = queue.candidate_queue()? else {
            return Ok(Err("base_queue_not_driven".to_owned()));
        };
        Ok(
            match self.exact_push_base_revision(wire, repo, &candidates, base)? {
                Ok(found) if found == base_revision => Ok(()),
                Ok(_) => Err("base_revision_differs".to_owned()),
                Err(reason) => Err(reason),
            },
        )
    }

    /// The retained receive of exactly `update` in the object store
    /// `store` whose publication is Published and names `importer` as its
    /// pusher (`None`: an erased pusher, for an erased importer's source).
    /// A pure read over the door's records, oldest provenance first.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn received_import_update(
        &self,
        store: &str,
        update: &ImportRefUpdate,
        importer: Option<EntityId>,
    ) -> Result<Option<ImportReceive>> {
        for (provenance, row) in self.received_code_ingress_rows(store)? {
            if row.source.ref_name != update.name.as_str()
                || row.source.old_oid.as_deref() != update.old.as_ref().map(GitOid::as_str)
                || row.source.new_oid.as_deref() != Some(update.new.as_str())
            {
                continue;
            }
            let Some((publication, true)) = self.received_ref_publication(provenance, &row)?
            else {
                continue;
            };
            let Some(record) = self.origin_publication(publication)? else {
                continue;
            };
            if record.expected_old_oid.as_ref() == update.old.as_ref()
                && record.actor_id.id() == importer
            {
                return Ok(Some(ImportReceive {
                    provenance,
                    publication,
                }));
            }
        }
        Ok(None)
    }

    /// [`Self::received_import_update`] for a live send, proved under the
    /// repository writer by the shared admitted-push check: the
    /// publication's own stored values validated as the door validated
    /// them, from a receive-pack, with the new tip's graph complete.
    ///
    /// # Errors
    /// A store or object store failure. An unproved send is `None`.
    pub(crate) fn proved_import_update(
        &self,
        wire: &GitWire<'_>,
        repo: &GitWireRepo,
        update: &ImportRefUpdate,
        importer: EntityId,
    ) -> Result<Option<ImportReceive>> {
        let _guard = lock_repository(repo.common_dir())?;
        let store = repo.identity().as_hex();
        let Some(found) = self.received_import_update(&store, update, Some(importer))? else {
            return Ok(None);
        };
        match self.require_admitted_push(wire, repo, found.publication, &update.name, &update.new) {
            Ok((record, _)) if record.actor_id.id() == Some(importer) => Ok(Some(found)),
            Ok(_) | Err(Error::Refused(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }
}
