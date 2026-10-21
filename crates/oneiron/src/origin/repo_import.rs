//! The owner's import of one admitted commit of a served repository (FIX
//! 6869, G4 PR1; `vault.code.import`).
//!
//! Nothing here receives, lands or copies objects. The owner first
//! registers the served repository and pushes the chosen history with stock
//! Git through the authenticated door; this import then names that push's
//! Published receive-pack publication and an exact chosen commit, the tip it
//! admitted or an ancestor of it. Under the repository writer it proves that
//! admission from the publication's own stored values, the chosen commit's
//! complete graph and its tree; captures the complete tree through the one
//! inventory; imports it through the shared checked snapshot writer; pins
//! the commit with every ancestor; and writes the compact, deterministic
//! `repo.import_manifest` claim. The owner, the anchor, the source and the
//! snapshot's custody are judged again in each final writer. A submodule
//! link or a withheld file refuses by name: an incomplete tree never calls
//! itself an import. A crash may leave a pin, a snapshot or an anchor, each
//! safe; never a manifest that was not proved, and never an approval.
use std::collections::BTreeMap;

use crate::code_revision::{
    CodeImportAnchor, CodeImportManifest, CodeTreeBlob, CodeTreeInventory, MODE_GITLINK,
    import_snapshot_custody_in_txn, manifest_digest, manifest_id,
};
use crate::codebase::RepoRef;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeKind;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitRefName, GitWire, GitWireRepo, lock_repository};
use crate::origin::publication::{
    OriginKeepRefKind, OriginPublicationRecord, OriginPublicationRequest, OriginPublicationStatus,
};
use crate::ports::EdgeStoreRead;
use crate::registry::ENTITY_TYPE_CODE_ARTIFACT;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{TimeRange, Vault};

/// What an owner names to import: the served repository, the PROJECT its
/// anchor belongs to, the admitted ref, the exact chosen commit and the
/// publication that admitted it.
pub(crate) struct ServedImportSource<'a> {
    pub(crate) repo: &'a str,
    pub(crate) project: EntityId,
    pub(crate) source_ref: &'a GitRefName,
    pub(crate) source_commit: &'a GitOid,
    pub(crate) admission_receipt: EntityId,
}

/// What an import proved and wrote: the manifest and the complete
/// inventory it binds.
pub(crate) struct ImportedCodeRepo {
    pub(crate) manifest_ref: EntityId,
    pub(crate) manifest: CodeImportManifest,
    pub(crate) blobs: BTreeMap<String, CodeTreeBlob>,
}

fn refused(detail: &str) -> Error {
    Error::Refused(detail.to_owned())
}

impl Vault {
    /// Imports `source`'s chosen commit as the live owner `owner` and
    /// writes its manifest; an identical repeat answers the same manifest.
    ///
    /// # Errors
    /// An owner refusal, an unadmitted or incomplete source, a submodule
    /// link, a withheld file, a manifest id holding another body, or a
    /// store or object store failure.
    pub(crate) fn import_served_code_repo(
        &self,
        owner: &AuthenticatedOwner,
        source: &ServedImportSource<'_>,
    ) -> Result<ImportedCodeRepo> {
        let anchor = self.bind_served_repo_anchor(owner, source.repo, source.project)?;
        let dir = crate::origin::smart_http::origin_repo_dir(self, source.repo)?;
        let git = GitWire::new(self)?;
        let repo = git.open_repo(
            RepoRef::LocalFolder {
                path: dir.to_string_lossy().into_owned(),
                commit: source.source_commit.as_str().to_owned(),
            },
            &dir,
        )?;
        let _guard = lock_repository(repo.common_dir())?;
        let (record, tree) = self.require_admitted_import_source(&git, &repo, source)?;
        let inventory =
            CodeTreeInventory::capture_pinned(self, &git, &repo, source.source_commit, &tree)?;
        let blobs = inventory.blobs().clone();
        let gitlinks: Vec<&str> = blobs
            .iter()
            .filter(|(_, blob)| blob.mode == MODE_GITLINK)
            .map(|(path, _)| path.as_str())
            .collect();
        if !gitlinks.is_empty() {
            return Err(Error::Refused(format!(
                "held_unsupported_tree: the chosen tree holds submodule links the import does \
                 not admit: {}",
                gitlinks.join(", ")
            )));
        }
        let now = self.store.clock.now_recorded_at();
        let imported = self
            .ingest_served_repo_as_owner(
                source.project.to_hex(),
                &dir,
                source.source_commit.as_str(),
                (
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                ),
                |txn| {
                    owner.revalidate_in_txn(self, txn)?;
                    self.import_source_still_admitted_in_txn(txn, anchor.repo, source, &record)
                },
            )?
            .map_err(Error::Refused)?;
        let complete = imported.snapshot.files.len() == blobs.len()
            && imported.snapshot.files.iter().all(|entry| {
                blobs.get(&entry.path).is_some_and(|blob| {
                    blob.content_hash == entry.content_hash
                        && blob.size_bytes == entry.size_bytes
                        && blob.mode == entry.mode
                })
            });
        if !complete {
            return Err(Error::Refused(format!(
                "custody withholds {} of the chosen tree's {} files: the import is not complete",
                blobs.len().saturating_sub(imported.snapshot.files.len()),
                blobs.len()
            )));
        }
        let anchor_value = CodeImportAnchor {
            repo: anchor.repo,
            project: source.project,
            served_repo: source.repo.to_owned(),
            object_store: repo.identity().as_hex(),
            source_ref: source.source_ref.as_str().to_owned(),
            source_commit: source.source_commit.as_str().to_owned(),
            source_tree: tree.as_str().to_owned(),
            admission_receipt: source.admission_receipt,
            receive_provenance: record.provenance_claim_id,
            snapshot: imported.code_artifact_id,
            snapshot_fork_hash: bytes_to_hex_lower(&imported.snapshot.fork_hash),
        };
        let digest = manifest_digest(&anchor_value, &blobs);
        let manifest_ref = manifest_id(&digest)?;
        let manifest = CodeImportManifest {
            schema_version: 1,
            anchor: anchor_value,
            inventory_digest: bytes_to_hex_lower(&CodeTreeInventory::blob_digest(&blobs)),
            digest,
        };
        // Physical first: the chosen commit and every ancestor are kept
        // before any claim names them.
        self.pin_origin_object(
            &git,
            &repo,
            OriginKeepRefKind::Snapshot,
            &manifest_ref.to_hex(),
            source.source_commit,
            now,
        )?;
        let body = manifest.claim_body()?;
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            self.import_source_still_admitted_in_txn(txn, anchor.repo, source, &record)?
                .map_err(Error::Refused)?;
            import_snapshot_custody_in_txn(self, txn, &manifest)?.map_err(Error::Refused)?;
            match self.get_claim_in_txn(txn, &manifest_ref)? {
                Some(stored) if CodeImportManifest::from_claim(&stored)? == manifest => Ok(()),
                Some(_) => Err(Error::CorruptedIndex(
                    "an import manifest id holds another body",
                )),
                None if self.get_raw_in(txn, &manifest_ref)?.is_some() => Err(
                    Error::CorruptedIndex("an import manifest id holds another record"),
                ),
                None => self.put_reserved_claim_in_txn(
                    txn,
                    &manifest_ref,
                    &body,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                ),
            }
        })?;
        Ok(ImportedCodeRepo {
            manifest_ref,
            manifest,
            blobs,
        })
    }

    /// The admitted source `source` names, judged under the repository
    /// writer: a Published receive-pack publication of this store and ref,
    /// by a pusher who is not erased, re-validated from its own stored
    /// values as the publication door validated it; the chosen commit that
    /// tip or its ancestor, with its complete graph present. Answers the
    /// publication and the chosen commit's tree. An export intent or a
    /// generic claim is no push admission.
    ///
    /// # Errors
    /// A refusal naming what is not admitted, or a store failure.
    pub(crate) fn require_admitted_import_source(
        &self,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        source: &ServedImportSource<'_>,
    ) -> Result<(OriginPublicationRecord, GitOid)> {
        self.require_admitted_push(
            git,
            repo,
            source.admission_receipt,
            source.source_ref,
            source.source_commit,
        )
    }

    /// [`Self::require_admitted_import_source`]'s one body over the bare
    /// admission, which an accepted push's candidate shares (G4 PR2): the
    /// Published receive-pack publication `admission_receipt` of `source_ref`
    /// in this store, and `chosen` its tip or an ancestor.
    ///
    /// # Errors
    /// As there.
    pub(crate) fn require_admitted_push(
        &self,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        admission_receipt: EntityId,
        source_ref: &GitRefName,
        chosen: &GitOid,
    ) -> Result<(OriginPublicationRecord, GitOid)> {
        let record = self
            .origin_publication(admission_receipt)?
            .ok_or_else(|| refused("the admission receipt is no publication of this vault"))?;
        let repo_id = crate::origin::lfs::lfs_repo_id(&repo.identity().as_hex())?;
        if record.status != OriginPublicationStatus::Published
            || record.repo_id != repo_id
            || record.ref_name != *source_ref
        {
            return Err(refused(
                "the admission receipt is no Published publication of this served ref",
            ));
        }
        let actor = record
            .actor_id
            .id()
            .ok_or_else(|| refused("the admitted push's pusher was erased"))?;
        if !self.has_receive_pack_evidence(record.provenance_claim_id)? {
            return Err(refused(
                "the admission receipt is not a receive-pack push's publication",
            ));
        }
        self.validate_receive_pack_publication(&OriginPublicationRequest {
            repo_id,
            repo: repo.clone(),
            ref_name: record.ref_name.clone(),
            expected_old_oid: record.expected_old_oid.clone(),
            new_oid: record.new_oid.clone(),
            required_objects: record.required_objects.clone(),
            required_lfs_oids: record.required_lfs_oids.clone(),
            provenance_claim_id: record.provenance_claim_id,
            actor_id: actor,
            occurred: record.occurred,
            learned_at: record.created_at,
        })?;
        if *chosen != record.new_oid
            && !git
                .merge_base(repo, chosen.as_str(), record.new_oid.as_str())
                .is_ok_and(|base| base == *chosen)
        {
            return Err(refused(
                "the chosen commit is neither the admitted tip nor its ancestor",
            ));
        }
        if !git.reachable_objects_present(repo, chosen, &[])? {
            return Err(refused("the chosen commit's history is not complete"));
        }
        let tree = git
            .commit_trees(repo, std::slice::from_ref(chosen))?
            .remove(chosen)
            .ok_or_else(|| refused("the chosen commit has no tree in this store"))?;
        Ok((record, tree))
    }

    /// The anchor still a live CODE_ARTIFACT of its PROJECT, and the
    /// admission still the same Published publication, in `txn`.
    /// `Ok(Err(_))` names what moved; a store failure stays an error.
    fn import_source_still_admitted_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        anchor: EntityId,
        source: &ServedImportSource<'_>,
        record: &OriginPublicationRecord,
    ) -> Result<std::result::Result<(), String>> {
        let live = matches!(
            live_entity_row_in_txn(&self.store, txn, &anchor)?,
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_CODE_ARTIFACT,
                ..
            }
        );
        let belongs = self
            .store
            .port_edge_get(txn, &anchor, EdgeKind::BelongsTo, &source.project)?
            .is_some();
        let published = self
            .origin_publication_in_txn(txn, source.admission_receipt)?
            .is_some_and(|now| {
                now.status == OriginPublicationStatus::Published
                    && now.new_oid == record.new_oid
                    && now.provenance_claim_id == record.provenance_claim_id
            });
        Ok(if live && belongs && published {
            Ok(())
        } else {
            Err(
                "the served anchor, its project or the admitted push moved during the import"
                    .to_owned(),
            )
        })
    }
}
