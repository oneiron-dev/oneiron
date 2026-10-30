//! A push received into a masked copy's private ingress, matched as the
//! canonical store's candidate (FIX 7608 slice 2b-ii-B2, ASK E, KEEP 3).
//!
//! The row's ingress store names its copy and canonical store through its
//! own record, and the receive's ingress proof stands under that copy. The
//! push is proved on the ingress exactly as an ordinary push is on its
//! store (Published publication, admitted push, fast-forward, source
//! operations against the COPY trees). Its old COPY tip maps back to ONE
//! ORIGINAL by the copy's object records (FIX 9235: every occurrence, never
//! a newest or equal guess), and CALL L resolves the canonical base from
//! that ORIGINAL only. Each changed file is translated onto its ORIGINAL
//! (VisibleDiff): a clean file takes the submitted bytes, a masked file
//! the uniquely mapped visible edit, an edited sealed placeholder its
//! exact replacement held as `sealed_file_edited`; a file with no unique
//! mapping holds the whole candidate as `projection_edit_conflict` with no
//! canonical target and no proposal. The canonical target tree is written
//! into the canonical store from the ORIGINAL base tree; untouched files
//! keep their ORIGINAL entries. ONE all-files proposal carries the
//! translated files, under the vault's existing landing path.

use std::collections::BTreeMap;

use super::super::document_candidate_types::{
    CodePushCandidate, CodePushCandidateHold, CodePushCandidateState, ReceivedRefIngress,
    ResolvedCandidateFile, ResolvedPushCandidate,
};
use super::super::publication::OriginPublicationStatus;
use super::super::tree::read_tree_files;
use super::projected::RepoProjectedCandidatePins;
use super::projected_files::{
    ProjectedCanonicalAfter, ProjectedFileInput, prepare_projected_candidate_files,
};
use super::projected_join::ProjectedRowSource;
use super::projected_tree::{
    commit_tree, file_input, presence, rebuild_tree, tree_blob, write_blob,
};
use super::{CandidateQueue, MODE_GITLINK, PreparedPushCandidate, PushCandidateBase};
use crate::code_document::CodeFileMetadataEdit;
use crate::code_revision::{CodeRevisionFork, CodeTreeBlob, CodeTreeInventory};
use crate::codebase::entity_id_from_hash_material;
use crate::error::{Error, Result};
use crate::git_wire::{GitObjectKind, GitOid, GitWire, GitWireRepo};
use crate::origin::lfs::lfs_repo_id;
use crate::origin::secret_marks::{RepoBlobAddress, RepoMarkFacts, RepoSecretMarkLookup};
use crate::origin::secret_projection::REPO_OPAQUE_FILE_BYTES;
use crate::origin::secret_projection::claims::RepoProjectionClaim;
use crate::origin::secret_projection::clearance::RepoProjectionHoldCause;
use crate::origin::secret_projection::edit::RepoProjectedFileCopy;
use crate::origin::secret_projection::git::projection_ingress_dir;
use crate::repo_mutation::proposal::RepoProposedFile;
use crate::repo_mutation::{
    ReceivedFilesProposalInput, received_file_operation, received_proposal_id,
};
use crate::secret_custody::KeyPlaces;
use crate::{EntityId, Vault};

/// A projected decision: the prepared attachment, or a hold with the pins
/// it keeps (none when no translation was reached).
pub(super) type ProjectedDecision = std::result::Result<
    PreparedPushCandidate,
    (CodePushCandidateHold, Option<RepoProjectedCandidatePins>),
>;

fn held(state: CodePushCandidateState, reason: &str) -> Result<Option<ProjectedDecision>> {
    Ok(Some(Err((
        CodePushCandidateHold {
            state,
            reason: reason.to_owned(),
        },
        None,
    ))))
}

impl Vault {
    /// Decides one projected candidate: `None` while its publication is in
    /// flight, a typed hold (with its pins once translated), or the
    /// prepared attachment.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub(super) fn decide_projected_candidate(
        &self,
        wire: &GitWire<'_>,
        canonical: &GitWireRepo,
        queue: &CandidateQueue,
        provenance: EntityId,
        row: &ReceivedRefIngress,
        id: EntityId,
        digest: [u8; 32],
        projection: &ProjectedRowSource,
    ) -> Result<Option<ProjectedDecision>> {
        use CodePushCandidateState::{HeldBase, HeldPredecessor, HeldShape};
        let source = &row.source;
        let Some(new_hex) = &source.new_oid else {
            return held(HeldShape, "ref_deleted");
        };
        let Some(old_hex) = &source.old_oid else {
            return held(HeldBase, "no_old_tip");
        };
        let ingress_dir =
            projection_ingress_dir(self, projection.canonical_store, projection.graph)?;
        let Some(ingress) = wire.existing_projection_ingress(&ingress_dir)? else {
            return held(HeldShape, "ingress_missing");
        };
        if ingress.identity().as_hex() != source.object_store {
            return held(HeldShape, "ingress_missing");
        }
        let new = GitOid::parse_hex(new_hex.clone())?;
        let old = GitOid::parse_hex(old_hex.clone())?;
        let kinds = wire.object_info(&ingress, &[old.clone(), new.clone()])?;
        if kinds.get(&new).map(String::as_str) != Some("commit")
            || kinds.get(&old).map(String::as_str) != Some("commit")
        {
            return held(HeldShape, "not_a_commit");
        }
        let ingress_id = lfs_repo_id(&source.object_store)?;
        let Some(record) = self.find_origin_publication(ingress_id, |record| {
            record.provenance_claim_id == provenance
                && record.ref_name.as_str() == source.ref_name
                && record.new_oid == new
        })?
        else {
            return Ok(None);
        };
        match record.status {
            OriginPublicationStatus::Prepared => return Ok(None),
            OriginPublicationStatus::Published => {}
            OriginPublicationStatus::Failed | OriginPublicationStatus::Conflicted => {
                return held(HeldShape, "publication_not_published");
            }
        }
        let (record, new_tree) = match self.require_admitted_push(
            wire,
            &ingress,
            record.publication_id,
            &record.ref_name,
            &new,
        ) {
            Ok(admitted) => admitted,
            Err(Error::Refused(_)) => return held(HeldShape, "push_not_admitted"),
            Err(error) => return Err(error),
        };
        let Some(pusher) = record.actor_id.id() else {
            return held(HeldShape, "pusher_erased");
        };
        if row.operations.is_empty() {
            return held(HeldShape, "no_change");
        }
        if wire.merge_base(&ingress, old.as_str(), new.as_str())? != old {
            return held(HeldShape, "non_fast_forward");
        }
        // The ORIGINAL the copy's old tip stands for, by every occurrence
        // the copy recorded; several hold (FIX 9235). An old tip no copy
        // object is continues the agent's own earlier push into this copy:
        // its base is the seal that consumed that push, at the canonical
        // commit its tested revision pinned, and an unsealed one holds as
        // the ordinary path's does (FIX 10273, KEEP 5).
        let originals = {
            let txn = self.store.env.read_txn()?;
            RepoProjectionClaim::originals_of_copy_in_txn(
                self,
                &txn,
                &projection.graph,
                &old,
                GitObjectKind::Commit,
            )?
        };
        let (canonical_old, base) = match originals.as_slice() {
            // CALL L on the canonical store, from the ORIGINAL only.
            [canonical_old] => {
                match self.resolve_push_candidate_base(wire, canonical, queue, canonical_old)? {
                    Ok(base) => (canonical_old.clone(), base),
                    Err(hold) => return Ok(Some(Err((hold, None)))),
                }
            }
            [] => {
                match self.projected_predecessor_base(canonical, queue, projection.graph, &old)? {
                    Some(sealed) => sealed,
                    None if self.received_predecessor_pending(&source.object_store, &old)? => {
                        return held(HeldPredecessor, "predecessor_unsealed");
                    }
                    None => return held(HeldBase, "no_exact_base_or_ambiguous_base"),
                }
            }
            _ => return held(HeldBase, "no_exact_base_or_ambiguous_base"),
        };
        let canonical_old = &canonical_old;
        let tested = base
            .revision
            .tested_queue
            .as_ref()
            .ok_or(Error::InvariantViolation(
                "a resolved base is a tested revision",
            ))?;
        let original_tree = commit_tree(wire, canonical, canonical_old)?;
        let copy_tree = commit_tree(wire, &ingress, &old)?;
        let original_entries = CodeTreeInventory::entries(wire, canonical, &original_tree)?;
        let copy_entries = CodeTreeInventory::entries(wire, &ingress, &copy_tree)?;
        let new_entries = CodeTreeInventory::entries(wire, &ingress, &new_tree)?;
        let original_files = read_tree_files(wire, canonical, &original_tree)?;
        let copy_files = read_tree_files(wire, &ingress, &copy_tree)?;
        let new_files = read_tree_files(wire, &ingress, &new_tree)?;
        // The source operations are exactly the COPY trees' change, by the
        // ordinary validator (never canonical-before == copy-before).
        let changed: Vec<&str> = copy_entries
            .keys()
            .chain(new_entries.keys())
            .map(String::as_str)
            .filter(|path| copy_entries.get(*path) != new_entries.get(*path))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut operations = BTreeMap::new();
        for operation in &row.operations {
            if operations
                .insert(operation.path.as_str(), operation)
                .is_some()
            {
                return held(HeldShape, "source_operation_mismatch");
            }
        }
        if operations.keys().copied().ne(changed.iter().copied()) {
            return held(HeldShape, "source_operation_mismatch");
        }
        for (path, operation) in &operations {
            let before = tree_blob(&copy_entries, &copy_files, path);
            let after = tree_blob(&new_entries, &new_files, path);
            if !super::files::validate_received_operation(
                operation,
                before.as_ref(),
                after.as_ref(),
            ) {
                return held(HeldShape, "source_operation_mismatch");
            }
        }
        // Each changed file's copy, as its masked reader was given it.
        let facts = {
            let txn = self.store.env.read_txn()?;
            RepoMarkFacts::read_in_txn(self, &txn, RepoSecretMarkLookup::ReadableClaims)?
        };
        let mut places: BTreeMap<&str, (KeyPlaces, bool)> = BTreeMap::new();
        for path in &changed {
            let (Some((original_oid, _)), Some((copy_oid, _))) =
                (original_entries.get(*path), copy_entries.get(*path))
            else {
                continue;
            };
            if original_oid == copy_oid {
                continue;
            }
            let original_oid = GitOid::parse_hex(original_oid.clone())?;
            let bytes = original_files
                .get(*path)
                .map_or(&[][..], |file| file.content.as_slice());
            let marks = {
                let addressed = facts.for_blob(&RepoBlobAddress {
                    store: projection.canonical_store,
                    blob: original_oid,
                });
                if addressed.is_empty() {
                    facts.for_hash(blake3::hash(bytes).as_bytes())
                } else {
                    addressed
                }
            };
            let copy_bytes = copy_files
                .get(*path)
                .map_or(&[][..], |file| file.content.as_slice());
            let opaque = marks.opaque() || copy_bytes == REPO_OPAQUE_FILE_BYTES;
            // A copy that differs from its original with no mark behind it
            // now has no visible map: it conflicts, never guesses.
            if !opaque && marks.is_empty() {
                places.insert(*path, (KeyPlaces::new(), false));
                continue;
            }
            places.insert(*path, (marks.places(), opaque));
        }
        // Each masked file's ORIGINAL key bytes: the only secret its
        // translation carries back into the proposal (FIX 10276).
        let original_spans: BTreeMap<String, Vec<Vec<u8>>> = places
            .iter()
            .filter(|(_, (_, opaque))| !*opaque)
            .filter_map(|(path, (spans, _))| {
                let content = &original_files.get(*path)?.content;
                let keys: Vec<Vec<u8>> = spans
                    .iter()
                    .filter(|(member, _)| member.is_empty())
                    .flat_map(|(_, spans)| spans.iter())
                    .filter_map(|&(start, end)| {
                        let range = usize::try_from(start).ok()?..usize::try_from(end).ok()?;
                        content.get(range).map(<[u8]>::to_vec)
                    })
                    .collect();
                (!keys.is_empty()).then(|| ((*path).to_owned(), keys))
            })
            .collect();
        let mut inputs = Vec::with_capacity(changed.len());
        let mut unmapped = Vec::new();
        for path in &changed {
            let original = file_input(&original_entries, &original_files, path)?;
            let submitted = file_input(&new_entries, &new_files, path)?;
            let copy = match (places.get(path), copy_entries.get(*path)) {
                (Some((spans, opaque)), Some((copy_oid, _))) => {
                    let copy_oid = GitOid::parse_hex(copy_oid.clone())?;
                    if *opaque {
                        Some((copy_oid, RepoProjectedFileCopy::Opaque))
                    } else if spans.is_empty() {
                        unmapped.push((*path).to_owned());
                        None
                    } else {
                        let bytes = copy_files
                            .get(*path)
                            .map_or(&[][..], |file| file.content.as_slice());
                        Some((
                            copy_oid,
                            RepoProjectedFileCopy::Masked {
                                copy: bytes,
                                places: spans,
                            },
                        ))
                    }
                }
                _ => None,
            };
            inputs.push(ProjectedFileInput {
                path: (*path).to_owned(),
                original,
                copy,
                submitted,
            });
        }
        let mut translated = prepare_projected_candidate_files(inputs)?;
        for file in &mut translated {
            if unmapped.contains(&file.pin.path) {
                file.after =
                    ProjectedCanonicalAfter::Held(RepoProjectionHoldCause::ProjectionEditConflict);
                file.pin.cause = Some(RepoProjectionHoldCause::ProjectionEditConflict);
                file.pin.canonical_blob = None;
            }
        }
        let mut pins = RepoProjectedCandidatePins {
            graph: projection.graph,
            ingress: projection.ingress,
            submitted_old: Some(old.as_str().to_owned()),
            submitted_new: new.as_str().to_owned(),
            canonical_base: Some(canonical_old.as_str().to_owned()),
            canonical_target_tree: None,
            files: translated.iter().map(|file| file.pin.clone()).collect(),
        };
        let is_conflict = |file: &&super::projected_files::ProjectedCandidateFile| {
            file.after
                == ProjectedCanonicalAfter::Held(RepoProjectionHoldCause::ProjectionEditConflict)
        };
        // CALL GRANT-CONFLICT-REPLACEMENT (FIX 10271): a conflict file a
        // live grant covers for the push's recipient takes its exact
        // submitted bytes below, its cause kept for the live recheck.
        let granted = super::projected_reveal::granted_projected_conflicts(
            self,
            provenance,
            &projection.graph,
            translated
                .iter()
                .filter(is_conflict)
                .map(|file| (file.pin.path.as_str(), file.pin.original_blob.as_ref())),
        )?;
        let conflict = translated
            .iter()
            .filter(is_conflict)
            .any(|file| !granted.contains(&file.pin.path));
        if conflict {
            // No unique translation: the source and pins stay, with no
            // canonical target and no proposal (ASK E).
            let hold = super::projected::refresh_projected_candidate_hold(
                &pins,
                Some(RepoProjectionHoldCause::ProjectionEditConflict),
            )
            .ok_or(Error::InvariantViolation("a conflict holds"))?;
            return Ok(Some(Err((hold, Some(pins)))));
        }
        // Each file's canonical after-state: an edited sealed placeholder's
        // exact replacement is what the owner (or a reveal) settles.
        let now = self.now_recorded_at();
        let mut after_files: BTreeMap<String, Option<(Vec<u8>, u32)>> = BTreeMap::new();
        for file in &translated {
            let path = file.pin.path.as_str();
            let bytes = match &file.after {
                ProjectedCanonicalAfter::Bytes(bytes) => Some(bytes.clone()),
                ProjectedCanonicalAfter::Delete => None,
                ProjectedCanonicalAfter::KeepOriginal => original_files
                    .get(path)
                    .map(|original| original.content.clone()),
                ProjectedCanonicalAfter::Held(_) => new_files
                    .get(path)
                    .map(|submitted| submitted.content.clone()),
            };
            // Present at the submitted mode while the push keeps the path.
            let after = new_entries
                .get(path)
                .and_then(|(_, mode)| bytes.map(|bytes| (bytes, *mode)));
            after_files.insert(path.to_owned(), after);
        }
        let mut blob_ids: BTreeMap<String, Option<(GitOid, u32)>> = BTreeMap::new();
        for (path, after) in &after_files {
            let entry = match after {
                Some((bytes, mode)) => Some((write_blob(wire, canonical, bytes, now)?, *mode)),
                None => None,
            };
            blob_ids.insert(path.clone(), entry);
        }
        let target = rebuild_tree(wire, canonical, Some(&original_tree), &blob_ids, now, true)?
            .ok_or(Error::InvariantViolation(
                "a canonical target tree is written",
            ))?;
        pins.canonical_target_tree = Some(target.as_str().to_owned());
        for pin in &mut pins.files {
            pin.canonical_blob = blob_ids
                .get(&pin.path)
                .and_then(|entry| entry.as_ref())
                .map(|(oid, _)| oid.as_str().to_owned());
        }
        // The proposal's canonical files: ORIGINAL before, translated after.
        let proposal = received_proposal_id(id)?;
        let mut files = Vec::with_capacity(after_files.len());
        for (path, after) in &after_files {
            let operation = operations
                .get(path.as_str())
                .ok_or(Error::InvariantViolation(
                    "a translated file has its operation",
                ))?;
            let before = tree_blob(&original_entries, &original_files, path);
            let after_blob = match (after, blob_ids.get(path).and_then(|entry| entry.as_ref())) {
                (Some((bytes, mode)), Some((oid, _))) => Some(CodeTreeBlob {
                    git_oid: oid.as_str().to_owned(),
                    content_hash: *blake3::hash(bytes).as_bytes(),
                    size_bytes: bytes.len() as u64,
                    mode: *mode,
                }),
                _ => None,
            };
            if before
                .iter()
                .chain(after_blob.iter())
                .any(|blob| blob.mode == MODE_GITLINK)
            {
                return held_with(HeldShape, "submodule_entry", pins);
            }
            let before_bytes = original_files.get(path).map(|file| file.content.clone());
            if before_bytes
                .iter()
                .chain(after.iter().map(|(bytes, _)| bytes))
                .any(|bytes| std::str::from_utf8(bytes).is_err())
            {
                return held_with(HeldShape, "binary_entry", pins);
            }
            let metadata_edit = CodeFileMetadataEdit::between(
                path,
                presence(before.as_ref()),
                presence(after_blob.as_ref()),
            );
            if metadata_edit.expected.validate().is_err()
                || metadata_edit.replacement.validate().is_err()
            {
                return held_with(HeldShape, "unsupported_mode", pins);
            }
            let base_frontier = base
                .revision
                .file_frontiers
                .values()
                .find(|frontier| frontier.path == *path)
                .cloned();
            let source_operation = EntityId::from_hex(&operation.operation_id)?;
            let document_operation = if after_blob.is_some() || base_frontier.is_some() {
                Some(received_file_operation(proposal, source_operation)?)
            } else {
                None
            };
            files.push((
                ResolvedCandidateFile {
                    source_operation,
                    path: path.clone(),
                    before,
                    after: after_blob,
                    base_frontier,
                    metadata_edit,
                    document_operation,
                },
                after.as_ref().map(|(bytes, _)| bytes.clone()),
            ));
        }
        let fork_session = entity_id_from_hash_material(
            b"oneiron:push-candidate-session:v1",
            &[id.as_bytes(), base.revision.revision_id.as_bytes()],
        )?;
        let message = format!(
            "Received push to {} from a masked copy: {}..{}",
            source.ref_name,
            &old.as_str()[..12],
            &new.as_str()[..12]
        );
        let input = ReceivedFilesProposalInput {
            candidate: id,
            proposal,
            folder: queue.folder.clone(),
            base_commit: GitOid::parse_hex(tested.commit.clone())?,
            pusher,
            session: fork_session,
            provenance,
            message,
            files: files
                .iter()
                .map(|file| RepoProposedFile {
                    path: file.0.path.clone(),
                    content: file.1.clone(),
                    source_operation: Some(file.0.source_operation),
                    metadata_edit: Some(file.0.metadata_edit.clone()),
                    withheld_base_blake3: None,
                })
                .collect(),
            created_at: row.received_at,
            original_spans,
        };
        let prepared = match self.prepare_received_files_proposal(canonical, input)? {
            Ok(prepared) => prepared,
            Err(reason) => return held_with(HeldShape, reason, pins),
        };
        let hold = super::projected::refresh_projected_candidate_hold(&pins, pins.hold_cause());
        Ok(Some(Ok(PreparedPushCandidate {
            candidate: CodePushCandidate {
                candidate: id,
                source_digest: digest,
                resolved: Some(ResolvedPushCandidate {
                    base_revision: base.revision.revision_id,
                    base_commit: tested.commit.clone(),
                    base_inventory_digest: tested.inventory_digest,
                    snapshot_anchor: base.anchor,
                    publication: record.publication_id,
                    new_tree: new_tree.as_str().to_owned(),
                    fork_session,
                    proposal_id: proposal,
                    resolved_at: row.received_at,
                    files: files.into_iter().map(|file| file.0).collect(),
                }),
                hold,
                projected: Some(pins),
            },
            fork: CodeRevisionFork::new(
                fork_session,
                base.revision.session_id,
                base.revision.revision_id,
                row.received_at,
            ),
            proposal: prepared,
        })))
    }
}

impl Vault {
    /// The seal that consumed the agent's earlier push into the copy
    /// `graph` whose COPY tip is `old` (FIX 10273, KEEP 5): the tested
    /// revision of the canonical store `canonical` on the queue's green
    /// chain whose complete link names it, with the canonical commit that
    /// revision pinned. `None` when no sealed revision consumed it.
    ///
    /// # Errors
    /// A store failure, or a pinned commit that is no object id.
    fn projected_predecessor_base(
        &self,
        canonical: &GitWireRepo,
        queue: &CandidateQueue,
        graph: EntityId,
        old: &GitOid,
    ) -> Result<Option<(GitOid, PushCandidateBase)>> {
        let store = canonical.identity().as_hex();
        let mut seen = std::collections::BTreeSet::new();
        let mut next = queue.green.clone();
        while let Some(revision) = next {
            if !seen.insert(revision.revision_id) {
                break;
            }
            if let Some(tested) = &revision.tested_queue
                && tested.store == store
                && tested.received_pushes.iter().any(|link| {
                    link.new_commit == old.as_str()
                        && link
                            .projection
                            .as_ref()
                            .is_some_and(|projected| projected.graph == graph)
                })
            {
                let commit = GitOid::parse_hex(tested.commit.clone())?;
                let anchor = self
                    .resolve_code_revision_import_anchor(revision.revision_id)?
                    .map(|manifest| crate::code_revision::manifest_id(&manifest.digest))
                    .transpose()?;
                return Ok(Some((commit, PushCandidateBase { revision, anchor })));
            }
            next = match revision.parent_revision_id {
                Some(parent) => self.get_code_revision(&parent)?,
                None => None,
            };
        }
        Ok(None)
    }
}

fn held_with(
    state: CodePushCandidateState,
    reason: &str,
    pins: RepoProjectedCandidatePins,
) -> Result<Option<ProjectedDecision>> {
    Ok(Some(Err((
        CodePushCandidateHold {
            state,
            reason: reason.to_owned(),
        },
        Some(pins),
    ))))
}
