//! The exact export preview (FIX 6869, G4 PR3): what `vault.code.export`
//! would write for one explicit sealed revision against one explicit ref
//! expectation, complete, or the blockers that stop it.
//!
//! It composes the export's own reads and nothing else: the shared load
//! (`export_input`) under the repository lock, the ONE materializer and
//! the pinned capture of the checked tree for the target, and the same
//! pinned capture of the expected commit for the base. It writes no
//! object, tree, map, keep-ref, promotion or publication, and no ordinary
//! export path reads it. A missing, withheld, unreviewed or unsupported
//! source is a blocker, never an error; invalid input, corruption and
//! store failures stay errors. The caller's credential, sight and Grant
//! are judged above it, at the door (`memory::origin_doors::preview`).
mod handles;
mod types;

use std::collections::{BTreeMap, BTreeSet};

pub use self::types::{
    CODE_EXPORT_PREVIEW_HELD, CodeExportBlockingSource, CodeExportByteHandle, CodeExportFileBytes,
    CodeExportFileDelta, CodeExportFileIdentity, CodeExportFileReadAnswer,
    CodeExportFileReadRequest, CodeExportPreview, CodeExportPreviewAnswer,
    CodeExportPreviewBlockReason, CodeExportPreviewBlocker, CodeExportPreviewHold,
    CodeExportPreviewRequest, CodeExportSide,
};

use self::handles::PreviewIdentity;
use super::export_input::{ExportGap, ExportPromotion, export_message};
use super::tree::OriginTreeFile;
use crate::code_revision::{
    CodeImportManifest, CodeRevision, CodeTreeBlob, CodeTreeInventory, MODE_GITLINK, manifest_id,
    materialize_code_revision_tree,
};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitRefName, GitWire, GitWireRepo, lock_repository};
use crate::merge_queue::QueueTestedTarget;
use crate::{EntityId, Vault};

/// One pinned leaf: its captured identity and its exact raw bytes.
#[derive(Debug, Clone)]
pub(crate) struct PinnedLeaf {
    pub(crate) blob: CodeTreeBlob,
    pub(crate) bytes: Vec<u8>,
}

/// A record the answer stands on, which the caller's credential must read.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PreviewSource {
    pub(crate) entity: EntityId,
    /// A record that must be a readable row, as the export's own
    /// revision and session are; any other is judged once it is a row.
    pub(crate) required: bool,
}

/// A preview resolved at the engine, before the door judges the caller:
/// the complete answer when nothing here blocks it, every blocker found
/// otherwise, each pinned leaf of both trees it reached and the records
/// the answer stands on.
#[derive(Debug)]
pub(crate) struct PinnedExportPreview {
    pub(crate) preview: Option<CodeExportPreview>,
    pub(crate) blockers: Vec<CodeExportPreviewBlocker>,
    pub(crate) before: BTreeMap<String, PinnedLeaf>,
    pub(crate) after: BTreeMap<String, PinnedLeaf>,
    pub(crate) sources: Vec<PreviewSource>,
}

impl PinnedExportPreview {
    /// Every path either pinned tree holds.
    pub(crate) fn paths(&self) -> BTreeSet<String> {
        self.before
            .keys()
            .chain(self.after.keys())
            .cloned()
            .collect()
    }

    /// The changed leaf `handle` selects, as [`handles::select_leaf`]
    /// reads it.
    ///
    /// # Errors
    /// A held preview, or a pinned leaf that differs from its identity.
    pub(crate) fn read_leaf(
        &self,
        handle: &CodeExportByteHandle,
    ) -> Result<std::result::Result<CodeExportFileBytes, &'static str>> {
        let preview = self.preview.as_ref().ok_or(Error::InvariantViolation(
            "a held export preview has no leaf to read",
        ))?;
        handles::select_leaf(preview, &self.before, &self.after, handle)
    }
}

/// The complete pinned base: its root, its captured blobs and its leaves.
struct PinnedSide {
    tree: Option<GitOid>,
    blobs: BTreeMap<String, CodeTreeBlob>,
    leaves: BTreeMap<String, PinnedLeaf>,
}

impl Vault {
    /// The exact preview of exporting `request.revision` to
    /// `request.ref_name` in `repo`'s object store (CALL N
    /// `require_exact_preview_sources`, its engine half). `base_published`
    /// says whether a Published publication of the expected commit on this
    /// full ref and store exists; the door reads it with the export's own
    /// publication lookup. The ref is observed once, never reserved
    /// (CALL O `observe_preview_ref`).
    ///
    /// # Errors
    /// An invalid ref or object id, an unfinalized revision, another
    /// store's revision or anchor, corruption or a store failure.
    pub(crate) fn preview_engine_commit_export(
        &self,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        request: &CodeExportPreviewRequest,
        base_published: bool,
    ) -> Result<PinnedExportPreview> {
        let _guard = lock_repository(repo.common_dir())?;
        let ref_name = GitRefName::parse_full(request.ref_name.clone())?;
        let expected = request
            .expected_old_oid
            .clone()
            .map(GitOid::parse_hex)
            .transpose()?;
        let store = repo.identity().as_hex();
        let verified =
            self.load_engine_export_revision(request.revision, ExportPromotion::Readiness)?;
        export_message(&verified.metadata, verified.provenance)?;
        let revision = &verified.revision;
        let mut pinned = PinnedExportPreview {
            preview: None,
            blockers: verified
                .gaps
                .iter()
                .map(|gap| gap_blocker(revision.revision_id, gap))
                .collect(),
            before: BTreeMap::new(),
            after: BTreeMap::new(),
            sources: revision_sources(revision),
        };
        let mut base = self.pin_preview_base(
            git,
            repo,
            &store,
            expected.as_ref(),
            base_published,
            &mut pinned.blockers,
        )?;
        if let Some(base) = &mut base {
            pinned.before = std::mem::take(&mut base.leaves);
        }
        let Some(tested) = &revision.tested_queue else {
            pinned.blockers.push(CodeExportPreviewBlocker::new(
                CodeExportBlockingSource::Entity {
                    entity: revision.revision_id,
                },
                CodeExportPreviewBlockReason::UnsupportedTree,
                "an ordinary document revision holds no complete checked tree; only a \
                 queue-sealed revision previews exactly",
                "Preview the revision the merge queue sealed for this change: the repository's \
                 green_revision, or the received candidate's revision_refs.",
            ));
            return Ok(pinned);
        };
        if tested.store != store {
            return Err(Error::InvariantViolation(
                "engine commit belongs to another object store or inventory",
            ));
        }
        // Its ancestors and its Baseline's import approval are sources too,
        // listed for the caller's credential, never judged again (FIX 8270).
        pinned.sources.extend(
            self.code_revision_ancestry_sources(revision.revision_id)?
                .into_iter()
                .map(|entity| PreviewSource {
                    entity,
                    required: false,
                }),
        );
        let manifest = self.resolve_code_revision_import_anchor(revision.revision_id)?;
        let anchor_repo = manifest
            .as_ref()
            .map_or(tested.repo, |manifest| manifest.anchor.repo);
        if request.code_repo != anchor_repo {
            return Err(Error::InvalidClaimBody(
                "code_repo is not the served code anchor this revision's queue serves",
            ));
        }
        let mut custody_clear = true;
        if let Some(manifest) = &manifest {
            if manifest.anchor.object_store != store {
                return Err(Error::InvariantViolation(
                    "the import manifest names another object store",
                ));
            }
            pinned.sources.extend(manifest_sources(manifest)?);
            custody_clear = self.preview_import_custody(manifest, &mut pinned.blockers)?;
        }
        let mut supported = true;
        for (path, _) in revision
            .blob_frontiers
            .iter()
            .filter(|(_, blob)| blob.mode == MODE_GITLINK)
        {
            supported = false;
            pinned
                .blockers
                .push(gitlink_blocker(CodeExportSide::After, path));
        }
        if !custody_clear || !supported {
            return Ok(pinned);
        }
        let commit = GitOid::parse_hex(tested.commit.clone())?;
        let tree = GitOid::parse_hex(tested.tree.clone())?;
        let files = materialize_code_revision_tree(self, git, repo, revision)?;
        let captured = CodeTreeInventory::capture_pinned(self, git, repo, &commit, &tree)?;
        pinned.after = pin_leaves(&captured.blobs, files)?;
        let target = captured.blobs;
        let Some(base) = base else {
            return Ok(pinned);
        };
        if !pinned.blockers.is_empty() {
            return Ok(pinned);
        }
        let origin_repo_id = crate::origin::lfs::lfs_repo_id(&store)?;
        let source_tree = base.tree.as_ref().map(|tree| tree.as_str().to_owned());
        let target_tree = tested.tree.clone();
        let preview_digest = PreviewIdentity {
            served: &request.repo,
            code_repo: anchor_repo,
            origin_repo_id,
            object_store: &store,
            revision: revision.revision_id,
            ref_name: ref_name.as_str(),
            expected_old_oid: expected.as_ref().map(GitOid::as_str),
            source_tree: source_tree.as_deref(),
            target_tree: &target_tree,
            inventory_digest: &tested.inventory_digest,
            before: &base.blobs,
            after: &target,
        }
        .digest();
        // Observed once for display (CALL O): never refused, rebound or
        // reserved; the export keeps its own compare-and-swap.
        let observed = git.read_ref(repo, &ref_name)?;
        pinned.preview = Some(CodeExportPreview {
            request: request.clone(),
            code_repo: anchor_repo,
            origin_repo_id,
            object_store: store,
            source_tree,
            target_tree,
            inventory_digest: bytes_to_hex_lower(&tested.inventory_digest),
            files: changed_files(&base.blobs, &target, &preview_digest),
            preview_digest,
            exact: true,
            expected_matches_observed: observed == expected,
            observed_ref_oid: observed.map(|oid| oid.as_str().to_owned()),
            before_paths: base.blobs.keys().cloned().collect(),
            after_paths: target.keys().cloned().collect(),
        });
        Ok(pinned)
    }

    /// The base side: empty for an absent expectation, otherwise the
    /// expected commit's complete pinned tree once a Published
    /// publication of it on this ref names it. `None` once blocked.
    fn pin_preview_base(
        &self,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        store: &str,
        expected: Option<&GitOid>,
        published: bool,
        blockers: &mut Vec<CodeExportPreviewBlocker>,
    ) -> Result<Option<PinnedSide>> {
        let Some(commit) = expected else {
            return Ok(Some(PinnedSide {
                tree: None,
                blobs: BTreeMap::new(),
                leaves: BTreeMap::new(),
            }));
        };
        let object = || CodeExportBlockingSource::Object {
            object_store: store.to_owned(),
            oid: commit.as_str().to_owned(),
        };
        if !published {
            blockers.push(CodeExportPreviewBlocker::new(
                object(),
                CodeExportPreviewBlockReason::IncompleteEvidence,
                "no Published publication of the expected commit on this ref and store names it",
                "Name the commit a Published publication of this ref recorded \
                 (vault.code.origin.publications), or null for an absent ref.",
            ));
            return Ok(None);
        }
        let Some(tree) = git
            .commit_trees(repo, std::slice::from_ref(commit))?
            .remove(commit)
        else {
            blockers.push(CodeExportPreviewBlocker::new(
                object(),
                CodeExportPreviewBlockReason::Unavailable,
                "this object store no longer holds the expected commit",
                "Restore the commit to the served store, or preview against the ref's current \
                 published commit.",
            ));
            return Ok(None);
        };
        let captured = CodeTreeInventory::capture_pinned(self, git, repo, commit, &tree)?;
        let mut supported = true;
        for (path, _) in captured
            .blobs
            .iter()
            .filter(|(_, blob)| blob.mode == MODE_GITLINK)
        {
            supported = false;
            blockers.push(gitlink_blocker(CodeExportSide::Before, path));
        }
        if !supported {
            return Ok(None);
        }
        let files = captured.render_captured(self, git, repo)?;
        Ok(Some(PinnedSide {
            leaves: pin_leaves(&captured.blobs, files)?,
            blobs: captured.blobs,
            tree: Some(tree),
        }))
    }

    /// The imported snapshot still holds its manifest's fork and custody
    /// withholds none of it: every withheld path is named, not only the
    /// first. `false` once anything here blocks.
    fn preview_import_custody(
        &self,
        manifest: &CodeImportManifest,
        blockers: &mut Vec<CodeExportPreviewBlocker>,
    ) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        let snapshot = manifest.anchor.snapshot;
        let gone = |message: &str| {
            CodeExportPreviewBlocker::new(
                CodeExportBlockingSource::Entity { entity: snapshot },
                CodeExportPreviewBlockReason::Unavailable,
                message,
                "Import the source commit again with vault.code.import, then seal and preview \
                 its checked baseline.",
            )
        };
        let Some(stored) = self.get_codebase_snapshot_in_txn(&txn, &snapshot)? else {
            blockers.push(gone("the imported snapshot is gone"));
            return Ok(false);
        };
        if bytes_to_hex_lower(&stored.fork_hash) != manifest.anchor.snapshot_fork_hash {
            blockers.push(gone(
                "the imported snapshot no longer holds its manifest's fork",
            ));
            return Ok(false);
        }
        let withheld = self.codebase_withheld_paths_in_txn(&txn, &stored.fork_hash)?;
        for path in &withheld {
            blockers.push(CodeExportPreviewBlocker::new(
                CodeExportBlockingSource::File {
                    side: CodeExportSide::After,
                    path: path.clone(),
                    entity: Some(snapshot),
                },
                CodeExportPreviewBlockReason::Withheld,
                "custody now withholds this imported file",
                "Clear the custody withholding of this imported file, then preview again.",
            ));
        }
        Ok(withheld.is_empty())
    }
}

/// The blocker one named load gap is.
fn gap_blocker(revision: EntityId, gap: &ExportGap) -> CodeExportPreviewBlocker {
    let entity = |entity| CodeExportBlockingSource::Entity { entity };
    match gap {
        ExportGap::UntouchedBytes(detail) => CodeExportPreviewBlocker::new(
            entity(revision),
            CodeExportPreviewBlockReason::Unreviewed,
            detail.clone(),
            "Accept the import manifest with vault.code.import (its manifest digest, this \
             baseline and the owner-selected catalog, with the review that catalog asks for), \
             then preview again.",
        ),
        ExportGap::Unreviewed(detail) => CodeExportPreviewBlocker::new(
            entity(revision),
            CodeExportPreviewBlockReason::Unreviewed,
            detail.clone(),
            "Review and settle each change this revision lands through its proposal \
             (vault.code.proposal_review, vault.code.proposal_settle), then preview the \
             revision the queue seals.",
        ),
        ExportGap::Provenance(provenance) => CodeExportPreviewBlocker::new(
            CodeExportBlockingSource::Evidence {
                reference: provenance.to_hex(),
            },
            CodeExportPreviewBlockReason::IncompleteEvidence,
            "this revision's provenance claim is gone or no longer active",
            "Restore the revision's provenance claim; a revision without active provenance \
             does not export.",
        ),
        ExportGap::Author(author) => CodeExportPreviewBlocker::new(
            entity(*author),
            CodeExportPreviewBlockReason::Unavailable,
            "this revision's author record is gone",
            "Restore the author's record; the export names its author.",
        ),
    }
}

/// A submodule link on `side`: kept visible, never exported.
fn gitlink_blocker(side: CodeExportSide, path: &str) -> CodeExportPreviewBlocker {
    CodeExportPreviewBlocker::new(
        CodeExportBlockingSource::File {
            side,
            path: path.to_owned(),
            entity: None,
        },
        CodeExportPreviewBlockReason::UnsupportedTree,
        "a submodule link the origin export does not write",
        "Remove the submodule link in a reviewed change, then preview the revision that \
         seals it.",
    )
}

/// The records a sealed revision's answer stands on: the revision and its
/// session, the queue's served anchor, and each source its seal applied or
/// consumed whole.
fn revision_sources(revision: &CodeRevision) -> Vec<PreviewSource> {
    let required = |entity| PreviewSource {
        entity,
        required: true,
    };
    let listed = |entity| PreviewSource {
        entity,
        required: false,
    };
    let mut sources = vec![
        required(revision.revision_id),
        required(revision.session_id),
    ];
    let Some(tested) = &revision.tested_queue else {
        return sources;
    };
    sources.push(listed(tested.repo));
    if let QueueTestedTarget::Landed { applied, .. } = &tested.target {
        for source in applied {
            sources.extend([
                listed(source.proposal),
                listed(source.session),
                listed(source.provenance_claim),
            ]);
        }
    }
    for push in &tested.received_pushes {
        sources.extend([
            listed(push.candidate),
            listed(push.provenance),
            listed(push.publication),
            listed(push.base_revision),
        ]);
    }
    sources
}

/// The import records the untouched bytes descend from.
fn manifest_sources(manifest: &CodeImportManifest) -> Result<Vec<PreviewSource>> {
    let listed = |entity| PreviewSource {
        entity,
        required: false,
    };
    Ok(vec![
        listed(manifest_id(&manifest.digest)?),
        listed(manifest.anchor.snapshot),
        listed(manifest.anchor.admission_receipt),
        listed(manifest.anchor.receive_provenance),
    ])
}

/// Each captured leaf with the exact bytes `files` renders for it: the
/// same paths, and for each its mode, size and hash.
///
/// # Errors
/// A rendered tree that is not the captured one.
fn pin_leaves(
    blobs: &BTreeMap<String, CodeTreeBlob>,
    mut files: BTreeMap<String, OriginTreeFile>,
) -> Result<BTreeMap<String, PinnedLeaf>> {
    let differs = || {
        Error::InvariantViolation(
            "a rendered preview tree is not the checked tree's bytes and modes",
        )
    };
    if files.len() != blobs.len() {
        return Err(differs());
    }
    let mut leaves = BTreeMap::new();
    for (path, blob) in blobs {
        let file = files.remove(path).ok_or_else(differs)?;
        if file.mode != blob.mode
            || file.content.len() as u64 != blob.size_bytes
            || blake3::hash(&file.content).as_bytes() != &blob.content_hash
        {
            return Err(differs());
        }
        leaves.insert(
            path.clone(),
            PinnedLeaf {
                blob: blob.clone(),
                bytes: file.content,
            },
        );
    }
    Ok(leaves)
}

/// Every path whose presence, bytes or mode differs between the two
/// complete trees, sorted by path bytes, each side with its handle. A
/// mode-only change keeps both sides; a rename is a removal and an
/// addition.
fn changed_files(
    before: &BTreeMap<String, CodeTreeBlob>,
    after: &BTreeMap<String, CodeTreeBlob>,
    digest: &str,
) -> Vec<CodeExportFileDelta> {
    let paths: BTreeSet<&String> = before.keys().chain(after.keys()).collect();
    let identity = |side, path: &str, blob: &CodeTreeBlob| CodeExportFileIdentity {
        mode: blob.mode,
        size_bytes: blob.size_bytes,
        git_oid: blob.git_oid.clone(),
        content_hash: bytes_to_hex_lower(&blob.content_hash),
        handle: CodeExportByteHandle {
            preview_digest: digest.to_owned(),
            side,
            path: path.to_owned(),
        },
    };
    let mut files = Vec::new();
    for path in paths {
        let (old, new) = (before.get(path), after.get(path));
        let changed = match (old, new) {
            (Some(old), Some(new)) => old.git_oid != new.git_oid || old.mode != new.mode,
            _ => true,
        };
        if changed {
            files.push(CodeExportFileDelta {
                path: path.clone(),
                before: old.map(|blob| identity(CodeExportSide::Before, path, blob)),
                after: new.map(|blob| identity(CodeExportSide::After, path, blob)),
            });
        }
    }
    files
}
