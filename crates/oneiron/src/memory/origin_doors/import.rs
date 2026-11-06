//! `vault.code.import` (FIX 6869, G4 PR1): the owner's import of one
//! admitted commit of a served repository, and its optional promotion.
//!
//! The owner's proof is judged before any name or id is looked up; the
//! engine judges it again in every writer. The import itself, its manifest
//! and the promotion are the engine's (`origin/repo_import.rs`,
//! `code_revision/import_promotion.rs`); this door only names them and
//! lists what the answer is read from.
use super::*;
use crate::code_revision::CodeImportHold;
use crate::entity_id::bytes_to_hex_lower;
use crate::git_wire::{GitOid, GitRefName};
use crate::memory::codebase_doors::CodeSnapshotFile;
use crate::origin::{ImportedCodeRepo, ServedImportSource};

impl Memory<'_> {
    /// `vault.code.import`: finalizes the chosen commit into a complete
    /// mode-preserving snapshot and its manifest, then, when the owner
    /// accepts it, promotes its exact checked Baseline. A repeat answers the
    /// same manifest and approval.
    pub fn code_repo_import_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeRepoImportRequest,
    ) -> MemoryResult<CodeRepoImportView> {
        self.origin_owner(owner)?;
        let source_ref = GitRefName::parse_full(input.source_ref.clone())?;
        let source_commit = GitOid::parse_hex(input.source_commit.clone())?;
        self.origin_readable(input.project)?;
        let imported = self.vault.import_served_code_repo(
            owner,
            &ServedImportSource {
                repo: &input.repo,
                project: input.project,
                source_ref: &source_ref,
                source_commit: &source_commit,
                admission_receipt: input.admission_receipt,
            },
        )?;
        let anchor = &imported.manifest.anchor;
        self.origin_listed([
            imported.manifest_ref,
            anchor.repo,
            anchor.snapshot,
            anchor.receive_provenance,
        ])?;
        let readiness =
            self.code_repo_import_readiness(owner, imported.manifest_ref, input.accept.as_ref())?;
        Ok(CodeRepoImportView {
            manifest: manifest_view(&imported),
            state: readiness.state,
            baseline_revision: readiness
                .baseline
                .or(input.accept.map(|accept| accept.baseline_revision)),
            promotion_receipt: readiness.receipt,
            hold: readiness.hold,
        })
    }

    /// CALL H "import readiness": no acceptance starts no check or review,
    /// and is `promoted` when a promotion of the manifest already holds (an
    /// approvals-by-manifest read, FIX 7393), else `manifest_ready`; an
    /// acceptance promotes exactly, or holds on the Baseline or the review
    /// it lacks, naming it. Corruption and store failures stay errors,
    /// never holds.
    fn code_repo_import_readiness(
        &self,
        owner: &AuthenticatedOwner,
        manifest_ref: EntityId,
        accept: Option<&CodeImportAcceptance>,
    ) -> MemoryResult<ImportReadiness> {
        let readiness = |state, baseline, receipt, hold| ImportReadiness {
            state,
            baseline,
            receipt,
            hold,
        };
        let Some(accept) = accept else {
            return Ok(
                match self.vault.imported_manifest_promotion(manifest_ref)? {
                    Ok(Some((baseline, approval))) => {
                        self.origin_listed([baseline, approval])?;
                        readiness(
                            CodeRepoImportState::Promoted,
                            Some(baseline),
                            Some(approval),
                            None,
                        )
                    }
                    Ok(None) => readiness(CodeRepoImportState::ManifestReady, None, None, None),
                    Err(detail) => {
                        readiness(CodeRepoImportState::ManifestReady, None, None, Some(detail))
                    }
                },
            );
        };
        Ok(
            match self
                .vault
                .promote_imported_code_revision(owner, manifest_ref, accept)?
            {
                Ok(approval) => {
                    self.origin_listed([accept.baseline_revision, approval])?;
                    readiness(CodeRepoImportState::Promoted, None, Some(approval), None)
                }
                Err(CodeImportHold::Baseline(detail)) => {
                    readiness(CodeRepoImportState::HeldBaseline, None, None, Some(detail))
                }
                Err(CodeImportHold::Review(detail)) => {
                    readiness(CodeRepoImportState::HeldReview, None, None, Some(detail))
                }
            },
        )
    }
}

/// Where one import's promotion stands, and what it stands on.
struct ImportReadiness {
    state: CodeRepoImportState,
    /// The checked Baseline a promotion read with no acceptance found.
    baseline: Option<EntityId>,
    receipt: Option<EntityId>,
    hold: Option<String>,
}

/// The manifest as the wire carries it: every file in path order.
fn manifest_view(imported: &ImportedCodeRepo) -> CodeImportManifestView {
    CodeImportManifestView {
        manifest_ref: imported.manifest_ref,
        digest: imported.manifest.digest.clone(),
        anchor: imported.manifest.anchor.clone(),
        inventory_digest: imported.manifest.inventory_digest.clone(),
        files: imported
            .blobs
            .iter()
            .map(|(path, blob)| CodeImportManifestFile {
                git_oid: blob.git_oid.clone(),
                file: CodeSnapshotFile {
                    path: path.clone(),
                    content_hash_blake3: bytes_to_hex_lower(&blob.content_hash),
                    size_bytes: blob.size_bytes,
                    mode: blob.mode,
                    projection: None,
                },
            })
            .collect(),
    }
}
