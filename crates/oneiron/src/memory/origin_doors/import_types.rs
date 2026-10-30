//! `vault.code.import` wire types (FIX 6869, G4 PR1): the owner names a
//! served repo, its PROJECT, the admitted ref, the exact chosen commit and
//! the push publication that admitted it, and optionally accepts one exact
//! manifest over its checked Baseline. No host path, actor, argv, caller
//! tree or file list, pass Boolean or implicit HEAD is taken.
use serde::{Deserialize, Serialize};

use crate::EntityId;
pub use crate::code_revision::{CodeImportAcceptance, CodeImportAnchor};
use crate::memory::codebase_doors::CodeSnapshotFile;

/// One import of a served repository's chosen commit.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeRepoImportRequest {
    /// The registered served name, with no `.git` suffix.
    pub repo: String,
    /// The live PROJECT the served repo's anchor belongs to.
    pub project: EntityId,
    /// The full admitted ref, e.g. `refs/heads/main`.
    pub source_ref: String,
    /// The chosen commit, 40 hex: the admitted tip or its ancestor, never
    /// a default HEAD.
    pub source_commit: String,
    /// The Published receive-pack publication that admitted the push.
    pub admission_receipt: EntityId,
    /// The owner's promotion of the exact manifest over its checked
    /// Baseline; `None` imports and answers `manifest_ready`, or `promoted`
    /// when a promotion of this manifest already holds.
    pub accept: Option<CodeImportAcceptance>,
}

/// Where an import stands (CALL H).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodeRepoImportState {
    /// The manifest is written; no check or review was started.
    ManifestReady,
    /// The named checked Baseline is not finalized, or its checks are gone.
    HeldBaseline,
    /// The selected catalog's saved Accept review of the manifest is missing.
    HeldReview,
    /// The Baseline's untouched bytes are promoted by this manifest.
    Promoted,
}

/// One manifest file: its snapshot entry, with its mode, and the exact Git
/// blob it is.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeImportManifestFile {
    /// The Git blob id, 40 lower-hex.
    pub git_oid: String,
    pub file: CodeSnapshotFile,
}

/// One import manifest: what it binds and every file of the chosen tree, in
/// path order. Submodule links are refused, never listed or dropped.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeImportManifestView {
    /// The `repo.import_manifest` claim.
    pub manifest_ref: EntityId,
    /// The manifest digest an acceptance names, 64 lower-hex.
    pub digest: String,
    pub anchor: CodeImportAnchor,
    /// The complete inventory digest a checked Baseline of this tree
    /// records, 64 lower-hex.
    pub inventory_digest: String,
    pub files: Vec<CodeImportManifestFile>,
}

/// An import's manifest and where its promotion stands.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeRepoImportView {
    pub manifest: CodeImportManifestView,
    pub state: CodeRepoImportState,
    /// The checked Baseline the acceptance named.
    pub baseline_revision: Option<EntityId>,
    /// The `repo.import_approval` claim, once promoted.
    pub promotion_receipt: Option<EntityId>,
    /// Why the promotion holds: the Baseline, review or approval it lacks
    /// (FIX 7393). `None` when it does not hold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hold: Option<String>,
}
