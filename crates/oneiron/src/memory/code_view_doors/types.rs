//! Account-local working views and immutable build results (ARCH-0050 / RC7).
use crate::EntityId;
use crate::code_view::VisibleFilePolicy;
use crate::memory::codebase_doors::RepoFileProjectionView;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeViewMaterializeRequest {
    pub repo: EntityId,
    /// A finalized CodeRevision with verified per-file tested frontiers.
    pub tested: EntityId,
    /// Expected account: the authenticated owner's PERSON id, not a grant.
    pub account: EntityId,
    pub policy: VisibleFilePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeViewRequest {
    pub view: EntityId,
    pub repo: EntityId,
    pub tested: EntityId,
    pub account: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeViewReadRequest {
    pub view: CodeViewRequest,
    pub path: String,
    /// Why the caller needs this marked file's real bytes (FIX 7608,
    /// CALL 3): absent reads the masked copy as before; a why from a proven
    /// agent asks the owner for this file's stored bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeViewFile {
    pub path: String,
    pub content_hash_blake3: String,
    /// The exact tested document identity and version vector, not a fabricated version ref;
    /// absent for an untouched blob.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontier: Option<crate::code_document::CodeDocumentFrontier>,
    /// The tested document text's SHA-256; absent for an untouched blob.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text_sha256: Option<String>,
    /// The Git object of an untouched blob of a tested queue revision's tree (FIX 9940);
    /// absent for a document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_oid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeWorkingView {
    pub view: EntityId,
    pub repo: EntityId,
    pub base: EntityId,
    pub account: EntityId,
    pub fork_hash: String,
    /// The immutable base file identities. Edits in this view do not change them.
    pub files: Vec<CodeViewFile>,
    pub receipt: EntityId,
    /// On the serving host only. It is not a client-side folder or authority.
    pub host_path: String,
    /// How many edits the view holds (`vault.code.views.edit`): the
    /// `expected_revision` the next edit names; 0 for a view never edited.
    #[serde(default)]
    pub revision: u64,
    /// Each file an edit changed, as the view holds it now; empty for a
    /// view never edited.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forks: Vec<CodeViewForkFile>,
}

/// One file of a working view as its edits left it (row 6
/// WORKING-VIEW-EDIT).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeViewForkFile {
    pub path: String,
    /// The BLAKE3 (64 hex) of the text the view holds.
    pub content_hash_blake3: String,
    /// The SHA-256 (64 hex) of that text, as `vault.code.views.read` names it.
    pub text_sha256: String,
    /// The view fork's document state: the tested state, or an untouched
    /// blob's birth state, with the view's edits on it.
    pub frontier: crate::code_document::CodeDocumentFrontier,
    /// How many edits of this file the view holds.
    pub edits: u64,
}

/// `vault.code.views.edit`'s input: one whole-file replacement of a file of
/// an owner working view, against the view revision and the file text the
/// caller last read.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeViewEditRequest {
    pub view: CodeViewRequest,
    /// A file of the view (an input `views.get` lists); no add, delete or
    /// rename.
    pub path: String,
    /// The view's `revision` the caller read; another refuses as stale.
    pub expected_revision: u64,
    /// The SHA-256 (64 hex) of the file's text the caller read, as
    /// `views.read` names it; another refuses as stale.
    pub expected_sha256: String,
    /// The file's whole new text (UTF-8). A secret it writes lands as its
    /// handle, as on every code document write.
    pub replacement_text: String,
}

/// `vault.code.views.edit`'s answer: the one operation the edit made.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeViewEdit {
    pub view: EntityId,
    pub path: String,
    /// The view's revision after the edit: the next edit's
    /// `expected_revision`.
    pub revision: u64,
    /// The operation the view fork recorded, naming its actor.
    pub operation: EntityId,
    /// The SHA-256 (64 hex) of the text before the edit.
    pub before_sha256: String,
    /// The SHA-256 (64 hex) of the text the view holds now: the next edit's
    /// `expected_sha256`. It differs from the replacement's when a secret
    /// in it landed as its handle.
    pub after_sha256: String,
    /// The view fork's document state after the edit.
    pub frontier: crate::code_document::CodeDocumentFrontier,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeViewFileBytes {
    pub path: String,
    pub bytes: Vec<u8>,
    pub sha256: String,
    /// How these bytes differ from the stored file a masked reader reads
    /// them for (FIX 7608): absent for the stored bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection: Option<RepoFileProjectionView>,
}

pub use crate::build_cache::command_spec::{CodeBuildClass, CodeBuildSpec, CodeSecretTaintRef};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeViewActionRequest {
    pub view: CodeViewRequest,
    pub spec: CodeBuildSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeActionDigest {
    /// SHA-256 of the engine's REAPI Action protobuf, in lower hex.
    pub hash: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeViewAction {
    pub action_digest: CodeActionDigest,
    /// Exact Command protobuf bytes and Directory digest for independent digest checks.
    pub command_bytes: Vec<u8>,
    pub input_root_digest: CodeActionDigest,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeViewBuildRequest {
    pub view: CodeViewRequest,
    pub spec: CodeBuildSpec,
    /// Must still match the frozen current view before dispatch or reuse.
    pub action_digest: CodeActionDigest,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeCacheReadRequest {
    pub account: EntityId,
    pub action_digest: CodeActionDigest,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeBuildOutput {
    pub artifact_ref: String,
    pub output_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeBuildEntry {
    pub action_digest: CodeActionDigest,
    pub account: EntityId,
    pub exit_code: i32,
    pub outputs: BTreeMap<String, CodeBuildOutput>,
    pub stdout_ref: Option<String>,
    pub stderr_ref: Option<String>,
    pub secret_taint_refs: Vec<CodeSecretTaintRef>,
    pub reusable: bool,
    /// Original producer, including on a reuse. Never a caller-supplied receipt.
    pub receipt: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodeCacheState {
    Hit,
    Miss,
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeCacheOutcome {
    pub state: CodeCacheState,
    pub entry: Option<CodeBuildEntry>,
    /// Source build receipt on a hit; the transport also keeps this call's own receipt.
    pub receipt: Option<String>,
}
