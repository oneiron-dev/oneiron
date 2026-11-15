//! Account-local working views and immutable build results (ARCH-0050 / RC7).
use crate::EntityId;
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_verb_wire::memory::code_view_doors::types::{
    CodeActionDigest, CodeBuildEntry, CodeBuildOutput, CodeCacheOutcome, CodeCacheReadRequest,
    CodeCacheState, CodeViewAction, CodeViewActionRequest, CodeViewBuildRequest, CodeViewFile,
    CodeViewFileBytes, CodeViewForkFile, CodeViewMaterializeRequest, CodeViewReadRequest,
    CodeViewRequest, CodeWorkingView,
};

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

pub use crate::build_cache::command_spec::{CodeBuildClass, CodeBuildSpec, CodeSecretTaintRef};
