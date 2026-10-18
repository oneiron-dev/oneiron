use serde::{Deserialize, Serialize};

use crate::EntityId;

/// One committed Git tree on the serving engine host.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeRepoPointer {
    /// An absolute folder inside a local Git repository on the host that
    /// serves this vault, not a path on the calling client. It grants nothing.
    pub local_folder: String,
    /// The full commit to import, 40 hex characters. No HEAD, branch or tag
    /// name is resolved for the caller.
    pub commit: String,
}

/// Imports one committed tree as a custody-filtered snapshot. It registers no
/// repository, takes no editable whitelist and grants no membership.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeSnapshotIngestRequest {
    /// The explicit project key the snapshot is indexed under. It names no
    /// PROJECT or WORLD record.
    pub project_id: String,
    pub pointer: CodeRepoPointer,
}

/// One code snapshot, pinned by its artifact and its fork hash.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeSnapshotRequest {
    /// The imported CODE_ARTIFACT id.
    pub repo: EntityId,
    /// Its fork hash, 64 lower-hex characters. A selector, not authority.
    pub snapshot: String,
}

/// One file of a pinned code snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeSnapshotReadRequest {
    /// The imported CODE_ARTIFACT id.
    pub repo: EntityId,
    /// Its fork hash, 64 lower-hex characters.
    pub snapshot: String,
    /// The normalized repository-relative path.
    pub path: String,
}

/// Rust symbol definitions by exact name within one pinned code snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeSnapshotDefinitionsRequest {
    /// The imported CODE_ARTIFACT id.
    pub repo: EntityId,
    /// Its fork hash, 64 lower-hex characters.
    pub snapshot: String,
    /// The exact symbol name.
    pub name: String,
}

/// One manifest entry: the stored blob identity of a file, not a document
/// version.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeSnapshotFile {
    pub path: String,
    /// The BLAKE3 hash of the stored bytes, 64 lower-hex characters.
    pub content_hash_blake3: String,
    pub size_bytes: u64,
}

/// One imported snapshot manifest. `repo` is the artifact of this one
/// snapshot, not a registered repository; `scope_key` is an index key, not a
/// grant.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeSnapshotView {
    /// The imported CODE_ARTIFACT id.
    pub repo: EntityId,
    /// The canonical repository pointer the import recorded.
    pub repo_ref: String,
    pub project_id: String,
    /// The Git commit, 40 lower-hex characters.
    pub commit: Option<String>,
    /// The fork hash, 64 lower-hex characters.
    pub snapshot: String,
    /// The codebase index key, 64 lower-hex characters.
    pub scope_key: String,
    pub files: Vec<CodeSnapshotFile>,
}

/// One frozen file of a pinned snapshot, read from its stored blob and never
/// from the folder on disk.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeSnapshotPinnedFile {
    pub repo: EntityId,
    pub snapshot: String,
    pub file: CodeSnapshotFile,
    /// The file text, strict UTF-8.
    pub content: String,
    /// The SHA-256 of exactly these bytes, 64 lower-hex characters.
    pub text_sha256: String,
}

/// One Rust symbol definition the snapshot symbol manifest records.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeSnapshotDefinition {
    /// The CODE_SYMBOL id.
    pub symbol: EntityId,
    pub path: String,
    pub name: String,
    pub kind: String,
    /// The symbol fingerprint, 64 lower-hex characters.
    pub fingerprint: String,
    pub start_line: u32,
    pub end_line: u32,
}

/// The exact-name Rust definitions of one pinned snapshot, in manifest order.
/// They are definitions only: no calls, imports or refs relation.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeSnapshotDefinitionsView {
    pub repo: EntityId,
    pub snapshot: String,
    pub definitions: Vec<CodeSnapshotDefinition>,
}
