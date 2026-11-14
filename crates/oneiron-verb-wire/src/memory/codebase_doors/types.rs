//! Moved from `crates/oneiron/src/memory/codebase_doors/types.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::origin::secret_projection::types::RepoFileProjectionKind;
pub use crate::origin::secret_projection::types::RepoFileProjectionView;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

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
/// repository, takes no editable whitelist and grants no membership: a
/// registered repository's whitelist is its own (FIX 4299).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeSnapshotIngestRequest {
    /// The explicit project key the snapshot is indexed under. Beside a
    /// `repository`, it is that repository's PROJECT (32 hex); without one,
    /// it names no PROJECT or WORLD record.
    pub project_id: String,
    pub pointer: CodeRepoPointer,
    /// The registered repository this capture belongs to (FIX 4299): its
    /// stable CODE anchor (32 hex), as `vault.repo.anchor.bind` returned
    /// it. The import must read that repository's own folder, and the
    /// capture's scope derives from the anchor. Omitted: an unregistered
    /// capture, read-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<EntityId>,
}

/// Captures current folder bytes on the serving host, without a Git commit.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeSnapshotCaptureRequest {
    pub project_id: String,
    /// Absolute host folder. It grants no repository membership or edit rights.
    pub local_folder: String,
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
    /// Why the caller needs this marked file's real bytes (FIX 7608,
    /// CALL 3): absent reads the masked copy as before; a why from a proven
    /// agent asks the owner for this file's stored bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
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
    /// The file's exact Git mode: 33188 (100644), 33261 (100755) or 40960
    /// (120000, a link whose bytes are its target).
    pub mode: u32,
    /// How the bytes a masked reader reads differ from the stored blob
    /// (FIX 7608): absent for the stored bytes, and for every unmarked file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection: Option<RepoFileProjectionView>,
}

/// One imported snapshot manifest. `repo` is the artifact of this one
/// snapshot, not a registered repository; `repository` is that (FIX 4299);
/// `scope_key` is an index key, not a grant.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeSnapshotView {
    /// The imported CODE_ARTIFACT id.
    pub repo: EntityId,
    /// The canonical repository pointer the import recorded.
    pub repo_ref: String,
    pub project_id: String,
    /// The Git commit, 40 lower-hex characters; absent for a current-folder capture.
    pub commit: Option<String>,
    /// The fork hash, 64 lower-hex characters.
    pub snapshot: String,
    /// The codebase index key, 64 lower-hex characters: the project and
    /// the repository, never the commit (FIX 4299).
    pub scope_key: String,
    pub files: Vec<CodeSnapshotFile>,
    /// The registered repository the capture belongs to, its stable CODE
    /// anchor; absent for an unregistered capture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<EntityId>,
    /// The committed capture's receipt, returned by ingest. Manifest reads
    /// omit it; retained captures remain available through `vault.receipts`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_receipt: Option<String>,
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
