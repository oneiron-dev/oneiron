mod ingest;
mod repo_ref;
mod snapshot;
mod store;

pub use self::ingest::{
    HostedMediaHashMatchDecision, HostedMediaHashMatchInput, HostedMediaHashMatchProvider,
    NoopHostedMediaHashMatchProvider, RepoIngestConfig, RepoIngestResult,
};
pub use self::repo_ref::{CODEBASE_COMMIT_HASH_HEX_LEN, CODEBASE_REPO_REF_MAX_BYTES, RepoRef};
pub use self::snapshot::{
    CODEBASE_CONTENT_HASH_LEN, CODEBASE_FILE_ENTRY_KEYS, CODEBASE_FILE_PATH_MAX_BYTES,
    CODEBASE_FORK_HASH_LEN, CODEBASE_PROJECT_ID_MAX_BYTES, CODEBASE_SCOPE_KEY_LEN,
    CODEBASE_SNAPSHOT_BODY_KEYS, CODEBASE_SNAPSHOT_MAX_FILES, CodebaseFileEntry, CodebaseForkHash,
    CodebaseScopeKey, CodebaseSnapshot, CodebaseSnapshotMount, decode_codebase_snapshot,
    encode_codebase_snapshot,
};
pub(crate) use self::store::{
    codebase_candidate_matches_filters, codebase_candidate_matches_scope_key,
    delete_codebase_snapshot_in_txn, entity_id_from_hash_material,
    reconcile_codebase_snapshot_after_code_artifact_put,
};
// Test-only seam: the sibling test module names these bare through
// `use super::*`, as it did when they were private items of the flat file.
#[cfg(test)]
pub(crate) use self::ingest::hosted_media_type_for_blob;
#[cfg(test)]
pub(crate) use self::store::{codebase_asset_entity_id, codebase_snapshot_entity_id};

#[cfg(test)]
mod tests;

// The flat codebase.rs module used to provide these names to the sibling test
// module through `use super::*`: its own private crate/std import header, and
// every codebase-internal item the tests name bare. After the directory split
// the seam re-imports both so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::Result;
#[cfg(test)]
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_CODE_ARTIFACT};
#[cfg(test)]
use rmpv::Value;
