//! Repository references, immutable snapshot manifests and their wire codecs.

use oneiron_store::code_snapshot::file_mode;
use oneiron_store::code_snapshot::ids;
pub(crate) use oneiron_store::code_snapshot::repo_ref;
pub(crate) use oneiron_store::code_snapshot::snapshot;
pub(crate) use oneiron_store::code_snapshot::validation;

pub use file_mode::DEFAULT_CODE_FILE_MODE;
pub(crate) use file_mode::validate_code_file_mode;
pub(crate) use ids::codebase_asset_entity_id as snapshot_asset_entity_id;
pub(crate) use ids::{
    archive_codebase_asset_id, codebase_asset_entity_id, codebase_snapshot_entity_id,
    entity_id_from_hash_material,
};
pub use repo_ref::{CODEBASE_COMMIT_HASH_HEX_LEN, CODEBASE_REPO_REF_MAX_BYTES, RepoRef};
pub use snapshot::{
    CODEBASE_CONTENT_HASH_LEN, CODEBASE_FILE_ENTRY_KEYS, CODEBASE_FILE_PATH_MAX_BYTES,
    CODEBASE_FORK_HASH_LEN, CODEBASE_PROJECT_ID_MAX_BYTES, CODEBASE_SCOPE_KEY_LEN,
    CODEBASE_SNAPSHOT_BODY_KEYS, CODEBASE_SNAPSHOT_MAX_FILES, CodebaseFileEntry, CodebaseForkHash,
    CodebaseScopeKey, CodebaseSnapshot, decode_codebase_snapshot, encode_codebase_snapshot,
};
