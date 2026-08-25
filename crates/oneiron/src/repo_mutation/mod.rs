mod conflict;
mod conflict_value;
mod git;
mod oplog;
mod queue;
mod snapshot;
mod support;
mod trailer;
mod types;
mod worktree;

#[cfg(test)]
mod tests;

pub use self::conflict_value::{
    REPO_CONFLICT_CLAIM_VALUE_SCHEMA_VERSION, REPO_CONFLICT_OPEN_VALUE_KEYS,
    REPO_CONFLICT_RESOLUTION_VALUE_KEYS,
};
pub use self::oplog::REPO_MUTATION_OPLOG_SCHEMA_VERSION;
pub use self::trailer::{
    REPO_PROVENANCE_DERIVATION_ENVELOPE_KEYS, REPO_PROVENANCE_NOTES_REF, REPO_PROVENANCE_PREDICATE,
    REPO_PROVENANCE_TRAILER_KEY, REPO_PROVENANCE_VALUE_KEYS, export_repo_provenance_git_note,
    parse_repo_provenance_trailer, repo_commit_for_provenance_claim, repo_commit_provenance,
    repo_commit_provenance_from_git_note, repo_provenance_git_note,
};
pub use self::types::{
    REPO_MUTATION_ALLOWED_OPERATION_KINDS, REPO_MUTATION_FORBIDDEN_GIT_COMMANDS,
    RepoCommitProvenance, RepoConflictClaim, RepoConflictResolutionClaim, RepoForkHash,
    RepoMutationOperation, RepoMutationOplogEntry, RepoMutationOutcome, RepoMutationRequest,
    RepoMutationStatus,
};

pub(crate) use self::conflict_value::validate_repo_conflict_claim_value;

// The flat repo_mutation.rs module used to provide these names to the test
// module through `use super::*`; after the directory split the seam re-imports
// them so the extracted sibling `tests.rs` resolves exactly as it did inline.
#[cfg(test)]
use self::conflict::tree_hash_for_ref;
#[cfg(test)]
use self::git::{
    canonical_repo_ref_for_root, current_head_commit, git_common_dir, resolve_mutable_repo_root,
    run_git, run_git_at_path, validate_base_ref, validate_relative_repo_path,
};
#[cfg(test)]
use self::oplog::{
    decode_stored_oplog_entry, encode_oplog_entry, repo_mutation_oplog_key,
    repo_mutation_repo_key_hash,
};
#[cfg(test)]
use self::queue::{
    INJECT_REPO_MUTATION_CRASH, REPO_MUTATION_LOCK_FILE_NAME, RepoMutationCrashPoint,
    repo_mutation_file_lock,
};
#[cfg(test)]
use self::support::{path_arg, truncate_failure, utf8_trimmed};
#[cfg(test)]
use self::trailer::{REPO_PROVENANCE_TRAILER_PREFIX, commit_message_with_provenance_trailer};
#[cfg(test)]
use self::worktree::{
    apply_prepared_commit_file, create_queue_worktree, is_queue_owned_worktree_path,
    write_repo_file_no_symlink,
};

#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::batch::ENTITY_METADATA_HEADER_LEN;
#[cfg(test)]
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, encode_claim_body,
};
#[cfg(test)]
use crate::codebase::CODEBASE_COMMIT_HASH_HEX_LEN;
#[cfg(test)]
use crate::codebase::RepoRef;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::Error;
#[cfg(test)]
use crate::registry::ENTITY_TYPE_CLAIM;
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use rmpv::Value;
#[cfg(test)]
use std::fs;
