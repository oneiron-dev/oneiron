//! Code revisions, tested forks and reviewed import promotion.
//! The revision value is `CodeRevision`.
//! Child modules own the types, codecs and promotion definitions re-exported here.

mod commit_metadata;
pub use commit_metadata::CodeCommitMetadata;
mod promotion;
pub use promotion::{CodeRevisionFileOps, CodeSessionRun};
mod codec;
mod file_frontiers;
mod forks;
mod frontier;
mod graph;
mod import_anchor;
mod import_promotion;
mod import_types;
mod integrity;
mod keys;
mod proposals;
mod queue;
mod queue_promotion;
mod queue_root;
mod storage;
mod tree_codec;
mod tree_inventory;
mod types;
pub(crate) use self::keys::archive_revision_tables;
pub(crate) use self::promotion::archive_promotion_table;
pub(crate) use self::proposals::archive_proposal_table;

pub(crate) use self::codec::CODE_REVISION_CLAIM_PREDICATE;
pub use self::codec::{
    CODE_REVISION_FORK_KEYS, CODE_REVISION_RECORD_KEYS, decode_code_revision,
    decode_code_revision_fork, encode_code_revision, encode_code_revision_fork,
};
pub(crate) use self::forks::attach_code_revision_fork_in_txn;
pub use self::proposals::{CodeRevisionProposal, CodeRevisionWriteOutcome};
pub(crate) use self::storage::checkpoint;
pub(crate) use self::storage::{
    delete_code_revision_lifecycle_in_txn, has_finalized_code_revision_in_txn,
};
pub use self::types::{CodeRevision, CodeRevisionFork, CodeRevisionKind};
// The tested queue revision (FIX 6868, G2 PR3).
pub(crate) use self::queue::{queue_aggregation_session, queue_provenance_id, queue_revision_id};
pub(crate) use self::queue_promotion::QueuePromotionGap;
pub(crate) use self::tree_inventory::MODE_GITLINK;
pub use self::tree_inventory::{CodeTreeBlob, CodeTreeInventory};
// The reviewed import and its untouched-byte promotion (FIX 6869, G4 PR1).
pub(crate) use self::import_anchor::import_snapshot_custody_in_txn;
pub use self::import_anchor::{materialize_code_revision_tree, read_code_revision_blobs};
pub(crate) use self::import_promotion::CodeImportHold;
pub use self::import_types::{CodeImportAcceptance, CodeImportAnchor, CodePathRetirement};
pub(crate) use self::import_types::{
    CodeImportManifest, IMPORT_MANIFEST_PREDICATE, manifest_digest, manifest_id,
};

#[cfg(test)]
mod tests;

// The flat code_revision.rs module used to provide these names to the sibling
// test module through `use super::*`: its own private crate/std import header,
// and every code-revision-internal item the tests name bare. After the
// directory split the seam re-imports both so `tests.rs` resolves exactly as
// it did before. (`frontier::*` is absent from the globs on purpose: the
// typed side tables cover what the tests used to reach into that module for,
// so its `pub(super)` items are no longer named bare and the glob would be an
// unused import.)
#[cfg(test)]
use self::{integrity::*, keys::*, storage::*, types::*};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::batch::ENTITY_METADATA_HEADER_LEN;
#[cfg(test)]
use crate::edge::EdgeKind;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::registry::ENTITY_TYPE_SESSION;
#[cfg(test)]
use crate::store::Store;
#[cfg(test)]
use rmpv::Value;
