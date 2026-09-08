mod codec;
mod frontier;
mod graph;
mod integrity;
mod keys;
mod storage;
mod types;

pub(crate) use self::codec::CODE_REVISION_CLAIM_PREDICATE;
pub use self::codec::{
    CODE_REVISION_FORK_KEYS, CODE_REVISION_RECORD_KEYS, decode_code_revision,
    decode_code_revision_fork, encode_code_revision, encode_code_revision_fork,
};
pub(crate) use self::storage::{
    delete_code_revision_lifecycle_in_txn, has_finalized_code_revision_in_txn,
};
pub use self::types::{CodeRevision, CodeRevisionFork, CodeRevisionKind};

#[cfg(test)]
mod tests;

// The flat code_revision.rs module used to provide these names to the sibling
// test module through `use super::*`: its own private crate/std import header,
// and every code-revision-internal item the tests name bare. After the
// directory split the seam re-imports both so `tests.rs` resolves exactly as
// it did before.
#[cfg(test)]
use self::{frontier::*, integrity::*, keys::*, storage::*, types::*};
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
