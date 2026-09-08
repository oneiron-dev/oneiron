//! Vault-meta key builders for the code-revision row families.

use crate::entity_id::{ENTITY_ID_LEN, EntityId, parse_entity_id};
use crate::error::Result;

const CODE_REVISION_RECORD_KEY_PREFIX: &[u8] = b"code_revision:record:v1:";

pub(super) const CODE_REVISION_SESSION_INDEX_KEY_PREFIX: &[u8] = b"code_revision:session:v1:";

pub(super) const CODE_REVISION_PARENT_INDEX_KEY_PREFIX: &[u8] = b"code_revision:parent:v1:";

const CODE_REVISION_FORK_KEY_PREFIX: &[u8] = b"code_revision:fork:v1:";

pub(super) const CODE_REVISION_FORK_PARENT_INDEX_KEY_PREFIX: &[u8] =
    b"code_revision:fork_parent:v1:";

const CODE_REVISION_INTEGRITY_KEY_PREFIX: &[u8] = b"code_revision:integrity:v1:";

pub(super) const CODE_REVISION_FRONTIER_KEY_PREFIX: &[u8] = b"code_revision:frontier:v1:";

pub(super) fn code_revision_record_key(id: &EntityId) -> Vec<u8> {
    keyed_id(CODE_REVISION_RECORD_KEY_PREFIX, id)
}

pub(super) fn code_revision_integrity_key(id: &EntityId) -> Vec<u8> {
    keyed_id(CODE_REVISION_INTEGRITY_KEY_PREFIX, id)
}

pub(super) fn code_revision_frontier_key(session_id: &EntityId) -> Vec<u8> {
    keyed_id(CODE_REVISION_FRONTIER_KEY_PREFIX, session_id)
}

pub(super) fn code_revision_session_index_prefix(session_id: &EntityId) -> Vec<u8> {
    keyed_id(CODE_REVISION_SESSION_INDEX_KEY_PREFIX, session_id)
}

pub(super) fn code_revision_session_index_key(
    session_id: &EntityId,
    revision_id: &EntityId,
) -> Vec<u8> {
    keyed_pair(
        CODE_REVISION_SESSION_INDEX_KEY_PREFIX,
        session_id,
        revision_id,
    )
}

pub(super) fn code_revision_parent_index_prefix(parent_revision_id: &EntityId) -> Vec<u8> {
    keyed_id(CODE_REVISION_PARENT_INDEX_KEY_PREFIX, parent_revision_id)
}

pub(super) fn code_revision_parent_index_key(
    parent_revision_id: &EntityId,
    revision_id: &EntityId,
) -> Vec<u8> {
    keyed_pair(
        CODE_REVISION_PARENT_INDEX_KEY_PREFIX,
        parent_revision_id,
        revision_id,
    )
}

pub(super) fn code_revision_fork_key(fork_session_id: &EntityId) -> Vec<u8> {
    keyed_id(CODE_REVISION_FORK_KEY_PREFIX, fork_session_id)
}

pub(super) fn code_revision_fork_parent_index_prefix(parent_session_id: &EntityId) -> Vec<u8> {
    keyed_id(
        CODE_REVISION_FORK_PARENT_INDEX_KEY_PREFIX,
        parent_session_id,
    )
}

pub(super) fn code_revision_fork_parent_index_key(
    parent_session_id: &EntityId,
    fork_session_id: &EntityId,
) -> Vec<u8> {
    keyed_pair(
        CODE_REVISION_FORK_PARENT_INDEX_KEY_PREFIX,
        parent_session_id,
        fork_session_id,
    )
}

fn keyed_id(prefix: &[u8], id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + ENTITY_ID_LEN);
    key.extend_from_slice(prefix);
    key.extend_from_slice(id.as_bytes());
    key
}

fn keyed_pair(prefix: &[u8], first: &EntityId, second: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + 2 * ENTITY_ID_LEN);
    key.extend_from_slice(prefix);
    key.extend_from_slice(first.as_bytes());
    key.extend_from_slice(second.as_bytes());
    key
}

pub(super) fn id_from_index_key(
    key: &[u8],
    offset: usize,
    context: &'static str,
) -> Result<EntityId> {
    parse_entity_id(key.get(offset..).unwrap_or_default(), context)
}
