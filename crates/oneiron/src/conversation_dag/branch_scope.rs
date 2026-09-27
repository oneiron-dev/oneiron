//! Shared branch ownership and bounded reply-span proof for mint and stored reads.

use super::graph::{self, chain, conversation_of, edge_ids, invalid, require_type};
use super::{ScopePath, ScopeSelector};
use crate::EntityId;
use crate::edge::EdgeKind;
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_SESSION};
use crate::store::Store;
use heed::RoTxn;

/// Proves a generic Branch anchor belongs to its declared worker session.
/// Returns that worker session, when the anchor is a worker record.
pub(crate) fn prove_branch_anchor(
    store: &Store,
    txn: &RoTxn<'_>,
    scope: &ScopeSelector,
    anchor: EntityId,
) -> Result<Option<EntityId>> {
    require_type(store, txn, &scope.conversation, ENTITY_TYPE_CONVERSATION)?;
    if conversation_of(store, txn, &anchor)? != scope.conversation {
        return Err(invalid("branch belongs to another conversation"));
    }
    if let Some(session) = scope.session {
        require_type(store, txn, &session, ENTITY_TYPE_SESSION)?;
    }
    if graph::is_sub_session_record(store, txn, &anchor)? {
        let membership = crate::compaction::turn_session_membership_in_txn(store, txn, &anchor)?;
        if scope.session.is_none() || scope.session != membership {
            return Err(invalid("branch anchor belongs to another session"));
        }
        return Ok(membership);
    }
    Ok(None)
}

/// Proves an exact historical reply chain. Neither HEAD nor newer siblings
/// enter the result, and the excluded anchor is never a covered record.
pub(crate) fn prove_branch_span(
    store: &Store,
    txn: &RoTxn<'_>,
    scope: &ScopeSelector,
    after: EntityId,
    through: EntityId,
) -> Result<Vec<EntityId>> {
    if !matches!(scope.path, ScopePath::BranchSpan { after: a, through: t } if a == after && t == through)
        || scope.include_forks
    {
        return Err(invalid("branch span requires no forks"));
    }
    require_type(store, txn, &scope.conversation, ENTITY_TYPE_CONVERSATION)?;
    if conversation_of(store, txn, &after)? != scope.conversation {
        return Err(invalid("branch anchor belongs to another conversation"));
    }
    if let Some(session) = scope.session {
        require_type(store, txn, &session, ENTITY_TYPE_SESSION)?;
    }
    let path = chain(store, txn, &scope.conversation, through)?;
    let boundary = path
        .iter()
        .position(|id| *id == after)
        .ok_or_else(|| invalid("branch span anchor is not an ancestor"))?;
    let replies = &path[boundary + 1..];
    if replies.is_empty() {
        return Err(invalid("branch span needs a reply"));
    }
    let mut parent = after;
    let mut parent_session =
        crate::compaction::turn_session_membership_in_txn(store, txn, &parent)?;
    for &reply in replies {
        if !graph::is_thread_record(store, txn, &reply)?
            || graph::parent(store, txn, &reply)? != Some(parent)
            || edge_ids(store, txn, &reply, EdgeKind::RepliesTo, false, 2)? != [parent]
        {
            return Err(invalid("branch span is not a reply chain"));
        }
        let session = crate::compaction::turn_session_membership_in_txn(store, txn, &reply)?;
        if scope
            .session
            .is_some_and(|selected| session != Some(selected))
        {
            return Err(invalid("branch span contains another session"));
        }
        let is_worker = graph::is_sub_session_record(store, txn, &reply)?;
        if session != parent_session {
            // Ordinary sittings may change on the trunk. A retained worker
            // boundary may change only at the spawning turn, exactly as at
            // append admission; leaving a worker for a plain sitting is barred.
            if is_worker {
                let next_session = session.ok_or_else(|| invalid("worker reply lacks session"))?;
                if edge_ids(store, txn, &next_session, EdgeKind::SpawnedBy, false, 2)? != [parent] {
                    return Err(invalid("branch span crosses a session without a spawn"));
                }
            } else if graph::is_sub_session_record(store, txn, &parent)? {
                return Err(invalid("branch span exits a worker session"));
            }
        }
        parent = reply;
        parent_session = session;
    }
    Ok(replies.to_vec())
}
