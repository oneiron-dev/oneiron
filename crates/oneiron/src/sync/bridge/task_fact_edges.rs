//! Board announcements on a replicated task-authority fact's link (FIX
//! 11931). Sync can commit a fact's row before its ScopedTo link to its TASK,
//! in separate entity and edge writes; the TASK's board announcement for the
//! fact's write then read the TASK before the fact counted in it. The link's
//! own write announces the TASK again, after its commit, as every TASK row's
//! put does ([`crate::batch::queue_task_updates`]).

use crate::Vault;
use crate::batch::BatchOp;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;

/// The ScopedTo links `ops` adds, as (source, TASK).
pub(super) fn scoped_to_links(ops: &[BatchOp]) -> Vec<(EntityId, EntityId)> {
    ops.iter()
        .filter_map(|op| match op {
            BatchOp::EdgeWithCreatedAt {
                src,
                kind: EdgeKind::ScopedTo,
                tgt,
                ..
            } => Some((*src, *tgt)),
            _ => None,
        })
        .collect()
}

/// Queues the post-commit board announcement of each TASK one of `links`
/// scopes a task-authority fact to, in the write that linked it. A source
/// that is no fact announces nothing.
pub(super) fn announce_linked_tasks_in_txn(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    links: Vec<(EntityId, EntityId)>,
) -> Result<()> {
    for (source, task) in links {
        if crate::task_authority::is_task_authority_fact_in(&vault.store, txn, &source)? {
            crate::batch::queue_task_updates(vault, txn, [task]);
        }
    }
    Ok(())
}
