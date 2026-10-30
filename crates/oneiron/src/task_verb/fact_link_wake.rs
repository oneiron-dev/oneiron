//! Wakes on a replicated task-authority fact's link (FIX 10697). Sync can
//! commit a fact's row before its ScopedTo link to its TASK, in separate
//! entity and edge writes; the fact reads through its TASK only once the
//! link lands, so the link's own write passes the fact to the hook every
//! TASK row's put passes ([`super::deliver_task_result_in_txn`]). A source
//! that is no fact, or one nobody waits on, delivers nothing.

use crate::Vault;
use crate::batch::BatchOp;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;

/// The sources of the ScopedTo links `ops` adds.
pub(crate) fn scoped_to_sources(ops: &[BatchOp]) -> Vec<EntityId> {
    ops.iter()
        .filter_map(|op| match op {
            BatchOp::EdgeWithCreatedAt {
                src,
                kind: EdgeKind::ScopedTo,
                ..
            } => Some(*src),
            _ => None,
        })
        .collect()
}

/// Passes each of `sources` that is a task-authority fact to the TASK put
/// hook, in the write that linked it.
pub(crate) fn wake_linked_facts_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    sources: Vec<EntityId>,
) -> Result<()> {
    for source in sources {
        if crate::task_authority::is_task_authority_fact_in(&vault.store, &*txn, &source)? {
            super::deliver_task_result_in_txn(vault, txn, source)?;
        }
    }
    Ok(())
}
