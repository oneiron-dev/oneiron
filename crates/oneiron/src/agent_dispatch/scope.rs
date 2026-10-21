//! Project descent for a dispatched child's resource scope (FIX 8626): a
//! child under a parent scope that names a project may name a project that
//! descends from it, proven here against the live project DAG in the
//! dispatch's own transaction.

use std::collections::BTreeSet;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// Whether `child` is `parent`, or descends from it through the effective
/// parents of live projects, read in `txn`. Every hop is a project whose
/// signed history the fold accepts now; one it does not, or a parent
/// reference that does not parse, carries no path, so missing or unreadable
/// state never proves descent. A read error is the result. A project shared
/// along two paths (a diamond) is walked once, and a cycle ends the walk.
pub(super) fn project_descends_from_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    child: EntityId,
    parent: EntityId,
) -> Result<bool> {
    let mut seen = BTreeSet::from([child]);
    let mut pending = vec![child];
    while let Some(project) = pending.pop() {
        let Some((_, effective)) = vault.effective_project_in_txn(txn, project)? else {
            continue;
        };
        if project == parent {
            return Ok(true);
        }
        for next in effective.parents {
            if let Ok(next) = EntityId::from_hex(&next)
                && seen.insert(next)
            {
                pending.push(next);
            }
        }
    }
    Ok(false)
}
