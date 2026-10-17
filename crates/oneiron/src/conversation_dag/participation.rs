//! A live append's participation (OF-529): the thread it lands in, and the
//! room's participation gate its writer passes before the record is written.

use super::AppendRecord;
use super::graph;
use crate::error::{Error, Result};
use crate::limits::MAX_ANCESTOR_DEPTH;
use crate::store::Store;
use crate::workspace_roster::{Admitted, JoinCause};
use crate::{EntityId, Vault};
use heed::RoTxn;

/// The thread a live append lands in: the root of its chain, the first
/// thread record walked up `Parent`, never the moving tip. A thread append
/// whose parent is a trunk record is the root itself. `None` for a trunk
/// append.
fn thread_root_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    parent: Option<EntityId>,
    record: EntityId,
    thread: bool,
) -> Result<Option<EntityId>> {
    if !thread {
        return Ok(None);
    }
    let mut root = record;
    let mut cursor = parent;
    let mut steps = 0;
    while let Some(id) = cursor {
        if !graph::is_thread_record(store, txn, &id)? {
            break;
        }
        steps += 1;
        if steps > MAX_ANCESTOR_DEPTH {
            return Err(Error::IndexOverflow("conversation_dag_walk"));
        }
        root = id;
        cursor = graph::parent(store, txn, &id)?;
    }
    Ok(Some(root))
}

/// Admits the writer of a live authored append, `record`, answering
/// `reply_to`, before it is written: a person with room standing writes on,
/// and a person new to an ordinary room joins it by this write. An agent
/// joins by no write: it stands there and speaks only when it is addressed
/// on the record it answers, holds that thread's task, or lands an accepted
/// offer (ARCH-0006a, ruled 2026-09-23). The caller records the fact once
/// the record is written.
pub(super) fn admit_append_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    input: &AppendRecord,
    record: EntityId,
    thread: bool,
    reply_to: Option<EntityId>,
) -> Result<Admitted> {
    let branch = thread_root_in_txn(&vault.store, txn, input.parent, record, thread)?;
    crate::workspace_roster::admit_participation_in_txn(
        vault,
        txn,
        input.conversation,
        branch,
        input.actor,
        JoinCause::Wrote { turn: record },
        reply_to,
        None,
        vault.store.clock.now_recorded_at(),
    )
}
