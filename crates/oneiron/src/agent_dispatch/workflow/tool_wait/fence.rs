//! Content-free evidence that this leaf has a retained tool checkpoint.
//! It survives when a checkpoint's actor/source compartment cannot open.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::{invalid, key};
use crate::Result;
use crate::attempt_queue::{AttemptId, AttemptRecord};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

const TABLE: SideTable<crate::EntityId, CheckpointFence, Named> =
    SideTable::new(&side_table::WORKFLOW_TOOL_CHECKPOINT_FENCE);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointFence {
    attempt: AttemptId,
    generation: u32,
}

pub(super) fn check(store: &Store, txn: &RoTxn<'_>, actual: &AttemptRecord) -> Result<bool> {
    let Some(row) = TABLE.get(store, txn, &key(actual.id)?)? else {
        return Ok(false);
    };
    if row.attempt != actual.id || row.generation != actual.attempt_count {
        return Err(invalid("workflow checkpoint fence has foreign generation"));
    }
    Ok(true)
}

pub(super) fn require(
    store: &Store,
    txn: &RoTxn<'_>,
    attempt: AttemptId,
    generation: u32,
) -> Result<()> {
    let row = TABLE
        .get(store, txn, &key(attempt)?)?
        .ok_or_else(|| invalid("workflow checkpoint fence is missing"))?;
    if row.attempt != attempt || row.generation != generation {
        return Err(invalid("workflow checkpoint fence has foreign generation"));
    }
    Ok(())
}

pub(super) fn put(store: &Store, txn: &mut RwTxn<'_>, actual: &AttemptRecord) -> Result<()> {
    TABLE.put(
        store,
        txn,
        &key(actual.id)?,
        &CheckpointFence {
            attempt: actual.id,
            generation: actual.attempt_count,
        },
    )
}
