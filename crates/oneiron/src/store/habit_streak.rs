//! Stored habit check-in reduction.

use heed::RwTxn;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{EdgeStoreRead, EntityStoreRead};
use crate::registry::ENTITY_TYPE_TASK;
use crate::store::Store;
use crate::write_envelope::task_body::{
    HabitStreak, TaskRole, streak_from_checkin_days, task_role_from_body_bytes,
};

/// UTC day-bucket width. `occurred_start / STREAK_DAY_SECS` is the whole
/// normalization: integer division, no calendar, no local zone, no "today".
const STREAK_DAY_SECS: u64 = 86_400;

/// Recomputes one Habit's counters from its persisted check-in children and
/// rewrites the stored body, inside the caller's transaction.
///
/// The caller has already established that `habit_id` is a stored Habit-role
/// TASK. Children qualify only as `ENTITY_TYPE_TASK` with role `HabitCheckin`,
/// decoded from the FINAL `edges_in` state of this transaction — so a batch
/// that adds and removes the same edge sees what it left behind, not what it
/// staged. Any error here propagates and aborts the whole transaction,
/// including the check-in entity and the `ChildOf` edge that triggered it.
pub(crate) fn recompute_habit_streak_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    habit_id: &EntityId,
) -> Result<HabitStreak> {
    let mut days = Vec::new();
    for entry in store.port_edges(
        wtxn,
        habit_id,
        crate::ports::EdgeDirection::In,
        Some(EdgeKind::ChildOf),
        None,
    )? {
        let edge_row = entry?;
        let child = edge_row.target;
        let Some(raw) = store
            .port_entity_record(wtxn, &child)?
            .map(|row| row.encode())
        else {
            continue;
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            return Err(Error::CorruptedIndex("entity header"));
        };
        if header.entity_type != ENTITY_TYPE_TASK
            || task_role_from_body_bytes(&raw[ENTITY_METADATA_HEADER_LEN..])?
                != TaskRole::HabitCheckin
        {
            continue;
        }
        days.push(header.occurred_start / STREAK_DAY_SECS);
    }

    let streak = streak_from_checkin_days(days)?;

    crate::ports::EntityStoreMaintenance::port_habit_streak_materialize(
        store, wtxn, habit_id, streak,
    )?;
    Ok(streak)
}
