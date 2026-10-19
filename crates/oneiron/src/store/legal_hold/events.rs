//! The two hold logs (C2, C3): customer holds' and the host-only one. The
//! owner reads both, a host order's through the one permitted view
//! (`LegalHold::owner_may_see`). Each event is ids, times and codes; no
//! memory content, no free text, no hash chain (OF-284 stays killed). Rows
//! key by hold, so a hold's log expires with it.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

use super::{HOST_ROWS, HoldActor};
use crate::deletion::{
    LegalHold, LegalHoldEvent, LegalHoldEventKind, LegalHoldKind, LegalHoldReason, LegalHoldTarget,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable, SideTableDbs};

type Events = SideTable<(EntityId, u64), LegalHoldEvent, Named>;

/// Customer holds' log. Key: id16 (hold) + u64be (sequence).
const EVENTS: Events = SideTable::new(&side_table::LEGAL_HOLD_EVENT);
/// The host-only log. Key: id16 (hold) + u64be (sequence).
const HOST_EVENTS: Events = SideTable::new(&side_table::LEGAL_HOLD_HOST_EVENT);

fn append_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    table: Events,
    event: &LegalHoldEvent,
) -> Result<()> {
    let last = table
        .iter_rev_from(dbs, txn, event.hold_id.as_bytes())?
        .next()
        .transpose()?;
    let sequence = match last {
        None => 0,
        Some(((_, sequence), _)) => sequence
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("legal hold event sequence"))?,
    };
    table.put(dbs, txn, &(event.hold_id, sequence), event)
}

/// Appends one event to `hold`'s own log: a customer hold's, or a host
/// order's host-only one, whole. The owner reads a host order's log through
/// the permitted view at read time, so nothing is copied, and nothing of it
/// shows while its silence runs (C2, WILL-PLAN L01 row 02).
#[allow(clippy::too_many_arguments, reason = "one argument per C3 field")]
pub(crate) fn log_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    hold: &LegalHold,
    event: LegalHoldEventKind,
    reason: LegalHoldReason,
    targets: Vec<LegalHoldTarget>,
    actor: &HoldActor,
    at: u64,
    request_id: Option<String>,
) -> Result<()> {
    let row = LegalHoldEvent {
        hold_id: hold.hold_id,
        kind: hold.kind,
        targets,
        actor_ref: actor.id.clone(),
        actor_kind: actor.kind,
        at,
        event,
        reason,
        matter_ref: hold.matter_ref.clone(),
        request_id,
    };
    let table = match hold.kind {
        LegalHoldKind::Customer => EVENTS,
        LegalHoldKind::HostOrder => HOST_EVENTS,
    };
    append_in_txn(dbs, txn, table, &row)
}

/// The newest event of `hold`'s own log.
pub(super) fn last_event_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    hold: &LegalHold,
) -> Result<Option<LegalHoldEvent>> {
    let table = match hold.kind {
        LegalHoldKind::Customer => EVENTS,
        LegalHoldKind::HostOrder => HOST_EVENTS,
    };
    Ok(table
        .iter_rev_from(dbs, txn, hold.hold_id.as_bytes())?
        .next()
        .transpose()?
        .map(|(_, event)| event))
}

fn by_time(table: Events, dbs: &impl SideTableDbs, txn: &RoTxn<'_>) -> Result<Vec<LegalHoldEvent>> {
    let mut events: Vec<LegalHoldEvent> = table
        .scan(dbs, txn)?
        .into_iter()
        .map(|(_, event)| event)
        .collect();
    // Stable: one hold's events keep their sequence within a second.
    events.sort_by_key(|event| event.at);
    Ok(events)
}

/// The owner-visible log at `now`, oldest first: every customer hold's
/// events, and every event of each host order the owner may see now, whole
/// (WILL-PLAN L01 row 02). Nothing of an order while its silence runs; once
/// it ends, the order's history shows with it.
pub(crate) fn owner_events_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    now: u64,
) -> Result<Vec<LegalHoldEvent>> {
    let visible: BTreeSet<EntityId> = HOST_ROWS
        .scan(dbs, txn)?
        .into_iter()
        .filter(|(_, hold)| hold.owner_may_see(now))
        .map(|(id, _)| id)
        .collect();
    let mut events = by_time(EVENTS, dbs, txn)?;
    events.extend(
        by_time(HOST_EVENTS, dbs, txn)?
            .into_iter()
            .filter(|event| visible.contains(&event.hold_id)),
    );
    // Stable: each log keeps its own order within a second.
    events.sort_by_key(|event| event.at);
    Ok(events)
}

/// The host-only log, oldest first.
pub(crate) fn host_events_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
) -> Result<Vec<LegalHoldEvent>> {
    by_time(HOST_EVENTS, dbs, txn)
}

/// Drops every row of `hold`'s logs; returns how many.
pub(super) fn drop_events_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    hold: &EntityId,
) -> Result<u64> {
    let mut dropped = 0_u64;
    for table in [EVENTS, HOST_EVENTS] {
        for key in table.scan_keys(dbs, txn, hold.as_bytes())? {
            table.delete(dbs, txn, &key)?;
            dropped = dropped.saturating_add(1);
        }
    }
    Ok(dropped)
}
