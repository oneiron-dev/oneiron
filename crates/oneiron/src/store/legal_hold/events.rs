//! The two hold logs (C2, C3): the owner-visible one and the host-only one.
//! Each event is ids, times and codes; no memory content, no free text, no
//! hash chain (OF-284 stays killed). Rows key by hold, so a hold's log
//! expires with it.

use heed::{RoTxn, RwTxn};

use super::HoldActor;
use crate::deletion::{
    LegalHold, LegalHoldActorKind, LegalHoldEvent, LegalHoldEventKind, LegalHoldKind,
    LegalHoldReason, LegalHoldTarget,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable, SideTableDbs};

type Events = SideTable<(EntityId, u64), LegalHoldEvent, Named>;

/// The owner-visible log. Key: id16 (hold) + u64be (sequence).
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

/// Appends one event to the logs `hold` writes: a customer hold's to the
/// owner-visible log; a host order's to the host-only log with its order
/// reference, and to the owner-visible log without it once the owner may be
/// told, never while an order keeps silence (C2).
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
    match hold.kind {
        LegalHoldKind::Customer => append_in_txn(dbs, txn, EVENTS, &row),
        LegalHoldKind::HostOrder => {
            append_in_txn(dbs, txn, HOST_EVENTS, &row)?;
            if hold.owner_told && !hold.secret_at(at) {
                // The owner sees that a legal order keeps the data, never
                // the order, its reference or the host operator.
                let host = actor.kind == LegalHoldActorKind::Host;
                let told = LegalHoldEvent {
                    matter_ref: None,
                    actor_ref: if host { None } else { row.actor_ref.clone() },
                    reason: if host {
                        LegalHoldReason::LegalOrder
                    } else {
                        reason
                    },
                    ..row
                };
                append_in_txn(dbs, txn, EVENTS, &told)?;
            }
            Ok(())
        }
    }
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

/// The owner-visible log, oldest first.
pub(crate) fn owner_events_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
) -> Result<Vec<LegalHoldEvent>> {
    by_time(EVENTS, dbs, txn)
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
