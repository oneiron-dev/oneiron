//! Pending inbound STOP markers and transactional put/delete maintenance.

use std::collections::HashSet;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::write_envelope::communication_record::{CommEventKind, CommRecord, decode_comm_record};

pub(crate) const PENDING: SideTable<EntityId, PendingStop, Named> =
    SideTable::new(&side_table::COMM_PENDING_STOP);

/// The party and normalized channel one pending STOP holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingStop {
    #[serde(with = "crate::entity_id::serde_hex")]
    pub(crate) party_ref: EntityId,
    pub(crate) channel_class: String,
}

/// The put door's half, staged before the body: an insert of a STOP row, or
/// an overwrite that makes a row a STOP, writes its marker.
pub(crate) fn maintain_pending_stop_put(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    body: &[u8],
) -> Result<()> {
    let Some(stop) = pending_stop(body) else {
        return Ok(());
    };
    // An erased shell holds no body, so a row put over it is new here. An
    // overwrite never re-arms a STOP that settled; it moves a pending one
    // with its fields, and a row it turns into a STOP holds from now (R1-F2).
    if let Some(old) = store
        .port_entity_raw_wiped(wtxn, id)?
        .filter(|old| old.len() > ENTITY_METADATA_HEADER_LEN)
        && pending_stop(&old[ENTITY_METADATA_HEADER_LEN..]).is_some()
        && !PENDING.contains(store, wtxn, id)?
    {
        return Ok(());
    }
    PENDING.put(store, wtxn, id, &stop)
}

/// The hold a COMM_RECORD body places, if it is a STOP.
fn pending_stop(body: &[u8]) -> Option<PendingStop> {
    let Ok(CommRecord::Event {
        kind: CommEventKind::InboundStop,
        party_ref,
        channel_class: Some(channel_class),
        ..
    }) = decode_comm_record(body)
    else {
        return None;
    };
    Some(PendingStop {
        party_ref,
        channel_class: crate::store::channel_class::normalize_channel_class(&channel_class),
    })
}

/// Both delete doors' half, before the door's missing-row return: a deleted
/// or erased event holds nothing.
pub(crate) fn clear_pending_stop_for_delete(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    PENDING.delete(store, wtxn, id)?;
    Ok(())
}

/// The projector's half, in the transaction that installed the STOP's
/// standing opt-out.
pub(crate) fn release_pending_stop_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    event_id: &EntityId,
) -> Result<()> {
    PENDING.delete(store, wtxn, event_id)?;
    Ok(())
}

/// Whether `event_id` still waits for this replica's projection.
pub(crate) fn holds_pending_stop_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    event_id: &EntityId,
) -> Result<bool> {
    PENDING.contains(store, txn, event_id)
}

/// Every event that still waits for this replica's projection.
pub(crate) fn pending_stop_ids_in_txn(store: &Store, txn: &RoTxn<'_>) -> Result<HashSet<EntityId>> {
    PENDING
        .scan_keys(store, txn, &[])
        .map(|ids| ids.into_iter().collect())
}
