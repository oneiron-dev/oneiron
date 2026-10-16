//! The send hold of an inbound STOP (F06): the external-effect gate's read
//! of a STOP's standing opt-out, and the marker of one this replica has not
//! projected yet.
//!
//! A STOP row first observed here writes one marker keyed by its event id:
//! the local record, or a peer's copy arriving by sync, whatever its
//! `projected` flag says, since a peer's projection installed nothing here.
//! An overwrite never creates one. The gate holds a send to the marker's
//! party and channel exactly as a projected STOP's opt-out does. This
//! replica's projector releases the marker in the transaction that installs
//! the standing opt-out; deleting the event clears it. A STOP a peer
//! projected settles here once that projection's opt-out, or a later ruling
//! that closed it, arrives. A STOP the projector keeps refusing keeps
//! holding.
//!
//! A STOP whose PERSON has not reached this replica names a party no send
//! can be matched to yet; the hold starts once that PERSON arrives.

use std::collections::{BTreeSet, HashSet};

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::claims::CommResult;
use super::consent::{
    OPT_OUT_REASON_STOP, claim_body_in_txn, parties_opt_out_subjects_in_txn, standing_opt_out_head,
    subject_claim_ids_in_txn,
};
use super::records::{CommEventKind, CommRecord, decode_comm_record};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::counterparty_contact::CounterpartyOptOutReason;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::scan_check::{EngineScan, ScanCount};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

const PENDING: SideTable<EntityId, PendingStop, Named> =
    SideTable::new(&side_table::COMM_PENDING_STOP);

/// The party and normalized channel one pending STOP holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingStop {
    #[serde(with = "crate::entity_id::serde_hex")]
    party_ref: EntityId,
    channel_class: String,
}

/// The put door's half, staged before the body: an insert of a STOP row
/// writes its marker.
pub(crate) fn maintain_pending_stop_put(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    body: &[u8],
) -> Result<()> {
    // An erased shell holds no body, so a row put over it is new here.
    if store
        .port_entity_raw_wiped(wtxn, id)?
        .is_some_and(|old| old.len() > ENTITY_METADATA_HEADER_LEN)
    {
        return Ok(());
    }
    let Ok(CommRecord::Event {
        kind: CommEventKind::InboundStop,
        party_ref,
        channel_class: Some(channel_class),
        ..
    }) = decode_comm_record(body)
    else {
        return Ok(());
    };
    let stop = PendingStop {
        party_ref,
        channel_class: crate::counterparty_contact::normalize_channel_class(&channel_class),
    };
    PENDING.put(store, wtxn, id, &stop)
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
pub(super) fn release_pending_stop_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    event_id: &EntityId,
) -> Result<()> {
    PENDING.delete(store, wtxn, event_id)?;
    Ok(())
}

/// Whether `event_id` still waits for this replica's projection.
pub(super) fn holds_pending_stop_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    event_id: &EntityId,
) -> Result<bool> {
    PENDING.contains(store, txn, event_id)
}

/// Every event that still waits for this replica's projection.
pub(super) fn pending_stop_ids_in_txn(store: &Store, txn: &RoTxn<'_>) -> Result<HashSet<EntityId>> {
    PENDING
        .scan_keys(store, txn, &[])
        .map(|ids| ids.into_iter().collect())
}

/// Whether a STOP this replica has not projected yet holds a send on
/// `channel_class` to one of `subjects`: the PERSONs that carry the send's
/// key and the redirect shells around them, where its opt-out will stand.
fn pending_stop_holds_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    subjects: &BTreeSet<EntityId>,
    channel_class: &str,
) -> Result<bool> {
    let mut count = ScanCount::start(store, txn, EngineScan::PendingCommStops, &[])?;
    let mut holds = false;
    for row in PENDING.iter_from(store, txn, &[])? {
        count.row();
        let (_, stop) = row?;
        if stop.channel_class == channel_class && subjects.contains(&stop.party_ref) {
            holds = true;
            break;
        }
    }
    count.defer(store);
    Ok(holds)
}

/// The receipt reason a comm STOP holds a send on `channel_class` under, read
/// with a `Store` on the external-effect gate's transaction (F06), for the
/// PERSONs that carry the send's key.
///
/// Two legs, on the subjects a party's opt-out heads are read on: a standing
/// channel-scoped `comm.opt_out` head, which the contact rows only cache and a
/// supported drop removes (R2-F5), and a STOP this replica has not projected
/// yet.
pub(crate) fn send_stop_reason_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    persons: &[EntityId],
    channel_class: &str,
) -> CommResult<Option<&'static str>> {
    if persons.is_empty() {
        return Ok(None);
    }
    let subjects = parties_opt_out_subjects_in_txn(store, txn, persons.iter().copied().collect())?;
    for subject in &subjects {
        for claim_id in subject_claim_ids_in_txn(store, txn, subject)? {
            let Some(body) = claim_body_in_txn(store, txn, &claim_id)? else {
                continue;
            };
            // A STOP's head names its channel. A party-wide head (a contact's
            // opt-out) reaches sends through the party's contact rows, each
            // scoped by its own class (ONE-1868), so it is not read here.
            if let Some(head) = standing_opt_out_head(&body)?
                && head.channel_class.is_some()
                && head.matches_channel(channel_class)
            {
                let reason = CounterpartyOptOutReason::from_receipt_reason(&head.reason).map_or(
                    OPT_OUT_REASON_STOP,
                    CounterpartyOptOutReason::receipt_reason,
                );
                return Ok(Some(reason));
            }
        }
    }
    let pending = pending_stop_holds_in_txn(store, txn, &subjects, channel_class)?;
    Ok(pending.then_some(OPT_OUT_REASON_STOP))
}
