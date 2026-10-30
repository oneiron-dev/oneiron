//! The send hold of an inbound STOP (F06): the external-effect gate's read
//! of a STOP's standing opt-out, the marker of one this replica has not
//! projected yet, and the projector's read of what a peer's projection of a
//! STOP left here.
//!
//! A STOP row first observed here writes one marker keyed by its event id:
//! the local record, or a peer's copy arriving by sync, whatever its
//! `projected` flag says, since a peer's projection installed nothing here.
//! An overwrite of a STOP never re-arms one that settled. The gate holds a
//! send to the marker's party and channel exactly as a projected STOP's
//! opt-out does. This replica's projector releases the marker in the
//! transaction that installs the standing opt-out; deleting the event clears
//! it. A STOP a peer projected settles here once that projection's own
//! opt-out, or a later head on its slot, arrives. A STOP the projector keeps
//! refusing keeps holding.
//!
//! A STOP whose PERSON has not reached this replica names a party no send
//! can be matched to yet; the hold starts once that PERSON arrives.
//!
//! The same read takes a party-wide opt-out (a contact's), on the channels
//! the party's contact claims name, so a dropped contact row loses no hold.

use std::collections::{BTreeSet, HashSet};

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::ProjectedCommEvent;
use super::claims::{CommClaimValue, CommError, CommResult, PREDICATE_COMM_OPT_OUT};
use super::consent::{
    OPT_OUT_REASON_STOP, claim_body_in_txn, parties_opt_out_subjects_in_txn, standing_opt_out_head,
    subject_claim_ids_in_txn,
};
use super::projection_writes::{
    latest_claim_transition_boundary, matching_claims_in_txn, projected_comm_claim_id,
};
use super::records::{CommEventKind, CommRecord, decode_comm_record};
use crate::Vault;
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
        channel_class: crate::counterparty_contact::normalize_channel_class(&channel_class),
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
/// Three legs, on the subjects a party's opt-out heads are read on, each of
/// which the contact rows only cache and a supported drop removes (R2-F5): a
/// standing channel-scoped `comm.opt_out` head, a STOP this replica has not
/// projected yet, and a standing party-wide head (a contact's opt-out).
pub(crate) fn send_stop_reason_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    persons: &[EntityId],
    counterparty: &str,
    channel_class: &str,
) -> CommResult<Option<&'static str>> {
    if persons.is_empty() {
        return Ok(None);
    }
    let subjects = parties_opt_out_subjects_in_txn(store, txn, persons.iter().copied().collect())?;
    let mut party_wide = None;
    for subject in &subjects {
        for claim_id in subject_claim_ids_in_txn(store, txn, subject)? {
            let Some(body) = claim_body_in_txn(store, txn, &claim_id)? else {
                continue;
            };
            let Some(head) = standing_opt_out_head(&body)? else {
                continue;
            };
            if !head.matches_channel(channel_class) {
                continue;
            }
            let reason = CounterpartyOptOutReason::from_receipt_reason(&head.reason).map_or(
                OPT_OUT_REASON_STOP,
                CounterpartyOptOutReason::receipt_reason,
            );
            // A STOP's head names its channel.
            if head.channel_class.is_some() {
                return Ok(Some(reason));
            }
            party_wide.get_or_insert(reason);
        }
    }
    if pending_stop_holds_in_txn(store, txn, &subjects, channel_class)? {
        return Ok(Some(OPT_OUT_REASON_STOP));
    }
    // A party-wide head covers every contact of the party, whatever its
    // channel (ONE-1752), and no channel the party has no contact on
    // (ONE-1868). The contact claims say which, and a drop keeps them.
    let Some(reason) = party_wide else {
        return Ok(None);
    };
    let held = crate::counterparty_contact::party_has_contact_on_class_in_claims_in_txn(
        store,
        txn,
        counterparty,
        channel_class,
    )?;
    Ok(held.then_some(reason))
}

/// What a peer's projection of a STOP left on this replica: `Some(true)`
/// when the STOP's own opt-out stands here, so the rule only consumes gates
/// and refreshes contacts; `Some(false)` when that opt-out arrived closed, or
/// a head after the STOP moved the slot; `None` until one of them arrives.
///
/// The rule never mints for a peer's STOP. Its own opt-out, or the later head
/// that answers it, arrives with the peer's state, and a copy minted here
/// first could stand against a clear the peer's human already made. An older
/// head standing here is no answer: its clear may be in flight (R1-F1).
pub(super) fn peer_stop_projection_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    event: &ProjectedCommEvent<'_>,
) -> CommResult<Option<bool>> {
    let channel = event.channel_class.ok_or(CommError::InvalidRecord)?;
    let own = projected_comm_claim_id(
        event.source_event_id,
        &CommClaimValue::OptOut {
            party_ref: event.party_ref,
            channel_class: Some(channel.to_owned()),
            reason: OPT_OUT_REASON_STOP.to_owned(),
            occurred_at: event.occurred_at,
        },
    )?;
    let history = matching_claims_in_txn(
        vault,
        rtxn,
        event.party_ref,
        PREDICATE_COMM_OPT_OUT,
        Some(channel),
        None,
        false,
    )?;
    if let Some((_, claim)) = history.iter().find(|(id, _)| *id == own) {
        return Ok(Some(claim.is_standing()));
    }
    let answered_later = latest_claim_transition_boundary(&history)
        .is_some_and(|boundary| event.occurred_at < boundary);
    Ok(answered_later.then_some(false))
}
