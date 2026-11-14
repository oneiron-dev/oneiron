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

pub(super) use crate::store::pending_comm_stop::{
    PENDING, holds_pending_stop_in_txn, pending_stop_ids_in_txn, release_pending_stop_in_txn,
};
pub(crate) use crate::store::pending_comm_stop::{
    clear_pending_stop_for_delete, maintain_pending_stop_put,
};

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
///
/// Any move of the slot after the STOP settles it here, a clear requested
/// before the STOP included. Nothing here says whether the peer minted the
/// STOP's own opt-out or folded the STOP into a head that already stood
/// there. When the peer minted one, it arrives with the peer's state and
/// holds sends as a standing head. A peer that folded the STOP in never
/// mints one, and waiting for it would hold sends here for good, with no
/// head a clear could find (COMM-STOP-LATE-ARRIVAL review round 2). The
/// replica that projects a STOP judges a clear's close by its request
/// (`stop_answering_boundary_in_txn`).
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

/// Test door (`test_doors::comm_late_stop`): rewrites the STOP recorded on
/// `party`'s `channel_class` at `occurred_at` as a peer's copy whose peer has
/// already projected it, keeping the hold its first sighting here armed.
/// Answers the event id.
#[cfg(oneiron_test_support)]
pub(crate) fn mark_recorded_stop_peer_projected(
    vault: &Vault,
    party: &str,
    channel_class: &str,
    occurred_at: u64,
) -> CommResult<EntityId> {
    let party_ref = super::parties::resolve_party(vault, party)?.ok_or(CommError::InvalidRecord)?;
    let channel = crate::counterparty_contact::normalize_channel_class(channel_class);
    vault.try_with_write_txn_grouped(|wtxn| {
        let (event_id, mut record) = super::records::comm_records_in_txn(vault, &*wtxn)?
            .into_iter()
            .find(|(_, record)| {
                matches!(record, CommRecord::Event {
                    kind: CommEventKind::InboundStop,
                    party_ref: event_party,
                    channel_class: Some(event_channel),
                    occurred_at: event_at,
                    projected: false,
                    ..
                } if *event_party == party_ref
                    && crate::counterparty_contact::normalize_channel_class(event_channel) == channel
                    && *event_at == occurred_at)
            })
            .ok_or(CommError::InvalidRecord)?;
        if let CommRecord::Event { projected, .. } = &mut record {
            *projected = true;
        }
        super::records::put_comm_record_in_txn(vault, wtxn, event_id, &record)?;
        Ok(event_id)
    })
}

/// Test door: whether the STOP `event_id` still holds sends here as one this
/// replica has not settled.
#[cfg(oneiron_test_support)]
pub(crate) fn recorded_stop_holds(vault: &Vault, event_id: &EntityId) -> CommResult<bool> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(holds_pending_stop_in_txn(&vault.store, &rtxn, event_id)?)
}

/// The outcome the test door gives an approved clear's receipt it keeps from
/// this replica's reads, as sync leaves a receipt that is still in flight.
#[cfg(oneiron_test_support)]
const WITHHELD_CLEAR_RECEIPT_OUTCOME: &str = "test_withheld_comm_opt_out_clear_approved";

/// Test door: rewrites the outcome `from` of each receipt on `party`'s
/// `channel_class` slot to `to`. Answers how many it rewrote.
#[cfg(oneiron_test_support)]
fn rewrite_clear_receipt_outcomes(
    vault: &Vault,
    party: &str,
    channel_class: &str,
    from: &str,
    to: &str,
) -> CommResult<usize> {
    let party_ref = super::parties::resolve_party(vault, party)?.ok_or(CommError::InvalidRecord)?;
    let channel = crate::counterparty_contact::normalize_channel_class(channel_class);
    vault.try_with_write_txn_grouped(|wtxn| {
        let mut rewritten = 0_usize;
        for (receipt_id, mut record) in super::records::comm_records_in_txn(vault, &*wtxn)? {
            let CommRecord::Receipt {
                party_ref: receipt_party,
                channel_class: receipt_channel,
                outcome,
                ..
            } = &mut record
            else {
                continue;
            };
            if *receipt_party != party_ref
                || crate::counterparty_contact::normalize_channel_class(receipt_channel) != channel
                || outcome.as_str() != from
            {
                continue;
            }
            to.clone_into(outcome);
            super::records::put_comm_record_in_txn(vault, wtxn, receipt_id, &record)?;
            rewritten += 1;
        }
        Ok(rewritten)
    })
}

/// Test door: keeps each approved clear's receipt on `party`'s
/// `channel_class` slot from this replica's reads, as a receipt sync has not
/// imported yet. Answers how many it withheld.
#[cfg(oneiron_test_support)]
pub(crate) fn withhold_clear_receipts(
    vault: &Vault,
    party: &str,
    channel_class: &str,
) -> CommResult<usize> {
    rewrite_clear_receipt_outcomes(
        vault,
        party,
        channel_class,
        super::consent::OPT_OUT_CLEAR_APPROVED,
        WITHHELD_CLEAR_RECEIPT_OUTCOME,
    )
}

/// Test door: delivers the receipts `withhold_clear_receipts` withheld.
/// Answers how many it delivered.
#[cfg(oneiron_test_support)]
pub(crate) fn deliver_withheld_clear_receipts(
    vault: &Vault,
    party: &str,
    channel_class: &str,
) -> CommResult<usize> {
    rewrite_clear_receipt_outcomes(
        vault,
        party,
        channel_class,
        WITHHELD_CLEAR_RECEIPT_OUTCOME,
        super::consent::OPT_OUT_CLEAR_APPROVED,
    )
}

/// Test door: retracts each standing opt-out head on `party`'s
/// `channel_class` slot through the generic claim door, as an owner's
/// `vault.claims.retract` does: no clear request and no receipt. Answers how
/// many it retracted.
#[cfg(oneiron_test_support)]
pub(crate) fn retract_standing_opt_outs(
    vault: &Vault,
    party: &str,
    channel_class: &str,
    at: u64,
) -> CommResult<usize> {
    let party_ref = super::parties::resolve_party(vault, party)?.ok_or(CommError::InvalidRecord)?;
    let channel = crate::counterparty_contact::normalize_channel_class(channel_class);
    let standing = {
        let rtxn = vault.store.env.read_txn()?;
        matching_claims_in_txn(
            vault,
            &rtxn,
            party_ref,
            PREDICATE_COMM_OPT_OUT,
            Some(channel.as_str()),
            None,
            true,
        )?
    };
    for (claim_id, _) in &standing {
        vault.retract_claim(claim_id, at)?;
    }
    Ok(standing.len())
}
