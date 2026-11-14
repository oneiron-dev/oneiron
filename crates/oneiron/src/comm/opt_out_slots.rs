//! One (party, channel) opt-out slot read across the party's redirect shells,
//! and the pending human-clear gates on it: what the clear flow in `consent`
//! reads and consumes.

use std::collections::BTreeSet;

use super::claims::{CommClaim, CommResult, PREDICATE_COMM_OPT_OUT};
use super::consent::{OPT_OUT_CLEAR_APPROVED, parties_opt_out_subjects_in_txn};
use super::parties::active_comm_party_key_in_txn;
use super::projection_writes::{claim_transition_boundary, matching_claims_in_txn};
use super::records::{CommEventKind, CommRecord, comm_records_in_txn, put_comm_record_in_txn};
use crate::Vault;
use crate::counterparty_contact::normalize_channel_class;
use crate::entity_id::EntityId;

/// One standing `comm.opt_out` head on a (party, channel) slot.
pub(super) struct OptOutSlotHead {
    /// The subject the head stands on: the party or one of its shells.
    pub(super) subject: EntityId,
    /// The head's own claim id.
    pub(super) claim_ref: EntityId,
    /// When the head became valid; 0 when the claim names no start.
    pub(super) valid_from: u64,
}

/// The standing `comm.opt_out` heads on one channel SLOT across `subjects`, in
/// claim-id order.
///
/// The slot read stays per subject (`matching_claims_in_txn`), as the projector
/// needs it; the clear flow unions it, because a clear must reach every head
/// the fold reads. One subject can hold several heads, since provider
/// spellings normalize to one slot (F06 H415).
pub(super) fn opt_out_slot_heads_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    subjects: &BTreeSet<EntityId>,
    channel_class: &str,
) -> CommResult<Vec<OptOutSlotHead>> {
    let mut heads = Vec::new();
    for subject in subjects {
        for (claim_ref, claim) in matching_claims_in_txn(
            vault,
            rtxn,
            *subject,
            PREDICATE_COMM_OPT_OUT,
            Some(channel_class),
            None,
            true,
        )? {
            heads.push(OptOutSlotHead {
                subject: *subject,
                claim_ref,
                valid_from: claim.valid_from.unwrap_or(0),
            });
        }
    }
    heads.sort_unstable_by_key(|head| head.claim_ref);
    Ok(heads)
}

/// When a pending clear gate for the normalized `channel_class` on one of
/// `subjects` was requested; `None` for every other record. A gate keeps the
/// spelling it was written with, so it is compared normalized (F06 R3-F3).
pub(super) fn pending_clear_request_at(
    record: &CommRecord,
    subjects: &BTreeSet<EntityId>,
    channel_class: &str,
) -> Option<u64> {
    match record {
        CommRecord::Gate {
            party_ref,
            channel_class: candidate,
            created_at,
            pending: true,
            ..
        } if subjects.contains(party_ref)
            && normalize_channel_class(candidate) == channel_class =>
        {
            Some(*created_at)
        }
        _ => None,
    }
}

/// The restrictive-wins rule of the clear flow: a STOP that occurred at
/// `stop_at` makes a clear requested at `request_at` stale when it occurred at
/// or after the request. Approval authorizes the request, not the current
/// state, so the restriction forces a fresh request. The approval in `consent`
/// and the projector's gate consume both decide by this rule.
pub(super) fn stop_supersedes_clear_request(stop_at: u64, request_at: u64) -> bool {
    stop_at >= request_at
}

/// The transition on `subject`'s `channel_class` slot that answers a STOP
/// that occurred at `stop_at`, given the slot's `history`: the latest
/// boundary after the STOP that answers it, or `None` when nothing after it
/// does.
///
/// A head on the slot closes in two ways. An approved clear closes it at its
/// ruling, or at the head's start when that came later, and writes its
/// receipt in the same transaction. The projector closes a late STOP's own
/// head at the boundary that answered it: a later head's start or a clear's
/// close. A later head's start answers the STOP: that head carries the
/// opt-out on.
///
/// A clear's close answers the STOP only when its receipt is here and the
/// clear was requested after the STOP. A clear requested at or before it is
/// stale against it (`stop_supersedes_clear_request`), and the approval
/// refuses such a clear when the STOP is already here (FIX 22384). A STOP
/// that reaches this replica only after the ruling (a delayed webhook, a
/// peer's copy by sync that its peer had not projected) is judged by the
/// same rule (COMM-STOP-LATE-ARRIVAL). A copy its peer had projected mints
/// nothing here (`peer_stop_projection_in_txn`).
/// A receipt that names no request was written before receipts did; its
/// close answers, as it did then.
///
/// A close that neither a receipt nor a later head's start explains answers
/// nothing: restrictive wins. Sync imports a closed head and its clear's
/// receipt as separate rows, so a STOP projected between the two cannot tell
/// which request the clear judged, and it stands. When the clear was in fact
/// requested after it, the STOP's opt-out outlives that clear, and a fresh
/// clear lifts it. The receipts are read only when some boundary falls after
/// the STOP.
pub(super) fn stop_answering_boundary_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    history: &[(EntityId, CommClaim)],
    subject: EntityId,
    channel_class: &str,
    stop_at: u64,
) -> CommResult<Option<u64>> {
    let later: Vec<(&CommClaim, u64)> = history
        .iter()
        .filter_map(|(_, claim)| claim_transition_boundary(claim).map(|at| (claim, at)))
        .filter(|(_, at)| *at > stop_at)
        .collect();
    if later.is_empty() {
        return Ok(None);
    }
    // When each approved clear on this slot that answers the STOP was ruled:
    // the clears requested after the STOP, and those whose receipt names no
    // request.
    let mut answering_rulings = Vec::new();
    for (_, record) in comm_records_in_txn(vault, rtxn)? {
        let CommRecord::Receipt {
            party_ref,
            channel_class: receipt_channel,
            occurred_at,
            outcome,
            requested_at,
            ..
        } = record
        else {
            continue;
        };
        if outcome != OPT_OUT_CLEAR_APPROVED
            || normalize_channel_class(&receipt_channel) != channel_class
            || requested_at
                .is_some_and(|requested_at| stop_supersedes_clear_request(stop_at, requested_at))
        {
            continue;
        }
        // The clear retracted the heads on its party and the party's
        // redirect shells.
        let subjects = parties_opt_out_subjects_in_txn(&vault.store, rtxn, [party_ref].into())?;
        if subjects.contains(&subject) {
            answering_rulings.push(occurred_at);
        }
    }
    Ok(later
        .into_iter()
        .filter(|(claim, at)| {
            claim.is_standing()
                || history
                    .iter()
                    .any(|(_, other)| other.valid_from == Some(*at))
                || answering_rulings
                    .iter()
                    .any(|ruled_at| (*ruled_at).max(claim.valid_from.unwrap_or(0)) == *at)
        })
        .map(|(_, at)| at)
        .max())
}

/// Whether `record` is an inbound STOP on one of `subjects` for the
/// normalized `channel_class` that re-asserts the opt-out past the newest
/// standing head (`newest_head`) and supersedes a clear requested at
/// `request_at`.
///
/// The `projected` flag is not read. A STOP recorded here but not projected
/// yet is the party's word as much as a projected one: an approval that let
/// it pass would close the slot at the ruling, and the STOP's own projection,
/// landing behind that boundary, would be retracted for good (FIX 22384).
/// The event keeps its source spelling, so it is compared normalized, as the
/// projector reads it (F06 R3-F3).
pub(super) fn recorded_stop_supersedes_clear(
    record: &CommRecord,
    subjects: &BTreeSet<EntityId>,
    channel_class: &str,
    request_at: u64,
    newest_head: u64,
) -> bool {
    matches!(record, CommRecord::Event {
        kind: CommEventKind::InboundStop,
        party_ref,
        channel_class: Some(event_channel),
        occurred_at,
        ..
    } if subjects.contains(party_ref)
        && normalize_channel_class(event_channel) == channel_class
        && *occurred_at > newest_head
        && stop_supersedes_clear_request(*occurred_at, request_at))
}

/// Marks each pending clear gate consumed, keeping what it recorded.
pub(super) fn consume_clear_gates_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    gates: &[(EntityId, &CommRecord, u64)],
) -> CommResult<()> {
    for (gate_id, gate, _) in gates {
        if let CommRecord::Gate {
            party_ref,
            channel_class,
            claim_ref,
            created_at,
            ..
        } = gate
        {
            let consumed = CommRecord::Gate {
                party_ref: *party_ref,
                channel_class: channel_class.clone(),
                claim_ref: *claim_ref,
                created_at: *created_at,
                pending: false,
            };
            put_comm_record_in_txn(vault, wtxn, *gate_id, &consumed)?;
        }
    }
    Ok(())
}

/// Re-derives the type-132 cache of every contact that folds a
/// `channel_class` head standing on one of `subjects`.
///
/// A contact folds the heads of the ACTIVE party its key resolves to, and that
/// party reads its shells through, so a head on a shell reaches the contacts of
/// every active party the shell points at: a twin's survivor shares its key
/// (F06 H170), and a merge of two different keys puts the survivor's contacts
/// under the shell's heads (F06 R2-F3). Those parties come from the witnesses
/// the fold's inbound walk reads, not the redirect table alone, and the walk
/// has no depth or cycle error, so a dropped table or a long chain can neither
/// narrow the refresh nor refuse the STOP (F06 R3-F1, R3-F2). A merged
/// entity's own key is skipped: no active party answers it, so a rebuild there
/// folds none of the heads it still carries and would drop its STOP (F06
/// R4-F1). That also keeps a chain at one refresh per active head (R4-F2).
/// Each key's contacts come from the full scan the send gate also uses:
/// the party-channel index (ONE-1868) cannot prove it lists every contact.
/// Channel scope stays the fold's class match, so an email STOP never
/// re-derives a telegram contact. Answers the contacts whose rows it
/// re-derived.
pub(super) fn rematerialize_subject_contacts_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    subjects: &BTreeSet<EntityId>,
    channel_class: &str,
    now: u64,
) -> CommResult<Vec<EntityId>> {
    let mut parties = subjects.clone();
    parties.extend(crate::identity_redirect::outbound_redirect_heads_in_txn(
        &vault.store,
        &*wtxn,
        subjects,
    )?);
    let mut party_keys = BTreeSet::new();
    for party in parties {
        party_keys.extend(active_comm_party_key_in_txn(&vault.store, &*wtxn, party)?);
    }
    let channel_class = normalize_channel_class(channel_class);
    let mut contacts = Vec::new();
    for party_key in party_keys {
        contacts.extend(
            crate::counterparty_contact::rematerialize_party_contact_cache_in_txn(
                vault,
                wtxn,
                &party_key,
                Some(&channel_class),
                now,
            )?,
        );
    }
    Ok(contacts)
}
