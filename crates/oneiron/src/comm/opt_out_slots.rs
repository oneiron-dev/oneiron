//! One (party, channel) opt-out slot read across the party's redirect shells,
//! and the pending human-clear gates on it: what the clear flow in `consent`
//! reads and consumes.

use std::collections::BTreeSet;

use super::claims::{CommResult, PREDICATE_COMM_OPT_OUT};
use super::parties::active_comm_party_key_in_txn;
use super::projection_writes::matching_claims_in_txn;
use super::records::{CommRecord, put_comm_record_in_txn};
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
