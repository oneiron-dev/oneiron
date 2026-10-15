//! One (party, channel) opt-out slot read across the party's redirect shells,
//! and the pending human-clear gates on it: what the clear flow in `consent`
//! reads and consumes.

use std::collections::BTreeSet;

use super::claims::{CommResult, PREDICATE_COMM_OPT_OUT};
use super::projection_writes::matching_claims_in_txn;
use super::records::{CommRecord, put_comm_record_in_txn};
use crate::Vault;
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

/// When a pending clear gate for `channel_class` on one of `subjects` was
/// requested; `None` for every other record.
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
        } if subjects.contains(party_ref) && candidate == channel_class => Some(*created_at),
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
