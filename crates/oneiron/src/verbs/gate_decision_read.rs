//! One gate decision under a live verb Grant and the explain door's visibility rule.

use super::ExplainGateRequest;
use crate::EntityId;
use crate::claim::{ClaimReadStatus, ScopedReadResult};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::store::GateDecisionId;

const GATE_DECISION_GET_READ_VERB: &str = "vault.gate.decision.get";

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::gate_decision_read::{
    GateDecisionReadNotice, GateDecisionReadView,
};

/// Reads one gate decision in the lane's serving snapshot: the verb Grant,
/// own/owner/readable-claim admission and reference screening are checked with
/// the ledger read. Malformed, unknown and invisible receipts all answer `None`.
/// The narrowing receipt is the lane's scope, not a new persisted gate receipt.
pub fn vault_gate_decision_get_embedded(
    memory: &Memory<'_>,
    input: ExplainGateRequest,
) -> MemoryResult<ScopedReadResult<Option<GateDecisionReadView>>> {
    let lane = memory.read_lane(ClaimReadStatus::Recorded)?;
    lane.read_projected(&[], None, |txn, _| {
        let standing = crate::authority::principal_standing_in_txn(
            memory.vault(),
            txn,
            memory.actor(),
            memory.actor_class(),
            GATE_DECISION_GET_READ_VERB,
        )?;
        if standing.is_none() {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                format!("{GATE_DECISION_GET_READ_VERB} takes a live Grant naming the verb"),
                &["Have the owner grant this caller the verb by name."],
            ));
        }
        let Some(decision_id) = decode_gate_read_receipt(&input.receipt) else {
            return Ok(None);
        };
        let Some(record) = memory
            .vault()
            .store
            .gate_decision_in_txn(txn, decision_id)?
        else {
            return Ok(None);
        };
        let policy = lane.live_policy_manifest_in(txn)?;
        let own = record.actor_ref.as_deref() == Some(lane.actor_key().actor_ref());
        let owner = lane.actor_key().reads_as_vault_owner();
        let claim = record.claim_id.and_then(|id| EntityId::from_bytes(id).ok());
        let claim_readable = match claim {
            Some(id) => lane.is_entity_readable_with_policy_in(txn, &policy, &id)?,
            None => false,
        };
        if !(own || owner || claim_readable) {
            return Ok(None);
        }
        let mut served = Vec::new();
        let actor_ref = match record.actor_ref.as_deref() {
            Some(actor) if own || owner => Some(actor.to_owned()),
            Some(actor) => match EntityId::from_hex(actor) {
                Ok(id) if lane.is_ref_readable_with_policy_in(txn, &policy, &id)? => {
                    served.push(id);
                    Some(id.to_hex())
                }
                _ => None,
            },
            None => None,
        };
        let grant_ref = match record.grant_ref.as_deref() {
            Some(reference) if own || owner => Some(reference.to_owned()),
            Some(reference) => match EntityId::from_hex(reference) {
                Ok(id) if lane.is_ref_readable_with_policy_in(txn, &policy, &id)? => {
                    served.push(id);
                    Some(reference.to_owned())
                }
                _ => None,
            },
            None => None,
        };
        let claim_ref = claim.filter(|_| claim_readable || owner).map(|id| {
            if claim_readable {
                served.push(id);
            }
            id.to_hex()
        });
        memory.produced_from(served);
        Ok(Some(GateDecisionReadView {
            receipt_id: format!("gate:{}", record.decision_id.to_hex()),
            decided_at: record.created_at,
            outcome: record.outcome,
            reason_codes: record.reason_codes,
            receipt_reasons: record.receipt_reasons,
            notices: record
                .system_notices
                .into_iter()
                .map(|notice| GateDecisionReadNotice {
                    notice_type: notice.notice_type,
                    row_ref: notice.row_ref,
                })
                .collect(),
            actor_class: record.actor_class,
            actor_ref,
            content_kind: record.content_kind,
            policy_manifest_version: record.policy_manifest_version,
            claim_ref,
            version: record.version,
            redacted_at: record.redacted_at,
            grant_ref,
            read_frontier_hash: (own || owner).then(|| {
                blake3::Hash::from_bytes(record.read_frontier_hash)
                    .to_hex()
                    .to_string()
            }),
        }))
    })
}

/// Accept the explain door's exact `gate:` plus sixteen-byte hex grammar.
fn decode_gate_read_receipt(receipt: &str) -> Option<GateDecisionId> {
    let hex = receipt
        .strip_prefix("gate:")
        .filter(|hex| hex.len() == 32)?;
    let mut bytes = [0_u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(GateDecisionId::from_bytes(bytes))
}
