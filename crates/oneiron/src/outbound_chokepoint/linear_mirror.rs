//! Current native two-principal policy for a frozen Linear mirror replay.

use crate::Vault;
use crate::consent::approval_proof::{AdmittedApproval, PinnedApproval};
use crate::error::Error;
use crate::gate::{self, GateOutcome};
use crate::linear_sync::LinearEffectHold;
use crate::outbound_intent_ledger::{
    IntentLedgerError, IntentLedgerRecord, keep_pinned_approval_in_txn, pinned_retry_approval,
};

use super::ordinary_slate::OrdinaryCandidate;
use super::types::{FirstPassAdmission, OutboundEffectResult};

pub(super) enum LinearRelease {
    Send,
    Spent,
    Held(LinearEffectHold),
}

/// A primary press alone cannot stand in for this mutation's other principal.
pub(super) fn is_candidate(
    vault: &Vault,
    record: &IntentLedgerRecord,
) -> Result<bool, IntentLedgerError> {
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    Ok(
        super::ordinary_slate::candidate_in_txn(vault, &txn, record)?
            .is_some_and(|candidate| candidate.mirror.is_some()),
    )
}

pub(super) fn release_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    record: &IntentLedgerRecord,
    candidate: &OrdinaryCandidate,
    admission: Option<&FirstPassAdmission>,
) -> Result<LinearRelease, IntentLedgerError> {
    let request = candidate
        .mirror
        .as_ref()
        .ok_or(IntentLedgerError::InvalidInput(
            "outbound intent names no native Linear mirror",
        ))?;
    let co = crate::linear_sync::linear_writer_co_actor_in_txn(vault, txn, request)?;
    let writer = co
        .effect
        .provenance
        .actor_entity_ref
        .ok_or(IntentLedgerError::InvalidBoundActor)?;
    let policy = gate::resolve_policy_manifest(&vault.store, txn)?;
    // These two in-memory proofs came from this very Pending admission's
    // Allow decisions. They survive its deliberately best-effort keepers.
    let primary_pass = admission
        .and_then(|pass| pass.primary_press)
        .filter(|digest| *digest == candidate.digest)
        .map(|digest| AdmittedApproval::from_gate(record.id, digest));
    let writer_pass = admission
        .and_then(|pass| pass.co_actor.as_ref())
        .filter(|pass| pass.effect == co.effect)
        .and_then(|pass| pass.spent_press)
        .filter(|digest| gate::external_effect_approval_digest(&co.effect) == Some(*digest))
        .map(|digest| AdmittedApproval::from_gate(record.id, digest));
    let primary =
        primary_pass.or_else(|| pinned_retry_approval(vault, txn, record.id, &candidate.gate));
    let pair = gate::check_external_effect_policy_pair(
        &vault.store,
        txn,
        &candidate.gate,
        &co.effect,
        &policy,
        false,
        [primary, writer_pass.or(co.kept_press)],
    )?
    .ok_or(Error::InvariantViolation(
        "a replayed Linear pair unexpectedly paced",
    ))?;
    if pair.admitted.is_none() {
        for ((_, outcome), effect) in pair.decisions.iter().zip([&candidate.gate, &co.effect]) {
            if *outcome == GateOutcome::Pending {
                super::ordinary_slate::queue_effect_ask_in_txn(vault, txn, record, effect)?;
            }
        }
        return Ok(LinearRelease::Held(
            crate::linear_sync::linear_outbound_pair_hold(
                &pair,
                [
                    (request.scheduler_actor, &candidate.gate),
                    (writer, &co.effect),
                ],
            ),
        ));
    }
    let [primary_spent, writer_spent] = pair.spent_presses;
    if let Some(digest) = primary_spent {
        keep_pinned_approval_in_txn(
            vault,
            txn,
            Some(PinnedApproval::new(
                candidate.family,
                AdmittedApproval::from_gate(record.id, digest),
            )),
        )?;
    }
    if let Some(digest) = writer_spent {
        (co.keep_press)(vault, txn, digest)?;
    }
    Ok(if primary_spent.is_some() || writer_spent.is_some() {
        LinearRelease::Spent
    } else {
        LinearRelease::Send
    })
}

pub(super) fn held_result(
    record: &IntentLedgerRecord,
    hold: LinearEffectHold,
    replayed: bool,
) -> OutboundEffectResult {
    let mut result = super::connector_slate::held(record, replayed, None);
    result.gate_decision_id = Some(hold.gate_decision_ref);
    result.gate_outcome = Some(hold.gate_outcome);
    result.approval_digest = hold.approval_digest;
    result.approval_actor = Some(hold.actor);
    result
}
