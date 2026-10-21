//! FIX 990: the tool's capability setting (DEC-0006) at the last boundary
//! before a Pending scoped call's send, live or hostless.
//!
//! The boundary reads one snapshot of the call's key, its approved manifest,
//! the tool's setting (a per-grant key's catalog slate included) and the
//! charters, after the live retry's Gate and the frozen binding check and
//! before the retry permit, the dedupe touch and the send. It is the last
//! observed state, not atomic with the network send that follows.
//!
//! `never allow` stops the request: its ledger row is abandoned, keeping
//! what it knew of its delivery, so no later sweep sends it. `always ask`
//! sends only on the owner's press on exactly this call: the press the
//! current pass's own admission spent, carried in memory (its kept copy is
//! best-effort); else the copy kept beside this row; else a still-available
//! marker for the row's own recomposed target, spent here once and kept for
//! its retry. A spent marker is no fresh authority. With none of them the
//! row stays Pending and names its approve-once digest. Nothing here
//! changes the row's payload, id, idempotency key, budget marker, retry
//! permit or delivery facts, and nothing is admitted or charged again.

use super::replay::{RecoveryGovernance, effect_result, recovery_governance};
use super::types::OutboundEffectResult;
use crate::Vault;
use crate::connector_key::SlateDisposition;
use crate::consent::EffectDigest;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, GateError};
use crate::outbound_consent::{SLATE_ALWAYS_ASK_REASON, frozen_scoped_candidate_in_txn};
use crate::outbound_intent_ledger::{
    AdmittedApproval, IntentEscalationReason, IntentLedgerError, IntentLedgerRecord, IntentState,
    PinnedApproval, PinnedApprovalFamily, abandon_record, keep_pinned_approval_in_txn,
    keep_press_after_admission, pinned_retry_approval, read_intent_record_in_txn,
};

/// What the writer found for an `always ask` call.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Release {
    /// A press already proved for this row, or the setting moved off ask.
    Send,
    /// An available exact marker, spent in this writer.
    Spent,
    /// No press: the call waits for the owner.
    Ask,
}

/// The last snapshot before `record`'s send: `None` lets the send go on;
/// otherwise the result the pass ends with. `pass_proof` is the press this
/// pass's own admission spent on this row, if it spent one.
///
/// # Errors
/// Storage errors.
pub(super) fn send_boundary(
    vault: &Vault,
    record: &IntentLedgerRecord,
    pass_proof: Option<EffectDigest>,
    now_ms: u64,
    replayed: bool,
) -> Result<Option<OutboundEffectResult>, IntentLedgerError> {
    let stop = |reason| -> Result<_, IntentLedgerError> {
        let abandoned = abandon_record(vault, record.id, reason, now_ms)?;
        Ok(Some(effect_result(
            &abandoned,
            None,
            replayed,
            Some(reason),
        )))
    };
    match recovery_governance(vault, record)? {
        RecoveryGovernance::Allow => Ok(None),
        RecoveryGovernance::Block(reason) => {
            let mut held = effect_result(record, None, replayed, None);
            held.gate_receipt_reasons.push(reason.to_owned());
            Ok(Some(held))
        }
        RecoveryGovernance::Revoke => stop(IntentEscalationReason::ConnectorRevoked),
        RecoveryGovernance::NeverAllow => stop(IntentEscalationReason::ConnectorSlateNeverAllow),
        // The Gate admitted this pass only on the press it spent.
        RecoveryGovernance::AlwaysAsk if pass_proof.is_some() => Ok(None),
        RecoveryGovernance::AlwaysAsk => always_ask(vault, record, replayed),
    }
}

/// An `always ask` row with no press of this pass: its kept press, else an
/// available exact marker, else a hold naming its approve-once digest.
fn always_ask(
    vault: &Vault,
    record: &IntentLedgerRecord,
    replayed: bool,
) -> Result<Option<OutboundEffectResult>, IntentLedgerError> {
    let candidate = {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        frozen_scoped_candidate_in_txn(vault, &txn, record)?
    };
    let Some(candidate) = candidate else {
        return Ok(Some(held(record, replayed, None)));
    };
    let digest = candidate.digest;
    let release = vault.try_with_write_txn(|wtxn| -> Result<Release, IntentLedgerError> {
        let current = read_intent_record_in_txn(vault, wtxn, &record.id)?;
        if current.is_none_or(|row| row.state != IntentState::Pending) {
            return Ok(Release::Ask);
        }
        match setting_in_txn(vault, wtxn, record)? {
            SlateDisposition::AlwaysAsk => {}
            // A later pass stops it.
            SlateDisposition::NeverAllow => return Ok(Release::Ask),
            SlateDisposition::Auto | SlateDisposition::AlwaysAllow => return Ok(Release::Send),
        }
        if pinned_retry_approval(vault, wtxn, record.id, &candidate.gate)
            .is_some_and(|kept| kept.effect_digest() == digest)
        {
            return Ok(Release::Send);
        }
        match crate::consent::approve_once_authorization_in_txn(&vault.store, wtxn, &digest) {
            Ok(Some(tap)) => {
                crate::consent::spend_approve_once_in_txn(&vault.store, wtxn, &tap)?;
                Ok(Release::Spent)
            }
            Ok(None) | Err(Error::Gate(GateError::ConsentApproveOnceSpent(_))) => Ok(Release::Ask),
            Err(error) => Err(error.into()),
        }
    })?;
    match release {
        Release::Send => Ok(None),
        Release::Spent => {
            let subject = bytes_to_hex_lower(&record.id);
            let kept = PinnedApproval::new(
                PinnedApprovalFamily::ScopedMcp,
                AdmittedApproval::from_gate(record.id, digest),
            );
            keep_press_after_admission(vault, &subject, |wtxn| {
                keep_pinned_approval_in_txn(vault, wtxn, Some(kept))
            })?;
            tracing::info!(
                reason = "connector_slate_always_ask_press_spent",
                intent = %subject,
                "the owner's press on an always-ask connector call was spent at its send"
            );
            Ok(None)
        }
        Release::Ask => Ok(Some(held(
            record,
            replayed,
            Some((digest, candidate.actor)),
        ))),
    }
}

/// The tool's setting under `record`'s key now, in `txn`. A row with no key
/// meets none.
fn setting_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &IntentLedgerRecord,
) -> Result<SlateDisposition, IntentLedgerError> {
    let Some(key_ref) = record.budget_accounting.key_ref.as_ref() else {
        return Ok(SlateDisposition::Auto);
    };
    let Some(key) = crate::connector_key::read_key_for_pack_in_txn(vault, txn, key_ref)? else {
        return Ok(SlateDisposition::AlwaysAsk);
    };
    Ok(crate::connector_key::connector_tool_setting_in_txn(
        &vault.store,
        txn,
        &key,
        &record.tool,
    )?)
}

/// `record` kept Pending for the owner's press, naming the digest and actor
/// of `target` when the row recomposes one.
fn held(
    record: &IntentLedgerRecord,
    replayed: bool,
    target: Option<(EffectDigest, EntityId)>,
) -> OutboundEffectResult {
    let mut held = effect_result(record, None, replayed, None);
    held.gate_outcome = Some("pending".to_owned());
    held.gate_receipt_reasons
        .push(SLATE_ALWAYS_ASK_REASON.to_owned());
    held.approval_digest = target.map(|(digest, _)| digest.to_hex());
    held.approval_actor = target.map(|(_, actor)| actor);
    held
}
