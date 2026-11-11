//! Same-intent frozen effect proof for an admitted code consent rebind.

use crate::Vault;
use crate::code_run::CodeConsentWaitRow;
use crate::consent::EffectDigest;
use crate::outbound_intent_ledger::{
    IntentLedgerError, IntentResolution, read_intent_for_attempt_in_txn,
};

use super::connector_call::{PENDING_CALLS, now_ms};
use super::connector_call_consent::frozen_scoped_candidate_in_txn;
use super::connector_call_pending::CONNECTOR_CALL_PENDING_TTL_MS;

/// Recompose only the existing admission's frozen call. Nothing is prepared,
/// admitted, sent, charged or changed here; all reads share the caller's writer.
pub(crate) fn code_wait_rebind_effects_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &CodeConsentWaitRow,
    current_binding: &[u8; 32],
    successor_binding: &[u8; 32],
) -> Result<(EffectDigest, EffectDigest), IntentLedgerError> {
    let changed = || IntentLedgerError::InvalidInput("the admitted code consent target changed");
    let admission = row.admission.as_ref().ok_or_else(changed)?;
    let call = row.binding.pending.connector_call().ok_or_else(changed)?;
    let pending = PENDING_CALLS
        .get(&vault.store, txn, &call.call_ref)?
        .ok_or_else(changed)?;
    if !row.approved_unsettled()
        || row.consumption.is_some()
        || pending.code_consent_wait != Some(row.binding.wait_id)
        || pending.settled.is_some()
        || pending.input.is_some()
        || pending.attempt_id.as_bytes() != &call.attempt_id
        || pending.call_seq != call.call_seq
        || pending.name != call.name
        || pending.tool != call.tool
        || pending.credential != call.credential_record
        || pending.grant_id.as_deref() != Some(call.grant_ref.to_hex().as_str())
        || (pending.paced_until.is_none()
            && now_ms()
                >= pending
                    .held_at_ms
                    .saturating_add(CONNECTOR_CALL_PENDING_TTL_MS))
    {
        return Err(changed());
    }
    let record = read_intent_for_attempt_in_txn(vault, txn, pending.attempt_id, pending.call_seq)?
        .filter(|record| record.id == admission.intent_id)
        .ok_or_else(changed)?;
    if !matches!(
        IntentResolution::from_record(&record)?,
        IntentResolution::Pending { .. }
    ) || blake3::hash(record.payload()).as_bytes() != &row.binding.frozen_input_digest
        || record
            .capability_provenance()
            .is_none_or(|capability| capability.grant_id() != call.grant_ref)
    {
        return Err(changed());
    }
    let candidate = frozen_scoped_candidate_in_txn(vault, txn, &record)?.ok_or_else(changed)?;
    let prepared = &candidate.prepared;
    let frozen = prepared.call();
    let manifest = prepared.manifest_binding().ok_or_else(changed)?;
    if candidate.principal_ref != pending.principal_ref
        || frozen.server != call.server
        || frozen.tool != call.tool
        || frozen.resolved_endpoint != call.endpoint
        || manifest.key_ref != call.key_ref.to_hex()
        || manifest.manifest_hash != call.manifest_hash
        || manifest.protocol_revision != call.protocol_revision
    {
        return Err(changed());
    }
    let gate =
        super::execution::scoped_mcp_gate_input(&candidate.principal_ref, call.grant_ref, frozen);
    let compose =
        |binding| crate::gate::code_wait_approval_digest(&gate, binding).ok_or_else(changed);
    if compose(&row.binding.binding_digest)?.as_bytes() != &row.binding.effect_digest {
        return Err(changed());
    }
    Ok((compose(current_binding)?, compose(successor_binding)?))
}

/// Resolve only the code wait owning this persisted frozen intent.
/// The native wait door validates its current consumed authorization in `txn`.
pub(crate) fn code_wait_retry_approval_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &crate::outbound_intent_ledger::IntentLedgerRecord,
) -> Result<bool, IntentLedgerError> {
    let Some(current) =
        crate::outbound_intent_ledger::read_intent_record_in_txn(vault, txn, &record.id)?
    else {
        return Ok(false);
    };
    if current.state != crate::outbound_intent_ledger::IntentState::Pending
        || current.attempt_id != record.attempt_id
        || current.call_seq != record.call_seq
        || current.payload() != record.payload()
        || current.server != record.server
        || current.tool != record.tool
        || current.resolved_endpoint != record.resolved_endpoint
        || current.budget_accounting.key_ref != record.budget_accounting.key_ref
        || current
            .capability_provenance()
            .map(|capability| capability.grant_id())
            != record
                .capability_provenance()
                .map(|capability| capability.grant_id())
    {
        return Ok(false);
    }
    let Some(candidate) = frozen_scoped_candidate_in_txn(vault, txn, &current)? else {
        return Ok(false);
    };
    let call_ref = super::connector_call::connector_call_ref(
        &candidate.principal_ref,
        super::connector_call::ConnectorCallInvocation {
            attempt_id: current.attempt_id,
            call_seq: current.call_seq,
        },
    )?;
    let Some(wait_id) = PENDING_CALLS
        .get(&vault.store, txn, &call_ref)?
        .and_then(|pending| pending.code_consent_wait)
    else {
        return Ok(false);
    };
    Ok(vault.code_consent_retry_approval_in_txn(txn, &current, wait_id)?)
}
