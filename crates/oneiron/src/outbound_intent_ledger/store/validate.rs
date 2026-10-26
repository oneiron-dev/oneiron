//! The ledger row's own validation: endpoint, binding, approval, budget
//! marker, state and outcome, payload hash and intent identity.

use super::super::dispatch::derive_intent_id;
use super::super::payload;
use super::super::types::{
    IntentLedgerError, IntentLedgerRecord, IntentLedgerResult, IntentState,
    OUTBOUND_BINDING_VERSION, RecordedOutboundOutcome,
};
use super::approval;
use crate::entity_id::bytes_to_hex_lower;

pub(crate) fn hash_frozen_payload(payload: &[u8]) -> [u8; 32] {
    *blake3::hash(payload).as_bytes()
}

pub(in crate::outbound_intent_ledger) fn validate_record(
    record: &IntentLedgerRecord,
) -> IntentLedgerResult<()> {
    if record.server.trim().is_empty() || record.tool.trim().is_empty() {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent endpoint is empty",
        ));
    }
    if record.updated_ms < record.created_ms {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent updated_ms predates created_ms",
        ));
    }
    if record.binding_version != OUTBOUND_BINDING_VERSION {
        return Err(IntentLedgerError::InvalidRecord(
            "unsupported outbound intent binding_version",
        ));
    }
    if record
        .resolved_endpoint
        .as_deref()
        .is_some_and(|endpoint| endpoint.trim().is_empty() || endpoint != endpoint.trim())
    {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent resolved_endpoint is invalid",
        ));
    }
    if record.capability_provenance.is_some() && record.resolved_endpoint.is_none() {
        return Err(IntentLedgerError::InvalidRecord(
            "capability-bound intent is missing resolved endpoint",
        ));
    }
    // An endpoint-bound row is produced only by scoped authorization. Keeping
    // its typed provenance is what prevents recovery from downgrading it to an
    // ordinary connector when the row is reconstructed.
    if record.resolved_endpoint.is_some() && record.capability_provenance.is_none() {
        return Err(IntentLedgerError::InvalidRecord(
            "endpoint-bound intent is missing capability provenance",
        ));
    }
    if let Some(capability) = record.capability_provenance.as_ref()
        && capability.server() != record.server
    {
        return Err(IntentLedgerError::InvalidRecord(
            "capability-bound intent server does not match provenance",
        ));
    }
    if record.resolved_endpoint.is_some() && record.authorization_binding.is_none() {
        return Err(IntentLedgerError::InvalidRecord(
            "endpoint-bound intent is missing authorization binding",
        ));
    }
    // A capability identity only ever exists on the verified scoped path, which
    // always mints an authorization binding in the same admission step; a row
    // carrying one without the other is not a row this engine wrote.
    if record.capability_provenance.is_some() && record.authorization_binding.is_none() {
        return Err(IntentLedgerError::InvalidRecord(
            "capability-bound intent is missing authorization binding",
        ));
    }
    // A sealed request is checked when it opens, an erased one never again
    // (FIX 9283, 9372): the stored form keeps its digest, not its hash.
    let readable = payload::readable_payload(record.payload())?;
    if let Some(payload) = readable {
        approval::validate_admitted_approval(record, payload)?;
    }
    if record.state == IntentState::Pending && payload::payload_erased(record.payload())? {
        return Err(IntentLedgerError::InvalidRecord(
            "an erased outbound intent cannot stay pending",
        ));
    }
    if record.budget_accounting.key_ref.is_none()
        && (!record.budget_accounting.matched_rows.is_empty()
            || record.budget_accounting.sends_debit != 0)
    {
        return Err(IntentLedgerError::InvalidRecord(
            "unkeyed budget marker contains a debit",
        ));
    }
    if record.budget_accounting.sends_debit > 1
        || (!record.budget_accounting.budget_class.is_send()
            && record.budget_accounting.sends_debit != 0)
    {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent sends debit is invalid",
        ));
    }
    if record
        .budget_accounting
        .matched_rows
        .windows(2)
        .any(|rows| rows[0] >= rows[1])
    {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent matched rows are not canonical",
        ));
    }
    let outcome_matches_state = matches!(
        (record.state, record.recorded_outcome),
        (IntentState::Pending, None)
            | (
                IntentState::Pending,
                Some(RecordedOutboundOutcome::DefiniteNonDelivery)
            )
            | (IntentState::Done, Some(RecordedOutboundOutcome::Acked))
            | (
                IntentState::Abandoned,
                Some(RecordedOutboundOutcome::Abandoned(_))
            )
    );
    if !outcome_matches_state {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent state and recorded_outcome disagree",
        ));
    }
    if readable.is_some_and(|payload| hash_frozen_payload(payload) != record.payload_hash) {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent payload hash mismatch",
        ));
    }
    if bytes_to_hex_lower(&record.id) != record.idempotency_key {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent idempotency key mismatch",
        ));
    }
    let derived = derive_intent_id(
        record.attempt_id,
        record.call_seq,
        &record.server,
        &record.tool,
        &record.payload_hash,
    )?;
    if derived != record.id {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent identity hash mismatch",
        ));
    }
    Ok(())
}
