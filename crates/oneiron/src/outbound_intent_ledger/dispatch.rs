//! Recovery walk, canonical-JSON intent identity, and test-only execute/recover/replay.

use super::codec::{INTENT_LEDGER_PRIVATE_PREFIX, id_from_ledger_key};
use super::store::decode_record_in_txn;
#[cfg(test)]
use super::store::{
    abandon_record, complete_record, force_sync, hash_frozen_payload, insert_pending_or_read,
    read_intent_record,
};
#[cfg(test)]
use super::types::{
    BudgetChargeMarker, BudgetClass, FrozenOutboundCall, IntentDispatchResult, IntentEscalation,
    IntentEscalationReason, IntentRecoveryFailure, IntentRecoveryReport, IntentState,
    OUTBOUND_BINDING_VERSION, OutboundCallClass, OutboundSendOutcome, OutboundSender,
    OutboundToolDescriptor, classify_outbound_tool,
};
use super::types::{
    IntentId, IntentLedgerCorruptRow, IntentLedgerError, IntentLedgerListing, IntentLedgerRecord,
    IntentLedgerResult, OutboundCallRequest,
};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::error::Error;

#[allow(clippy::large_enum_variant)]
pub(crate) enum IntentRecoveryEntry {
    Valid(IntentLedgerRecord),
    Corrupt(Option<IntentId>),
}

pub(crate) fn intent_recovery_entries(
    vault: &Vault,
) -> IntentLedgerResult<Vec<IntentRecoveryEntry>> {
    let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
    let mut entries = Vec::new();
    for row in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, INTENT_LEDGER_PRIVATE_PREFIX)?
    {
        let (key, value) = row?;
        entries.push(match decode_record_in_txn(vault, &rtxn, &key, &value) {
            Ok(record) => IntentRecoveryEntry::Valid(record),
            Err(IntentLedgerError::InvalidRecord(_)) => {
                IntentRecoveryEntry::Corrupt(id_from_ledger_key(&key))
            }
            Err(error) => return Err(error),
        });
    }
    Ok(entries)
}

/// Derives the replay-stable BLAKE3 identity from canonical call identity.
///
/// Intent identity keeps its shipped canonical-JSON preimage: it names rows
/// that already exist on device, and it is not what this ledger's content
/// digest covers. The JSON canonicalizer and the entire serde-JSON surface it
/// needs are declared inside this function so no other path in this module —
/// `record_content_digest` above all — can reach a JSON detour.
pub fn derive_intent_id(
    attempt_id: AttemptId,
    call_seq: u64,
    server: &str,
    tool: &str,
    payload_hash: &[u8; 32],
) -> IntentLedgerResult<[u8; 32]> {
    use std::collections::BTreeMap;

    use serde::Serialize;
    use serde_json::{Map as JsonMap, Value as JsonValue};

    #[derive(Serialize)]
    struct IntentIdentity<'a> {
        attempt_id: &'a [u8; 16],
        call_seq: u64,
        server: &'a str,
        tool: &'a str,
        payload_hash: &'a [u8; 32],
    }

    fn canonicalize_json(value: JsonValue) -> JsonValue {
        match value {
            JsonValue::Array(values) => {
                JsonValue::Array(values.into_iter().map(canonicalize_json).collect())
            }
            JsonValue::Object(entries) => {
                let mut sorted = BTreeMap::new();
                for (key, value) in entries {
                    sorted.insert(key, canonicalize_json(value));
                }
                let mut canonical = JsonMap::new();
                for (key, value) in sorted {
                    canonical.insert(key, value);
                }
                JsonValue::Object(canonical)
            }
            scalar => scalar,
        }
    }

    fn canonical_hash<T: Serialize>(value: &T) -> IntentLedgerResult<[u8; 32]> {
        const FAILED: &str = "outbound intent identity canonicalization failed";
        let value =
            serde_json::to_value(value).map_err(|_| IntentLedgerError::InvalidRecord(FAILED))?;
        let bytes = serde_json::to_vec(&canonicalize_json(value))
            .map_err(|_| IntentLedgerError::InvalidRecord(FAILED))?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }

    canonical_hash(&IntentIdentity {
        attempt_id: attempt_id.as_bytes(),
        call_seq,
        server,
        tool,
        payload_hash,
    })
}

/// Test-only ledger primitive fixture. Production effects enter through
/// `outbound_chokepoint::execute_outbound_effect`.
#[cfg(test)]
pub(crate) fn execute_outbound_call<S: OutboundSender + ?Sized>(
    vault: &Vault,
    descriptor: OutboundToolDescriptor,
    request: OutboundCallRequest,
    sender: &mut S,
) -> IntentLedgerResult<IntentDispatchResult> {
    validate_request(&request)?;
    let payload_hash = hash_frozen_payload(&request.payload);
    let intent_id = derive_intent_id(
        request.attempt_id,
        request.call_seq,
        &request.server,
        &request.tool,
        &payload_hash,
    )?;
    if let Some(record) = read_intent_record(vault, &intent_id)? {
        validate_replay_matches_request(&record, &request, &payload_hash)?;
        // Mirror insert_pending_or_read's existing-row fence before replay/resend.
        force_sync(vault)?;
        return replay_dispatch(vault, record, sender, request.now_ms);
    }

    let class = classify_outbound_tool(descriptor);
    if class == OutboundCallClass::ReadOnly {
        let call = FrozenOutboundCall::read_only(request, payload_hash);
        let outcome = sender.send(&call);
        return Ok(IntentDispatchResult {
            class,
            intent_id: None,
            state: None,
            send_outcome: Some(outcome),
            replayed: false,
            escalation: None,
        });
    }

    let authorization_binding =
        request
            .authorization_binding
            .ok_or(IntentLedgerError::InvalidInput(
                "effectful call requires an authorization binding",
            ))?;
    let attempt_id = request.attempt_id;
    let call_seq = request.call_seq;
    let now_ms = request.now_ms;
    let idempotency_supported = descriptor.idempotency_supported();
    let call =
        FrozenOutboundCall::effectful(request, payload_hash, intent_id, idempotency_supported);
    let idempotency_key = call
        .idempotency_key
        .clone()
        .ok_or(IntentLedgerError::InvalidRecord(
            "effectful frozen call is missing idempotency key",
        ))?;
    let new_record = IntentLedgerRecord {
        id: intent_id,
        attempt_id,
        call_seq,
        server: call.server.clone(),
        tool: call.tool.clone(),
        payload_hash: call.payload_hash,
        payload: call.payload.to_vec(),
        idempotency_key,
        idempotency_supported,
        authorization_binding: Some(authorization_binding),
        binding_version: OUTBOUND_BINDING_VERSION,
        resolved_endpoint: call.resolved_endpoint.clone(),
        capability_provenance: call.capability_provenance.clone(),
        budget_accounting: BudgetChargeMarker {
            key_ref: None,
            budget_class: BudgetClass::Send,
            matched_rows: Vec::new(),
            sends_debit: 0,
            accounted_at_ms: now_ms,
        },
        recorded_outcome: None,
        state: IntentState::Pending,
        created_ms: now_ms,
        updated_ms: now_ms,
    };

    let (record, replayed) = insert_pending_or_read(vault, &new_record)?;
    if replayed {
        validate_replay_matches(&record, &call)?;
        return replay_dispatch(vault, record, sender, now_ms);
    }

    let persisted_call = FrozenOutboundCall::from_record(&record);
    let send_outcome = sender.send(&persisted_call);
    finish_send(vault, record, send_outcome, now_ms, false)
}

/// Audits every device-local intent receipt, per row.
///
/// Valid rows land in `records` and every row that fails decode or integrity
/// verification lands in `corrupt` with its full key bytes and typed error, in
/// LMDB prefix order within each vector. A damaged row is never returned as
/// valid, rewritten, deleted, or silently omitted, and this listing is purely
/// observational: recovery remains the only per-row crash walk, and targeted
/// reads stay strict.
///
/// An unavailable storage substrate is not row damage: opening the read
/// transaction, creating the prefix iterator, and advancing a failed iterator
/// all stay top-level errors.
pub fn intent_ledger_records(vault: &Vault) -> IntentLedgerResult<IntentLedgerListing> {
    let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
    let mut listing = IntentLedgerListing::default();
    for row in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, INTENT_LEDGER_PRIVATE_PREFIX)?
    {
        let (key, value) = row?;
        match decode_record_in_txn(vault, &rtxn, &key, &value) {
            Ok(record) => listing.records.push(record),
            Err(error @ IntentLedgerError::InvalidRecord(_)) => {
                listing.corrupt.push(IntentLedgerCorruptRow {
                    key: key.to_vec().into_boxed_slice(),
                    error,
                });
            }
            Err(error) => return Err(error),
        }
    }
    Ok(listing)
}

/// Walks device-local intent rows after a crash. Resends use only persisted
/// frozen bytes and the persisted key/authorization binding.
///
/// This is a quiescent startup sweep and must not run concurrently with live
/// dispatch of the same intent. ONE-1690/the driver owns lease-based concurrency.
#[cfg(test)]
pub(crate) fn recover_outbound_intents<S: OutboundSender + ?Sized>(
    vault: &Vault,
    sender: &mut S,
    now_ms: u64,
) -> IntentLedgerResult<IntentRecoveryReport> {
    enum RecoveryRow {
        Valid(Box<IntentLedgerRecord>),
        Corrupt(Option<[u8; 32]>),
    }

    let rows = {
        let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
        let mut rows = Vec::new();
        for row in vault
            .store
            .vault_meta
            .prefix_iter(&rtxn, INTENT_LEDGER_PRIVATE_PREFIX)?
        {
            let (key, value) = row?;
            match decode_record_in_txn(vault, &rtxn, &key, &value) {
                Ok(record) => rows.push(RecoveryRow::Valid(Box::new(record))),
                Err(IntentLedgerError::InvalidRecord(_)) => {
                    rows.push(RecoveryRow::Corrupt(id_from_ledger_key(&key)));
                }
                Err(error) => return Err(error),
            }
        }
        rows
    };
    // A prior caller may have observed a force-sync error after LMDB commit.
    // Re-establish durability before any recovery send can leave this node.
    force_sync(vault)?;

    let mut report = IntentRecoveryReport {
        scanned: rows.len(),
        ..IntentRecoveryReport::default()
    };
    for row in rows {
        let record = match row {
            RecoveryRow::Valid(record) => record,
            RecoveryRow::Corrupt(intent_id) => {
                report.escalations.push(IntentEscalation {
                    intent_id,
                    reason: IntentEscalationReason::CorruptLedgerRow,
                });
                continue;
            }
        };

        match record.state {
            IntentState::Done => report.skipped_done += 1,
            IntentState::Abandoned => {
                report.skipped_abandoned += 1;
                // Durable Abandoned state re-derives the signal after a crash.
                report.escalations.push(IntentEscalation {
                    intent_id: Some(record.id),
                    reason: IntentEscalationReason::PreviouslyAbandoned,
                });
            }
            IntentState::Pending if !record.idempotency_supported => {
                let abandoned = abandon_record(
                    vault,
                    record.id,
                    IntentEscalationReason::NonIdempotentPending,
                    now_ms,
                )?;
                debug_assert_eq!(abandoned.state, IntentState::Abandoned);
                report.escalations.push(IntentEscalation {
                    intent_id: Some(record.id),
                    reason: IntentEscalationReason::NonIdempotentPending,
                });
            }
            IntentState::Pending => {
                report.resent += 1;
                let call = FrozenOutboundCall::from_record(&record);
                match sender.send(&call) {
                    OutboundSendOutcome::Acked => {
                        complete_record(vault, record.id, now_ms)?;
                        report.completed += 1;
                    }
                    OutboundSendOutcome::Ambiguous => report.pending += 1,
                    OutboundSendOutcome::Failed(failure) => {
                        // Recovery reaches this arm only for idempotent Pending rows.
                        report.pending += 1;
                        report.failures.push(IntentRecoveryFailure {
                            intent_id: record.id,
                            failure,
                        });
                    }
                }
            }
        }
    }
    Ok(report)
}

pub(super) fn validate_request(request: &OutboundCallRequest) -> IntentLedgerResult<()> {
    if request.server.trim().is_empty() {
        return Err(IntentLedgerError::InvalidInput("server must not be empty"));
    }
    if request.tool.trim().is_empty() {
        return Err(IntentLedgerError::InvalidInput("tool must not be empty"));
    }
    Ok(())
}

#[cfg(test)]
fn validate_replay_matches(
    record: &IntentLedgerRecord,
    call: &FrozenOutboundCall,
) -> IntentLedgerResult<()> {
    if record.server != call.server
        || record.tool != call.tool
        || record.payload_hash != call.payload_hash
        || record.payload() != call.payload()
        || Some(&record.id) != call.intent_id()
    {
        return Err(IntentLedgerError::InvalidRecord(
            "replay input does not match persisted intent",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn validate_replay_matches_request(
    record: &IntentLedgerRecord,
    request: &OutboundCallRequest,
    payload_hash: &[u8; 32],
) -> IntentLedgerResult<()> {
    let intent_id = derive_intent_id(
        request.attempt_id,
        request.call_seq,
        &request.server,
        &request.tool,
        payload_hash,
    )?;
    if record.server != request.server
        || record.tool != request.tool
        || record.payload_hash != *payload_hash
        || record.payload() != request.payload.as_slice()
        || record.id != intent_id
    {
        return Err(IntentLedgerError::InvalidRecord(
            "replay input does not match persisted intent",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn replay_dispatch<S: OutboundSender + ?Sized>(
    vault: &Vault,
    record: IntentLedgerRecord,
    sender: &mut S,
    now_ms: u64,
) -> IntentLedgerResult<IntentDispatchResult> {
    match record.state {
        IntentState::Done => Ok(dispatch_without_send(&record, true, None)),
        IntentState::Abandoned => Ok(dispatch_without_send(
            &record,
            true,
            Some(IntentEscalationReason::PreviouslyAbandoned),
        )),
        IntentState::Pending if !record.idempotency_supported => {
            let abandoned = abandon_record(
                vault,
                record.id,
                IntentEscalationReason::NonIdempotentPending,
                now_ms,
            )?;
            Ok(dispatch_without_send(
                &abandoned,
                true,
                Some(IntentEscalationReason::NonIdempotentPending),
            ))
        }
        IntentState::Pending => {
            let call = FrozenOutboundCall::from_record(&record);
            let outcome = sender.send(&call);
            finish_send(vault, record, outcome, now_ms, true)
        }
    }
}

#[cfg(test)]
fn dispatch_without_send(
    record: &IntentLedgerRecord,
    replayed: bool,
    escalation_reason: Option<IntentEscalationReason>,
) -> IntentDispatchResult {
    IntentDispatchResult {
        class: OutboundCallClass::Effectful,
        intent_id: Some(record.id),
        state: Some(record.state),
        send_outcome: None,
        replayed,
        escalation: escalation_reason.map(|reason| IntentEscalation {
            intent_id: Some(record.id),
            reason,
        }),
    }
}

#[cfg(test)]
fn finish_send(
    vault: &Vault,
    record: IntentLedgerRecord,
    outcome: OutboundSendOutcome,
    now_ms: u64,
    replayed: bool,
) -> IntentLedgerResult<IntentDispatchResult> {
    let (state, escalation) = match outcome {
        OutboundSendOutcome::Acked => {
            let done = complete_record(vault, record.id, now_ms)?;
            (Some(done.state), None)
        }
        OutboundSendOutcome::Ambiguous if record.idempotency_supported => {
            (Some(IntentState::Pending), None)
        }
        OutboundSendOutcome::Ambiguous => {
            let abandoned = abandon_record(
                vault,
                record.id,
                IntentEscalationReason::NonIdempotentAmbiguous,
                now_ms,
            )?;
            (
                Some(abandoned.state),
                Some(IntentEscalation {
                    intent_id: Some(record.id),
                    reason: IntentEscalationReason::NonIdempotentAmbiguous,
                }),
            )
        }
        OutboundSendOutcome::Failed(_) => (Some(IntentState::Pending), None),
    };
    Ok(IntentDispatchResult {
        class: OutboundCallClass::Effectful,
        intent_id: Some(record.id),
        state,
        send_outcome: Some(outcome),
        replayed,
        escalation,
    })
}
