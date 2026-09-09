//! Storage-transaction reads, inserts, transitions, and the admission-gate validator.

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

use super::codec::{
    INTENT_LEDGER_PRIVATE_PREFIX, decode_record, encode_record, id_from_ledger_key,
    intent_ledger_key,
};
use super::dispatch::derive_intent_id;
use super::types::{
    IntentEscalationReason, IntentId, IntentLedgerError, IntentLedgerRecord, IntentLedgerResult,
    IntentState, OUTBOUND_BINDING_VERSION, RecordedOutboundOutcome,
};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Error;

// Unique logical call -> immutable intent id, committed with the Pending row.
pub(super) const INTENT_ATTEMPT_PREFIX: &[u8] = b"outbound:intent_attempt:v1:"; // + attempt(16) + seq(8)

pub(super) const INTENT_ATTEMPT_FORMAT_KEY: &[u8] = b"outbound:intent_attempt_format";

#[cfg(test)]
pub(super) static FORCE_SYNC_CALLS: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
pub(crate) fn read_intent_record(
    vault: &Vault,
    id: &[u8; 32],
) -> IntentLedgerResult<Option<IntentLedgerRecord>> {
    let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
    read_intent_record_in_txn(vault, &rtxn, id)
}

pub(crate) fn read_intent_record_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &[u8; 32],
) -> IntentLedgerResult<Option<IntentLedgerRecord>> {
    let key = intent_ledger_key(id);
    let Some(raw) = vault.store.vault_meta.get(txn, &key)? else {
        return Ok(None);
    };
    decode_record_in_txn(vault, txn, &key, &raw).map(Some)
}

pub(super) fn decode_record_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &[u8],
    raw: &[u8],
) -> IntentLedgerResult<IntentLedgerRecord> {
    let record = decode_record(key, raw)?;
    check_intent_attempt_format(vault, txn)?;
    let attempt_key = intent_attempt_key(record.attempt_id, record.call_seq);
    let indexed_id = vault.store.vault_meta.get(txn, &attempt_key)?;
    if indexed_id.as_deref() != Some(record.id.as_slice()) {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent is missing its unique attempt binding",
        ));
    }
    Ok(record)
}

pub(super) fn intent_attempt_key(attempt_id: AttemptId, call_seq: u64) -> Vec<u8> {
    let mut key = INTENT_ATTEMPT_PREFIX.to_vec();
    key.extend_from_slice(attempt_id.as_bytes());
    key.extend_from_slice(&call_seq.to_be_bytes());
    key
}

fn check_intent_attempt_format(vault: &Vault, txn: &heed::RoTxn<'_>) -> IntentLedgerResult<()> {
    match vault.store.vault_meta.get(txn, INTENT_ATTEMPT_FORMAT_KEY)? {
        Some(version) if version.as_ref() == b"1" => return Ok(()),
        Some(_) => {
            return Err(IntentLedgerError::InvalidRecord(
                "invalid outbound attempt index format",
            ));
        }
        None => {}
    }
    // No pre-release compatibility reader: an unindexed ledger is not empty.
    // Probe only the first key; never decode unrelated rows on a dispatch path.
    for prefix in [INTENT_LEDGER_PRIVATE_PREFIX, INTENT_ATTEMPT_PREFIX] {
        if vault
            .store
            .vault_meta
            .prefix_iter(txn, prefix)?
            .next()
            .transpose()?
            .is_some()
        {
            return Err(IntentLedgerError::InvalidRecord(
                "outbound attempt index is missing",
            ));
        }
    }
    Ok(())
}

/// Exact logical-call lookup. Admission repeats this read under its write lock.
/// A corrupt pointer or target fails closed, without inspecting unrelated calls.
pub(crate) fn read_intent_for_attempt_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt_id: AttemptId,
    call_seq: u64,
) -> IntentLedgerResult<Option<IntentLedgerRecord>> {
    check_intent_attempt_format(vault, txn)?;
    let key = intent_attempt_key(attempt_id, call_seq);
    let Some(raw) = vault.store.vault_meta.get(txn, &key)? else {
        return Ok(None);
    };
    let id: IntentId = raw
        .as_ref()
        .try_into()
        .map_err(|_| IntentLedgerError::InvalidRecord("invalid outbound attempt index target"))?;
    let record = read_intent_record_in_txn(vault, txn, &id)?.ok_or(
        IntentLedgerError::InvalidRecord("outbound attempt index target is missing"),
    )?;
    if record.attempt_id != attempt_id || record.call_seq != call_seq {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound attempt index binding mismatch",
        ));
    }
    Ok(Some(record))
}

#[cfg(test)]
pub(super) fn insert_pending_or_read(
    vault: &Vault,
    pending: &IntentLedgerRecord,
) -> IntentLedgerResult<(IntentLedgerRecord, bool)> {
    let mut wtxn = vault.store.env.write_txn().map_err(Error::from)?;
    if let Some(existing) =
        read_intent_for_attempt_in_txn(vault, &wtxn, pending.attempt_id, pending.call_seq)?
    {
        drop(wtxn);
        // A prior commit may be visible even if its force-sync reported an
        // error. Replay cannot send until the existing intent is durable.
        force_sync(vault)?;
        return Ok((existing, true));
    }

    insert_pending_in_txn(vault, &mut wtxn, pending)?;
    wtxn.commit().map_err(Error::from)?;
    force_sync(vault)?;
    Ok((pending.clone(), false))
}

pub(crate) fn insert_pending_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    pending: &IntentLedgerRecord,
) -> IntentLedgerResult<()> {
    if pending.state != IntentState::Pending || pending.recorded_outcome.is_some() {
        return Err(IntentLedgerError::InvalidRecord(
            "only outcome-free Pending may be inserted",
        ));
    }
    if read_intent_for_attempt_in_txn(vault, wtxn, pending.attempt_id, pending.call_seq)?.is_some()
    {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound attempt already has an admitted binding",
        ));
    }
    let key = intent_ledger_key(&pending.id);
    if vault.store.vault_meta.get(&*wtxn, &key)?.is_some() {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent insert target already exists",
        ));
    }
    validate_record(&key, pending)?;
    let encoded = encode_record(pending)?;
    vault.store.vault_meta.put(wtxn, &key, &encoded)?;
    vault
        .store
        .vault_meta
        .put(wtxn, INTENT_ATTEMPT_FORMAT_KEY, b"1")?;
    vault.store.vault_meta.put(
        wtxn,
        &intent_attempt_key(pending.attempt_id, pending.call_seq),
        &pending.id,
    )?;
    Ok(())
}

#[cfg(test)]
pub(super) fn transition_record(
    vault: &Vault,
    id: [u8; 32],
    next: IntentState,
    now_ms: u64,
) -> IntentLedgerResult<IntentLedgerRecord> {
    let outcome = match next {
        IntentState::Done => RecordedOutboundOutcome::Acked,
        IntentState::Abandoned => {
            RecordedOutboundOutcome::Abandoned(IntentEscalationReason::PreviouslyAbandoned)
        }
        IntentState::Pending => {
            let record = read_intent_record(vault, &id)?.ok_or(
                IntentLedgerError::InvalidRecord("transition target is missing"),
            )?;
            return Err(IntentLedgerError::InvalidTransition {
                from: record.state,
                to: IntentState::Pending,
            });
        }
    };
    transition_record_with_outcome(vault, id, next, outcome, now_ms)
}

pub(crate) fn complete_record(
    vault: &Vault,
    id: [u8; 32],
    now_ms: u64,
) -> IntentLedgerResult<IntentLedgerRecord> {
    transition_record_with_outcome(
        vault,
        id,
        IntentState::Done,
        RecordedOutboundOutcome::Acked,
        now_ms,
    )
}

pub(crate) fn abandon_record(
    vault: &Vault,
    id: [u8; 32],
    reason: IntentEscalationReason,
    now_ms: u64,
) -> IntentLedgerResult<IntentLedgerRecord> {
    transition_record_with_outcome(
        vault,
        id,
        IntentState::Abandoned,
        RecordedOutboundOutcome::Abandoned(reason),
        now_ms,
    )
}

pub(crate) fn record_definite_non_delivery(
    vault: &Vault,
    id: [u8; 32],
    now_ms: u64,
) -> IntentLedgerResult<IntentLedgerRecord> {
    update_pending_recorded_outcome(
        vault,
        id,
        None,
        Some(RecordedOutboundOutcome::DefiniteNonDelivery),
        now_ms,
    )
}

pub(crate) fn begin_definite_non_delivery_retry(
    vault: &Vault,
    id: [u8; 32],
    now_ms: u64,
) -> IntentLedgerResult<IntentLedgerRecord> {
    update_pending_recorded_outcome(
        vault,
        id,
        Some(RecordedOutboundOutcome::DefiniteNonDelivery),
        None,
        now_ms,
    )
}

fn update_pending_recorded_outcome(
    vault: &Vault,
    id: [u8; 32],
    expected: Option<RecordedOutboundOutcome>,
    next: Option<RecordedOutboundOutcome>,
    now_ms: u64,
) -> IntentLedgerResult<IntentLedgerRecord> {
    let key = intent_ledger_key(&id);
    let mut wtxn = vault.store.env.write_txn().map_err(Error::from)?;
    let raw = vault
        .store
        .vault_meta
        .get(&wtxn, &key)?
        .ok_or(IntentLedgerError::InvalidRecord(
            "pending outcome target is missing",
        ))?;
    let mut record = decode_record(&key, &raw)?;
    if record.state != IntentState::Pending || record.recorded_outcome != expected {
        return Err(IntentLedgerError::InvalidRecord(
            "pending outcome transition is invalid",
        ));
    }
    record.recorded_outcome = next;
    record.updated_ms = now_ms.max(record.created_ms);
    let encoded = encode_record(&record)?;
    vault.store.vault_meta.put(&mut wtxn, &key, &encoded)?;
    wtxn.commit().map_err(Error::from)?;
    force_sync(vault)?;
    Ok(record)
}

fn transition_record_with_outcome(
    vault: &Vault,
    id: [u8; 32],
    next: IntentState,
    outcome: RecordedOutboundOutcome,
    now_ms: u64,
) -> IntentLedgerResult<IntentLedgerRecord> {
    let key = intent_ledger_key(&id);
    let mut wtxn = vault.store.env.write_txn().map_err(Error::from)?;
    let raw = vault
        .store
        .vault_meta
        .get(&wtxn, &key)?
        .ok_or(IntentLedgerError::InvalidRecord(
            "transition target is missing",
        ))?;
    let mut record = decode_record(&key, &raw)?;
    if record.state == next {
        drop(wtxn);
        if record.recorded_outcome != Some(outcome) {
            return Err(IntentLedgerError::InvalidRecord(
                "terminal replay outcome does not match persisted outcome",
            ));
        }
        return Ok(record);
    }
    if !record.state.may_transition_to(next) {
        return Err(IntentLedgerError::InvalidTransition {
            from: record.state,
            to: next,
        });
    }
    record.state = next;
    record.recorded_outcome = Some(outcome);
    record.updated_ms = now_ms.max(record.created_ms);
    let encoded = encode_record(&record)?;
    vault.store.vault_meta.put(&mut wtxn, &key, &encoded)?;
    wtxn.commit().map_err(Error::from)?;
    force_sync(vault)?;
    Ok(record)
}

pub(crate) fn force_sync(vault: &Vault) -> IntentLedgerResult<()> {
    #[cfg(test)]
    FORCE_SYNC_CALLS.fetch_add(1, AtomicOrdering::SeqCst);
    vault.store.env.force_sync().map_err(Error::from)?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn replace_intent_record_for_test(
    vault: &Vault,
    record: &IntentLedgerRecord,
) -> IntentLedgerResult<()> {
    let key = intent_ledger_key(&record.id);
    validate_record(&key, record)?;
    let encoded = encode_record(record)?;
    let mut wtxn = vault.store.env.write_txn().map_err(Error::from)?;
    if vault.store.vault_meta.get(&wtxn, &key)?.is_none() {
        return Err(IntentLedgerError::InvalidRecord(
            "test replacement target is missing",
        ));
    }
    vault.store.vault_meta.put(&mut wtxn, &key, &encoded)?;
    wtxn.commit().map_err(Error::from)?;
    force_sync(vault)
}

pub(crate) fn hash_frozen_payload(payload: &[u8]) -> [u8; 32] {
    *blake3::hash(payload).as_bytes()
}

pub(super) fn validate_record(key: &[u8], record: &IntentLedgerRecord) -> IntentLedgerResult<()> {
    if id_from_ledger_key(key) != Some(record.id) {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent key does not match id",
        ));
    }
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
    if hash_frozen_payload(record.payload()) != record.payload_hash {
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
