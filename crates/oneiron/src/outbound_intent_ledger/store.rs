//! Storage-transaction reads, inserts, transitions, and the admission-gate validator.

use super::codec::decode_record;
use super::dispatch::derive_intent_id;
use super::types::{
    IntentEscalationReason, IntentId, IntentLedgerError, IntentLedgerRecord, IntentLedgerResult,
    IntentState, OUTBOUND_BINDING_VERSION, RecordedOutboundOutcome,
};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Error;
use crate::side_table::{self, Raw, SideKey, SideTable};

/// Durable outbound-send intent ledger row: state machine, endpoint binding, and accounting.
/// Key: hash32 (the intent id).
const LEDGER: SideTable<[u8; 32], IntentLedgerRecord, Raw> =
    SideTable::new(&side_table::OUTBOUND_INTENT_LEDGER_RECORD);

/// Unique logical call -> immutable intent id, committed with the Pending row.
/// Key: id16(attempt) + u64be(call seq).
const INTENT_ATTEMPT_INDEX: SideTable<AttemptCallKey, [u8; 32], Raw> =
    SideTable::new(&side_table::OUTBOUND_INTENT_ATTEMPT_INDEX);

/// Format-version marker gating the attempt index; a non-empty unindexed ledger fails closed.
/// Key: ().
const INTENT_ATTEMPT_FORMAT: SideTable<(), [u8; 1], Raw> =
    SideTable::new(&side_table::OUTBOUND_INTENT_ATTEMPT_FORMAT);

/// One logical dispatch call's index key: `attempt_id.as_bytes()` (16) then `call_seq` big-endian
/// (8) — spelled explicitly because [`AttemptId`] is a foreign type this module cannot implement
/// [`SideKey`] on directly.
#[derive(Debug, Clone, Copy)]
struct AttemptCallKey {
    attempt_id: AttemptId,
    call_seq: u64,
}

impl SideKey for AttemptCallKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.attempt_id.as_bytes());
        out.extend_from_slice(&self.call_seq.to_be_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (attempt, seq) = bytes.split_at_checked(16)?;
        Some(Self {
            attempt_id: AttemptId::from_bytes(attempt).ok()?,
            call_seq: u64::from_be_bytes(seq.try_into().ok()?),
        })
    }
}

/// Reads and fully decodes one ledger row, checking that the row found under `id` actually
/// carries that id (the typed table has no key to check against inside the value codec, so the
/// check happens here). A decode failure surfaces as [`IntentLedgerError::InvalidRecord`], same
/// as every other row-corruption path in this module.
fn get_ledger_record(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &[u8; 32],
) -> IntentLedgerResult<Option<IntentLedgerRecord>> {
    let record = match LEDGER.get(&vault.store, txn, id) {
        Ok(record) => record,
        Err(Error::CorruptedIndex(_)) => {
            return Err(IntentLedgerError::InvalidRecord(
                "outbound intent ledger record failed to decode",
            ));
        }
        Err(error) => return Err(error.into()),
    };
    match record {
        Some(record) if record.id == *id => Ok(Some(record)),
        Some(_) => Err(IntentLedgerError::InvalidRecord(
            "outbound intent key does not match id",
        )),
        None => Ok(None),
    }
}

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
    let Some(record) = get_ledger_record(vault, txn, id)? else {
        return Ok(None);
    };
    check_intent_attempt_format(vault, txn)?;
    let indexed_id = INTENT_ATTEMPT_INDEX.get_bytes(
        &vault.store,
        txn,
        &AttemptCallKey {
            attempt_id: record.attempt_id,
            call_seq: record.call_seq,
        },
    )?;
    if indexed_id.as_deref() != Some(record.id.as_slice()) {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent is missing its unique attempt binding",
        ));
    }
    Ok(Some(record))
}

/// Every ledger row undecoded, each with its FULL stored key, for the recovery/listing walks:
/// damage there is tolerated per row rather than failing the whole walk, and a row whose key is
/// malformed is still reported by its own key bytes.
pub(super) fn ledger_rows<'txn>(
    vault: &Vault,
    txn: &'txn heed::RoTxn<'_>,
) -> IntentLedgerResult<impl Iterator<Item = crate::Result<(Vec<u8>, Vec<u8>)>> + 'txn> {
    let prefix = LEDGER.decl().prefix;
    Ok(LEDGER
        .iter_raw_from(&vault.store, txn, &[])?
        .map(move |row| row.map(|(key, value)| ([prefix, key.as_slice()].concat(), value))))
}

/// Decodes one raw row already read by a full-table walk ([`ledger_rows`]). Shares the
/// attempt-binding check with [`read_intent_record_in_txn`].
pub(super) fn decode_record_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &[u8],
    raw: &[u8],
) -> IntentLedgerResult<IntentLedgerRecord> {
    let record = decode_record(key, raw)?;
    check_intent_attempt_format(vault, txn)?;
    let indexed_id = INTENT_ATTEMPT_INDEX.get_bytes(
        &vault.store,
        txn,
        &AttemptCallKey {
            attempt_id: record.attempt_id,
            call_seq: record.call_seq,
        },
    )?;
    if indexed_id.as_deref() != Some(record.id.as_slice()) {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent is missing its unique attempt binding",
        ));
    }
    Ok(record)
}

/// Reconstructs the full raw key an attempt-index row lives under, for tests that plant or
/// inspect rows through the raw `vault_meta` door directly.
#[cfg(test)]
pub(super) fn intent_attempt_key(attempt_id: AttemptId, call_seq: u64) -> Vec<u8> {
    INTENT_ATTEMPT_INDEX.key_bytes(&AttemptCallKey {
        attempt_id,
        call_seq,
    })
}

fn check_intent_attempt_format(vault: &Vault, txn: &heed::RoTxn<'_>) -> IntentLedgerResult<()> {
    match INTENT_ATTEMPT_FORMAT.get(&vault.store, txn, &())? {
        Some([b'1']) => return Ok(()),
        Some(_) => {
            return Err(IntentLedgerError::InvalidRecord(
                "invalid outbound attempt index format",
            ));
        }
        None => {}
    }
    // No pre-release compatibility reader: an unindexed ledger is not empty.
    // Probe only the keys; never decode a row's value on this cold path.
    if !LEDGER.scan_keys(&vault.store, txn, &[])?.is_empty()
        || !INTENT_ATTEMPT_INDEX
            .scan_keys(&vault.store, txn, &[])?
            .is_empty()
    {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound attempt index is missing",
        ));
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
    let Some(raw) = INTENT_ATTEMPT_INDEX.get_bytes(
        &vault.store,
        txn,
        &AttemptCallKey {
            attempt_id,
            call_seq,
        },
    )?
    else {
        return Ok(None);
    };
    let id: IntentId = raw
        .as_slice()
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
    if LEDGER.contains(&vault.store, wtxn, &pending.id)? {
        return Err(IntentLedgerError::InvalidRecord(
            "outbound intent insert target already exists",
        ));
    }
    validate_record(pending)?;
    LEDGER.put(&vault.store, wtxn, &pending.id, pending)?;
    INTENT_ATTEMPT_FORMAT.put(&vault.store, wtxn, &(), b"1")?;
    INTENT_ATTEMPT_INDEX.put(
        &vault.store,
        wtxn,
        &AttemptCallKey {
            attempt_id: pending.attempt_id,
            call_seq: pending.call_seq,
        },
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
    let mut wtxn = vault.store.env.write_txn().map_err(Error::from)?;
    let mut record = get_ledger_record(vault, &wtxn, &id)?.ok_or(
        IntentLedgerError::InvalidRecord("pending outcome target is missing"),
    )?;
    if record.state != IntentState::Pending || record.recorded_outcome != expected {
        return Err(IntentLedgerError::InvalidRecord(
            "pending outcome transition is invalid",
        ));
    }
    record.recorded_outcome = next;
    record.updated_ms = now_ms.max(record.created_ms);
    LEDGER.put(&vault.store, &mut wtxn, &id, &record)?;
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
    let mut wtxn = vault.store.env.write_txn().map_err(Error::from)?;
    let mut record = get_ledger_record(vault, &wtxn, &id)?.ok_or(
        IntentLedgerError::InvalidRecord("transition target is missing"),
    )?;
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
    LEDGER.put(&vault.store, &mut wtxn, &id, &record)?;
    wtxn.commit().map_err(Error::from)?;
    force_sync(vault)?;
    Ok(record)
}

pub(crate) fn force_sync(vault: &Vault) -> IntentLedgerResult<()> {
    #[cfg(test)]
    vault.test_hooks().note_force_sync();
    vault.store.env.force_sync().map_err(Error::from)?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn replace_intent_record_for_test(
    vault: &Vault,
    record: &IntentLedgerRecord,
) -> IntentLedgerResult<()> {
    validate_record(record)?;
    let mut wtxn = vault.store.env.write_txn().map_err(Error::from)?;
    if !LEDGER.contains(&vault.store, &wtxn, &record.id)? {
        return Err(IntentLedgerError::InvalidRecord(
            "test replacement target is missing",
        ));
    }
    LEDGER.put(&vault.store, &mut wtxn, &record.id, record)?;
    wtxn.commit().map_err(Error::from)?;
    force_sync(vault)
}

pub(crate) fn hash_frozen_payload(payload: &[u8]) -> [u8; 32] {
    *blake3::hash(payload).as_bytes()
}

pub(super) fn validate_record(record: &IntentLedgerRecord) -> IntentLedgerResult<()> {
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
