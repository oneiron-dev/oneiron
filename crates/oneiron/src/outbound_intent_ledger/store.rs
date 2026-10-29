//! Storage-transaction reads, inserts, transitions, and the admission-gate validator.

use super::codec::decode_record;
use super::payload::open_payload_in_txn;
use super::types::{
    IntentEscalationReason, IntentId, IntentLedgerError, IntentLedgerRecord, IntentLedgerResult,
    IntentState, RecordedOutboundOutcome,
};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::error::Error;
use crate::side_table::{self, Raw, SideKey, SideTable};

mod approval;
pub(crate) mod checkpoint;
pub(super) mod payload_erase;
pub(super) mod pending;
mod remote_task;
mod transition;
mod validate;

pub(crate) use self::remote_task::defer_record;
pub(crate) use self::validate::hash_frozen_payload;
pub(super) use self::validate::validate_record;

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
/// as every other row-corruption path in this module. The row comes back in its stored form;
/// a door that hands it to a caller opens it ([`super::payload`]).
pub(super) fn get_ledger_record(
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

/// One row by id, its attempt binding checked, opened for its caller.
pub(crate) fn read_intent_record_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &[u8; 32],
) -> IntentLedgerResult<Option<IntentLedgerRecord>> {
    let Some(mut record) = read_stored_intent_record_in_txn(vault, txn, id)? else {
        return Ok(None);
    };
    open_payload_in_txn(vault, txn, &mut record)?;
    Ok(Some(record))
}

/// [`read_intent_record_in_txn`] in the row's stored form, for a reader of its state alone or
/// a writer that puts it back.
pub(super) fn read_stored_intent_record_in_txn(
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

/// How many ledger rows of this server and tool were created or last touched
/// at or after `since_ms`, read in the caller's transaction. A row counts in
/// the window it was admitted in and in any window a retry renewed it or an
/// ack landed on it; counting it twice only ever holds. Every row is an
/// admitted call, settled or not, except a suppressed semantic duplicate,
/// which was never admitted for transport, and the `exclude`d attempt (an
/// exact retry's own row). Server and tool compare as the capability lookup spells them
/// (trimmed, ASCII case folded). A row that does not decode counts as well:
/// an accounting gap never opens a bound.
pub(crate) fn admitted_calls_since_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    server: &str,
    tool: &str,
    since_ms: u64,
    exclude: Option<crate::attempt_queue::AttemptId>,
) -> IntentLedgerResult<u32> {
    let same = |stored: &str, wanted: &str| stored.trim().eq_ignore_ascii_case(wanted.trim());
    let mut admitted = 0_u32;
    for row in ledger_rows(vault, txn)? {
        let (key, raw) = row?;
        let counts = match decode_record(&key, &raw) {
            Ok(record) => {
                same(&record.server, server)
                    && same(&record.tool, tool)
                    && record.created_ms.max(record.updated_ms) >= since_ms
                    && Some(record.attempt_id) != exclude
                    && record.recorded_outcome
                        != Some(RecordedOutboundOutcome::Abandoned(
                            IntentEscalationReason::DedupeSuppressed,
                        ))
            }
            Err(_) => true,
        };
        if counts {
            admitted = admitted.saturating_add(1);
        }
    }
    Ok(admitted)
}

/// Decodes one raw row already read by a full-table walk ([`ledger_rows`]). Shares the
/// attempt-binding check with [`read_intent_record_in_txn`].
pub(super) fn decode_record_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &[u8],
    raw: &[u8],
) -> IntentLedgerResult<IntentLedgerRecord> {
    let mut record = decode_record(key, raw)?;
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
    open_payload_in_txn(vault, txn, &mut record)?;
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

/// [`check_intent_attempt_format`] for a caller that keeps the ledger-wide
/// attempt index's failure apart from one row's (the e-sign delivery mint,
/// FIX 6455): every attempt read runs it first.
pub(crate) fn check_intent_attempt_format_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> IntentLedgerResult<()> {
    check_intent_attempt_format(vault, txn)
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
    let mut wtxn = vault.store.env.write_txn()?;
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
    if pending.state != IntentState::Pending
        || pending.recorded_outcome.is_some()
        || pending.delivery_uncertain
    {
        return Err(IntentLedgerError::InvalidRecord(
            "only outcome-free Pending may be inserted",
        ));
    }
    insert_intent_in_txn(vault, wtxn, pending)
}

/// A denied semantic duplicate is a terminal replayable attempt, without a
/// Pending phase, budget debit, or transport. Only the exact typed reason may
/// take this one additional admission shape.
pub(crate) fn insert_suppressed_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    suppressed: &IntentLedgerRecord,
) -> IntentLedgerResult<()> {
    if suppressed.state != IntentState::Abandoned
        || suppressed.recorded_outcome
            != Some(RecordedOutboundOutcome::Abandoned(
                IntentEscalationReason::DedupeSuppressed,
            ))
    {
        return Err(IntentLedgerError::InvalidRecord(
            "not a suppressed outbound attempt",
        ));
    }
    insert_intent_in_txn(vault, wtxn, suppressed)
}

fn insert_intent_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    pending: &IntentLedgerRecord,
) -> IntentLedgerResult<()> {
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
        IntentState::Deferred => RecordedOutboundOutcome::Deferred,
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

/// The send's terminal Done with nothing bridged: the ledger's own tests'
/// door. Production sends complete through [`complete_record_bridged`].
#[cfg(test)]
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

/// A send's terminal Done, with `bridge` writing in the same transaction
/// (DOOR-141 PR2): a turn program's step settles with the send's result
/// there. The bridge returns nothing, so it cannot fail the transition;
/// Pending, Done and replay are the plain transition's. A row already Done
/// runs no bridge.
pub(crate) fn complete_record_bridged(
    vault: &Vault,
    id: [u8; 32],
    now_ms: u64,
    bridge: impl FnOnce(&mut heed::RwTxn<'_>, &IntentLedgerRecord),
) -> IntentLedgerResult<IntentLedgerRecord> {
    transition_record_with_outcome_and(
        vault,
        id,
        IntentState::Done,
        RecordedOutboundOutcome::Acked,
        now_ms,
        bridge,
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

/// Persist positive uncertainty before a later attempt can replace the
/// current attempt's outcome with definite non-delivery. Never reset this bit
/// on retry; only confirmed Done or an explicit reconciliation can resolve it.
///
/// The bit pays for no admission, so the row's timestamp stays where its
/// admission, renewal or last outcome put it: an aged retry marked here,
/// even one a full ceiling then holds, still meets today's ceiling next time.
pub(crate) fn record_possible_delivery(
    vault: &Vault,
    id: [u8; 32],
) -> IntentLedgerResult<IntentLedgerRecord> {
    let mut wtxn = vault.store.env.write_txn()?;
    let mut record = get_ledger_record(vault, &wtxn, &id)?.ok_or(
        IntentLedgerError::InvalidRecord("possible delivery target is missing"),
    )?;
    if record.state != IntentState::Pending || record.recorded_outcome.is_some() {
        return Err(IntentLedgerError::InvalidRecord(
            "possible delivery requires outcome-free Pending",
        ));
    }
    let marked = !record.delivery_uncertain;
    if marked {
        record.delivery_uncertain = true;
        LEDGER.put(&vault.store, &mut wtxn, &id, &record)?;
    }
    open_payload_in_txn(vault, &wtxn, &mut record)?;
    if marked {
        wtxn.commit().map_err(Error::from)?;
    } else {
        drop(wtxn);
    }
    force_sync(vault)?;
    Ok(record)
}

/// Resolve a scheduled TASK's exact frozen logical send under the same writer
/// that publishes its terminal receipt/TASK/queue. `stop` only forbids a
/// future attempt; it never changes the meaning of a prior ACK.
pub(crate) fn reconcile_connector_intent_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    attempt_id: AttemptId,
    binding: &super::resolution::ConnectorIntentBinding<'_>,
    stop: Option<IntentEscalationReason>,
    now_ms: u64,
) -> IntentLedgerResult<Option<super::resolution::IntentResolution>> {
    let Some(mut record) = read_intent_for_attempt_in_txn(vault, &*wtxn, attempt_id, 0)? else {
        return Ok(None);
    };
    binding.verify(&record)?;
    if let Some(reason) = stop
        && record.state == IntentState::Pending
    {
        // A pre-send authority refusal cannot negate a prior in-flight call.
        // Pending/None is durable admission and may have crossed the wire.
        record.delivery_uncertain |= record.recorded_outcome.is_none();
        record.state = IntentState::Abandoned;
        record.recorded_outcome = Some(RecordedOutboundOutcome::Abandoned(reason));
        record.updated_ms = now_ms.max(record.created_ms);
        put_ledger_record(vault, wtxn, &record)?;
        super::settlement::settle_reservation_in_txn(vault, wtxn, &record)?;
    }
    Ok(Some(super::resolution::IntentResolution::from_record(
        &record,
    )?))
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
        |_, _| Ok(()),
    )
}

/// A provider's rate or quota refusal (FIX 8818): the send certainly did not
/// go, as [`record_definite_non_delivery`] records, and the provider's wait
/// is kept with it in the same writer, so no attempt goes before its edge.
pub(crate) fn record_provider_refusal(
    vault: &Vault,
    id: [u8; 32],
    directive: super::settlement::ProviderRetryDirective,
    now_ms: u64,
) -> IntentLedgerResult<IntentLedgerRecord> {
    update_pending_recorded_outcome(
        vault,
        id,
        None,
        Some(RecordedOutboundOutcome::DefiniteNonDelivery),
        now_ms,
        |wtxn, _| super::settlement::keep_provider_wait_in_txn(vault, wtxn, &id, directive),
    )
}

/// Renews a Pending retry's admission at `now_ms`, in the caller's
/// writer-locked transaction, so the window it is about to send in counts it.
pub(crate) fn renew_admission_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &IntentLedgerRecord,
    now_ms: u64,
) -> IntentLedgerResult<()> {
    let mut renewed = record.clone();
    renewed.updated_ms = now_ms.max(record.updated_ms);
    put_ledger_record(vault, wtxn, &renewed)
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
        // The retry this claim opens ends the provider's wait (FIX 8818); a
        // takeover's abandon gives its reserved budget back (FIX 7964).
        |wtxn, record| {
            super::settlement::clear_provider_wait_in_txn(vault, wtxn, &id)?;
            super::settlement::settle_reservation_in_txn(vault, wtxn, record)
        },
    )
}

fn update_pending_recorded_outcome(
    vault: &Vault,
    id: [u8; 32],
    expected: Option<RecordedOutboundOutcome>,
    next: Option<RecordedOutboundOutcome>,
    now_ms: u64,
    also: impl FnOnce(&mut heed::RwTxn<'_>, &IntentLedgerRecord) -> IntentLedgerResult<()>,
) -> IntentLedgerResult<IntentLedgerRecord> {
    let mut wtxn = vault.store.env.write_txn()?;
    let mut record = get_ledger_record(vault, &wtxn, &id)?.ok_or(
        IntentLedgerError::InvalidRecord("pending outcome target is missing"),
    )?;
    if record.state != IntentState::Pending || record.recorded_outcome != expected {
        return Err(IntentLedgerError::InvalidRecord(
            "pending outcome transition is invalid",
        ));
    }
    if expected == Some(RecordedOutboundOutcome::DefiniteNonDelivery)
        && next.is_none()
        && !crate::outbound_chokepoint::dedupe::owns_retry(vault, &wtxn, &id)?
    {
        // A newer semantic attempt took over after the no-wire window. The
        // old permit must never reopen that sender after the takeover.
        record.state = IntentState::Abandoned;
        record.recorded_outcome = Some(RecordedOutboundOutcome::Abandoned(
            IntentEscalationReason::DedupeReservationReplaced,
        ));
    } else {
        record.recorded_outcome = next;
    }
    record.updated_ms = now_ms.max(record.created_ms);
    LEDGER.put(&vault.store, &mut wtxn, &id, &record)?;
    also(&mut wtxn, &record)?;
    open_payload_in_txn(vault, &wtxn, &mut record)?;
    wtxn.commit().map_err(Error::from)?;
    let synced = force_sync(vault);
    // A takeover may have abandoned the row: the owner's waiting shed looks
    // again, as at a terminal transition (FIX 10688).
    vault.wake_owner_shed();
    synced?;
    Ok(record)
}

fn transition_record_with_outcome(
    vault: &Vault,
    id: [u8; 32],
    next: IntentState,
    outcome: RecordedOutboundOutcome,
    now_ms: u64,
) -> IntentLedgerResult<IntentLedgerRecord> {
    transition_record_with_outcome_and(vault, id, next, outcome, now_ms, |_, _| {})
}

fn transition_record_with_outcome_and(
    vault: &Vault,
    id: [u8; 32],
    next: IntentState,
    outcome: RecordedOutboundOutcome,
    now_ms: u64,
    also: impl FnOnce(&mut heed::RwTxn<'_>, &IntentLedgerRecord),
) -> IntentLedgerResult<IntentLedgerRecord> {
    let mut wtxn = vault.store.env.write_txn()?;
    let mut record =
        match transition::transition_record_in_txn(vault, &mut wtxn, id, next, outcome, now_ms)? {
            transition::Transitioned::Moved(record) => record,
            transition::Transitioned::Replayed(mut record) => {
                open_payload_in_txn(vault, &wtxn, &mut record)?;
                drop(wtxn);
                return Ok(record);
            }
        };
    open_payload_in_txn(vault, &wtxn, &mut record)?;
    also(&mut wtxn, &record);

    wtxn.commit().map_err(Error::from)?;
    let synced = force_sync(vault);
    // The terminal row is committed: the owner's waiting shed looks again (FIX 10157).
    vault.wake_owner_shed();
    synced?;
    Ok(record)
}

/// Writes `record`, which a read door may have opened, back over its row in the stored form the
/// row already keeps: a row's payload is written once, at admission, and only an erase
/// rewrites it.
fn put_ledger_record(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &IntentLedgerRecord,
) -> IntentLedgerResult<()> {
    let stored = get_ledger_record(vault, &*wtxn, &record.id)?.ok_or(
        IntentLedgerError::InvalidRecord("outbound intent update target is missing"),
    )?;
    let mut kept = record.clone();
    kept.payload = stored.payload;
    LEDGER.put(&vault.store, wtxn, &record.id, &kept)?;
    Ok(())
}

/// Writes an actor's erase of `record` past the side-row wall (FIX 9283): what
/// [`crate::side_table::ErasedForm`] leaves of it. The call's checkpoint
/// compartment is erased with it (KS7-4b), so no old checkpoint opens the
/// request either.
pub(super) fn put_erased_record(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: IntentLedgerRecord,
) -> crate::Result<()> {
    let (id, attempt_id, call_seq) = (record.id, record.attempt_id, record.call_seq);
    LEDGER.put_erased(
        &vault.store,
        wtxn,
        &id,
        crate::side_table::Erased::of(record)?,
    )?;
    payload_erase::erase_call_compartment_in_txn(vault, wtxn, &attempt_id, call_seq)
}

pub(crate) fn force_sync(vault: &Vault) -> IntentLedgerResult<()> {
    vault.store.env.force_sync().map_err(Error::from)?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn replace_intent_record_for_test(
    vault: &Vault,
    record: &IntentLedgerRecord,
) -> IntentLedgerResult<()> {
    validate_record(record)?;
    let mut wtxn = vault.store.env.write_txn()?;
    if !LEDGER.contains(&vault.store, &wtxn, &record.id)? {
        return Err(IntentLedgerError::InvalidRecord(
            "test replacement target is missing",
        ));
    }
    LEDGER.put(&vault.store, &mut wtxn, &record.id, record)?;
    wtxn.commit().map_err(Error::from)?;
    force_sync(vault)
}
