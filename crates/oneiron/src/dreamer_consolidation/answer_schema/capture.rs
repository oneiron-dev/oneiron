//! One TURN extraction call kept for the nightly answer-schema check (HOUSE-SCHEMA-CHECK):
//! the request whole, the TURN rows its transcript was read from, and when it was kept.
//!
//! Both TURN callers keep their call after the request is final and before it is sent, only
//! while the call carries the schema. A memo hit keeps nothing new: the key already names the
//! call. NOTE reviews never capture. The check deletes every capture under its night when its
//! receipt lands, and older captures go after eight days; an erase of a row listed in
//! `sources` drops the capture in the erase's own transaction.

use serde::{Deserialize, Serialize};

use super::super::support::invalid_consolidation;
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideKey, SideTable};
use crate::store::Store;
use oneiron_model::llm::LlmRequest;

/// The captures, keyed by child attempt and the call's step hash.
const CAPTURES: SideTable<(AttemptId, [u8; 32]), CapturedTurnCall, Named> =
    SideTable::new(&side_table::DREAMER_ANSWER_SCHEMA_CAPTURE);

/// One TURN extraction call kept for the check: the request whole, as sent, the rows its
/// transcript was read from, and when it was kept (Unix seconds).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CapturedTurnCall {
    pub(crate) request: LlmRequest,
    pub(crate) sources: Vec<EntityId>,
    pub(crate) captured_at: u64,
}

/// Keeps `request`, built with the answer schema by `attempt`, for the check: one row under
/// the call's step hash, in one small write transaction. `sources` are the TURN rows the
/// transcript was read from; `captured_at` is Unix seconds. A row already under the key
/// (a memo hit) keeps nothing new.
///
/// # Errors
///
/// The request does not hash; storage faults.
pub(crate) fn capture_turn_call(
    vault: &Vault,
    attempt: AttemptId,
    request: &LlmRequest,
    sources: &[EntityId],
    captured_at: u64,
) -> Result<()> {
    let step = request
        .canonical_hash()
        .map_err(|_| invalid_consolidation("the capture's request did not hash"))?;
    let key = (attempt, step);
    vault.with_write_txn_grouped(|txn| {
        if CAPTURES.contains(&vault.store, &*txn, &key)? {
            return Ok(());
        }
        CAPTURES.put(
            &vault.store,
            txn,
            &key,
            &CapturedTurnCall {
                request: request.clone(),
                sources: sources.to_vec(),
                captured_at,
            },
        )
    })
}

/// Reads one capture by key, if it decodes.
///
/// # Errors
///
/// Storage faults.
pub(crate) fn capture_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &(AttemptId, [u8; 32]),
) -> Result<Option<CapturedTurnCall>> {
    Ok(CAPTURES
        .get_bytes(store, txn, key)?
        .and_then(|bytes| CAPTURES.decode_value(&bytes).ok()))
}

/// Every decodable capture of `attempt`, in key order. A row that does not decode is no
/// capture.
///
/// # Errors
///
/// Storage faults.
pub(crate) fn captures_of_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
) -> Result<Vec<((AttemptId, [u8; 32]), CapturedTurnCall)>> {
    let mut out = Vec::new();
    for row in CAPTURES.iter_raw_from(store, txn, attempt.as_bytes())? {
        let (key, value) = row?;
        let (Some(key), Ok(capture)) = (
            <(AttemptId, [u8; 32]) as SideKey>::decode_key(&key),
            CAPTURES.decode_value(&value),
        ) else {
            continue;
        };
        out.push((key, capture));
    }
    Ok(out)
}

/// How many capture rows the table holds, decodable or not, for
/// `test_doors::dreamer_answer_schema`.
///
/// # Errors
///
/// Storage faults.
#[cfg(oneiron_test_support)]
pub(crate) fn capture_count_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> Result<usize> {
    Ok(CAPTURES.scan_keys(store, txn, &[])?.len())
}

/// Deletes every capture under `attempt`, decodable or not.
///
/// # Errors
///
/// Storage faults.
pub(crate) fn delete_captures_of_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
) -> Result<()> {
    let keys = CAPTURES.scan_keys(store, &*txn, attempt.as_bytes())?;
    for key in &keys {
        CAPTURES.delete(store, txn, key)?;
    }
    Ok(())
}

/// Deletes every capture older than `max_age_secs` at `now` (both Unix seconds), and every
/// capture that no longer decodes: the check cannot draw it.
///
/// # Errors
///
/// Storage faults.
pub(crate) fn delete_old_captures_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    now: u64,
    max_age_secs: u64,
) -> Result<()> {
    let mut doomed = Vec::new();
    for row in CAPTURES.iter_raw_from(store, &*txn, &[])? {
        let (key, value) = row?;
        let Some(key) = <(AttemptId, [u8; 32]) as SideKey>::decode_key(&key) else {
            continue;
        };
        let too_old = match CAPTURES.decode_value(&value) {
            Ok(capture) => now.saturating_sub(capture.captured_at) > max_age_secs,
            Err(_) => true,
        };
        if too_old {
            doomed.push(key);
        }
    }
    for key in &doomed {
        CAPTURES.delete(store, txn, key)?;
    }
    Ok(())
}

/// Deletes every capture that lists `source` among its rows, in the erase's own transaction.
/// A capture that does not decode names no source.
///
/// # Errors
///
/// Storage faults.
pub(crate) fn erase_captures_for_source_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    source: &EntityId,
) -> Result<()> {
    let mut doomed = Vec::new();
    for row in CAPTURES.iter_raw_from(store, &*txn, &[])? {
        let (key, value) = row?;
        let (Some(key), Ok(capture)) = (
            <(AttemptId, [u8; 32]) as SideKey>::decode_key(&key),
            CAPTURES.decode_value(&value),
        ) else {
            continue;
        };
        if capture.sources.contains(source) {
            doomed.push(key);
        }
    }
    for key in &doomed {
        CAPTURES.delete(store, txn, key)?;
    }
    Ok(())
}

/// The capture table's actor scrub: an erase of `actor` takes the captures that list that id
/// among their rows, in the erase's own writer. Erasure of a source row is the primary path
/// ([`erase_captures_for_source_in_txn`], wired in `deletion::derived_rows`); this covers the
/// actor-erase walk over the table.
///
/// # Errors
///
/// Storage faults.
pub(crate) fn erase_capture_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    erase_captures_for_source_in_txn(&vault.store, txn, actor)
}
