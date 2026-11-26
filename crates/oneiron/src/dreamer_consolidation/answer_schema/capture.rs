//! One TURN extraction call kept for the nightly answer-schema check (HOUSE-SCHEMA-CHECK):
//! the request whole, the TURN rows its transcript was read from, and when it was kept.
//!
//! Both TURN callers keep their call after the request is final and before it is sent, only
//! while the call carries the schema. A memo hit keeps nothing new: the key already names the
//! call. NOTE reviews never capture. The check deletes every capture under its night when its
//! receipt lands, and older captures go after eight days; an erase of a row listed in
//! `sources` drops the capture in the erase's own transaction.
//!
//! A durable step's stamps name one subject, and a capture's words come from every row in
//! `sources`, so the capture binds the check's calls itself (REVIEW-10538 round 2): each call
//! is listed on the capture before it goes out, and whenever the capture goes (an erase of
//! any of its rows, the landing, its age) the reply and kept request of every call it lists
//! go in the same transaction.

use serde::{Deserialize, Serialize};

use super::super::support::invalid_consolidation;
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::settings::ReadDestination;
use crate::side_table::{self, Named, SideKey, SideTable};
use crate::store::Store;
use oneiron_model::llm::LlmRequest;

/// The captures, keyed by child attempt and the call's step hash.
const CAPTURES: SideTable<(AttemptId, [u8; 32]), CapturedTurnCall, Named> =
    SideTable::new(&side_table::DREAMER_ANSWER_SCHEMA_CAPTURE);

/// One TURN extraction call kept for the check: the request whole, as sent, the rows its
/// transcript was read from, when it was kept (Unix seconds), and the check's calls sent
/// from it, each as its check attempt and step hash.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CapturedTurnCall {
    pub(crate) request: LlmRequest,
    pub(crate) sources: Vec<EntityId>,
    pub(crate) captured_at: u64,
    #[serde(default)]
    pub(crate) check_calls: Vec<(AttemptId, [u8; 32])>,
}

/// Keeps `request`, built with the answer schema by `attempt`, for the check: one row under
/// the call's step hash, in one small write transaction. `sources` are the TURN rows the
/// transcript was read from; `captured_at` is Unix seconds. A row already under the key
/// (a memo hit) keeps nothing new, and neither does a call with a source the write's own
/// transaction reads as erased, deleted or withdrawn: an erase that committed before this
/// write found no capture to drop, so the words must not be stored again here
/// (REVIEW-10538 P1-2). One that commits after it drops the row, as above.
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
        if sources
            .iter()
            .any(|source| crate::code_run::source_row_withdrawn_in(vault, &*txn, source))
        {
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
                check_calls: Vec::new(),
            },
        )
    })
}

/// Lists the check's call `request`, sent by the check attempt `check`, on the capture `key`
/// before the call goes out, in one small write transaction. `false`, listing nothing, when
/// the capture is gone or one of its rows reads as erased, deleted or withdrawn in that
/// transaction: the call must not go.
///
/// # Errors
///
/// The request does not hash; storage faults.
pub(crate) fn bind_check_call(
    vault: &Vault,
    key: &(AttemptId, [u8; 32]),
    check: AttemptId,
    request: &LlmRequest,
) -> Result<bool> {
    let step = request
        .canonical_hash()
        .map_err(|_| invalid_consolidation("the check call's request did not hash"))?;
    vault.with_write_txn_grouped(|txn| {
        let Some(mut capture) = capture_in_txn(&vault.store, &*txn, key)? else {
            return Ok(false);
        };
        if capture
            .sources
            .iter()
            .any(|source| crate::code_run::source_row_withdrawn_in(vault, &*txn, source))
        {
            return Ok(false);
        }
        if !capture.check_calls.contains(&(check, step)) {
            capture.check_calls.push((check, step));
            CAPTURES.put(&vault.store, txn, key, &capture)?;
        }
        Ok(true)
    })
}

/// Takes the reply and kept request of every check call `capture` lists, in the writer that
/// deletes the capture.
fn take_check_calls_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    capture: &CapturedTurnCall,
) -> Result<()> {
    for (check, step) in &capture.check_calls {
        crate::llm::erase_step_state_key_in_txn(store, txn, *check, step)?;
    }
    Ok(())
}

/// The capture rows whose key starts with `prefix`: each key with its capture, `None` for a
/// row that does not decode.
fn rows_from_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    prefix: &[u8],
) -> Result<Vec<(Vec<u8>, Option<CapturedTurnCall>)>> {
    let mut out = Vec::new();
    for row in CAPTURES.iter_raw_from(store, txn, prefix)? {
        let (key, value) = row?;
        out.push((key, CAPTURES.decode_value(&value).ok()));
    }
    Ok(out)
}

/// Whether the capture `key` may still go to the house rung at `destination`
/// (REVIEW-10538 round 2): it stands, none of its rows reads as erased, deleted or
/// withdrawn, no world withheld from `destination` keeps one of them, and the world its
/// request names may go there. A capture kept while its world could go stays here once the
/// world is made device-only; nothing is withheld from a rung on this device.
///
/// # Errors
///
/// Storage faults; a world settings read that fails.
pub(crate) fn capture_may_go(
    vault: &Vault,
    key: &(AttemptId, [u8; 32]),
    destination: &ReadDestination,
) -> Result<bool> {
    let capture = {
        let txn = vault.store.env.read_txn()?;
        capture_in_txn(&vault.store, &txn, key)?
    };
    let Some(capture) = capture else {
        return Ok(false);
    };
    if crate::code_run::source_rows_withdrawn(vault, &capture.sources) {
        return Ok(false);
    }
    if !destination.is_off_device() {
        return Ok(true);
    }
    for row in &capture.sources {
        if vault.device_local_keeps_for(row, destination)? {
            return Ok(false);
        }
    }
    Ok(vault
        .model_call_hold_for(capture.request.envelope.scope.world, destination)?
        .is_none())
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

/// Deletes every capture under `attempt`, decodable or not, with the replies of the check
/// calls each lists.
///
/// # Errors
///
/// Storage faults.
pub(crate) fn delete_captures_of_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
) -> Result<()> {
    for capture in rows_from_in_txn(store, &*txn, attempt.as_bytes())?
        .into_iter()
        .filter_map(|(_, capture)| capture)
    {
        take_check_calls_in_txn(store, txn, &capture)?;
    }
    let keys = CAPTURES.scan_keys(store, &*txn, attempt.as_bytes())?;
    for key in &keys {
        CAPTURES.delete(store, txn, key)?;
    }
    Ok(())
}

/// Deletes every capture older than `max_age_secs` at `now` (both Unix seconds), with the
/// replies of the check calls each lists, and every capture that no longer decodes: the
/// check cannot draw it.
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
    for (key, capture) in rows_from_in_txn(store, &*txn, &[])? {
        let Some(key) = <(AttemptId, [u8; 32]) as SideKey>::decode_key(&key) else {
            continue;
        };
        match capture {
            Some(capture) if now.saturating_sub(capture.captured_at) <= max_age_secs => {}
            capture => doomed.push((key, capture)),
        }
    }
    for (key, capture) in &doomed {
        if let Some(capture) = capture {
            take_check_calls_in_txn(store, txn, capture)?;
        }
        CAPTURES.delete(store, txn, key)?;
    }
    Ok(())
}

/// Deletes every capture that lists `source` among its rows, with the replies of the check
/// calls each lists, in the erase's own transaction: an erase of any row a check call's
/// words came from takes that call's reply, the first row or not (REVIEW-10538 round 2). A
/// capture that does not decode names no source.
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
    for (key, capture) in rows_from_in_txn(store, &*txn, &[])? {
        let (Some(key), Some(capture)) = (
            <(AttemptId, [u8; 32]) as SideKey>::decode_key(&key),
            capture,
        ) else {
            continue;
        };
        if capture.sources.contains(source) {
            doomed.push((key, capture));
        }
    }
    for (key, capture) in &doomed {
        take_check_calls_in_txn(store, txn, capture)?;
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
