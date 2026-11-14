//! How a held call ends without its turn: its deadline passes
//! ([`Vault::expire_paced_verb_calls`]), or a permanent erase removes a row
//! its args name (FIX 22240). An erase's scrub ends each such call as its
//! deadline's expiry would ([`scrub_erased_paced_in_txn`]), the hold keeps
//! such args out, and a turn's claim ends one ([`end_erased_in_txn`]), so
//! the call never runs on that row or shows it.

use serde_json::Value;

use crate::memory::MEMORY_CODE_INVALID_STATE;
use crate::receipt::admission::refuse_held_intent_in_txn;
use crate::runtime_hooks::filter;
use crate::runtime_hooks::store::ErasedIds;
use crate::{Result, Vault};

use super::super::ask::SavedOutcome;
use super::{CALLS, InvocationId, PacedState, PacedVerbCall, WITNESSES, not_retained};

/// How long an ended call's row stays for its caller's retry.
const PACED_VERB_KEEP_SECS: u64 = 7 * 24 * 60 * 60;
/// What a call whose deadline passed before its turn ends with.
const EXPIRED: &str = "this paced call's deadline passed before its turn; it never ran";
/// What a call whose args named a row since erased ends with, unrun.
const ERASED: &str = "this paced call's args named a row since erased; it never ran";
/// What an ended call's saved error says once it named an erased id.
const ERASED_ERROR: &str = "this paced call ended with an error that named a row since erased";

impl Vault {
    /// Ends each held call whose deadline passed, unrun, its witness
    /// dropped, and deletes ended rows past their keep; at most `limit`
    /// rows. A call a turn runs now is left to that turn. It charges,
    /// spends and runs nothing, so any housekeeping pass may call it.
    /// Returns how many rows it ended or deleted.
    ///
    /// # Errors
    ///
    /// Storage errors as they occur.
    pub fn expire_paced_verb_calls(&self, limit: usize) -> Result<usize> {
        self.with_write_txn_grouped(|txn| {
            let now = self.store.clock.now_recorded_at();
            let mut touched = 0;
            for (key, mut row) in CALLS.scan(&self.store, txn)? {
                if touched >= limit {
                    break;
                }
                if row.state == PacedState::Ended {
                    if row
                        .ended_at
                        .is_some_and(|at| at.saturating_add(PACED_VERB_KEEP_SECS) <= now)
                    {
                        CALLS.delete(&self.store, txn, &key)?;
                        touched += 1;
                    }
                    continue;
                }
                if row.deadline > now
                    || self
                        .runtime()
                        .verb_hook_state()
                        .drain_holds(InvocationId(key))
                {
                    continue;
                }
                row.outcome = Some(if row.landed {
                    not_retained()
                } else {
                    refuse_held_intent_in_txn(
                        self,
                        txn,
                        row.actor,
                        filter::edge_class(row.class),
                        InvocationId(key),
                        MEMORY_CODE_INVALID_STATE,
                        EXPIRED,
                    )?;
                    SavedOutcome::error(MEMORY_CODE_INVALID_STATE.to_owned(), EXPIRED, None)
                });
                row.state = PacedState::Ended;
                row.ended_at = Some(now);
                CALLS.put(&self.store, txn, &key, &row)?;
                WITNESSES.delete(&self.store, txn, &key)?;
                touched += 1;
            }
            Ok(touched)
        })
    }
}

/// Ends each held call whose args name an id in `erased`, scanned whole, in
/// the erase's write at `at` (Unix seconds), by [`end_erased_in_txn`]. A
/// call whose effect landed, or whose turn runs now, may have run. A row
/// that does not decode and names one goes, its witness with it.
pub(in crate::runtime_hooks) fn scrub_erased_paced_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    erased: &ErasedIds,
    at: u64,
) -> Result<()> {
    let mut named = Vec::new();
    let mut gone = Vec::new();
    for entry in CALLS.iter_raw_from(&vault.store, txn, &[])? {
        let (key, value) = entry?;
        let Ok(key) = <[u8; 16]>::try_from(key.as_slice()) else {
            continue;
        };
        match CALLS.decode_value(&value) {
            Ok(row) if erased.named_by_json(&row.args) => named.push((key, row)),
            Err(_) if erased.named_in(&String::from_utf8_lossy(&value)) => gone.push(key),
            Ok(_) | Err(_) => {}
        }
    }
    for (key, row) in named {
        let ran = row.landed
            || (row.state == PacedState::Running
                && vault
                    .runtime()
                    .verb_hook_state()
                    .drain_holds(InvocationId(key)));
        end_erased_in_txn(vault, txn, key, row, erased, at, ran)?;
    }
    for key in gone {
        CALLS.delete(&vault.store, txn, &key)?;
        WITNESSES.delete(&vault.store, txn, &key)?;
    }
    Ok(())
}

/// Ends `row`, held under `key`, whose args name an id in `erased`, at
/// `now`, keeping nothing of what it would run on: its args emptied and its
/// witness dropped. One that waits ends unrun, as its deadline's expiry ends
/// it, its held admission intent refused; one that `ran` (its effect landed,
/// or its turn runs now) ends as one whose answer was not kept, so it is
/// never sent again. One that already ended keeps that, without a result
/// that could show the row or an error that names it.
pub(super) fn end_erased_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: [u8; 16],
    mut row: PacedVerbCall,
    erased: &ErasedIds,
    now: u64,
    ran: bool,
) -> Result<()> {
    row.args = Value::Null.to_string();
    row.outcome = match row.outcome.take() {
        _ if row.state != PacedState::Ended && ran => Some(not_retained()),
        _ if row.state != PacedState::Ended => {
            refuse_held_intent_in_txn(
                vault,
                txn,
                row.actor,
                filter::edge_class(row.class),
                InvocationId(key),
                MEMORY_CODE_INVALID_STATE,
                ERASED,
            )?;
            Some(SavedOutcome::error(
                MEMORY_CODE_INVALID_STATE.to_owned(),
                ERASED,
                None,
            ))
        }
        Some(SavedOutcome::Ok { .. }) => Some(not_retained()),
        Some(SavedOutcome::Err {
            code,
            message,
            hook_notice,
            receipt,
            mut reason_codes,
        }) => {
            reason_codes.retain(|reason| !erased.named_in(reason));
            Some(SavedOutcome::Err {
                code,
                message: if erased.named_in(&message) {
                    ERASED_ERROR.to_owned()
                } else {
                    message
                },
                hook_notice,
                receipt,
                reason_codes,
            })
        }
        None => None,
    };
    if row.state != PacedState::Ended {
        row.state = PacedState::Ended;
        row.ended_at = Some(now);
    }
    CALLS.put(&vault.store, txn, &key, &row)?;
    WITNESSES.delete(&vault.store, txn, &key).map(drop)
}
