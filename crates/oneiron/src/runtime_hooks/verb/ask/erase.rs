//! A stopped call's saved args after a permanent erase (FIX 22240): a call
//! whose saved args name an erased row never runs on that row or shows it.
//! The erase's scrub ends each such call ([`scrub_erased_asks_in_txn`]),
//! the write that saves one keeps such args out, and a resume refuses them
//! ([`ERASED_ARGS`]).

use serde_json::Value;

use super::{
    ASKS, HOOK_OUTCOME_UNCERTAIN, HOOK_RESULT_NOT_RETAINED, SavedOutcome, VerbAsk, VerbAskState,
};
use crate::runtime_hooks::store::ErasedIds;
use crate::runtime_hooks::verb::credential;
use crate::{Result, Vault};

/// Why a stopped call whose saved args name an erased row does not run.
pub(super) const ERASED_ARGS: &str =
    "the call's saved args name a row since erased; it does not run";

/// What a used call whose args named an erased row, and which kept no
/// outcome, ends with.
const ERASED_UNCERTAIN: &str = "this call's saved args named a row since erased; the verb may or \
     may not have run, and it will not run again under this invocation";

/// What a used call whose args named an erased row, and which kept a
/// result, ends with in its place.
const ERASED_RESULT: &str = "this call ran, but its args named a row since erased, so its \
     result was not kept; do not send it again";

/// What a used call's saved error says once it named an erased id.
const ERASED_ERROR: &str = "this call ended with an error that named a row since erased";

/// Ends each stopped call whose saved args name an id in `erased`, scanned
/// whole, in the erase's write at `at` (Unix seconds). One still waiting
/// on its ask goes, its witness with it, as the drain's prune takes an old
/// one: its retry then meets what a pruned call's does. One whose answer
/// was used, or that the drain is running, stays used so it never runs
/// again under its invocation, its args and captured inputs emptied and
/// any result it kept no longer shown. A row that does not decode and
/// names one goes.
pub(in crate::runtime_hooks) fn scrub_erased_asks_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    erased: &ErasedIds,
    at: u64,
) -> Result<()> {
    let mut gone = Vec::new();
    let mut used = Vec::new();
    for entry in ASKS.iter_raw_from(&vault.store, txn, &[])? {
        let (key, value) = entry?;
        let Ok(key) = <[u8; 16]>::try_from(key.as_slice()) else {
            continue;
        };
        match ASKS.decode_value(&value) {
            Ok(row) if !erased.named_by_json(&row.args) => {}
            Ok(row) if row.state == VerbAskState::Open && !row.running => gone.push(key),
            Ok(row) => used.push((key, row)),
            Err(_) if erased.named_in(&String::from_utf8_lossy(&value)) => gone.push(key),
            Err(_) => {}
        }
    }
    for key in gone {
        ASKS.delete(&vault.store, txn, &key)?;
        credential::forget_in_txn(vault, txn, key)?;
    }
    for (key, mut row) in used {
        retire_used(&mut row, erased, at);
        ASKS.put(&vault.store, txn, &key, &row)?;
        credential::forget_in_txn(vault, txn, key)?;
    }
    Ok(())
}

/// Keeps a used or running call used, so it never runs again under its
/// invocation, with nothing of what it ran on: its args and inputs emptied,
/// a result it kept no longer shown, and an error naming an erased id
/// without that text. One that kept no outcome reads as one whose outcome
/// is unknown.
fn retire_used(row: &mut VerbAsk, erased: &ErasedIds, at: u64) {
    row.args = Value::Null.to_string();
    row.inputs = None;
    row.state = VerbAskState::Consumed;
    row.consumed_at.get_or_insert(at);
    row.ready = false;
    row.running = false;
    row.outcome = Some(match row.outcome.take() {
        None => SavedOutcome::error(HOOK_OUTCOME_UNCERTAIN.to_owned(), ERASED_UNCERTAIN, None),
        Some(SavedOutcome::Ok { hook_notice, .. }) => SavedOutcome::error(
            HOOK_RESULT_NOT_RETAINED.to_owned(),
            ERASED_RESULT,
            hook_notice,
        ),
        Some(SavedOutcome::Err {
            code,
            message,
            hook_notice,
            receipt,
            mut reason_codes,
        }) => SavedOutcome::Err {
            code,
            message: if erased.named_in(&message) {
                ERASED_ERROR.to_owned()
            } else {
                message
            },
            hook_notice,
            receipt,
            reason_codes: {
                reason_codes.retain(|reason| !erased.named_in(reason));
                reason_codes
            },
        },
    });
}
