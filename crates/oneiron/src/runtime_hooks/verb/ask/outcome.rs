//! What a call the drain ran returned, as its stopped call's row keeps it
//! for the caller's retry of the same invocation: the result, beside the
//! rows its door listed it derived from (FIX 1435), or the error; each with
//! the completed chain's notice metadata when its source supplied one
//! (FIX 12517).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{ASKS, MAX_SAVED_VERB_ERROR_BYTES, cut};
use crate::runtime_hooks::{InvocationId, VerbHookStop};
use crate::{EntityId, Error, Result, Vault};

#[doc(hidden)]
pub(in crate::runtime_hooks::verb) use oneiron_records::runtime_hooks::verb::ask::outcome::SavedOutcome;

/// The stop a retry of a drained call gets: what the call returned.
pub(super) fn completed(invocation: InvocationId, outcome: &SavedOutcome) -> Result<VerbHookStop> {
    Ok(match outcome {
        SavedOutcome::Ok {
            result,
            hook_notice,
            ..
        } => VerbHookStop::Completed {
            invocation: invocation.to_hex(),
            result: serde_json::from_str(result)
                .map_err(|_| Error::CorruptedIndex("verb hook ask outcome"))?,
            hook_notice: *hook_notice,
        },
        SavedOutcome::Err {
            code,
            message,
            hook_notice,
            receipt,
        } => VerbHookStop::CompletedWithError {
            invocation: invocation.to_hex(),
            code: code.clone(),
            message: message.clone(),
            receipt_ref: receipt.clone(),
            hook_notice: *hook_notice,
        },
    })
}

/// The rows the result a drained call saved under `invocation` was derived
/// from, as its door listed them (FIX 1435). `None` when no result is saved
/// there, or its door listed none.
pub(in crate::runtime_hooks::verb) fn saved_producers(
    vault: &Vault,
    invocation: InvocationId,
) -> Result<Option<Vec<EntityId>>> {
    let rtxn = vault.store.env.read_txn()?;
    let outcome = ASKS
        .get(&vault.store, &rtxn, &invocation.0)?
        .and_then(|row| row.outcome);
    Ok(match outcome {
        Some(SavedOutcome::Ok { producers, .. }) => {
            producers.map(|producers| producers.into_iter().collect())
        }
        _ => None,
    })
}
