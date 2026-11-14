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

/// What a call the drain ran returned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::runtime_hooks::verb) enum SavedOutcome {
    /// The caller's view of the result, as JSON.
    Ok {
        result: String,
        /// The rows the result was derived from, when its door listed them
        /// (FIX 1435). The door that answers the retry releases the result
        /// by them.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "crate::serialize::entity_ref::optional_set"
        )]
        producers: Option<BTreeSet<EntityId>>,
        /// From the actual completed chain; absent when its source supplied none.
        hook_notice: Option<bool>,
    },
    Err {
        code: String,
        message: String,
        /// From the actual completed chain; absent when its source supplied none.
        hook_notice: Option<bool>,
        /// The refusal receipt a credential call that ended refused left.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        receipt: Option<String>,
        /// The error's reason codes, for a paced call's retry: a
        /// `CHECK_IN_PENDING` keeps the one naming the check-in it waits on
        /// (2k8g review). Empty on an ask's outcome, and on a row saved
        /// before.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        reason_codes: Vec<String>,
    },
}

impl SavedOutcome {
    /// What a drained call that returned `value` saves: its full JSON for
    /// the caller's retry of this same invocation, beside `producers`, the
    /// rows its door listed it derived from (FIX 1435), and the chain's
    /// `hook_notice`.
    pub(in crate::runtime_hooks::verb) fn result(
        value: &Value,
        producers: Option<Vec<EntityId>>,
        hook_notice: Option<bool>,
    ) -> Result<Self> {
        serde_json::to_string(value)
            .map(|result| Self::Ok {
                result,
                producers: producers.map(|producers| producers.into_iter().collect()),
                hook_notice,
            })
            .map_err(|_| Error::InvariantViolation("verb hook ask outcome encode"))
    }

    /// What a drained call that failed with `code` saves: its message cut to
    /// [`MAX_SAVED_VERB_ERROR_BYTES`].
    pub(in crate::runtime_hooks::verb) fn error(
        code: String,
        message: &str,
        hook_notice: Option<bool>,
    ) -> Self {
        Self::Err {
            code,
            message: cut(message, MAX_SAVED_VERB_ERROR_BYTES),
            hook_notice,
            receipt: None,
            reason_codes: Vec::new(),
        }
    }
}

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
            ..
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
