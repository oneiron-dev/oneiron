//! What a call the drain ran returned, as its stopped call's row keeps it
//! for the caller's retry of the same invocation: the result, beside the
//! rows its door listed it derived from (FIX 1435), or the error.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{ASKS, MAX_SAVED_VERB_ERROR_BYTES, cut};
use crate::runtime_hooks::InvocationId;
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
    },
    Err {
        code: String,
        message: String,
        /// The refusal receipt a credential call that ended refused left.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        receipt: Option<String>,
    },
}

impl SavedOutcome {
    /// What a drained call that returned `value` saves: its full JSON for
    /// the caller's retry of this same invocation, beside `producers`, the
    /// rows its door listed it derived from (FIX 1435).
    pub(in crate::runtime_hooks::verb) fn result(
        value: &Value,
        producers: Option<Vec<EntityId>>,
    ) -> Result<Self> {
        serde_json::to_string(value)
            .map(|result| Self::Ok {
                result,
                producers: producers.map(|producers| producers.into_iter().collect()),
            })
            .map_err(|_| Error::InvariantViolation("verb hook ask outcome encode"))
    }

    /// What a drained call that failed with `code` saves: its message cut to
    /// [`MAX_SAVED_VERB_ERROR_BYTES`].
    pub(in crate::runtime_hooks::verb) fn error(code: String, message: &str) -> Self {
        Self::Err {
            code,
            message: cut(message, MAX_SAVED_VERB_ERROR_BYTES),
            receipt: None,
        }
    }
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
