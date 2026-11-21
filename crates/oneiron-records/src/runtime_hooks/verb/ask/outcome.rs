//! Moved from `crates/oneiron/src/runtime_hooks/verb/ask/outcome.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::runtime_hooks::verb::ask::MAX_SAVED_VERB_ERROR_BYTES;
use crate::runtime_hooks::verb::ask::cut;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;

/// What a call the drain ran returned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedOutcome {
    /// The caller's view of the result, as JSON.
    Ok {
        result: String,
        /// The rows the result was derived from, when its door listed them
        /// (FIX 1435). The door that answers the retry releases the result
        /// by them.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "oneiron_contracts::serialize::entity_ref::optional_set"
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
    },
}

impl SavedOutcome {
    /// What a drained call that returned `value` saves: its full JSON for
    /// the caller's retry of this same invocation, beside `producers`, the
    /// rows its door listed it derived from (FIX 1435), and the chain's
    /// `hook_notice`.
    pub fn result(
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
    pub fn error(code: String, message: &str, hook_notice: Option<bool>) -> Self {
        Self::Err {
            code,
            message: cut(message, MAX_SAVED_VERB_ERROR_BYTES),
            hook_notice,
            receipt: None,
        }
    }
}
