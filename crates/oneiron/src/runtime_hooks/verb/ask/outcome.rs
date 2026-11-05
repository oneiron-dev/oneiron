//! A drained verb call's saved answer and its retry metadata.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::runtime_hooks::{InvocationId, VerbHookStop};
use crate::{Error, Result};

use super::{MAX_SAVED_VERB_ERROR_BYTES, cut};

/// What a call the drain ran returned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::runtime_hooks::verb) enum SavedOutcome {
    /// The caller's view of the result, as JSON.
    Ok {
        result: String,
        /// From the actual completed chain; absent when its source supplied none.
        hook_notice: Option<bool>,
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
    /// the caller's retry of this same invocation.
    pub(in crate::runtime_hooks::verb) fn result(
        value: &Value,
        hook_notice: Option<bool>,
    ) -> Result<Self> {
        serde_json::to_string(value)
            .map(|result| Self::Ok {
                result,
                hook_notice,
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

/// The stop a retry of a drained call gets: what the call returned.
pub(super) fn completed(invocation: InvocationId, outcome: &SavedOutcome) -> Result<VerbHookStop> {
    Ok(match outcome {
        SavedOutcome::Ok {
            result,
            hook_notice,
        } => VerbHookStop::Completed {
            invocation: invocation.to_hex(),
            result: serde_json::from_str(result)
                .map_err(|_| Error::CorruptedIndex("verb hook ask outcome"))?,
            hook_notice: *hook_notice,
        },
        SavedOutcome::Err {
            code,
            message,
            receipt,
        } => VerbHookStop::CompletedWithError {
            invocation: invocation.to_hex(),
            code: code.clone(),
            message: message.clone(),
            receipt_ref: receipt.clone(),
        },
    })
}
