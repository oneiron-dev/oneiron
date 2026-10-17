//! A verb hook's stop (ARCH-0080 §3): the typed answer a caller gets when a
//! pre-hook skipped or asked, a blocking hook failed safe, or settlement
//! already ran the call it stopped.

use serde::{Deserialize, Serialize};

/// Why the verb did not run, or why its result stays hidden.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum VerbHookStop {
    /// A pre-hook skipped the verb; on a host verb, terminated it.
    Skipped { hook: String, reason: String },
    /// A pre-hook asked, or a blocking hook failed on a write: the ask is
    /// open, and a retry with the same invocation returns the same handle.
    Pending { invocation: String, ask: String },
    /// A blocking hook failed on a read, or a post-hook did before a result
    /// was released: the caller's view stays hidden.
    Hidden { hook: String },
    /// The ask was answered proceed and settlement ran the call once: what
    /// it returned. A row door answers with `result` itself.
    Completed {
        invocation: String,
        result: serde_json::Value,
    },
    /// The ask was answered proceed and settlement ran the call once, which
    /// failed, or refused it before it ran (a credential that no longer
    /// holds): its error's code and message, and the refusal's receipt
    /// (`call:<32hex>`) when it left one.
    CompletedWithError {
        invocation: String,
        code: String,
        message: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        receipt_ref: Option<String>,
    },
}

impl std::fmt::Display for VerbHookStop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Skipped { hook, reason } => write!(f, "hook {hook} skipped the verb: {reason}"),
            Self::Pending { invocation, ask } => {
                write!(
                    f,
                    "a hook asked first: ask {ask}; retry invocation {invocation}"
                )
            }
            Self::Hidden { hook } => write!(f, "hook {hook} failed safe; the result stays hidden"),
            Self::Completed { invocation, .. } => write!(
                f,
                "invocation {invocation} already ran once its hook's ask was answered"
            ),
            Self::CompletedWithError {
                invocation,
                code,
                message,
                ..
            } => write!(
                f,
                "invocation {invocation} ran once its hook's ask was answered and failed: {code}: {message}"
            ),
        }
    }
}

impl From<VerbHookStop> for super::Error {
    fn from(stop: VerbHookStop) -> Self {
        Self::VerbHook(Box::new(stop))
    }
}
