//! Moved from `crates/oneiron/src/policy_model/verdict.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Why a plane that wanted a model answer has none. A closed set, so a ledger
/// row or a host can name the cause without carrying an error's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PolicySkipReason {
    /// The door had no safeguard model in reach.
    NoBackend,
    /// The plane wants model coverage but the owner wrote no policy document
    /// for a model to read.
    NoDocument,
    /// The model call failed.
    BackendUnavailable,
    /// The model answered, but not in a form the plane can resolve.
    ResponseUnusable,
    /// The classifier budget refused the call.
    BudgetExhausted,
    /// The budget guard denied admission without spending the classifier budget.
    AdmissionDenied,
    /// The policy moved under every pass, so no verdict could be pinned to it.
    PolicyMoving,
}

impl PolicySkipReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoBackend => "no_backend",
            Self::NoDocument => "no_document",
            Self::BackendUnavailable => "backend_unavailable",
            Self::ResponseUnusable => "response_unusable",
            Self::BudgetExhausted => "budget_exhausted",
            Self::AdmissionDenied => "admission_denied",
            Self::PolicyMoving => "policy_moving",
        }
    }
}
