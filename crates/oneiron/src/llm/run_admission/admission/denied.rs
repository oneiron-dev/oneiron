//! Why the run admission refuses a call or an edit, and the model error each
//! refusal reads as.
use serde::Serialize;

use crate::llm::run_admission::{AllocationRefusal, LeaseUnit};
use crate::llm::{BudgetDenied, DispatchRefused, LlmError, ModelId, RetryableLlmError};

/// Why the run admission refused a call or an edit. Every refusal comes
/// before any byte leaves and leaves no reservation behind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, thiserror::Error)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RunDenied {
    #[error("the run did not declare teacher {model}")]
    UndeclaredTeacher { model: ModelId },
    /// The selector names no model id and no alias the run froze. A caller
    /// may pass any text there, so the denial keeps only its length.
    #[error("the run knows no model or alias by the {len}-byte selector given")]
    UnknownSelector { len: usize },
    #[error("the offer binds another model than the call names")]
    OfferMismatch,
    #[error("no offer on this host serves {model}")]
    NoOffer { model: ModelId },
    #[error("the call's locality differs from its route's")]
    LocalityMismatch,
    #[error("the call picks its model or route through {key}")]
    RouteOverride { key: String },
    #[error("the route's backend refused the call before sending it")]
    BackendRefused,
    #[error("a declared run keeps its paid keys at T0")]
    KeyAtT1,
    #[error("the run did not declare connector {connector}")]
    UndeclaredConnector { connector: String },
    #[error("no rate converts {from:?} into {to:?}")]
    UnitMismatch { from: LeaseUnit, to: LeaseUnit },
    #[error("budget: {denied}")]
    Budget { denied: BudgetDenied },
    #[error("the host has delivered no allocation")]
    NoAllocation,
    #[error("the allocation is spent")]
    AllocationExhausted,
    #[error("the host refused a fresh allocation: {reason:?}")]
    AllocationRefused { reason: AllocationRefusal },
    /// The resident's share of the allocation, which the owner pinned, does
    /// not fit the call (FIX 7767). An unpinned share never refuses.
    #[error("the owner's pinned share for this resident is spent")]
    ResidentShareSpent { resident: crate::EntityId },
    #[error("dispatch refused: {refused}")]
    Dispatch { refused: DispatchRefused },
    #[error("a run never edits its own declaration")]
    DeclarationEditRefused,
    /// A fallback to this offer would take the call's work off the device
    /// while its world stays here, for a content-free reason (FIX 4939):
    /// the owner's recipient choice for that world, or an integrity hold.
    #[error("the call's world stays on this device: {reason}")]
    KeptOnDevice { reason: &'static str },
}

impl From<RunDenied> for LlmError {
    fn from(denied: RunDenied) -> Self {
        match denied {
            RunDenied::Budget { denied } => Self::BudgetDenied(denied),
            RunDenied::NoAllocation
            | RunDenied::AllocationExhausted
            | RunDenied::ResidentShareSpent { .. } => Self::BudgetDenied(BudgetDenied::Exhausted),
            // The account owner's question holds the work: never a spent
            // budget (FIX 9924).
            RunDenied::AllocationRefused {
                reason: AllocationRefusal::HostCheck,
            } => Self::BudgetDenied(BudgetDenied::HostCheck),
            RunDenied::Dispatch { refused } => Self::BudgetDenied(refused.into()),
            // A privacy hold stays one: never a budget refusal.
            RunDenied::KeptOnDevice { reason } => {
                Self::Retryable(RetryableLlmError::KeptOnDevice {
                    retry_after: None,
                    resets_at: Vec::new(),
                    reason: Some(reason.to_owned()),
                })
            }
            RunDenied::UndeclaredTeacher { .. }
            | RunDenied::UnknownSelector { .. }
            | RunDenied::OfferMismatch
            | RunDenied::NoOffer { .. }
            | RunDenied::LocalityMismatch
            | RunDenied::RouteOverride { .. }
            | RunDenied::BackendRefused
            | RunDenied::KeyAtT1
            | RunDenied::UndeclaredConnector { .. }
            | RunDenied::UnitMismatch { .. }
            | RunDenied::DeclarationEditRefused => {
                Self::BudgetDenied(BudgetDenied::AdmissionDenied)
            }
        }
    }
}
