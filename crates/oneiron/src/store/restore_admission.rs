//! Restore refusal vocabulary lives in recovery; this store path re-exports it.

pub(crate) use crate::recovery::checkpoint::{Rejected, because};
pub use crate::recovery::checkpoint::{
    RestoreAdmissionError, RestoreAdmissionReason, RestoreDestinationState, RestorePhase,
};
