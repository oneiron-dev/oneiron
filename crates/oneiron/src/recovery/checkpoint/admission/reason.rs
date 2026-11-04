//! Restore refusal vocabulary, defined at the store layer.

pub(crate) use crate::store::restore_admission::{Rejected, because};
pub use crate::store::restore_admission::{
    RestoreAdmissionError, RestoreAdmissionReason, RestoreDestinationState, RestorePhase,
};
