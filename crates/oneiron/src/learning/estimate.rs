//! Measured-state estimate vocabulary, defined with claim values.

pub use crate::claim::learning_estimate::{
    BetaView, ESTIMATOR_VERSION, Estimate, EstimateForm, EstimateLabels, EstimateValue, Prior,
    PriorOrigin, Window,
};
pub(crate) use crate::claim::learning_estimate::{OwnTally, fold_value};
