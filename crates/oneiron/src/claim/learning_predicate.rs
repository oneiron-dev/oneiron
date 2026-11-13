//! Measured-state predicate vocabulary and its permitted estimate forms.

use serde::{Deserialize, Serialize};

use crate::claim::learning_estimate::EstimateForm;
use crate::write_envelope::learning_predicate::{
    PREDICATE_LEARNING_EDIT_COST, PREDICATE_LEARNING_RELIABILITY, PREDICATE_LEARNING_RETEST_NOISE,
    PREDICATE_LEARNING_SETTING,
};

#[doc(hidden)]
pub use oneiron_verb_wire::claim::learning_predicate::{
    LearningPredicate, MeasuredLearningPredicate,
};
