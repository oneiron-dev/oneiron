//! Explicit standing-question preparation before provider work and its admission.

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::llm::decision::questions::GraphQuestionInput;
use crate::llm::decision::{DecisionDial, DecisionQuestion, TypedDecision};

#[doc(hidden)]
pub use oneiron_verb_wire::receipt::questions::standing_admit::{
    QuestionAdmitRequest, QuestionPrepareRequest, QuestionPrepared, QuestionPreparedSource,
};
