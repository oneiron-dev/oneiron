//! Question-class band policy input from settled human ask receipts.
//!
//! The policy owns the displacement. This module supplies factual labels and
//! validates the proposed band; it has no per-label step size or training rule.

use crate::EntityId;
use crate::error::Result;
use crate::llm::decision::DecisionBand;

#[derive(Debug, Clone, PartialEq)]
pub struct AskBandLabel {
    pub receipt: EntityId,
    pub word: EntityId,
    pub changed: bool,
    pub probability: Option<f64>,
}

/// Called with newly admitted labels only, for one principal and class.
/// Implementations must be bounded and side-effect free: the write transaction
/// holds the band state until the proposed revision is validated and stored.
pub trait AskBandPolicy {
    fn revise(&self, current: DecisionBand, labels: &[AskBandLabel]) -> Result<DecisionBand>;
}
