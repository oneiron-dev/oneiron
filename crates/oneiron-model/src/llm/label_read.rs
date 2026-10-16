//! Label-read seam: a host model scores a closed label set instead of generating text.
//!
//! One read evaluates its readouts over the same bounded state in one forward pass: the
//! caller's question over its labels, the paired yes/no question ("does this need more
//! thinking?") and, when asked, the person yes/no question ("ask a person?"). The host owns
//! the tokenizer, the label verbalizers, the read position and calibration. This seam carries
//! only the probabilities and the usage to settle.

use super::{BudgetLease, LlmResult, LlmUsage};
use serde_json::Value as JsonValue;

/// The labels a readout scores, in the order its probabilities are reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelSet<'a> {
    /// Two labels: yes, then no.
    Noul,
    /// The caller's closed options, in their declared order.
    Choice(&'a [String]),
}

/// One question and the labels it is read over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabelReadout<'a> {
    pub text: &'a str,
    pub labels: LabelSet<'a>,
}

/// The primary readout and the yes/no questions read with it, over one state.
#[derive(Debug, Clone, Copy)]
pub struct LabelReadRequest<'a> {
    /// Caller-scoped, bounded state; never an implicit vault dump.
    pub state: &'a JsonValue,
    pub primary: LabelReadout<'a>,
    /// The paired yes/no question, read in the same forward evaluation as `primary`.
    pub paired: &'a str,
    /// The person yes/no question, read in that same evaluation when present.
    pub person: Option<&'a str>,
}

/// Probabilities from one forward evaluation.
#[derive(Debug, Clone, PartialEq)]
pub struct LabelReadResponse {
    /// The primary readout's distribution over its labels, in request order.
    pub primary: Vec<f64>,
    /// P(yes) for the paired question.
    pub paired_yes: f64,
    /// P(yes) for the person question; present exactly when the request asked it.
    pub person_yes: Option<f64>,
    /// Tokens this read used; settled against its own lease.
    pub usage: LlmUsage,
}

/// A host model in decision-read mode. One call returns every readout the request asks
/// (the primary, the paired and, when asked, the person readout) from one forward
/// evaluation, and generates no text.
pub trait LabelReadModel: Send + Sync {
    /// The exact model this reader serves.
    fn model(&self) -> &str;
    /// The exact revision (weights and read recipe) this reader serves.
    fn revision(&self) -> &str;
    fn read(
        &self,
        request: &LabelReadRequest<'_>,
        lease: &BudgetLease,
    ) -> LlmResult<LabelReadResponse>;
}
