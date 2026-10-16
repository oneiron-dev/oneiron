//! Label-read seam: a host model scores a closed label set instead of generating text.
//!
//! One read is a pack: several typed questions over the same bounded state, sent in one
//! request, each its own readout over its own labels and normalized alone (idle-fold test
//! 6b: a separate read, not one joint table). The caller's questions, the paired yes/no
//! question ("does this need more thinking?") and the person yes/no question ("ask a
//! person?") are each one question of the pack. The host owns the tokenizer, the label
//! verbalizers, the prompt each question renders over the shared state, and calibration.
//! This seam carries only the probabilities and the usage to settle.

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

impl LabelSet<'_> {
    /// How many labels the readout reports.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Noul => 2,
            Self::Choice(options) => options.len(),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One question, its own description, and the labels it is read over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabelReadout<'a> {
    pub text: &'a str,
    pub labels: LabelSet<'a>,
}

/// A pack: the questions read apart over one state, in one request.
#[derive(Debug, Clone, Copy)]
pub struct LabelReadRequest<'a> {
    /// Caller-scoped, bounded state; never an implicit vault dump. Every question reads
    /// the same state: it is the pack's shared prefix.
    pub state: &'a JsonValue,
    pub questions: &'a [LabelReadout<'a>],
    /// When the decision's work time ends; the reader's client waits no later, so its
    /// own preparation counts against it. None keeps the provider's own timeout.
    pub work_until: Option<std::time::Instant>,
}

/// One distribution per question of the pack.
#[derive(Debug, Clone, PartialEq)]
pub struct LabelReadResponse {
    /// Each question's distribution over its own labels, in request order.
    pub readouts: Vec<Vec<f64>>,
    /// Tokens the whole pack used, its retries included; settled against its own lease.
    pub usage: LlmUsage,
}

/// A host model in decision-read mode. One call reads every question of the pack, each
/// over its own labels, and generates no text.
pub trait LabelReadModel: Send + Sync {
    /// The exact model this reader serves.
    fn model(&self) -> &str;
    /// The exact revision (weights and read recipe) this reader serves.
    fn revision(&self) -> &str;
    /// The most labels one question may carry; a read never trims a question to fit.
    fn max_labels(&self) -> usize {
        64
    }
    fn read(
        &self,
        request: &LabelReadRequest<'_>,
        lease: &BudgetLease,
    ) -> LlmResult<LabelReadResponse>;
}
