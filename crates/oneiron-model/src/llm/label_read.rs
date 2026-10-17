//! Label-read seam: a host model scores a closed label set instead of generating text.
//!
//! One read is a pack: several typed questions over the same bounded state, sent in one
//! request, each its own readout. A caller's question and the paired yes/no question ("does
//! this need more thinking?") stay joint (ARCH-0076 `#ask-a-person`): one readout over
//! single-token joint labels, one per (option, paired answer), normalized once over all of
//! them. The person yes/no question ("ask a person?") is read separately, its own readout
//! over yes and no. The host owns the tokenizer, the label verbalizers, the prompt each
//! question renders over the shared state, and calibration. This seam carries only the
//! probabilities and the usage to settle.

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
    /// The paired yes/no question read jointly with this one. The readout then scores
    /// two joint labels per label `i`: row `2i` is (`i`, no), row `2i + 1` is (`i`, yes).
    pub paired: Option<&'a str>,
}

impl LabelReadout<'_> {
    /// How many probabilities the readout reports: one per label, or one per joint label.
    #[must_use]
    pub fn width(&self) -> usize {
        self.labels.len() * if self.paired.is_some() { 2 } else { 1 }
    }
}

/// A joint readout's marginals: each label's probability, then the paired P(yes).
#[must_use]
pub fn joint_marginals(readout: &[f64]) -> (Vec<f64>, f64) {
    let labels = readout
        .chunks_exact(2)
        .map(|cells| cells[0] + cells[1])
        .collect();
    let paired = readout.chunks_exact(2).map(|cells| cells[1]).sum();
    (labels, paired)
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
    /// Each question's distribution over its own labels (or joint labels), in request order.
    pub readouts: Vec<Vec<f64>>,
    /// Tokens the whole pack used, its retries included; settled against its own lease.
    pub usage: LlmUsage,
}

/// A host model in decision-read mode. One call reads every question of the pack, each
/// over its own labels or joint labels, and generates no text.
pub trait LabelReadModel: Send + Sync {
    /// The exact model this reader serves.
    fn model(&self) -> &str;
    /// The exact revision (weights and read recipe) this reader serves.
    fn revision(&self) -> &str;
    /// The most labels one readout may score, joint labels counted one each; a read never
    /// trims a question to fit.
    fn max_labels(&self) -> usize {
        64
    }
    fn read(
        &self,
        request: &LabelReadRequest<'_>,
        lease: &BudgetLease,
    ) -> LlmResult<LabelReadResponse>;
}
