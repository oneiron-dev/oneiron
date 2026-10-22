//! The task highway's three surface questions, asked through the shared
//! decision ladder (OF-220).
//!
//! The surface supplies the question, its rule text, reversibility and safe
//! default; routing, budget, batching and the outcome ledger stay the
//! ladder's (ARCH-0076). No answer grants a lease, a scope or an approval:
//! decide() advises and never grants access. When no host brings a ladder,
//! every question answers "ask up", so the person is asked: the safe branch.

use std::time::{Duration, Instant};

use crate::entity_id::EntityId;
use crate::llm::decision::{
    DecisionAnswer, DecisionBandPolicy, DecisionDial, DecisionLadder, DecisionQuestion,
    DecisionReceipt, DecisionRung, ProviderPin, Reversibility,
};
use crate::retrieval_depth::RetrievalDeadline;

/// A host's decision path for the task surface: its ladder, dial and learned
/// bands, the three yes/no questions it asks, and each question's clock.
pub struct TaskDecisions<'a> {
    pub ladder: DecisionLadder<'a>,
    pub dial: DecisionDial,
    pub bands: DecisionBandPolicy,
    /// "Take this proposal?", asked for the addressed agent definition.
    pub take: DecisionQuestion,
    /// "Done means met?", asked over the result and the brief's criteria.
    pub done: DecisionQuestion,
    /// "Ask up now?", asked on a listed escalation trigger.
    pub ask_up: DecisionQuestion,
    pub budget: Duration,
}

/// Which surface question is asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TaskQuestion {
    Take,
    DoneMet,
    AskUp,
}

/// The routed answer. `AskUp` covers an abstention, a refused call and an
/// absent ladder alike: each one sends the question to a person.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PortAnswer {
    Yes,
    No,
    AskUp,
}

impl PortAnswer {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Yes => "yes",
            Self::No => "no",
            Self::AskUp => "ask_up",
        }
    }
}

/// A routed answer beside the model whose answer stands (FIX 1877): the
/// provider pin of the rung that answered, `None` when no model did (a rule,
/// a person's queue, an abstention, a refused call or no ladder).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TracedAnswer {
    pub(super) answer: PortAnswer,
    pub(super) answered_by: Option<ProviderPin>,
}

/// Asks one surface question for `principal` over `evidence` and the bounded
/// `state` object.
pub(super) fn ask(
    decisions: Option<&TaskDecisions<'_>>,
    question: TaskQuestion,
    principal: EntityId,
    evidence: &[EntityId],
    state: &serde_json::Value,
    reversibility: Reversibility,
) -> PortAnswer {
    ask_traced(
        decisions,
        question,
        principal,
        evidence,
        state,
        reversibility,
    )
    .answer
}

/// [`ask`], beside the model whose answer stands.
pub(super) fn ask_traced(
    decisions: Option<&TaskDecisions<'_>>,
    question: TaskQuestion,
    principal: EntityId,
    evidence: &[EntityId],
    state: &serde_json::Value,
    reversibility: Reversibility,
) -> TracedAnswer {
    let unanswered = TracedAnswer {
        answer: PortAnswer::AskUp,
        answered_by: None,
    };
    let Some(decisions) = decisions else {
        return unanswered;
    };
    let typed = match question {
        TaskQuestion::Take => &decisions.take,
        TaskQuestion::DoneMet => &decisions.done,
        TaskQuestion::AskUp => &decisions.ask_up,
    };
    let decided = decisions.ladder.run(
        typed,
        principal,
        evidence,
        state,
        decisions.dial,
        &decisions.bands,
        reversibility,
        &RetrievalDeadline::hard(Instant::now(), decisions.budget),
    );
    let Ok(decision) = decided else {
        return unanswered;
    };
    let answer = match decision.answer {
        DecisionAnswer::Noul(true) => PortAnswer::Yes,
        DecisionAnswer::Noul(false) => PortAnswer::No,
        _ => return unanswered,
    };
    TracedAnswer {
        answer,
        answered_by: answering_model(&decision.receipt),
    }
}

/// The pin of the model whose answer stands on `receipt`: the last provider
/// read on its answered rung. `None` when no rung answered, or a rule or a
/// person did: neither is a model.
fn answering_model(receipt: &DecisionReceipt) -> Option<ProviderPin> {
    let rung = receipt.time?.answered?;
    if matches!(rung, DecisionRung::Rule | DecisionRung::Human) {
        return None;
    }
    receipt
        .providers
        .iter()
        .rev()
        .find(|pin| pin.rung == rung)
        .cloned()
}
