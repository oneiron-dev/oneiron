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

/// One surface question's routed answer and, when the ladder decided it, the
/// receipt the ladder returned with it (FIX 10179): its question version,
/// provider pins, paired readings and deadline record, carried to the
/// lifecycle or proposal effect the answer drives. An absent ladder, an
/// abstention or a refused call has no receipt, and none is made up.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct PortDecision {
    pub(super) answer: PortAnswer,
    pub(super) receipt: Option<DecisionReceipt>,
}

impl PortDecision {
    /// "Ask up", with no receipt: no ladder decided it.
    const fn ask_up() -> Self {
        Self {
            answer: PortAnswer::AskUp,
            receipt: None,
        }
    }

    /// The receipt, whole, as one lifecycle field's value: `None` when the
    /// ladder kept none, or when it does not encode.
    pub(super) fn receipt_field(&self) -> Option<String> {
        self.receipt
            .as_ref()
            .and_then(|receipt| serde_json::to_string(receipt).ok())
    }

    /// The model whose answer stands (FIX 1877): the provider pin of the rung
    /// that answered, `None` when no model did (a rule, a person's queue, an
    /// abstention, a refused call or no ladder).
    pub(super) fn answered_by(&self) -> Option<ProviderPin> {
        if self.answer == PortAnswer::AskUp {
            return None;
        }
        answering_model(self.receipt.as_ref()?)
    }
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
) -> PortDecision {
    let Some(decisions) = decisions else {
        return PortDecision::ask_up();
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
        return PortDecision::ask_up();
    };
    let answer = match decision.answer {
        DecisionAnswer::Noul(true) => PortAnswer::Yes,
        DecisionAnswer::Noul(false) => PortAnswer::No,
        _ => PortAnswer::AskUp,
    };
    PortDecision {
        answer,
        receipt: Some(decision.receipt),
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
