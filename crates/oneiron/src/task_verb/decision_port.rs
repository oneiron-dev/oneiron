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
    Reversibility,
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
    let Some(decisions) = decisions else {
        return PortAnswer::AskUp;
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
    match decided.map(|decision| decision.answer) {
        Ok(DecisionAnswer::Noul(true)) => PortAnswer::Yes,
        Ok(DecisionAnswer::Noul(false)) => PortAnswer::No,
        Ok(_) | Err(_) => PortAnswer::AskUp,
    }
}
