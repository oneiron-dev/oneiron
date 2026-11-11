//! Closed answer contracts and engine-owned decision receipts.

use super::{AskRole, AskTo, DecisionAsk, RoleRank};
use crate::EntityId;

#[doc(hidden)]
pub use oneiron_wake_contract::llm::decision::types::{
    DecisionReceipt, ImagePin, ReceiptAnswerer, ReceiptAsk, TypedDecision,
};

/// This receipt naming `ask`, the ask its decision went up as or was answered by: the
/// role it is at, its route and, once one landed, who answered as which role.
pub fn decision_receipt_bind_ask(decision_receipt: &mut DecisionReceipt, ask: &DecisionAsk) {
    decision_receipt.asked = Some(crate::llm::decision::receipt_ask_of(ask));
}

/// The route `to` as the ladder queued it, numbered `seq` when the queue numbered it,
/// before the vault resolved a role.
pub(crate) fn receipt_ask_queued(to: &AskTo, seq: Option<u64>) -> ReceiptAsk {
    let (role, project) = role_parts(&to.role);
    ReceiptAsk {
        seq,
        role,
        project,
        ceiling: to.ceiling,
        act: to.act,
        answered: None,
    }
}

/// `ask` as a receipt keeps it: the role it is at (its bound role while none
/// resolved), its route, and its answer once one landed.
#[must_use]
pub fn receipt_ask_of(ask: &DecisionAsk) -> ReceiptAsk {
    let at = ask.role.as_ref().map_or(&ask.to.role, |at| &at.role);
    let (role, project) = role_parts(at);
    ReceiptAsk {
        seq: Some(ask.seq),
        role,
        project,
        ceiling: ask.to.ceiling,
        act: ask.to.act,
        answered: ask.answer.as_ref().map(|answer| {
            let (role, project) = role_parts(&answer.role);
            ReceiptAnswerer {
                role,
                project,
                kind: answer.kind,
            }
        }),
    }
}

/// A role's rank and the project whose boards it walks, never the actor it names.
fn role_parts(role: &AskRole) -> (RoleRank, Option<EntityId>) {
    let project = match role {
        AskRole::Responsible { project, .. } => *project,
        AskRole::Board { project } => Some(*project),
        AskRole::Owner => None,
    };
    (role.rank(), project)
}

pub(super) use crate::model_decision::invalid;
pub(crate) use crate::model_decision::paired_valid;
pub use crate::model_decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionClass, DecisionDial, DecisionQuestion,
    DecisionQuestionInput, DecisionRung, DecisionTime, EvidenceVersion, HumanAskReason, ImageBox,
    ImagePoint, PairedReading, PersonChangedAnswer, ProviderPin, Reasoning, ReasoningCause,
    StateCut, StopCause,
};
