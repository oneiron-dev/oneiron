//! The ask a kept decision went up as, kept actor-free (FIX 4591). A
//! consolidation write keeps the ask's arrival number, the route's ranks,
//! project and act, and the holder's answer. Who answered, and the actor a
//! responsible role named, stay on the ask row alone: an erase scrubs that
//! row, and attribution reads it there, so a signed write's provenance holds
//! no copy of either.

use crate::Vault;
use crate::llm::decision::{AskAnswer, AskRole, AskTo, DecisionAsk};
use crate::model_decision::AnswerActor;

#[doc(hidden)]
pub use oneiron_wake_contract::dreamer_consolidation::kept_ask::{
    KeptAnswer, KeptAsk, KeptRole, KeptRoute,
};

fn kept_role_of(role: &AskRole) -> KeptRole {
    let project = match role {
        AskRole::Responsible { project, .. } => *project,
        AskRole::Board { project } => Some(*project),
        AskRole::Owner => None,
    };
    KeptRole {
        rank: role.rank(),
        project,
    }
}

fn kept_answer_of(answer: &AskAnswer) -> KeptAnswer {
    KeptAnswer {
        answer: answer.answer.clone(),
        answered_at: answer.answered_at,
        role: crate::dreamer_consolidation::kept_ask::kept_role_of(&answer.role),
        kind: answer.kind,
        changed: answer.changed,
        reason: answer.reason.clone(),
        rule: answer.rule.clone(),
    }
}

/// `ask` as a write keeps it, naming no actor.
#[must_use]
pub(crate) fn kept_ask_of(ask: &DecisionAsk) -> KeptAsk {
    let AskTo { role, ceiling, act } = &ask.to;
    KeptAsk {
        seq: ask.seq,
        to: KeptRoute {
            role: crate::dreamer_consolidation::kept_ask::kept_role_of(role),
            ceiling: *ceiling,
            act: *act,
        },
        answer: ask
            .answer
            .as_ref()
            .map(crate::dreamer_consolidation::kept_ask::kept_answer_of),
    }
}

/// Who gave the kept answer, read from its ask row as it stands: no one
/// once that actor was erased. None while the ask waits, or when the
/// vault holds no ask with this number and answer; it never stands in
/// another actor.
///
/// # Errors
///
/// Storage errors, or an ask row that cannot be read.
#[allow(dead_code)] // no caller, as the method KeptAsk::answerer had none (FIX-LIST 9 Nov)
pub(crate) fn kept_ask_answerer(
    kept_ask: &KeptAsk,
    vault: &Vault,
) -> crate::error::Result<Option<AnswerActor>> {
    let Some(kept) = &kept_ask.answer else {
        return Ok(None);
    };
    Ok(vault
        .decision_ask(kept_ask.seq)?
        .and_then(|ask| ask.answer)
        .filter(|held| held.answered_at == kept.answered_at && held.answer == kept.answer)
        .map(|held| held.by))
}
