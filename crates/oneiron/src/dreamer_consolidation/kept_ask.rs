//! The ask a kept decision went up as, kept actor-free (FIX 4591). A
//! consolidation write keeps the ask's arrival number, the route's ranks,
//! project and act, and the holder's answer. Who answered, and the actor a
//! responsible role named, stay on the ask row alone: an erase scrubs that
//! row, and attribution reads it there, so a signed write's provenance holds
//! no copy of either.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::llm::decision::{
    AnswerActor, AskAct, AskAnswer, AskRole, AskTo, DecisionAnswer, DecisionAsk, HolderKind,
    HostRuleRef, RoleRank,
};

/// A role on an ask's route as a write keeps it: where it sits on the chain
/// and the project whose boards it walks, never the actor it names.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct KeptRole {
    pub rank: RoleRank,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::entity_id::serde_hex::optional"
    )]
    #[schemars(with = "Option<String>")]
    pub project: Option<EntityId>,
}

impl KeptRole {
    fn of(role: &AskRole) -> Self {
        let project = match role {
            AskRole::Responsible { project, .. } => *project,
            AskRole::Board { project } => Some(*project),
            AskRole::Owner => None,
        };
        Self {
            rank: role.rank(),
            project,
        }
    }
}

/// The route the Dreamer bound, as a write keeps it.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct KeptRoute {
    /// The role asked first.
    pub role: KeptRole,
    /// The highest rank the ask may climb to.
    pub ceiling: RoleRank,
    pub act: AskAct,
}

/// A holder's answer as a write keeps it: what it answered and when, as
/// which role, person or agent, and the owner's reason and rule row, never
/// who answered.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KeptAnswer {
    pub answer: DecisionAnswer,
    /// Vault clock seconds when the answer landed.
    pub answered_at: u64,
    pub role: KeptRole,
    pub kind: HolderKind,
    /// Whether the answer changed the ladder's prior.
    pub changed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<HostRuleRef>,
}

impl KeptAnswer {
    fn of(answer: &AskAnswer) -> Self {
        Self {
            answer: answer.answer.clone(),
            answered_at: answer.answered_at,
            role: KeptRole::of(&answer.role),
            kind: answer.kind,
            changed: answer.changed,
            reason: answer.reason.clone(),
            rule: answer.rule.clone(),
        }
    }
}

/// The ask a decision went up as: its arrival number, the route the Dreamer
/// bound and the holder's answer once one landed, each actor-free. Two copies
/// of one ask are equal whoever was erased since. A request never reads as a
/// grant.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KeptAsk {
    pub seq: u64,
    pub to: KeptRoute,
    pub answer: Option<KeptAnswer>,
}

impl KeptAsk {
    /// `ask` as a write keeps it, naming no actor.
    #[must_use]
    pub fn of(ask: &DecisionAsk) -> Self {
        let AskTo { role, ceiling, act } = &ask.to;
        Self {
            seq: ask.seq,
            to: KeptRoute {
                role: KeptRole::of(role),
                ceiling: *ceiling,
                act: *act,
            },
            answer: ask.answer.as_ref().map(KeptAnswer::of),
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
    pub fn answerer(&self, vault: &Vault) -> crate::error::Result<Option<AnswerActor>> {
        let Some(kept) = &self.answer else {
            return Ok(None);
        };
        Ok(vault
            .decision_ask(self.seq)?
            .and_then(|ask| ask.answer)
            .filter(|held| held.answered_at == kept.answered_at && held.answer == kept.answer)
            .map(|held| held.by))
    }
}
