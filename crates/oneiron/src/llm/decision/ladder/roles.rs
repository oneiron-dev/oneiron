//! Decision ladder person asks and the roles they go to.
//! Entry: HumanDecisionRequest.
//! Definitions: this module; the parent re-exports the old paths.

use super::ProviderDecision;
use crate::llm::decision::types::invalid;
use crate::llm::decision::{
    DecisionAnswer, DecisionQuestion, HumanAskReason, PersonChangedAnswer, ProviderPin,
};
use crate::{EntityId, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq)]
pub struct HumanDecisionRequest {
    pub question: DecisionQuestion,
    pub principal: EntityId,
    pub evidence: Vec<EntityId>,
    pub reason: HumanAskReason,
    pub prior: Option<ProviderDecision>,
    /// The provider that read `prior`; the engine sets it with the prior.
    pub prior_provider: Option<ProviderPin>,
    /// Host-issued versioned queue identity; the host renders its own text.
    pub queue_pin: ProviderPin,
    /// Who the ask goes to, as the caller bound it ([`DecisionLadder::ask_to`](super::DecisionLadder::ask_to)).
    pub to: AskTo,
    /// The work the ask decides, as the caller named it ([`DecisionLadder::correlation`](super::DecisionLadder::correlation)).
    pub correlation: Option<EntityId>,
}

impl HumanDecisionRequest {
    /// The record of the person's answer changing the model's. None when there was no model
    /// answer to change or the person gave the same one.
    pub fn changed_by(&self, person: DecisionAnswer) -> Result<Option<PersonChangedAnswer>> {
        if person == DecisionAnswer::Abstain || !self.question.contract.accepts(&person) {
            return Err(invalid("invalid person answer"));
        }
        let Some(prior) = self
            .prior
            .as_ref()
            .filter(|prior| prior.answer != DecisionAnswer::Abstain && prior.answer != person)
        else {
            return Ok(None);
        };
        let provider = self
            .prior_provider
            .clone()
            .ok_or_else(|| invalid("a prior without its provider"))?;
        Ok(Some(PersonChangedAnswer {
            question: self.question.id,
            question_version: self.question.version,
            principal: self.principal,
            reason: self.reason,
            prior: prior.answer.clone(),
            prior_probability: prior.probability,
            prior_paired: prior.paired.map(|reading| reading.bind(provider.clone())),
            prior_person: prior.person.map(|reading| reading.bind(provider.clone())),
            prior_provider: provider,
            person,
            queue_pin: self.queue_pin.clone(),
        }))
    }
}

pub trait HumanDecisionQueue: Send + Sync {
    fn queue(&self, request: HumanDecisionRequest) -> Result<()>;

    /// [`Self::queue`] with the state the ladder's reads weighed (FIX 2424): the
    /// caller-scoped pack snapshot, built from the request's own evidence, so a holder
    /// answers over the same candidate values the model read. The arrival number when the
    /// queue numbers its asks. A queue that keeps no state queues the request as it is.
    fn queue_with_state(
        &self,
        request: HumanDecisionRequest,
        _state: &serde_json::Value,
    ) -> Result<Option<u64>> {
        self.queue(request).map(|()| None)
    }
}

/// A role an ask can go to (Q3 by role). A role names authority, not a person: the host
/// resolves who holds it when the ask is queued, and the answer door rechecks it. The
/// model asks for escalation; it never names the role or the actor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum AskRole {
    /// The actor responsible for what the question is over (a schedule's, a question's or
    /// a unit's), as the caller binds it, and no one once it was erased (FIX 4588); with a
    /// project, the chain then walks that project's boards.
    Responsible {
        #[serde(with = "crate::llm::decision::codec::answer_actor")]
        actor: crate::llm::decision::AnswerActor,
        #[serde(default, with = "crate::llm::decision::codec::optional_entity")]
        project: Option<EntityId>,
    },
    /// A project's effective board; the chain then walks its parents' boards.
    Board {
        #[serde(with = "crate::llm::decision::codec::entity")]
        project: EntityId,
    },
    /// The vault's live owners, where every chain ends.
    Owner,
}

impl AskRole {
    /// Where the role sits on a chain.
    #[must_use]
    pub fn rank(&self) -> RoleRank {
        match self {
            Self::Responsible { .. } => RoleRank::Responsible,
            Self::Board { .. } => RoleRank::Board,
            Self::Owner => RoleRank::Owner,
        }
    }
}

/// How far up a chain a role sits: an ask climbs from its role toward the owners.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RoleRank {
    Responsible,
    Board,
    Owner,
}

/// What an answer to an ask authorises. An e-signature or a person-authorised payment
/// resolves only to a natural person, whoever else holds the role.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AskAct {
    #[default]
    Judgment,
    ESignature,
    Payment,
}

impl AskAct {
    /// Whether only a natural person may answer.
    #[must_use]
    pub fn person_only(self) -> bool {
        matches!(self, Self::ESignature | Self::Payment)
    }
}

/// Who a call's ask goes to: bound by the caller from trusted context, never from
/// model-authored state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AskTo {
    /// The role asked first.
    pub role: AskRole,
    /// The highest rank the ask may climb to.
    pub ceiling: RoleRank,
    pub act: AskAct,
}

impl AskTo {
    /// The vault's owners, for a judgment: where an ask goes when its caller names no role.
    #[must_use]
    pub fn owner() -> Self {
        Self {
            role: AskRole::Owner,
            ceiling: RoleRank::Owner,
            act: AskAct::Judgment,
        }
    }

    /// A role at or under its ceiling.
    pub fn validate(&self) -> Result<()> {
        if self.role.rank() > self.ceiling {
            return Err(invalid("an ask's role is above its ceiling"));
        }
        Ok(())
    }
}

/// Whether a role holder is a natural person or a bound agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HolderKind {
    Person,
    Agent,
}

/// A live actor holding a role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleHolder {
    #[serde(with = "crate::llm::decision::codec::entity")]
    pub actor: EntityId,
    pub kind: HolderKind,
}

/// A role on an ask's chain and the live actors who held it, as resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedRole {
    pub role: AskRole,
    /// Never empty.
    pub holders: Vec<RoleHolder>,
}

/// The host's role chain (Q3 by role): the next role an ask goes to.
pub trait AskRoleResolver: Send + Sync {
    /// The first role on `to`'s chain after `after` (from `to.role` when none), up to
    /// `to.ceiling`, with a live holder who may answer for `to.act`. None when no role up
    /// to the ceiling has one: the ask stays unresolved, never with wider authority.
    fn next_role(&self, to: &AskTo, after: Option<&AskRole>) -> Result<Option<ResolvedRole>>;
}
