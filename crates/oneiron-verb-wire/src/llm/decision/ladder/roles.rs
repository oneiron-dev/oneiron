//! Moved from `crates/oneiron/src/llm/decision/ladder/roles.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::store::decision_ask_role::AskRole;
use oneiron_base::error::Result as VaultResult;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_store::model_decision::AskAct;
use oneiron_store::model_decision::DecisionAnswer;
use oneiron_store::model_decision::DecisionQuestion;
pub use oneiron_store::model_decision::HolderKind;
use oneiron_store::model_decision::HumanAskReason;
use oneiron_store::model_decision::PersonChangedAnswer;
use oneiron_store::model_decision::ProviderDecision;
use oneiron_store::model_decision::ProviderPin;
pub use oneiron_store::model_decision::RoleRank;
use oneiron_store::model_decision::invalid;
use serde::Deserialize;
use serde::Serialize;

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
    pub fn changed_by(&self, person: DecisionAnswer) -> VaultResult<Option<PersonChangedAnswer>> {
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

/// Who a call's ask goes to: bound by the caller from trusted context, never from
/// model-authored state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
    pub fn validate(&self) -> VaultResult<()> {
        if self.role.rank() > self.ceiling {
            return Err(invalid("an ask's role is above its ceiling"));
        }
        Ok(())
    }
}

/// A live actor holding a role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoleHolder {
    #[serde(with = "oneiron_store::model_decision::codec::entity")]
    #[schemars(with = "String")]
    pub actor: EntityId,
    pub kind: HolderKind,
}

/// A role on an ask's chain and the live actors who held it, as resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResolvedRole {
    pub role: AskRole,
    /// Never empty.
    pub holders: Vec<RoleHolder>,
}
