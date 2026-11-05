//! Stored retrieval policy actions, trajectories and learned evidence.

mod posterior;
pub use posterior::RetrievalPolicyPosterior;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::RetrievalState;
use serde::{Deserialize, Serialize};

/// These are policy verbs, not the invocation categories in `RetrievalAction`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalPolicyAction {
    Search = 1,
    Expand = 2,
    WidenTemporal = 3,
    Stop = 4,
    Abstain = 5,
}

impl RetrievalPolicyAction {
    pub(crate) const fn state_tag(self) -> u8 {
        match self {
            Self::Search => RetrievalState::ACTION_SEARCH,
            Self::Expand => RetrievalState::ACTION_EXPAND,
            Self::WidenTemporal => RetrievalState::ACTION_WIDEN_TEMPORAL,
            Self::Stop => RetrievalState::ACTION_STOP,
            Self::Abstain => RetrievalState::ACTION_ABSTAIN,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalPolicyIdentity {
    pub user: EntityId,
    pub persona: Option<EntityId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalPolicyEnvelope {
    /// Additional retrieval attempts after the initial Search.
    pub max_steps: u8,
    pub max_hops: u8,
    /// Initial temporal round included. Never exceeds ADAPTIVE_ROUNDS.
    pub temporal_rounds: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalPolicyTier {
    User,
    Persona,
    /// Only this account's evidence. No cross-vault or cross-account lookup.
    Global,
    Seed,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalPolicyDecision {
    pub state: RetrievalState,
    pub action: RetrievalPolicyAction,
    pub tier: RetrievalPolicyTier,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalPolicyTrace {
    pub identity: RetrievalPolicyIdentity,
    pub envelope: RetrievalPolicyEnvelope,
    pub bandit_enabled: bool,
    /// Exact pre-decision states; only the linked terminal outcome labels them.
    pub decisions: Vec<RetrievalPolicyDecision>,
}

impl RetrievalPolicyTrace {
    pub(crate) fn validate(&self) -> Result<()> {
        let invalid = || Error::InvalidConfig("invalid retrieval policy trajectory".into());
        if self.decisions.is_empty()
            || self.decisions.len() > usize::from(self.envelope.max_steps) + 2
            || self.decisions[0].action != RetrievalPolicyAction::Search
            || !matches!(
                self.decisions.last().map(|d| d.action),
                Some(RetrievalPolicyAction::Stop | RetrievalPolicyAction::Abstain)
            )
        {
            return Err(invalid());
        }
        let mut hops = 0;
        let mut temporal = 1;
        for (index, decision) in self.decisions.iter().enumerate() {
            decision.state.validate()?;
            match decision.action {
                RetrievalPolicyAction::Search if index != 0 => return Err(invalid()),
                RetrievalPolicyAction::Expand => hops += 1,
                RetrievalPolicyAction::WidenTemporal => temporal += 1,
                RetrievalPolicyAction::Stop | RetrievalPolicyAction::Abstain
                    if index + 1 != self.decisions.len() =>
                {
                    return Err(invalid());
                }
                _ => {}
            }
        }
        if hops > usize::from(self.envelope.max_hops)
            || temporal > usize::from(self.envelope.temporal_rounds)
        {
            return Err(invalid());
        }
        Ok(())
    }
}
