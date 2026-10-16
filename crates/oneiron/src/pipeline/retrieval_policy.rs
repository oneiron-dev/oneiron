//! OF-092: a bounded retrieval FSM and contextual Thompson selection.
//!
//! Recall tiers select account-local learned evidence, never read authority.
//! The seeded FSM remains usable with learning disabled and without telemetry.

mod posterior;
pub use posterior::RetrievalPolicyPosterior;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::Effort;
use crate::store::RetrievalState;
use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalIntent {
    #[default]
    Unknown = 0,
    FactRetrieval = 1,
    ComplexReasoning = 2,
    ContextualSummarize = 3,
    CreativeGeneration = 4,
}

impl RetrievalIntent {
    /// Cheap fallback classifier. A host's semantic classification takes precedence.
    pub fn classify(query: &str) -> Self {
        let query = query.to_lowercase();
        let words: Vec<_> = query.split(|c: char| !c.is_alphanumeric()).collect();
        let has = |terms: &[&str]| words.iter().any(|word| terms.contains(word));
        if has(&["summarize", "summary", "recap"]) {
            Self::ContextualSummarize
        } else if has(&["brainstorm", "imagine", "draft", "creative"]) {
            Self::CreativeGeneration
        } else if has(&["compare", "why", "relationship", "connect", "explain"]) {
            Self::ComplexReasoning
        } else {
            Self::FactRetrieval
        }
    }
}

/// These are policy verbs, not the invocation categories in `RetrievalAction`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalPolicyAction {
    Search = 1,
    Expand = 2,
    WidenTemporal = 3,
    Stop = 4,
    Abstain = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetrievalPolicyIdentity {
    pub user: EntityId,
    pub persona: Option<EntityId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetrievalPolicyEnvelope {
    /// Additional retrieval attempts after the initial Search.
    pub max_steps: u8,
    pub max_hops: u8,
    /// Initial temporal round included. Never exceeds ADAPTIVE_ROUNDS.
    pub temporal_rounds: u8,
}

impl RetrievalPolicyEnvelope {
    pub fn for_effort(effort: Effort) -> Self {
        Self {
            max_steps: match effort {
                Effort::Light => 1,
                Effort::Medium => 2,
                Effort::High => 3,
                Effort::Xhigh => 5,
                Effort::Max => 12,
            },
            max_hops: effort.graph_depth() as u8,
            temporal_rounds: super::types::ADAPTIVE_ROUNDS as u8,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RetrievalPolicyOptions {
    pub identity: RetrievalPolicyIdentity,
    pub intent: RetrievalIntent,
    pub effort: Effort,
    pub bandit_enabled: bool,
}

impl RetrievalPolicyOptions {
    pub fn new(user: EntityId, effort: Effort) -> Self {
        Self {
            identity: RetrievalPolicyIdentity {
                user,
                persona: None,
            },
            intent: RetrievalIntent::Unknown,
            effort,
            bandit_enabled: true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalPolicyTier {
    User,
    Persona,
    /// Only this account's evidence. No cross-vault or cross-account lookup.
    Global,
    Seed,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RetrievalPolicyDecision {
    pub state: RetrievalState,
    pub action: RetrievalPolicyAction,
    pub tier: RetrievalPolicyTier,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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

/// Admissibility is independent of the estimator. A sample cannot buy steps,
/// bypass weak-evidence abstention, or widen an explicit caller filter.
#[derive(Clone, Copy, Debug)]
pub struct RetrievalPolicyChoices {
    pub expand: bool,
    pub widen_temporal: bool,
}

fn sufficient(state: &RetrievalState) -> bool {
    state.result_count > 0
        && state.top_score_norm >= 0.5
        && (state.signal_agreement >= 2 || state.score_gap_ratio >= 0.15)
}

pub fn seeded_action(
    state: &RetrievalState,
    choices: RetrievalPolicyChoices,
) -> RetrievalPolicyAction {
    use RetrievalPolicyAction::*;
    if sufficient(state) {
        return Stop;
    }
    if state.budget_remaining == 0 {
        return Abstain;
    }
    if choices.expand
        && (state.intent_class == RetrievalIntent::ComplexReasoning as u8
            || !choices.widen_temporal)
    {
        Expand
    } else if choices.widen_temporal {
        WidenTemporal
    } else {
        Abstain
    }
}

pub fn choose_action<R: Rng + ?Sized>(
    posterior: &RetrievalPolicyPosterior,
    options: RetrievalPolicyOptions,
    state: &RetrievalState,
    choices: RetrievalPolicyChoices,
    rng: &mut R,
) -> Result<RetrievalPolicyDecision> {
    state.validate()?;
    let baseline = seeded_action(state, choices);
    let mut decision = RetrievalPolicyDecision {
        state: state.clone(),
        action: baseline,
        tier: RetrievalPolicyTier::Seed,
    };
    if !options.bandit_enabled || state.budget_remaining == 0 {
        return Ok(decision);
    }
    let mut allowed = vec![RetrievalPolicyAction::Abstain];
    if sufficient(state) {
        allowed.push(RetrievalPolicyAction::Stop);
    }
    if choices.expand {
        allowed.push(RetrievalPolicyAction::Expand);
    }
    if choices.widen_temporal {
        allowed.push(RetrievalPolicyAction::WidenTemporal);
    }
    if let Some((action, tier)) = posterior.pick(options.identity, state, &allowed, rng)? {
        decision.action = action;
        decision.tier = tier;
    }
    Ok(decision)
}
