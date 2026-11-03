//! OF-092: a bounded retrieval FSM and contextual Thompson selection.
//!
//! Recall tiers select account-local learned evidence, never read authority.
//! The seeded FSM remains usable with learning disabled and without telemetry.

mod posterior;
pub use posterior::RetrievalPolicyPosterior;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::memory::Effort;
use crate::store::RetrievalState;
use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
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

pub use crate::store::retrieval_policy::{
    RetrievalPolicyAction, RetrievalPolicyDecision, RetrievalPolicyEnvelope,
    RetrievalPolicyIdentity, RetrievalPolicyTier, RetrievalPolicyTrace,
};

/// Effort-derived pipeline limits for the stored policy envelope.
pub trait RetrievalPolicyEnvelopeExt {
    fn for_effort(effort: Effort) -> Self;
}

impl RetrievalPolicyEnvelopeExt for RetrievalPolicyEnvelope {
    fn for_effort(effort: Effort) -> Self {
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
