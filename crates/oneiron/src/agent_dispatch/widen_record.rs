//! Exact, durable widen intents. Records confer no authority without a board act.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::AttemptId;
use crate::consent::{
    ActionClass, ActionEnvelope, ActorBound, CatastropheClass, ComposedEffect, ConsentProposal,
    EffectFacts, GrantBound,
};
use crate::context_projection::{ChatProjection, ContextSpec, MemoryProjection};
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};

use super::{AgentDispatchTarget, AgentSpawnContext, DispatchAgent};

pub(super) const WIDEN_PREFIX: &[u8] = b"agent.dispatch.widen.v1\0";
pub(super) const PROPOSAL_PREFIX: &[u8] = b"agent.dispatch.widen_id.v1\0";
pub(super) const SLICE_PREFIX: &[u8] = b"agent.dispatch.slice.v1\0";

/// A parked dispatch. This is a proposal, never a read or dispatch grant.
#[derive(Debug, Clone, PartialEq)]
pub struct ContextWidenProposal {
    pub proposal_id: String,
    pub parent_attempt: AttemptId,
    /// Absent means the board cannot be proven; approval fails closed.
    pub board_attempt: Option<AttemptId>,
    pub parent_context: ContextSpec,
    pub requested_context: ContextSpec,
    pub widened_parent_context: ContextSpec,
    pub consent: ConsentProposal,
}

/// Preserve the caller's target kind. A wrapper is never an AGENT_DEF actor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", deny_unknown_fields)]
pub(super) enum WidenTarget {
    Agent(String),
    Workflow(String),
}

/// Approval replay returns the original typed landing, not a guessed agent row.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(tag = "kind", content = "attempt", deny_unknown_fields)]
pub(super) enum WidenLanding {
    Agent(AttemptId),
    Workflow(AttemptId),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WidenIntent {
    pub target: WidenTarget,
    pub parent: AttemptId,
    pub dedupe_key: Option<String>,
    pub run_id: Option<String>,
    pub spec: ContextSpec,
    pub context_from: Vec<String>,
    pub depth: Option<u8>,
}

impl WidenIntent {
    pub(super) fn new(input: &DispatchAgent, spawn: &AgentSpawnContext) -> Result<Self> {
        let target = match &input.target {
            AgentDispatchTarget::Custom(id) => WidenTarget::Agent(id.to_hex()),
            AgentDispatchTarget::Workflow(id) => WidenTarget::Workflow(id.to_hex()),
        };
        Ok(Self {
            target,
            parent: input
                .parent_attempt
                .ok_or_else(|| invalid("widen requires a parent"))?,
            dedupe_key: input.dedupe_key.clone(),
            run_id: input.run_id.clone(),
            spec: spawn.context_spec.clone().unwrap_or_default(),
            context_from: spawn.context_from.iter().map(EntityId::to_hex).collect(),
            depth: spawn.depth_remaining,
        })
    }

    pub(super) fn dispatch(
        &self,
        proposal_id: &str,
        now: u64,
    ) -> Result<(DispatchAgent, AgentSpawnContext)> {
        Ok((
            DispatchAgent {
                target: match &self.target {
                    WidenTarget::Agent(id) => AgentDispatchTarget::Custom(EntityId::from_hex(id)?),
                    WidenTarget::Workflow(id) => {
                        AgentDispatchTarget::Workflow(EntityId::from_hex(id)?)
                    }
                },
                parent_attempt: Some(self.parent),
                dedupe_key: Some(
                    self.dedupe_key
                        .clone()
                        .unwrap_or_else(|| format!("widen:{proposal_id}")),
                ),
                run_id: self.run_id.clone(),
                now,
            },
            AgentSpawnContext {
                healer_case: None,
                context_spec: Some(self.spec.clone()),
                context_from: self
                    .context_from
                    .iter()
                    .map(|id| EntityId::from_hex(id))
                    .collect::<Result<_>>()?,
                depth_remaining: self.depth,
                scope: None,
            },
        ))
    }

    pub(super) fn key(&self) -> Result<Vec<u8>> {
        let identity = match &self.dedupe_key {
            Some(key) => json(&("dedupe", key))?,
            None => json(self)?,
        };
        let mut key = WIDEN_PREFIX.to_vec();
        key.extend_from_slice(blake3::hash(&identity).as_bytes());
        Ok(key)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WidenRequest {
    pub intent: WidenIntent,
    pub target_fingerprint: String,
    pub board: Option<AttemptId>,
    pub parent_spec: ContextSpec,
    pub widened_spec: ContextSpec,
}

impl WidenRequest {
    pub(super) fn id(&self) -> Result<String> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron.agent_dispatch.widen.v1\0");
        hasher.update(&json(self)?);
        Ok(hasher.finalize().to_hex().to_string())
    }

    pub(super) fn proposal(&self) -> Result<ContextWidenProposal> {
        let id = self.id()?;
        let bound = GrantBound::action(
            ActorBound::new(crate::entity_id::bytes_to_hex_lower(
                self.intent.parent.as_bytes(),
            ))?,
            ActionClass::new(CatastropheClass::WidenOwnAuthority.as_str())?,
            ActionEnvelope::new([format!("proposal:{id}")])?,
        )?;
        let effect = ComposedEffect::new(
            EffectFacts::new("agents.propose_widen")?
                .with_catastrophe(CatastropheClass::WidenOwnAuthority),
        )
        .with_action_requirement(bound.clone())?;
        Ok(ContextWidenProposal {
            proposal_id: id,
            parent_attempt: self.intent.parent,
            board_attempt: self.board,
            parent_context: self.parent_spec.clone(),
            requested_context: self.intent.spec.clone(),
            widened_parent_context: self.widened_spec.clone(),
            consent: ConsentProposal {
                effect_digest: effect.digest(),
                suggested_bound: bound,
                confidence: 1.0,
            },
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WidenRecord {
    pub version: u8,
    pub request: WidenRequest,
    pub landed: Option<WidenLanding>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SliceOverride {
    pub proposal_id: String,
    pub board: AttemptId,
    pub owner: String,
    pub spec: ContextSpec,
}

pub(super) fn proposal_key(id: &str) -> Result<Vec<u8>> {
    if id.len() != 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid("widen proposal id is not a canonical digest"));
    }
    let mut key = PROPOSAL_PREFIX.to_vec();
    key.extend_from_slice(id.as_bytes());
    Ok(key)
}

pub(super) fn slice_key(attempt: AttemptId) -> Vec<u8> {
    let mut key = SLICE_PREFIX.to_vec();
    key.extend_from_slice(attempt.as_bytes());
    key
}

pub(super) fn json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| invalid("widen record does not encode"))
}

pub(super) fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|_| invalid("widen record does not decode"))
}

pub(super) fn invalid(message: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidAgentDispatchInput(message))
}

/// Add only the refused explicit axes. Defaults keep their inherited meaning.
pub(super) fn widened_parent(parent: &ContextSpec, child: &ContextSpec) -> ContextSpec {
    let mut result = parent.clone();
    for layer in &child.layers {
        if !result.layers.contains(layer) {
            result.layers.push(layer.clone());
        }
    }
    if let MemoryProjection::Scoped { domains, limit } = &child.memory {
        match &mut result.memory {
            MemoryProjection::Default => {}
            MemoryProjection::Exclude => result.memory = child.memory.clone(),
            MemoryProjection::Scoped {
                domains: known,
                limit: bound,
            } => {
                for domain in domains {
                    if !known.contains(domain) {
                        known.push(domain.clone());
                    }
                }
                *bound = (*bound).max(*limit);
            }
        }
    }
    if let ChatProjection::Recent { last_n } = child.chat {
        match &mut result.chat {
            ChatProjection::Default => {}
            ChatProjection::Exclude => result.chat = child.chat.clone(),
            ChatProjection::Recent { last_n: bound } => *bound = (*bound).max(last_n),
        }
    }
    result
}
