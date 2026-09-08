//! `dispatch(agent)` — AGENT-3 (ONE-1445, OF-334) over the OF-193 durable
//! runner substrate.
//!
//! Dispatch instantiates a saved [`AgentDefinition`] row as a durable
//! run-tree branch: it rides the dreamer runner queue
//! (kind `"dreamer"`, payload `job_type "agent.dispatch"`), inheriting BLAKE3
//! dedupe, atomic budgeted admission, lease-timeout recovery, park/resume and
//! durable milestone claims with zero new queue machinery. Authority
//! separation lives in the `WriteEnvelope` actor, never in queue plumbing.
//!
//! The one subtle rule (design D11): the definition's **composition** is
//! frozen into the payload at dispatch time — checkpoint/resume replays
//! exactly what was dispatched — while its **authority** (ceiling) is never
//! read from the snapshot; the gate resolves it live from the stored entity +
//! manifest at every write, so narrowing or revoking bites a running agent
//! immediately. The snapshot's embedded `ceiling` field is ignored uniformly.
//!
//! The dispatchability predicate here is a liveness/UX check, not a security
//! boundary: the queue and codec are `pub`, so a hand-crafted payload can be
//! enqueued around it — and is still bounded live by the envelope/gate
//! lattice.

mod attenuation;
mod codec;
mod context;
mod dispatch;
mod kill;
mod types;

pub use self::codec::{
    agent_dispatch_actor, agent_dispatch_payload_agent_id, decode_agent_dispatch_input,
    encode_agent_dispatch_input,
};
pub use self::dispatch::AgentDispatcher;
pub use self::types::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AGENT_DISPATCH_COMPAT_DEPTH_CAP, AGENT_DISPATCH_INPUT_KEYS,
    AGENT_DISPATCH_INPUT_SCHEMA_VERSION, AGENT_DISPATCH_MILESTONE_AGENT_KEY,
    AGENT_DISPATCH_ROOT_DEPTH_REMAINING, AgentDispatchInput, AgentDispatchOutcome,
    AgentDispatchStatus, AgentDispatchTarget, AgentSpawnContext, AttenuatedDispatchTarget,
    DEFAULT_BASE_LOGICAL_ID, DispatchAgent, DispatchHealer, HealerSlot, HealerSlotOutcome,
    KillOutcome, KillProposal, restrict_agent_ceiling,
};

#[cfg(test)]
mod kill_spawn;
#[cfg(test)]
mod tests;

// The flat agent_dispatch.rs module used to provide these names to the sibling
// test module through `use super::*`: free helpers the tests name bare, and
// the crate imports the tests name bare. After the directory split the seam
// re-imports both so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::attenuation::*;
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::agent_def::{AgentDefinition, encode_agent_definition};
#[cfg(test)]
use crate::attempt_queue::{
    AttemptId, AttemptInterventionEffect, AttemptInterventionKind, AttemptQueue, AttemptState,
    CancelStanding, InterveneAttempt,
};
#[cfg(test)]
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
#[cfg(test)]
use crate::context_projection::{CONTEXT_PROJECTION_MAX_ANCESTORS, ContextSpec};
#[cfg(test)]
use crate::dreamer_runner::{DreamerAttemptPayload, DreamerRunnerStore};
#[cfg(test)]
use crate::edge::EdgeActorClass;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::failure_ladder::HealerCase;
#[cfg(test)]
use rmpv::Value;
