//! `dispatch(agent)` — AGENT-3 (ONE-1445, OF-334) over the OF-193 durable
//! runner substrate.
//!
//! Dispatch instantiates a saved [`AgentDefinition`] (or an enabled system
//! preset) as a durable run-tree branch: it rides the dreamer runner queue
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
//! immediately. The snapshot's embedded `ceiling` field is ignored uniformly
//! for both target kinds.
//!
//! The dispatchability predicate here is a liveness/UX check, not a security
//! boundary: the queue and codec are `pub`, so a hand-crafted payload can be
//! enqueued around it — and is still bounded live by the envelope/gate
//! lattice.

use rmpv::Value;

use crate::Vault;
use crate::agent_def::{
    AgentDefinition, SystemAgentPreset, decode_agent_definition, encode_agent_definition,
};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::dreamer_runner::{
    DreamerJobStatus, DreamerRunnerStore, EnqueueDreamerJob, EnqueueDreamerJobOutcome,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::job_queue::{JobId, JobRecord};
use crate::write_envelope::WriteActor;

/// Payload-level job type carried inside the `"dreamer"` queue kind —
/// invisible to existing dreamer consumers, which match on their own types.
pub const AGENT_DISPATCH_JOB_TYPE: &str = "agent.dispatch";
/// Pinned schema version of the dispatch input map; decode rejects others.
pub const AGENT_DISPATCH_INPUT_SCHEMA_VERSION: u64 = 1;
/// The pinned dispatch-input body keys (dreamer-payload-side snake_case).
pub const AGENT_DISPATCH_INPUT_KEYS: [&str; 5] = [
    "schema_version",
    "target",
    "agent_def",
    "preset",
    "definition",
];

const KEY_SCHEMA_VERSION: &str = AGENT_DISPATCH_INPUT_KEYS[0];
const KEY_TARGET: &str = AGENT_DISPATCH_INPUT_KEYS[1];
const KEY_AGENT_DEF: &str = AGENT_DISPATCH_INPUT_KEYS[2];
const KEY_PRESET: &str = AGENT_DISPATCH_INPUT_KEYS[3];
const KEY_DEFINITION: &str = AGENT_DISPATCH_INPUT_KEYS[4];

const TARGET_CUSTOM: &str = "custom";
const TARGET_SYSTEM: &str = "system";

/// What a dispatch names: a stored custom definition or a compiled system
/// preset. Labels carry no authority — actor identity at the gate is keyed on
/// the entity id (custom) or the pinned preset actor id (system).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentDispatchTarget {
    System(SystemAgentPreset),
    Custom(EntityId),
}

/// The decoded dispatch payload: the target plus the composition snapshot
/// frozen at dispatch time.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentDispatchInput {
    pub target: AgentDispatchTarget,
    pub definition: AgentDefinition,
}

/// Caller input for [`AgentDispatcher::dispatch`].
#[derive(Debug, Clone, PartialEq)]
pub struct DispatchAgent {
    pub target: AgentDispatchTarget,
    /// Run-tree branch parent (pass-through to the queue payload).
    pub parent_job: Option<JobId>,
    /// Caller dedupe key; namespaced at the queue level as
    /// `"agent.dispatch:" + key` so `Existing` always names an agent-dispatch
    /// row (M6 resolution 2026-07-10).
    pub dedupe_key: Option<String>,
    /// Pass-through run id; dispatch never mints one (host concern).
    pub run_id: Option<String>,
    pub now: u64,
}

/// A dispatched (or deduped-existing) job row plus its decoded input.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentDispatchStatus {
    pub job: JobRecord,
    pub input: AgentDispatchInput,
}

/// Typed dispatch outcome mirroring the queue's enqueue outcome.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum AgentDispatchOutcome {
    Dispatched(AgentDispatchStatus),
    Existing(AgentDispatchStatus),
}

/// Encodes a dispatch input into its pinned-key MessagePack `Value` map.
pub fn encode_agent_dispatch_input(input: &AgentDispatchInput) -> Result<Value> {
    let mut entries = vec![(
        Value::from(KEY_SCHEMA_VERSION),
        Value::from(AGENT_DISPATCH_INPUT_SCHEMA_VERSION),
    )];
    match &input.target {
        AgentDispatchTarget::Custom(id) => {
            entries.push((Value::from(KEY_TARGET), Value::from(TARGET_CUSTOM)));
            entries.push((Value::from(KEY_AGENT_DEF), Value::from(id.to_hex())));
        }
        AgentDispatchTarget::System(preset) => {
            entries.push((Value::from(KEY_TARGET), Value::from(TARGET_SYSTEM)));
            entries.push((Value::from(KEY_PRESET), Value::from(preset.preset_id())));
        }
    }
    let definition = encode_agent_definition(&input.definition).map_err(|_| {
        Error::InvalidAgentDispatchInput("definition must encode as a valid AGENT_DEF body")
    })?;
    entries.push((Value::from(KEY_DEFINITION), Value::Binary(definition)));
    Ok(Value::Map(entries))
}

/// Decodes a pinned-key dispatch input map (strict: map shape, string keys,
/// pinned key set, no duplicates, schema version 1, the target/agent_def/
/// preset cross-field invariant, and a definition snapshot that re-validates
/// structurally).
pub fn decode_agent_dispatch_input(value: &Value) -> Result<AgentDispatchInput> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidAgentDispatchInput(
            "agent dispatch input must be a MessagePack map",
        ));
    };

    let mut schema_version = None;
    let mut target = None;
    let mut agent_def = None;
    let mut preset = None;
    let mut definition = None;
    let mut seen = [false; AGENT_DISPATCH_INPUT_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidAgentDispatchInput(
                "agent dispatch input keys must be strings",
            ));
        };
        let Some(index) = AGENT_DISPATCH_INPUT_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::InvalidAgentDispatchInput(
                "agent dispatch input key is not in the pinned AGENT_DISPATCH_INPUT_KEYS set",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidAgentDispatchInput(
                "duplicate agent dispatch input key",
            ));
        }
        seen[index] = true;

        match AGENT_DISPATCH_INPUT_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(value.as_u64().ok_or(Error::InvalidAgentDispatchInput(
                    "agent dispatch input schema_version must be an integer",
                ))?);
            }
            KEY_TARGET => {
                target = Some(match value.as_str() {
                    Some(TARGET_CUSTOM) => TARGET_CUSTOM,
                    Some(TARGET_SYSTEM) => TARGET_SYSTEM,
                    _ => {
                        return Err(Error::InvalidAgentDispatchInput(
                            "agent dispatch target must be one of custom|system",
                        ));
                    }
                });
            }
            KEY_AGENT_DEF => {
                let hex = value.as_str().ok_or(Error::InvalidAgentDispatchInput(
                    "agent_def must be a hex-encoded EntityId string",
                ))?;
                agent_def = Some(EntityId::from_hex(hex).map_err(|_| {
                    Error::InvalidAgentDispatchInput(
                        "agent_def must be a hex-encoded EntityId string",
                    )
                })?);
            }
            KEY_PRESET => {
                preset = Some(value.as_str().and_then(SystemAgentPreset::parse).ok_or(
                    Error::InvalidAgentDispatchInput(
                        "preset must name a known system agent preset",
                    ),
                )?);
            }
            KEY_DEFINITION => {
                let Value::Binary(bytes) = value else {
                    return Err(Error::InvalidAgentDispatchInput(
                        "definition must be a binary AGENT_DEF body",
                    ));
                };
                definition = Some(decode_agent_definition(bytes).map_err(|_| {
                    Error::InvalidAgentDispatchInput(
                        "definition must decode as a valid AGENT_DEF body",
                    )
                })?);
            }
            _ => unreachable!("index resolved from AGENT_DISPATCH_INPUT_KEYS"),
        }
    }

    let schema_version = schema_version.ok_or(Error::InvalidAgentDispatchInput(
        "missing required agent dispatch input key schema_version",
    ))?;
    if schema_version != AGENT_DISPATCH_INPUT_SCHEMA_VERSION {
        return Err(Error::InvalidAgentDispatchInput(
            "agent dispatch input schema_version must be 1",
        ));
    }
    let target = target.ok_or(Error::InvalidAgentDispatchInput(
        "missing required agent dispatch input key target",
    ))?;
    let definition = definition.ok_or(Error::InvalidAgentDispatchInput(
        "missing required agent dispatch input key definition",
    ))?;

    // Cross-field target invariant (mirrors `resolve_scope` in agent_def.rs):
    // the id/preset key is present iff the target discriminant selects it.
    let target = match target {
        TARGET_CUSTOM => {
            if preset.is_some() {
                return Err(Error::InvalidAgentDispatchInput(
                    "preset key is only valid when target is system",
                ));
            }
            AgentDispatchTarget::Custom(agent_def.ok_or(Error::InvalidAgentDispatchInput(
                "target custom requires an agent_def key",
            ))?)
        }
        TARGET_SYSTEM => {
            if agent_def.is_some() {
                return Err(Error::InvalidAgentDispatchInput(
                    "agent_def key is only valid when target is custom",
                ));
            }
            AgentDispatchTarget::System(preset.ok_or(Error::InvalidAgentDispatchInput(
                "target system requires a preset key",
            ))?)
        }
        _ => unreachable!("target parsed from the pinned discriminants"),
    };

    Ok(AgentDispatchInput { target, definition })
}

/// Derives the dispatched agent's write actor: the AGENT_DEF entity id for
/// custom targets, the pinned preset actor id for system targets — class
/// `Agent` either way. This is the identity the gate's live ceiling resolver
/// and `actor_ceilings` rows key on.
#[must_use]
pub fn agent_dispatch_actor(input: &AgentDispatchInput) -> WriteActor {
    match &input.target {
        AgentDispatchTarget::Custom(id) => WriteActor::new(*id, EdgeActorClass::Agent),
        AgentDispatchTarget::System(preset) => {
            WriteActor::new(preset.actor_entity_id(), EdgeActorClass::Agent)
        }
    }
}

/// Dispatch adapter over an already-open vault (house pattern:
/// `RunTreeAdapter::new`, `DreamerRunnerStore::new`). The OF-334 verb home is
/// [`AgentDispatcher::dispatch`]; there is deliberately no `Vault` alias.
pub struct AgentDispatcher<'a> {
    vault: &'a Vault,
    runner: DreamerRunnerStore<'a>,
}

impl<'a> AgentDispatcher<'a> {
    /// Opens a dispatch adapter over an already-open vault.
    #[must_use]
    pub fn new(vault: &'a Vault) -> Self {
        Self {
            vault,
            runner: DreamerRunnerStore::new(vault),
        }
    }

    /// Checks dispatchability, freezes the composition snapshot, and enqueues
    /// the durable dispatch job.
    ///
    /// # Errors
    ///
    /// [`Error::AgentNotDispatchable`] when a custom target is missing, not
    /// Active, or not approved; [`Error::SystemAgentDisabled`] when a system
    /// target is toggled off; [`Error::InvalidAgentDispatchInput`] when a
    /// deduped-existing row's payload fails the pinned codec (fail-closed).
    pub fn dispatch(&self, input: DispatchAgent) -> Result<AgentDispatchOutcome> {
        let definition = match &input.target {
            AgentDispatchTarget::Custom(id) => {
                let definition = self
                    .vault
                    .get_agent_definition(id)?
                    .ok_or(Error::AgentNotDispatchable("agent definition not found"))?;
                if definition.lifecycle_status != ClaimLifecycleStatus::Active {
                    return Err(Error::AgentNotDispatchable(
                        "agent definition is not active",
                    ));
                }
                if !matches!(
                    definition.approval_status,
                    ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
                ) {
                    return Err(Error::AgentNotDispatchable(
                        "agent definition is not approved",
                    ));
                }
                definition
            }
            AgentDispatchTarget::System(preset) => {
                if !self.vault.system_agent_enabled(*preset)? {
                    return Err(Error::SystemAgentDisabled(
                        "dispatch requires an enabled system agent preset",
                    ));
                }
                preset.template()
            }
        };

        let dispatch_input = AgentDispatchInput {
            target: input.target,
            definition,
        };
        let encoded = encode_agent_dispatch_input(&dispatch_input)?;
        let outcome = self.runner.enqueue(EnqueueDreamerJob {
            job_type: AGENT_DISPATCH_JOB_TYPE.to_owned(),
            input: encoded,
            parent_job: input.parent_job,
            dedupe_key: input
                .dedupe_key
                .map(|key| format!("{AGENT_DISPATCH_JOB_TYPE}:{key}")),
            run_id: input.run_id,
            now: input.now,
        })?;

        Ok(match outcome {
            EnqueueDreamerJobOutcome::Enqueued(status) => {
                AgentDispatchOutcome::Dispatched(agent_dispatch_status(status)?)
            }
            EnqueueDreamerJobOutcome::Existing(status) => {
                AgentDispatchOutcome::Existing(agent_dispatch_status(status)?)
            }
        })
    }
}

fn agent_dispatch_status(status: DreamerJobStatus) -> Result<AgentDispatchStatus> {
    if status.payload.job_type != AGENT_DISPATCH_JOB_TYPE {
        return Err(Error::InvalidAgentDispatchInput(
            "existing dedupe row does not carry an agent dispatch payload",
        ));
    }
    let input = decode_agent_dispatch_input(&status.payload.input)?;
    Ok(AgentDispatchStatus {
        job: status.job,
        input,
    })
}

#[cfg(test)]
mod tests;
