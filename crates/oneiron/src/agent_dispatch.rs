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

use rmpv::Value;

use crate::Vault;
use crate::agent_def::{AgentDefinition, decode_agent_definition, encode_agent_definition};
use crate::attempt_queue::{
    AttemptId, AttemptInterventionEffect, AttemptInterventionKind, AttemptQueue, AttemptRecord,
    AttemptState, InterveneAttempt,
};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::dreamer_runner::{
    DreamerAttemptPayload, DreamerAttemptStatus, DreamerRunnerStore, EnqueueDreamerAttempt,
    EnqueueDreamerAttemptOutcome, decode_dreamer_attempt_payload,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::write_envelope::WriteActor;

/// Payload-level attempt type carried inside the `"dreamer"` queue kind —
/// invisible to existing dreamer consumers, which match on their own types.
pub const AGENT_DISPATCH_ATTEMPT_TYPE: &str = "agent.dispatch";
/// Envelope-provenance key carrying the dispatched agent's label on
/// milestone claims (the B1 attribution home). The milestone machinery
/// STAMPS this key from the attempt payload at the admission door and the
/// durable index refuses milestones whose stamped value disagrees with the
/// payload — attribution cannot be forged to another agent.
pub const AGENT_DISPATCH_MILESTONE_AGENT_KEY: &str = "agent";
/// Stable logical id of the always-available generic base agent definition.
pub const DEFAULT_BASE_LOGICAL_ID: &str = "sys.default";
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
/// Legacy `target` discriminant. DECODER-PRIVATE after ONE-1890: encode never
/// emits it again; it survives only so persisted pre-1890 dispatch rows stay
/// recoverable (crash-recovery carve-out to the no-legacy law).
const TARGET_SYSTEM: &str = "system";

/// What a dispatch names: a stored AGENT_DEF row. Labels carry no authority —
/// actor identity at the gate is keyed on the entity id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentDispatchTarget {
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
    pub parent_attempt: Option<AttemptId>,
    /// Caller dedupe key; namespaced at the queue level as
    /// `"agent.dispatch:" + key` so `Existing` always names an agent-dispatch
    /// row (M6 resolution 2026-07-10).
    ///
    /// ACCEPTED RESIDUAL: the prefix is forgeable — any caller of the open
    /// `DreamerRunnerStore::enqueue` API can preclaim a namespaced key with a
    /// non-dispatch payload, failing later dispatches on that one key
    /// (targeted dedupe DoS). Closing it would require hashing the attempt type
    /// into the queue-level dedupe key inside `attempt_queue.rs`, which is
    /// deliberately untouched (hypnos coordination wall). The residual is
    /// bounded: enqueue requires vault-local access — the same trust domain
    /// as dispatch itself per the D13 non-boundary ruling — and a preclaimed
    /// key surfaces as a typed `InvalidAgentDispatchInput` error, never a
    /// silent wrong-attempt reuse.
    pub dedupe_key: Option<String>,
    /// Pass-through run id; dispatch never mints one (host concern).
    pub run_id: Option<String>,
    /// Current wall-clock unix SECONDS chosen by the caller. Queue readiness
    /// timestamps (`ready_at`) are seconds, never milliseconds (E5).
    pub now: u64,
}

/// A dispatched (or deduped-existing) attempt row plus its decoded input.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentDispatchStatus {
    pub attempt: AttemptRecord,
    pub input: AgentDispatchInput,
}

/// Typed dispatch outcome mirroring the queue's enqueue outcome.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum AgentDispatchOutcome {
    Dispatched(AgentDispatchStatus),
    Existing(AgentDispatchStatus),
}

/// An unauthorized kill request parked for an authority decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KillProposal {
    pub spawn_attempt_id: AttemptId,
    pub proposer: AttemptId,
}

/// Typed result of requesting cancellation of an agent spawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KillOutcome {
    /// The spawn transitioned to `Cancelled` synchronously.
    Killed,
    /// A leased spawn received a durable cooperative interrupt request.
    CancellationRequested,
    /// The spawn was already terminal, so no kill effect occurred.
    AlreadyTerminal,
    Proposed(KillProposal),
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
                let logical_id = value.as_str().ok_or(Error::InvalidAgentDispatchInput(
                    "preset must name a known system agent preset",
                ))?;
                preset = Some(
                    crate::agent_def::legacy_logical_id_row(logical_id)
                        .ok()
                        .flatten()
                        .ok_or(Error::InvalidAgentDispatchInput(
                            "preset must name a known system agent preset",
                        ))?,
                );
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
        // Compat-only legacy arm: a persisted pre-1890 `target="system"` row
        // decodes to the pinned seeded row its preset string names. Encode
        // never produces this shape again.
        TARGET_SYSTEM => {
            if agent_def.is_some() {
                return Err(Error::InvalidAgentDispatchInput(
                    "agent_def key is only valid when target is custom",
                ));
            }
            AgentDispatchTarget::Custom(preset.ok_or(Error::InvalidAgentDispatchInput(
                "target system requires a preset key",
            ))?)
        }
        _ => unreachable!("target parsed from the pinned discriminants"),
    };

    Ok(AgentDispatchInput { target, definition })
}

/// Extracts the dispatched agent's label from a dreamer attempt payload when
/// (and only when) it carries an agent-dispatch input. `None` for non-agent
/// payloads AND for an agent-dispatch payload whose input fails the pinned
/// codec — callers treat the latter as unattributable and fail closed.
#[must_use]
pub fn agent_dispatch_payload_agent_id(payload: &DreamerAttemptPayload) -> Option<String> {
    if payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
        return None;
    }
    decode_agent_dispatch_input(&payload.input)
        .ok()
        .map(|input| input.definition.agent_id)
}

/// Derives the dispatched agent's write actor: the AGENT_DEF row id, class
/// `Agent`. This is the identity the gate's live ceiling resolver and
/// `actor_ceilings` rows key on.
#[must_use]
pub fn agent_dispatch_actor(input: &AgentDispatchInput) -> WriteActor {
    match &input.target {
        AgentDispatchTarget::Custom(id) => WriteActor::new(*id, EdgeActorClass::Agent),
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
    /// the durable dispatch attempt.
    ///
    /// # Errors
    ///
    /// [`Error::AgentDefinitionNotFound`] when the named row is absent;
    /// [`Error::AgentNotDispatchable`] when it is not Active or not approved;
    /// [`Error::AgentDefinitionDisabled`] when its stored `enabled` is off;
    /// [`Error::InvalidAgentDispatchInput`] when a deduped-existing row's
    /// payload fails the pinned codec (fail-closed).
    pub fn dispatch(&self, input: DispatchAgent) -> Result<AgentDispatchOutcome> {
        let definition = match &input.target {
            AgentDispatchTarget::Custom(id) => {
                let definition = self
                    .vault
                    .get_agent_definition(id)?
                    .ok_or(Error::AgentDefinitionNotFound { id: *id })?;
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
                if !definition.enabled {
                    return Err(Error::AgentDefinitionDisabled { id: *id });
                }
                definition
            }
        };

        let requested_parent = input.parent_attempt;
        let dispatch_input = AgentDispatchInput {
            target: input.target,
            definition,
        };
        let encoded = encode_agent_dispatch_input(&dispatch_input)?;
        let outcome = self.runner.enqueue(EnqueueDreamerAttempt {
            attempt_type: AGENT_DISPATCH_ATTEMPT_TYPE.to_owned(),
            input: encoded,
            parent_attempt: requested_parent,
            dedupe_key: input
                .dedupe_key
                .map(|key| format!("{AGENT_DISPATCH_ATTEMPT_TYPE}:{key}")),
            run_id: input.run_id,
            now: input.now,
        })?;

        Ok(match outcome {
            EnqueueDreamerAttemptOutcome::Enqueued(status) => {
                AgentDispatchOutcome::Dispatched(agent_dispatch_status(status)?)
            }
            EnqueueDreamerAttemptOutcome::Existing(status) => {
                let status = agent_dispatch_status(status)?;
                if status.input.target != dispatch_input.target {
                    return Err(Error::InvalidAgentDispatchInput(
                        "existing dedupe row targets a different agent",
                    ));
                }
                let existing_parent =
                    decode_dreamer_attempt_payload(&status.attempt.payload)?.parent_attempt;
                if existing_parent != requested_parent {
                    return Err(Error::InvalidAgentDispatchInput(
                        "existing dedupe row belongs to a different parent",
                    ));
                }
                AgentDispatchOutcome::Existing(status)
            }
        })
    }

    /// Dispatches the always-available generic base without a caller-supplied
    /// definition or target selection: the seeded `sys.default` row, resolved
    /// through the canonical manifest — no compiled pinned-id constant.
    pub fn dispatch_default_base(
        &self,
        parent_attempt: Option<AttemptId>,
        dedupe_key: Option<String>,
        run_id: Option<String>,
        now: u64,
    ) -> Result<AgentDispatchOutcome> {
        let (id, _) = self
            .vault
            .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)?
            .ok_or(Error::AgentNotDispatchable(
                "the seeded default base agent definition is absent",
            ))?;
        self.dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(id),
            parent_attempt,
            dedupe_key,
            run_id,
            now,
        })
    }

    /// Cancels a direct child spawn when the executing attempt is its spawner.
    ///
    /// `killer_attempt` MUST be the runtime-authenticated executing attempt.
    /// The caller/runtime owns that binding; this trusted wrapper is not a raw
    /// agent verb, and queue intervention must not be exposed around it.
    /// Requests from any other attempt leave the spawn unchanged and surface
    /// a typed proposal.
    pub fn kill_spawn(
        &self,
        spawn_attempt_id: &AttemptId,
        killer_attempt: &AttemptId,
        now: u64,
    ) -> Result<KillOutcome> {
        let queue = AttemptQueue::new(self.vault);
        let mut wtxn = self.vault.store.env.write_txn()?;
        let record = queue.get_in_write_txn(&wtxn, *spawn_attempt_id)?.ok_or(
            Error::InvalidAgentDispatchInput("kill target attempt not found"),
        )?;
        if record.kind != crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND {
            return Err(Error::InvalidAgentDispatchInput(
                "kill target must be a dreamer attempt",
            ));
        }
        let payload = decode_dreamer_attempt_payload(&record.payload)?;
        if payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
            return Err(Error::InvalidAgentDispatchInput(
                "kill target must be an agent dispatch attempt",
            ));
        }
        decode_agent_dispatch_input(&payload.input)?;

        let Some(killer) = queue.get_in_write_txn(&wtxn, *killer_attempt)? else {
            return Ok(KillOutcome::Proposed(KillProposal {
                spawn_attempt_id: *spawn_attempt_id,
                proposer: *killer_attempt,
            }));
        };
        if !matches!(
            killer.state,
            AttemptState::Queued | AttemptState::Leased | AttemptState::Paused
        ) {
            return Ok(KillOutcome::Proposed(KillProposal {
                spawn_attempt_id: *spawn_attempt_id,
                proposer: *killer_attempt,
            }));
        }
        if killer.kind != crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND {
            return Ok(KillOutcome::Proposed(KillProposal {
                spawn_attempt_id: *spawn_attempt_id,
                proposer: *killer_attempt,
            }));
        }
        // The killer's authority is read from its own stored row, and every check that
        // cannot confirm it as a real agent-dispatch parent fails closed to a proposal
        // (found / live / kind / attempt-type / decodes / parent). Its payload bytes are
        // caller-reachable — `AttemptQueue::enqueue` stores arbitrary bytes under any
        // kind, and `DreamerRunnerStore::enqueue` stores an unvalidated input `Value` —
        // so a killer whose envelope or dispatch input does not decode is an
        // unconfirmable killer, not storage corruption: classify it, do not error.
        let Ok(killer_payload) = decode_dreamer_attempt_payload(&killer.payload) else {
            return Ok(KillOutcome::Proposed(KillProposal {
                spawn_attempt_id: *spawn_attempt_id,
                proposer: *killer_attempt,
            }));
        };
        if killer_payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
            return Ok(KillOutcome::Proposed(KillProposal {
                spawn_attempt_id: *spawn_attempt_id,
                proposer: *killer_attempt,
            }));
        }
        if decode_agent_dispatch_input(&killer_payload.input).is_err() {
            return Ok(KillOutcome::Proposed(KillProposal {
                spawn_attempt_id: *spawn_attempt_id,
                proposer: *killer_attempt,
            }));
        }

        if payload.parent_attempt != Some(*killer_attempt) {
            return Ok(KillOutcome::Proposed(KillProposal {
                spawn_attempt_id: *spawn_attempt_id,
                proposer: *killer_attempt,
            }));
        }

        let intervention_kind = match record.state {
            // A scheduled child has not started: kill it the same way a queued
            // one is killed.
            AttemptState::Queued
            | AttemptState::Paused
            | AttemptState::Cancelled
            | AttemptState::Scheduled => AttemptInterventionKind::Cancel,
            AttemptState::Leased => AttemptInterventionKind::Interrupt,
            AttemptState::Completed | AttemptState::Failed => {
                return Ok(KillOutcome::AlreadyTerminal);
            }
        };
        let outcome = queue.intervene_in_txn(
            &mut wtxn,
            InterveneAttempt {
                id: *spawn_attempt_id,
                kind: intervention_kind,
                actor: crate::entity_id::bytes_to_hex_lower(killer_attempt.as_bytes()),
                note: None,
                now,
            },
        )?;
        wtxn.commit()?;
        match outcome.effect {
            AttemptInterventionEffect::Cancelled => Ok(KillOutcome::Killed),
            AttemptInterventionEffect::AlreadyCancelled => Ok(KillOutcome::AlreadyTerminal),
            AttemptInterventionEffect::Interrupted => Ok(KillOutcome::CancellationRequested),
            _ => Err(Error::InvariantViolation("kill spawn intervention effect")),
        }
    }
}

fn agent_dispatch_status(status: DreamerAttemptStatus) -> Result<AgentDispatchStatus> {
    if status.payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
        return Err(Error::InvalidAgentDispatchInput(
            "existing dedupe row does not carry an agent dispatch payload",
        ));
    }
    let input = decode_agent_dispatch_input(&status.payload.input)?;
    Ok(AgentDispatchStatus {
        attempt: status.attempt,
        input,
    })
}

#[cfg(test)]
mod one_1698_tests {
    use super::*;
    use crate::VaultConfig;
    use crate::agent_def::{AgentCeiling, AgentScope};
    use crate::attempt_queue::{
        ClaimAttempt, ClaimOutcome, CompleteAttempt, CompleteOutcome, EnqueueAttempt,
        EnqueueOutcome,
    };
    use crate::claim::ClaimSource;
    use crate::temporal::TimeRange;

    /// The seeded row a `sys.*` logical id names, as a dispatch target.
    fn seeded_target(vault: &Vault, logical_id: &str) -> AgentDispatchTarget {
        let (id, _) = vault
            .get_seeded_agent_definition_by_logical_id(logical_id)
            .expect("seeded roster resolves")
            .expect("seeded row exists");
        AgentDispatchTarget::Custom(id)
    }

    /// An ordinary user-authored AGENT_DEF row, dispatchable and preset-free.
    fn put_custom_definition(vault: &Vault, id: &EntityId, agent_id: &str) -> Result<()> {
        let definition = AgentDefinition::new(
            agent_id,
            "custom dispatch fixture",
            "1",
            None,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
            AgentScope::All,
            AgentCeiling::Proposed,
            None,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
            ClaimSource::UserStated,
            1.0,
            false,
            true,
            Value::Map(vec![(Value::from("fixture"), Value::from(agent_id))]),
            None,
            true,
            None,
        );
        vault.put_agent_definition(id, &definition, TimeRange { start: 1, end: 1 }, 1)
    }

    fn dispatched_status(outcome: AgentDispatchOutcome) -> AgentDispatchStatus {
        let AgentDispatchOutcome::Dispatched(status) = outcome else {
            panic!("expected fresh dispatch");
        };
        status
    }

    fn dispatch_child(
        dispatcher: &AgentDispatcher<'_>,
        target: AgentDispatchTarget,
        parent: AttemptId,
        now: u64,
    ) -> Result<AgentDispatchStatus> {
        dispatcher
            .dispatch(DispatchAgent {
                target,
                parent_attempt: Some(parent),
                dedupe_key: None,
                run_id: None,
                now,
            })
            .map(dispatched_status)
    }

    #[test]
    fn zero_config_dispatch_resolves_system_default_base() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let dispatcher = AgentDispatcher::new(&vault);
        let status = dispatched_status(dispatcher.dispatch_default_base(None, None, None, 1)?);

        assert_eq!(
            status.input.target,
            seeded_target(&vault, DEFAULT_BASE_LOGICAL_ID)
        );
        assert_eq!(status.input.definition.agent_id, DEFAULT_BASE_LOGICAL_ID);
        assert_eq!(
            status.input.definition.logical_id.as_deref(),
            Some(DEFAULT_BASE_LOGICAL_ID)
        );
        Ok(())
    }

    #[test]
    fn kill_authority_is_spawner_only_and_class_independent() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let custom_id = EntityId::from_bytes([0x61; 16])?;
        put_custom_definition(&vault, &custom_id, "custom")?;

        let dispatcher = AgentDispatcher::new(&vault);
        let spawner = dispatched_status(dispatcher.dispatch_default_base(None, None, None, 2)?);
        let non_spawner = dispatched_status(dispatcher.dispatch_default_base(None, None, None, 3)?);
        let system_child = dispatch_child(
            &dispatcher,
            seeded_target(&vault, "sys.scout"),
            spawner.attempt.id,
            4,
        )?;
        let custom_child = dispatch_child(
            &dispatcher,
            AgentDispatchTarget::Custom(custom_id),
            spawner.attempt.id,
            5,
        )?;
        let proposed_child = dispatch_child(
            &dispatcher,
            seeded_target(&vault, "sys.creative"),
            spawner.attempt.id,
            6,
        )?;

        let outcomes = [
            dispatcher.kill_spawn(&system_child.attempt.id, &spawner.attempt.id, 7)?,
            dispatcher.kill_spawn(&custom_child.attempt.id, &spawner.attempt.id, 8)?,
        ];
        let killed = outcomes
            .into_iter()
            .filter(|outcome| matches!(outcome, KillOutcome::Killed))
            .count();
        assert_eq!(killed, 2);

        let proposal =
            dispatcher.kill_spawn(&proposed_child.attempt.id, &non_spawner.attempt.id, 9)?;
        assert_eq!(
            proposal,
            KillOutcome::Proposed(KillProposal {
                spawn_attempt_id: proposed_child.attempt.id,
                proposer: non_spawner.attempt.id,
            })
        );

        let queue = AttemptQueue::new(&vault);
        assert_eq!(
            queue
                .get(system_child.attempt.id)?
                .expect("system child")
                .state,
            AttemptState::Cancelled
        );
        assert_eq!(
            queue
                .get(custom_child.attempt.id)?
                .expect("custom child")
                .state,
            AttemptState::Cancelled
        );
        assert_eq!(
            queue
                .get(proposed_child.attempt.id)?
                .expect("proposed child")
                .state,
            AttemptState::Queued
        );
        Ok(())
    }

    #[test]
    fn spawner_authority_does_not_depend_on_target_class() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let custom_id = EntityId::from_bytes([0x62; 16])?;
        put_custom_definition(&vault, &custom_id, "custom")?;

        let dispatcher = AgentDispatcher::new(&vault);
        let spawner = dispatched_status(dispatcher.dispatch_default_base(None, None, None, 2)?);
        let system_child = dispatch_child(
            &dispatcher,
            seeded_target(&vault, "sys.scout"),
            spawner.attempt.id,
            3,
        )?;
        let custom_child = dispatch_child(
            &dispatcher,
            AgentDispatchTarget::Custom(custom_id),
            spawner.attempt.id,
            4,
        )?;

        let outcomes = [
            dispatcher.kill_spawn(&system_child.attempt.id, &spawner.attempt.id, 5)?,
            dispatcher.kill_spawn(&custom_child.attempt.id, &spawner.attempt.id, 6)?,
        ];
        assert_eq!(
            outcomes
                .into_iter()
                .filter(|outcome| matches!(outcome, KillOutcome::Killed))
                .count(),
            2
        );
        assert_eq!(
            AttemptQueue::new(&vault)
                .get(system_child.attempt.id)?
                .expect("system child")
                .state,
            AttemptState::Cancelled
        );
        assert_eq!(
            AttemptQueue::new(&vault)
                .get(custom_child.attempt.id)?
                .expect("custom child")
                .state,
            AttemptState::Cancelled
        );
        Ok(())
    }

    #[test]
    fn fabricated_and_terminal_killers_only_propose() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let dispatcher = AgentDispatcher::new(&vault);
        let fabricated = AttemptId::from_bytes(&[0xF1; 16])?;
        let fabricated_child = dispatch_child(
            &dispatcher,
            seeded_target(&vault, "sys.scout"),
            fabricated,
            1,
        )?;
        let fabricated_outcome =
            dispatcher.kill_spawn(&fabricated_child.attempt.id, &fabricated, 2)?;
        assert_eq!(
            fabricated_outcome,
            KillOutcome::Proposed(KillProposal {
                spawn_attempt_id: fabricated_child.attempt.id,
                proposer: fabricated,
            })
        );

        let terminal_killer =
            dispatched_status(dispatcher.dispatch_default_base(None, None, None, 3)?);
        let terminal_child = dispatch_child(
            &dispatcher,
            seeded_target(&vault, "sys.keeper"),
            terminal_killer.attempt.id,
            4,
        )?;
        let queue = AttemptQueue::new(&vault);
        let cancelled = queue.intervene(InterveneAttempt {
            id: terminal_killer.attempt.id,
            kind: AttemptInterventionKind::Cancel,
            actor: "runtime".to_owned(),
            note: None,
            now: 5,
        })?;
        assert_eq!(cancelled.effect, AttemptInterventionEffect::Cancelled);
        let terminal_outcome =
            dispatcher.kill_spawn(&terminal_child.attempt.id, &terminal_killer.attempt.id, 6)?;
        assert_eq!(
            terminal_outcome,
            KillOutcome::Proposed(KillProposal {
                spawn_attempt_id: terminal_child.attempt.id,
                proposer: terminal_killer.attempt.id,
            })
        );
        assert_eq!(
            [fabricated_child.attempt.id, terminal_child.attempt.id]
                .into_iter()
                .filter(|id| {
                    queue
                        .get(*id)
                        .expect("read child")
                        .expect("child exists")
                        .state
                        == AttemptState::Queued
                })
                .count(),
            2
        );
        Ok(())
    }

    #[test]
    fn non_agent_killer_proposes() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let queue = AttemptQueue::new(&vault);
        let EnqueueOutcome::Enqueued(non_agent) = queue.enqueue(EnqueueAttempt {
            kind: crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND.to_owned(),
            payload: crate::dreamer_runner::encode_dreamer_attempt_payload(
                &DreamerAttemptPayload {
                    attempt_type: "maintenance".to_owned(),
                    input: Value::Nil,
                    parent_attempt: None,
                },
            )?,
            dedupe_key: None,
            run_id: None,
            now: 1,
        })?
        else {
            panic!("expected fresh non-agent attempt");
        };
        let dispatcher = AgentDispatcher::new(&vault);
        let child = dispatch_child(
            &dispatcher,
            seeded_target(&vault, "sys.scout"),
            non_agent.id,
            2,
        )?;

        let outcome = dispatcher.kill_spawn(&child.attempt.id, &non_agent.id, 3)?;
        assert_eq!(
            outcome,
            KillOutcome::Proposed(KillProposal {
                spawn_attempt_id: child.attempt.id,
                proposer: non_agent.id,
            })
        );
        assert_eq!(
            queue.get(child.attempt.id)?.expect("child exists").state,
            AttemptState::Queued
        );
        Ok(())
    }

    #[test]
    fn malformed_agent_dispatch_killer_proposes() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let queue = AttemptQueue::new(&vault);
        // A caller can enqueue a live "agent.dispatch" row carrying arbitrary input:
        // enqueue validates only the attempt-type string, never the dispatch codec.
        let EnqueueOutcome::Enqueued(malformed_killer) = queue.enqueue(EnqueueAttempt {
            kind: crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND.to_owned(),
            payload: crate::dreamer_runner::encode_dreamer_attempt_payload(
                &DreamerAttemptPayload {
                    attempt_type: AGENT_DISPATCH_ATTEMPT_TYPE.to_owned(),
                    input: Value::Nil,
                    parent_attempt: None,
                },
            )?,
            dedupe_key: None,
            run_id: None,
            now: 1,
        })?
        else {
            panic!("expected fresh malformed agent-dispatch attempt");
        };
        let dispatcher = AgentDispatcher::new(&vault);
        let child = dispatch_child(
            &dispatcher,
            seeded_target(&vault, "sys.scout"),
            malformed_killer.id,
            2,
        )?;

        // The killer is the child's named parent, but its input never decodes as a
        // valid agent dispatch, so it cannot be confirmed as a real killer. The old
        // `?` aborted with InvalidAgentDispatchInput; it must fail closed to Proposed
        // with the target left alive.
        let outcome = dispatcher.kill_spawn(&child.attempt.id, &malformed_killer.id, 3)?;
        assert_eq!(
            outcome,
            KillOutcome::Proposed(KillProposal {
                spawn_attempt_id: child.attempt.id,
                proposer: malformed_killer.id,
            })
        );
        assert_eq!(
            queue.get(child.attempt.id)?.expect("child exists").state,
            AttemptState::Queued
        );
        Ok(())
    }

    #[test]
    fn undecodable_killer_envelope_proposes() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let queue = AttemptQueue::new(&vault);
        // The generic queue stores arbitrary payload bytes under any kind, so a caller
        // can enqueue a live dreamer-kind killer whose envelope never decodes as a
        // DreamerAttemptPayload (0xC1 is the reserved, never-valid MessagePack marker).
        let EnqueueOutcome::Enqueued(undecodable_killer) = queue.enqueue(EnqueueAttempt {
            kind: crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND.to_owned(),
            payload: vec![0xC1],
            dedupe_key: None,
            run_id: None,
            now: 1,
        })?
        else {
            panic!("expected fresh undecodable killer");
        };
        let dispatcher = AgentDispatcher::new(&vault);
        let child = dispatch_child(
            &dispatcher,
            seeded_target(&vault, "sys.scout"),
            undecodable_killer.id,
            2,
        )?;

        // The killer is the child's named parent, but its envelope does not decode, so
        // it cannot be confirmed as a real killer. The old `?` aborted the call with a
        // decode error; it must fail closed to Proposed with the target left alive.
        let outcome = dispatcher.kill_spawn(&child.attempt.id, &undecodable_killer.id, 3)?;
        assert_eq!(
            outcome,
            KillOutcome::Proposed(KillProposal {
                spawn_attempt_id: child.attempt.id,
                proposer: undecodable_killer.id,
            })
        );
        assert_eq!(
            queue.get(child.attempt.id)?.expect("child exists").state,
            AttemptState::Queued
        );
        Ok(())
    }

    #[test]
    fn leased_spawn_receives_cooperative_cancellation_request() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let dispatcher = AgentDispatcher::new(&vault);
        let spawner = dispatched_status(dispatcher.dispatch_default_base(None, None, None, 1)?);
        let child = dispatch_child(
            &dispatcher,
            seeded_target(&vault, "sys.scout"),
            spawner.attempt.id,
            2,
        )?;
        let queue = AttemptQueue::new(&vault);
        let ClaimOutcome::Claimed(claimed_spawner) = queue.claim(ClaimAttempt {
            lease_owner: "worker-a".to_owned(),
            now: 3,
        })?
        else {
            panic!("expected spawner lease");
        };
        let ClaimOutcome::Claimed(claimed_child) = queue.claim(ClaimAttempt {
            lease_owner: "worker-b".to_owned(),
            now: 4,
        })?
        else {
            panic!("expected child lease");
        };
        assert_eq!(claimed_spawner.id, spawner.attempt.id);
        assert_eq!(claimed_child.id, child.attempt.id);

        let outcome = dispatcher.kill_spawn(&child.attempt.id, &spawner.attempt.id, 5)?;
        assert_eq!(outcome, KillOutcome::CancellationRequested);
        let observed = queue.get(child.attempt.id)?.expect("child exists");
        assert_eq!(observed.state, AttemptState::Leased);
        assert_eq!(
            observed
                .events
                .iter()
                .filter(|event| event.kind == AttemptInterventionKind::Interrupt)
                .count(),
            1
        );
        Ok(())
    }

    #[test]
    fn kill_spawn_uses_current_leased_and_terminal_target_states() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let dispatcher = AgentDispatcher::new(&vault);
        let spawner = dispatched_status(dispatcher.dispatch_default_base(None, None, None, 1)?);
        let leased_child = dispatch_child(
            &dispatcher,
            seeded_target(&vault, "sys.scout"),
            spawner.attempt.id,
            2,
        )?;
        let completed_child = dispatch_child(
            &dispatcher,
            seeded_target(&vault, "sys.keeper"),
            spawner.attempt.id,
            3,
        )?;
        let queue = AttemptQueue::new(&vault);

        let ClaimOutcome::Claimed(claimed_spawner) = queue.claim(ClaimAttempt {
            lease_owner: "worker-a".to_owned(),
            now: 4,
        })?
        else {
            panic!("expected spawner lease");
        };
        let ClaimOutcome::Claimed(claimed_leased_child) = queue.claim(ClaimAttempt {
            lease_owner: "worker-b".to_owned(),
            now: 5,
        })?
        else {
            panic!("expected leased child lease");
        };
        let ClaimOutcome::Claimed(claimed_completed_child) = queue.claim(ClaimAttempt {
            lease_owner: "worker-c".to_owned(),
            now: 6,
        })?
        else {
            panic!("expected completed child lease");
        };
        assert_eq!(claimed_spawner.id, spawner.attempt.id);
        assert_eq!(claimed_leased_child.id, leased_child.attempt.id);
        assert_eq!(claimed_completed_child.id, completed_child.attempt.id);

        let CompleteOutcome::Completed(completed) = queue.complete(CompleteAttempt {
            id: claimed_completed_child.id,
            lease_owner: "worker-c".to_owned(),
            attempt_count: claimed_completed_child.attempt_count,
            now: 7,
        })?
        else {
            panic!("expected completed child transition");
        };
        assert_eq!(completed.state, AttemptState::Completed);

        assert_eq!(
            dispatcher.kill_spawn(&leased_child.attempt.id, &spawner.attempt.id, 8)?,
            KillOutcome::CancellationRequested
        );
        assert_eq!(
            dispatcher.kill_spawn(&completed_child.attempt.id, &spawner.attempt.id, 9)?,
            KillOutcome::AlreadyTerminal
        );
        assert_eq!(
            queue
                .get(leased_child.attempt.id)?
                .expect("leased child exists")
                .state,
            AttemptState::Leased
        );
        assert_eq!(
            queue
                .get(completed_child.attempt.id)?
                .expect("completed child exists")
                .state,
            AttemptState::Completed
        );
        Ok(())
    }

    #[test]
    fn already_cancelled_spawn_is_not_reported_killed_again() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let dispatcher = AgentDispatcher::new(&vault);
        let spawner = dispatched_status(dispatcher.dispatch_default_base(None, None, None, 1)?);
        let child = dispatch_child(
            &dispatcher,
            seeded_target(&vault, "sys.scout"),
            spawner.attempt.id,
            2,
        )?;

        assert_eq!(
            dispatcher.kill_spawn(&child.attempt.id, &spawner.attempt.id, 3)?,
            KillOutcome::Killed
        );
        assert_eq!(
            dispatcher.kill_spawn(&child.attempt.id, &spawner.attempt.id, 4)?,
            KillOutcome::AlreadyTerminal
        );
        assert_eq!(
            AttemptQueue::new(&vault)
                .get(child.attempt.id)?
                .expect("child exists")
                .state,
            AttemptState::Cancelled
        );
        Ok(())
    }

    #[test]
    fn non_dreamer_row_cannot_masquerade_as_spawn() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let dispatcher = AgentDispatcher::new(&vault);
        let spawner = dispatched_status(dispatcher.dispatch_default_base(None, None, None, 1)?);
        let child = dispatch_child(
            &dispatcher,
            seeded_target(&vault, "sys.scout"),
            spawner.attempt.id,
            2,
        )?;
        let queue = AttemptQueue::new(&vault);
        let EnqueueOutcome::Enqueued(masquerader) = queue.enqueue(EnqueueAttempt {
            kind: "worker".to_owned(),
            payload: child.attempt.payload,
            dedupe_key: None,
            run_id: None,
            now: 3,
        })?
        else {
            panic!("expected fresh masquerader");
        };

        let error = dispatcher
            .kill_spawn(&masquerader.id, &spawner.attempt.id, 4)
            .expect_err("non-dreamer target must be rejected");
        assert!(matches!(error, Error::InvalidAgentDispatchInput(_)));
        assert_eq!(
            queue
                .get(masquerader.id)?
                .expect("masquerader exists")
                .state,
            AttemptState::Queued
        );
        Ok(())
    }

    #[test]
    fn default_dispatch_rejects_cross_target_and_cross_parent_dedupe() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let dispatcher = AgentDispatcher::new(&vault);
        let scout = dispatcher.dispatch(DispatchAgent {
            target: seeded_target(&vault, "sys.scout"),
            parent_attempt: None,
            dedupe_key: Some("shared".to_owned()),
            run_id: None,
            now: 1,
        })?;
        let AgentDispatchOutcome::Dispatched(_) = scout else {
            panic!("expected fresh scout dispatch");
        };
        let mismatch = dispatcher
            .dispatch_default_base(None, Some("shared".to_owned()), None, 2)
            .expect_err("cross-target dedupe must fail closed");
        let Error::InvalidAgentDispatchInput(reason) = mismatch else {
            panic!("expected invalid agent dispatch input");
        };
        assert_eq!(reason, "existing dedupe row targets a different agent");

        let first_default = dispatched_status(dispatcher.dispatch_default_base(
            None,
            Some("default-only".to_owned()),
            None,
            3,
        )?);
        let AgentDispatchOutcome::Existing(second_default) =
            dispatcher.dispatch_default_base(None, Some("default-only".to_owned()), None, 4)?
        else {
            panic!("expected parentless existing dispatch");
        };
        assert_eq!(second_default, first_default);

        let parent = AttemptId::from_bytes(&[0xD1; 16])?;
        let other_parent = AttemptId::from_bytes(&[0xD2; 16])?;
        let first_parented = dispatched_status(dispatcher.dispatch_default_base(
            Some(parent),
            Some("parent-owned".to_owned()),
            None,
            5,
        )?);
        let AgentDispatchOutcome::Existing(second_parented) = dispatcher.dispatch_default_base(
            Some(parent),
            Some("parent-owned".to_owned()),
            None,
            6,
        )?
        else {
            panic!("expected same-parent existing dispatch");
        };
        assert_eq!(second_parented, first_parented);

        let mismatch = dispatcher
            .dispatch_default_base(Some(other_parent), Some("parent-owned".to_owned()), None, 7)
            .expect_err("cross-parent dedupe must fail closed");
        let Error::InvalidAgentDispatchInput(reason) = mismatch else {
            panic!("expected invalid agent dispatch input");
        };
        assert_eq!(reason, "existing dedupe row belongs to a different parent");
        Ok(())
    }
}

#[cfg(test)]
mod tests;
