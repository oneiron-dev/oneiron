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
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::agent_def::{
    AgentCeiling, AgentDefinition, decode_agent_definition, encode_agent_definition,
};
use crate::attempt_queue::{
    AttemptId, AttemptInterventionEffect, AttemptInterventionKind, AttemptQueue, AttemptRecord,
    AttemptState, CancelStanding, InterveneAttempt, LandingTrigger, RequestAttemptCancel,
};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::context_projection::{
    CONTEXT_PROJECTION_MAX_ANCESTORS, ContextResolutionRequest, ContextSpec,
    ResolvedContextProjection, normalize_context_spec, resolve_context_spec, validate_context_spec,
    validate_spec_narrows,
};
use crate::dreamer_runner::{
    DreamerAttemptPayload, DreamerAttemptStatus, DreamerRunnerStore, EnqueueDreamerAttempt,
    EnqueueDreamerAttemptOutcome, decode_dreamer_attempt_payload,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::failure_ladder::HealerCase;
use crate::registry::ENTITY_TYPE_AGENT_DEF;
use crate::temporal::TimeRange;
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
///
/// ONE-1709 bumps the codec ADDITIVELY, not by version: the three spawn keys
/// below are optional and default to absent, so a persisted schema-v1 row
/// decodes exactly as it did before this ticket, with `None`/empty defaults.
pub const AGENT_DISPATCH_INPUT_SCHEMA_VERSION: u64 = 1;
/// The pinned dispatch-input body keys (dreamer-payload-side snake_case).
pub const AGENT_DISPATCH_INPUT_KEYS: [&str; 8] = [
    "schema_version",
    "target",
    "agent_def",
    "preset",
    "definition",
    "context_spec",
    "context_from",
    "depth_remaining",
];

const KEY_SCHEMA_VERSION: &str = AGENT_DISPATCH_INPUT_KEYS[0];
const KEY_TARGET: &str = AGENT_DISPATCH_INPUT_KEYS[1];
const KEY_AGENT_DEF: &str = AGENT_DISPATCH_INPUT_KEYS[2];
const KEY_PRESET: &str = AGENT_DISPATCH_INPUT_KEYS[3];
const KEY_DEFINITION: &str = AGENT_DISPATCH_INPUT_KEYS[4];
const KEY_CONTEXT_SPEC: &str = AGENT_DISPATCH_INPUT_KEYS[5];
const KEY_CONTEXT_FROM: &str = AGENT_DISPATCH_INPUT_KEYS[6];
const KEY_DEPTH_REMAINING: &str = AGENT_DISPATCH_INPUT_KEYS[7];

/// Recursion budget every NEW ROOT dispatch persists when the caller names
/// none. Structural, not policy: the ceiling lattice bounds authority, this
/// bounds how many levels of it can exist at all. Admission additionally
/// CLAMPS the persisted root budget to [`CONTEXT_PROJECTION_MAX_ANCESTORS`],
/// so no stored lineage can exceed the ancestor-projection walk.
pub const AGENT_DISPATCH_ROOT_DEPTH_REMAINING: u8 = 8;
/// The configured compatibility cap for a parent whose persisted depth is
/// absent or unreadable — a schema-v1 row, or an attempt that is not an
/// agent dispatch at all. Such a parent yields children at `cap - 1`, so a
/// legacy lineage is bounded rather than unbounded.
pub const AGENT_DISPATCH_COMPAT_DEPTH_CAP: u8 = 4;
/// Domain separator for the deterministic attenuated-fork row id.
const ATTENUATED_FORK_ID_DOMAIN: &[u8] = b"oneiron.agent_dispatch.attenuated_fork.v1";

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
    /// Additive/defaulted. A DESCRIPTOR, resolved at dispatch — never a frozen
    /// projection, so a resumed agent reads fresh state.
    pub context_spec: Option<ContextSpec>,
    /// Additive/defaulted. SETTLED sibling TASK ids only — each must bind at
    /// dispatch to that task's `Completed` terminal result ref under the
    /// spawning parent attempt and run; deliberately kept separate from
    /// `context_spec`, because panel blindness relies on the separation.
    pub context_from: Vec<EntityId>,
    /// Additive/defaulted v1 compatibility field; every new root writes `Some`.
    /// LOAD-BEARING: [`AgentDispatcher::dispatch`] refuses to enqueue a child
    /// under a parent whose stored value is `Some(0)`.
    pub depth_remaining: Option<u8>,
}

impl AgentDispatchInput {
    /// The pre-ONE-1709 payload shape: no spawn context, no depth budget.
    #[must_use]
    pub const fn frozen(target: AgentDispatchTarget, definition: AgentDefinition) -> Self {
        Self {
            target,
            definition,
            context_spec: None,
            context_from: Vec::new(),
            depth_remaining: None,
        }
    }
}

/// The lead's typed spawn input: what a spawning agent contributes beyond the
/// target itself.
///
/// A side-struct rather than three more [`DispatchAgent`] fields, so ONE-1699's
/// and ONE-1700's dispatch call sites keep their exact literals. Every value
/// here is a REQUEST: the dispatcher clamps `depth_remaining` to the stored
/// parent budget and refuses a `context_spec` that widens the parent's.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AgentSpawnContext {
    pub context_spec: Option<ContextSpec>,
    pub context_from: Vec<EntityId>,
    pub depth_remaining: Option<u8>,
}

impl AgentSpawnContext {
    #[must_use]
    pub fn with_context_spec(mut self, spec: ContextSpec) -> Self {
        self.context_spec = Some(spec);
        self
    }

    #[must_use]
    pub fn with_context_from(mut self, context_from: Vec<EntityId>) -> Self {
        self.context_from = context_from;
        self
    }

    #[must_use]
    pub const fn with_depth_remaining(mut self, depth_remaining: u8) -> Self {
        self.depth_remaining = Some(depth_remaining);
        self
    }
}

/// The target a parented dispatch actually enqueued, after the live parent
/// ceiling clamped the requested child row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttenuatedDispatchTarget {
    pub target: AgentDispatchTarget,
    pub requested_definition_ref: EntityId,
    pub dispatched_definition_ref: EntityId,
    pub parent_ceiling: AgentCeiling,
    pub effective_child_ceiling: AgentCeiling,
    pub forked_for_attenuation: bool,
}

/// `min` over the two-point authority lattice: `Proposed` wins over `Auto`.
#[must_use]
pub const fn restrict_agent_ceiling(requested: AgentCeiling, parent: AgentCeiling) -> AgentCeiling {
    if requested.widens_beyond(parent) {
        parent
    } else {
        requested
    }
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

/// Refusal reason for the configured-healer arm (ONE-1887 §5).
///
/// A configured healer needs the failing case's INDIVIDUALLY DURABLE refs —
/// the failing `attempt_id`, `evidence_ref`, `pre_fail_checkpoint_ref`, and
/// `qa_thread_ref`. This base exposes no reference-context seam that can carry
/// them: [`AgentDispatchInput::context_spec`] is a projection DESCRIPTOR and
/// [`AgentDispatchInput::context_from`] admits only SETTLED sibling TASK
/// results under the spawning parent attempt and run. Case material must never
/// be smuggled through `dedupe_key`, `run_id`, a briefing string, or a new
/// parallel queue payload, so the arm refuses until that seam lands rather
/// than dispatching a healer that cannot read its own case.
const HEALER_REFERENCE_CONTEXT_SEAM_ABSENT: &str =
    "healer slot dispatch requires a durable reference-context seam this base does not expose";

/// Which healer a failure scope routes its cases to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealerSlot {
    /// The default slot until the configured ARCH-0066 healer agent exists. It
    /// is an explicit typed outcome, never a silently dropped case.
    Reserved,
    /// Lowercase-hex EntityId spelling.
    AgentDef { agent_def_ref: String },
}

/// Caller input for [`AgentDispatcher::dispatch_healer_slot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchHealer {
    pub slot: HealerSlot,
    pub case: HealerCase,
    pub run_id: Option<String>,
    pub now: u64,
}

/// Typed healer-slot outcome.
#[derive(Debug, Clone, PartialEq)]
pub enum HealerSlotOutcome {
    Reserved { case: HealerCase },
    Dispatched(AgentDispatchStatus),
    Existing(AgentDispatchStatus),
}

impl AgentDispatcher<'_> {
    /// Resolves one failure case onto its configured healer slot.
    ///
    /// `Reserved` mutates NO queue state and is unconditional; it still yields
    /// a typed outcome that carries immediate surface-card data. `AgentDef`
    /// parses the ref, enforces the propose-only ceiling against the LIVE
    /// stored row, and then refuses on this base because the reference-context
    /// seam it needs is absent (ONE-1887 §5).
    ///
    /// There is deliberately no force-cancel handle here or anywhere on the
    /// healer path. A healer asking a live attempt to land calls ONE-1896's
    /// public soft `request_cancel`/landing-request API separately; force
    /// termination stays authority-only.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidAgentDispatchInput`] when `agent_def_ref` is not a hex
    /// EntityId or when the reference-context seam is absent;
    /// [`Error::AgentNotDispatchable`] when the named row's live ceiling
    /// exceeds propose-only, plus everything the dispatchability predicate
    /// raises for a missing, inactive, unapproved, or disabled row.
    pub fn dispatch_healer_slot(&self, input: DispatchHealer) -> Result<HealerSlotOutcome> {
        match input.slot {
            HealerSlot::Reserved => Ok(HealerSlotOutcome::Reserved { case: input.case }),
            HealerSlot::AgentDef { agent_def_ref } => {
                let healer_ref = EntityId::from_hex(&agent_def_ref).map_err(|_| {
                    Error::InvalidAgentDispatchInput(
                        "healer agent_def_ref must be a hex-encoded EntityId string",
                    )
                })?;
                // Read LIVE, never the frozen payload snapshot: a healer that
                // could act at `Auto` would repair the agent it is diagnosing
                // without anyone proposing it.
                let definition =
                    self.dispatchable_definition(&AgentDispatchTarget::Custom(healer_ref))?;
                if definition.ceiling.widens_beyond(AgentCeiling::Proposed) {
                    return Err(Error::AgentNotDispatchable(
                        "healer agent definition exceeds the propose-only ceiling",
                    ));
                }
                Err(Error::InvalidAgentDispatchInput(
                    HEALER_REFERENCE_CONTEXT_SEAM_ABSENT,
                ))
            }
        }
    }
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
    // Additive keys are ELIDED when absent, so a dispatch carrying none encodes
    // byte-identically to a pre-ONE-1709 row.
    if let Some(spec) = &input.context_spec {
        let json = serde_json::to_string(spec).map_err(|_| {
            Error::InvalidAgentDispatchInput("context_spec must encode as a descriptor")
        })?;
        entries.push((Value::from(KEY_CONTEXT_SPEC), Value::from(json.as_str())));
    }
    if !input.context_from.is_empty() {
        entries.push((
            Value::from(KEY_CONTEXT_FROM),
            Value::Array(
                input
                    .context_from
                    .iter()
                    .map(|id| Value::from(id.to_hex()))
                    .collect(),
            ),
        ));
    }
    if let Some(depth_remaining) = input.depth_remaining {
        entries.push((
            Value::from(KEY_DEPTH_REMAINING),
            Value::from(u64::from(depth_remaining)),
        ));
    }
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
    let mut context_spec = None;
    let mut context_from = Vec::new();
    let mut depth_remaining = None;
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
            KEY_CONTEXT_SPEC => {
                let json = value.as_str().ok_or(Error::InvalidAgentDispatchInput(
                    "context_spec must be a serialized descriptor",
                ))?;
                let spec: ContextSpec = serde_json::from_str(json).map_err(|_| {
                    Error::InvalidAgentDispatchInput("context_spec must be a serialized descriptor")
                })?;
                validate_context_spec(&spec)?;
                context_spec = Some(spec);
            }
            KEY_CONTEXT_FROM => {
                let Value::Array(refs) = value else {
                    return Err(Error::InvalidAgentDispatchInput(
                        "context_from must be an array of hex EntityId strings",
                    ));
                };
                for entry in refs {
                    let hex = entry.as_str().ok_or(Error::InvalidAgentDispatchInput(
                        "context_from must be an array of hex EntityId strings",
                    ))?;
                    context_from.push(EntityId::from_hex(hex).map_err(|_| {
                        Error::InvalidAgentDispatchInput(
                            "context_from must be an array of hex EntityId strings",
                        )
                    })?);
                }
            }
            KEY_DEPTH_REMAINING => {
                let depth = value.as_u64().ok_or(Error::InvalidAgentDispatchInput(
                    "depth_remaining must be an integer",
                ))?;
                depth_remaining = Some(u8::try_from(depth).map_err(|_| {
                    Error::InvalidAgentDispatchInput("depth_remaining must fit in a u8")
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

    Ok(AgentDispatchInput {
        target,
        definition,
        context_spec,
        context_from,
        depth_remaining,
    })
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
        self.dispatch_with_context(input, AgentSpawnContext::default())
    }

    /// [`Self::dispatch`] plus the spawning agent's typed spawn input.
    ///
    /// With a parent this MUST, in this order: enforce the stored depth budget
    /// (zero rejects before any fork, resolution, or enqueue), attenuate the
    /// live target row against the parent's live ceiling, resolve the context
    /// descriptor against fresh state, and only then enqueue once.
    ///
    /// # Errors
    ///
    /// Everything [`Self::dispatch`] raises, plus
    /// [`Error::InvalidAgentDispatchInput`] when the parent's depth budget is
    /// exhausted, when the requested context descriptor widens the parent's, or
    /// when the attenuated fork cannot be registered. A dispatch that cannot
    /// attenuate NEVER falls back to the wider source row.
    pub fn dispatch_with_context(
        &self,
        input: DispatchAgent,
        spawn: AgentSpawnContext,
    ) -> Result<AgentDispatchOutcome> {
        // Normalize the descriptor exactly ONCE here, before it is resolved,
        // compared, or persisted: the stored `AgentDispatchInput.context_spec`
        // is then canonical, so declared-narrowing and dedupe comparisons
        // never false-reject whitespace-equivalent tokens.
        let spawn = AgentSpawnContext {
            context_spec: spawn.context_spec.map(normalize_context_spec),
            ..spawn
        };
        // Zero rejects HERE, before the descriptor is resolved, before any fork
        // row is registered, and before anything is enqueued. The in-transaction
        // computation below is the authority; this is the ordering guarantee.
        if let Some(parent_attempt) = input.parent_attempt {
            self.child_depth_remaining(parent_attempt)?;
        }
        // Resolution runs outside the write transaction on purpose: it is a
        // pure read of live state, and the vault's read seams open their own
        // snapshots. The resolved projection is deliberately NOT persisted —
        // the executor re-resolves it, so a resumed agent reads fresh state.
        let target_definition = self.dispatchable_definition(&input.target)?;
        self.resolve_dispatch_context(
            input.parent_attempt,
            spawn.context_spec.as_ref(),
            &spawn.context_from,
            input.run_id.as_deref(),
            target_definition.scope.to_world_scope(),
        )?;

        let mut wtxn = self.vault.store.env.write_txn()?;
        let outcome = self.dispatch_in_txn(&mut wtxn, None, input, spawn)?;
        wtxn.commit()?;
        Ok(outcome)
    }

    /// Dispatches an in-process child that REALIZES a TASK: identical to
    /// [`Self::dispatch`] except the queued attempt carries the TASK backlink,
    /// and the caller owns the transaction so the TASK and its realizing
    /// dispatch commit together (ONE-1700 assignee routing).
    pub(crate) fn dispatch_for_task_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        task_ref: EntityId,
        input: DispatchAgent,
    ) -> Result<AgentDispatchOutcome> {
        self.dispatch_in_txn(wtxn, Some(task_ref), input, AgentSpawnContext::default())
    }

    fn dispatch_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        task_ref: Option<EntityId>,
        input: DispatchAgent,
        spawn: AgentSpawnContext,
    ) -> Result<AgentDispatchOutcome> {
        let requested_parent = input.parent_attempt;

        // 1. STRUCTURAL BOUND FIRST. Zero rejects here, before any fork
        //    registration, context resolution, or enqueue — so an exhausted
        //    lineage cannot leave a fork row behind as a side effect.
        let depth_remaining = match requested_parent {
            None => Some(
                spawn
                    .depth_remaining
                    .unwrap_or(AGENT_DISPATCH_ROOT_DEPTH_REMAINING)
                    .min(CONTEXT_PROJECTION_MAX_ANCESTORS as u8),
            ),
            Some(parent_attempt) => {
                let bound = self.child_depth_remaining_in_txn(wtxn, parent_attempt)?;
                // A recursive child can never supply a LARGER depth than its
                // stored parent allows; a smaller self-limit is honoured.
                Some(
                    spawn
                        .depth_remaining
                        .map_or(bound, |asked| asked.min(bound)),
                )
            }
        };

        let requested_definition = self.dispatchable_definition(&input.target)?;

        // 2. AUTHORITY BOUND. Both sides read the LIVE stored rows; the frozen
        //    payload ceiling stays non-authoritative on every path.
        let (target, definition) = match requested_parent {
            None => (input.target, requested_definition),
            Some(parent_attempt) => {
                let AgentDispatchTarget::Custom(requested_ref) = input.target;
                let (attenuated, definition) = self.attenuate_child_target(
                    wtxn,
                    parent_attempt,
                    requested_ref,
                    requested_definition,
                    input.run_id.as_deref(),
                    input.now,
                )?;
                (attenuated.target, definition)
            }
        };

        // 3. The descriptor rides the payload UNRESOLVED. It was validated
        //    against live parent state in `dispatch_with_context`; the executor
        //    resolves it again at read time, which is what keeps it fresh.
        let dispatch_input = AgentDispatchInput {
            target,
            definition,
            context_spec: spawn.context_spec,
            context_from: spawn.context_from,
            depth_remaining,
        };
        let encoded = encode_agent_dispatch_input(&dispatch_input)?;
        let outcome = self.runner.enqueue_with_task_ref_in_txn(
            wtxn,
            EnqueueDreamerAttempt {
                attempt_type: AGENT_DISPATCH_ATTEMPT_TYPE.to_owned(),
                input: encoded,
                parent_attempt: requested_parent,
                dedupe_key: input
                    .dedupe_key
                    .map(|key| format!("{AGENT_DISPATCH_ATTEMPT_TYPE}:{key}")),
                run_id: input.run_id,
                now: input.now,
            },
            task_ref.map(|task_ref| task_ref.to_hex()),
        )?;

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
                // The dedupe key names the INTENT, so the persisted row must
                // carry the SAME effective spawn input; a different one is a
                // typed error, never a silent reuse.
                if status.input.context_spec != dispatch_input.context_spec
                    || status.input.context_from != dispatch_input.context_from
                    || status.input.depth_remaining != dispatch_input.depth_remaining
                {
                    return Err(Error::InvalidAgentDispatchInput(
                        "existing dedupe row carries a different spawn context",
                    ));
                }
                AgentDispatchOutcome::Existing(status)
            }
        })
    }

    /// Loads a dispatch target's LIVE stored row and applies the dispatchability
    /// predicate. Fails closed on a missing, non-`AGENT_DEF`, malformed,
    /// inactive, unapproved, or disabled row.
    fn dispatchable_definition(&self, target: &AgentDispatchTarget) -> Result<AgentDefinition> {
        let AgentDispatchTarget::Custom(id) = target;
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
        Ok(definition)
    }

    /// The depth budget a child of `parent_attempt` must be persisted with.
    ///
    /// Reads the parent's persisted [`AgentDispatchInput`]. A stored `Some(0)`
    /// is the exhausted lineage and REJECTS here, before any fork registration,
    /// context resolution, or enqueue — so zero cannot enqueue another level.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidAgentDispatchInput`] when the parent's budget is
    /// exhausted.
    pub fn child_depth_remaining(&self, parent_attempt: AttemptId) -> Result<u8> {
        child_depth_from(self.parent_dispatch_input(parent_attempt)?)
    }

    fn child_depth_remaining_in_txn(
        &self,
        wtxn: &heed::RwTxn<'_>,
        parent_attempt: AttemptId,
    ) -> Result<u8> {
        child_depth_from(self.parent_dispatch_input_in_txn(wtxn, parent_attempt)?)
    }

    /// The parent attempt's decoded dispatch input, read outside any caller
    /// transaction.
    fn parent_dispatch_input(
        &self,
        parent_attempt: AttemptId,
    ) -> Result<Option<AgentDispatchInput>> {
        Ok(AttemptQueue::new(self.vault)
            .get(parent_attempt)?
            .and_then(|record| record_dispatch_input(&record)))
    }

    fn parent_dispatch_input_in_txn(
        &self,
        wtxn: &heed::RwTxn<'_>,
        parent_attempt: AttemptId,
    ) -> Result<Option<AgentDispatchInput>> {
        Ok(AttemptQueue::new(self.vault)
            .get_in_write_txn(wtxn, parent_attempt)?
            .and_then(|record| record_dispatch_input(&record)))
    }

    /// Clamps the requested child row to the parent's LIVE ceiling, minting a
    /// deterministic run-scoped fork when the request is wider.
    ///
    /// Both ceilings come from STORED rows. Comparing the two frozen payload
    /// snapshots would not be enforcement: the snapshot's `ceiling` is ignored
    /// uniformly (design D11) and the gate resolves authority live at every
    /// write, so only the DISPATCHED ROW's stored ceiling binds anything.
    ///
    /// # Errors
    ///
    /// [`Error::AgentDefinitionNotFound`] / [`Error::AgentNotDispatchable`] /
    /// [`Error::AgentDefinitionDisabled`] when the parent's own target row does
    /// not resolve, and [`Error::InvalidAgentDispatchInput`] when the
    /// attenuated fork cannot be registered. Never falls back to the wider row.
    fn attenuate_child_target(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        parent_attempt: AttemptId,
        requested_ref: EntityId,
        requested_definition: AgentDefinition,
        run_id: Option<&str>,
        now: u64,
    ) -> Result<(AttenuatedDispatchTarget, AgentDefinition)> {
        let unattenuated = |ceiling: AgentCeiling, definition: AgentDefinition| {
            (
                AttenuatedDispatchTarget {
                    target: AgentDispatchTarget::Custom(requested_ref),
                    requested_definition_ref: requested_ref,
                    dispatched_definition_ref: requested_ref,
                    parent_ceiling: ceiling,
                    effective_child_ceiling: definition.ceiling,
                    forked_for_attenuation: false,
                },
                definition,
            )
        };
        let Some(parent_input) = self.parent_dispatch_input_in_txn(wtxn, parent_attempt)? else {
            // No resolvable dispatch lineage means no grant to attenuate: the
            // requested row stands on its own live ceiling, which the gate
            // still clamps at every write.
            let ceiling = requested_definition.ceiling;
            return Ok(unattenuated(ceiling, requested_definition));
        };
        // The parent's ACTUAL target row, read live — its own attenuated fork
        // when it was itself clamped, which is what makes this hold recursively.
        let parent_ceiling = self.dispatchable_definition(&parent_input.target)?.ceiling;
        let effective_child_ceiling =
            restrict_agent_ceiling(requested_definition.ceiling, parent_ceiling);
        if effective_child_ceiling == requested_definition.ceiling {
            return Ok(unattenuated(parent_ceiling, requested_definition));
        }

        let source_fingerprint = source_content_fingerprint(&requested_definition)?;
        let fork_ref =
            attenuated_fork_id(requested_ref, &source_fingerprint, parent_attempt, run_id)?;
        // The fork is the row this dispatch NAMES, so its in-memory body is
        // also the composition snapshot: re-reading it would open a second
        // snapshot that cannot see this transaction's own write.
        let fork = self.register_attenuated_fork(
            wtxn,
            fork_ref,
            requested_ref,
            &requested_definition,
            &source_fingerprint,
            effective_child_ceiling,
            parent_attempt,
            run_id,
            now,
        )?;
        Ok((
            AttenuatedDispatchTarget {
                target: AgentDispatchTarget::Custom(fork_ref),
                requested_definition_ref: requested_ref,
                dispatched_definition_ref: fork_ref,
                parent_ceiling,
                effective_child_ceiling,
                forked_for_attenuation: true,
            },
            fork,
        ))
    }

    /// Writes (or idempotently reuses) the attenuated fork row through the
    /// ordinary AGENT_DEF entity door: copied composition, restricted ceiling,
    /// provenance naming the source row, the parent attempt, and the run.
    #[expect(
        clippy::too_many_arguments,
        reason = "the fork's provenance triple is the point; bundling it would hide it"
    )]
    fn register_attenuated_fork(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        fork_ref: EntityId,
        source_ref: EntityId,
        source: &AgentDefinition,
        source_fingerprint: &blake3::Hash,
        ceiling: AgentCeiling,
        parent_attempt: AttemptId,
        run_id: Option<&str>,
        now: u64,
    ) -> Result<AgentDefinition> {
        let mut fork = source.clone();
        fork.ceiling = ceiling;
        fork.forked_from = Some(source_ref);
        // `sys.*` logical ids are reserved to seeded rows: a fork is an ordinary
        // row and must not claim one.
        fork.logical_id = None;
        fork.provenance = Value::Map(vec![
            (
                Value::from("source_agent_def"),
                Value::from(source_ref.to_hex()),
            ),
            (
                Value::from("parent_attempt"),
                Value::from(crate::entity_id::bytes_to_hex_lower(
                    parent_attempt.as_bytes(),
                )),
            ),
            (
                Value::from("run_id"),
                run_id.map_or(Value::Nil, Value::from),
            ),
            (
                Value::from("source_fingerprint"),
                Value::from(source_fingerprint.to_hex().as_str()),
            ),
            (
                Value::from("attenuated_ceiling"),
                Value::from(ceiling.as_str()),
            ),
        ]);

        if let Some(raw) = self.vault.store.entities.get(wtxn, fork_ref.as_bytes())? {
            // Deterministic id: a retried spawn finds its own fork. Anything
            // else occupying the id is a typed failure, never a silent reuse of
            // a row with foreign composition (ceiling, provenance, body).
            let header = crate::batch::EntityMetadataHeader::parse(&raw).ok_or(
                Error::InvalidAgentDispatchInput("attenuated fork row header is malformed"),
            )?;
            if header.entity_type != ENTITY_TYPE_AGENT_DEF {
                return Err(Error::InvalidAgentDispatchInput(
                    "attenuated fork id is occupied by a foreign row",
                ));
            }
            let stored = decode_agent_definition(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
                .map_err(|_| {
                    Error::InvalidAgentDispatchInput("attenuated fork row does not decode")
                })?;
            // Idempotent reuse requires the full expected composition — matching
            // ceiling + forked_from alone must not accept a foreign body.
            if stored != fork {
                return Err(Error::InvalidAgentDispatchInput(
                    "attenuated fork id is occupied by a foreign row",
                ));
            }
            return Ok(stored);
        }

        let body = encode_agent_definition(&fork).map_err(|_| {
            Error::InvalidAgentDispatchInput("attenuated fork does not encode as an AGENT_DEF body")
        })?;
        self.vault
            .batch_in()
            .put(
                &fork_ref,
                ENTITY_TYPE_AGENT_DEF,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                &body,
            )
            .apply(wtxn)
            .map_err(|_| {
                Error::InvalidAgentDispatchInput("attenuated fork row could not be registered")
            })?;
        Ok(fork)
    }

    /// Resolves the requested descriptor against LIVE state, folding the
    /// ancestor chain root-down so a `Default` projection inherits what its
    /// parent actually saw rather than the widest default.
    fn resolve_dispatch_context(
        &self,
        parent_attempt: Option<AttemptId>,
        context_spec: Option<&ContextSpec>,
        context_from: &[EntityId],
        run_id: Option<&str>,
        world_scope: crate::pipeline::WorldScope,
    ) -> Result<ResolvedContextProjection> {
        let parent = match parent_attempt {
            None => None,
            Some(parent_attempt) => {
                // DECLARED bound: the child's requested scope against the
                // parent's stored scope, checked before either is resolved.
                if let (Some(parent_spec), Some(child_spec)) = (
                    self.parent_dispatch_input(parent_attempt)?
                        .and_then(|input| input.context_spec),
                    context_spec,
                ) {
                    validate_spec_narrows(&parent_spec, child_spec)?;
                }
                self.resolve_ancestor_projection(parent_attempt, world_scope)?
            }
        };
        let projection = resolve_context_spec(
            self.vault,
            ContextResolutionRequest {
                spec: context_spec.cloned().unwrap_or_default(),
                parent,
                context_from: context_from.to_vec(),
                world_scope: Some(world_scope),
            },
        )?;
        self.require_sibling_result_lineage(parent_attempt, run_id, context_from)?;
        Ok(projection)
    }

    /// `contextFrom` admission, stage two — SAME-PARENT/RUN LINEAGE, proved
    /// from attempt-tree data at the dispatch site (stage one, settlement and
    /// the result_ref binding, already failed closed inside
    /// `resolve_context_spec`). Each named TASK must have been created by the
    /// parent attempt's DISPATCHED agent row (its recorded create-owner), and
    /// the spawn must ride the parent attempt's exact run. A root spawn has no
    /// siblings to name; a foreign parent or run rejects with the same typed
    /// error — never a silent skip.
    fn require_sibling_result_lineage(
        &self,
        parent_attempt: Option<AttemptId>,
        run_id: Option<&str>,
        context_from: &[EntityId],
    ) -> Result<()> {
        if context_from.is_empty() {
            return Ok(());
        }
        let Some(parent_attempt) = parent_attempt else {
            return Err(Error::InvalidAgentDispatchInput(
                "contextFrom names sibling results but there is no parent attempt",
            ));
        };
        let Some(parent_record) = AttemptQueue::new(self.vault).get(parent_attempt)? else {
            return Err(Error::InvalidAgentDispatchInput(
                "contextFrom requires a parent attempt row",
            ));
        };
        if parent_record.run_id.as_deref() != run_id {
            return Err(Error::InvalidAgentDispatchInput(
                "contextFrom is admitted only inside the parent attempt's run",
            ));
        }
        let Some(parent_input) = record_dispatch_input(&parent_record) else {
            return Err(Error::InvalidAgentDispatchInput(
                "contextFrom requires a parent with agent dispatch lineage",
            ));
        };
        let AgentDispatchTarget::Custom(parent_row) = parent_input.target;
        for entity_ref in context_from {
            if crate::task_verb::task_create_owner(self.vault, *entity_ref)? != Some(parent_row) {
                return Err(Error::InvalidAgentDispatchInput(
                    "contextFrom names a settled result from a different parent",
                ));
            }
        }
        Ok(())
    }

    /// Rebuilds what `attempt` projects, by folding its ancestors root-down.
    /// `None` when no ancestor carries a descriptor at all.
    ///
    /// The fold is what makes `MemoryProjection::Default` honest: resolving an
    /// ancestor's spec standalone would hand it the widest default, so a
    /// `Default` under an excluding grandparent would silently WIDEN.
    fn resolve_ancestor_projection(
        &self,
        attempt: AttemptId,
        _world_scope: crate::pipeline::WorldScope,
    ) -> Result<Option<ResolvedContextProjection>> {
        let queue = AttemptQueue::new(self.vault);
        let mut chain: Vec<(ContextSpec, crate::pipeline::WorldScope)> = Vec::new();
        let mut cursor = Some(attempt);
        while let Some(id) = cursor {
            if chain.len() >= CONTEXT_PROJECTION_MAX_ANCESTORS {
                break;
            }
            let Some(record) = queue.get(id)? else { break };
            let Some(input) = record_dispatch_input(&record) else {
                break;
            };
            chain.push((
                input.context_spec.unwrap_or_default(),
                input.definition.scope.to_world_scope(),
            ));
            cursor = decode_dreamer_attempt_payload(&record.payload)
                .ok()
                .and_then(|payload| payload.parent_attempt);
        }
        if chain.is_empty() {
            return Ok(None);
        }

        let mut projection = None;
        // Root-down: each level narrows the one above it.
        for (index, (spec, ancestor_scope)) in chain.iter().rev().enumerate() {
            if index > 0 {
                validate_spec_narrows(&chain[chain.len() - index].0, spec)?;
            }
            projection = Some(resolve_context_spec(
                self.vault,
                ContextResolutionRequest {
                    spec: spec.clone(),
                    parent: projection,
                    context_from: Vec::new(),
                    world_scope: Some(*ancestor_scope),
                },
            )?);
        }
        Ok(projection)
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
        // ONE-1896: a LANDING parent is live work — it still holds its lease
        // and its runtime — so it keeps the standing its lease gives it.
        // Omitting it read a landing spawner as dead and downgraded its ask to
        // a proposal precisely when it was tidying up its own children.
        if !matches!(
            killer.state,
            AttemptState::Queued
                | AttemptState::Leased
                | AttemptState::Paused
                | AttemptState::Landing
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

        let killer_actor = crate::entity_id::bytes_to_hex_lower(killer_attempt.as_bytes());
        let intervention_kind = match record.state {
            // A scheduled child has not started: kill it the same way a queued
            // one is killed.
            AttemptState::Queued
            | AttemptState::Paused
            | AttemptState::Cancelled
            | AttemptState::Scheduled => AttemptInterventionKind::Cancel,
            // A RUNNING child is asked, never killed (ONE-1896 rung 1). The
            // spawner's proven parent link is peer standing, which is standing
            // to ASK; only the owner/authority or a runtime ground can force,
            // and this trusted wrapper mints neither.
            AttemptState::Leased | AttemptState::Landing => AttemptInterventionKind::Interrupt,
            AttemptState::Completed | AttemptState::Failed => {
                return Ok(KillOutcome::AlreadyTerminal);
            }
        };
        if record.state.is_running() {
            queue.request_cancel_in_txn(
                &mut wtxn,
                RequestAttemptCancel {
                    id: *spawn_attempt_id,
                    actor: killer_actor.clone(),
                    standing: CancelStanding::PeerAgent,
                    trigger: LandingTrigger::CancelRequest,
                    reason: None,
                    now,
                },
            )?;
        }
        let outcome = queue.intervene_in_txn(
            &mut wtxn,
            InterveneAttempt {
                id: *spawn_attempt_id,
                kind: intervention_kind,
                actor: killer_actor,
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

/// A queue row's decoded dispatch input, or `None` when the row is not an
/// agent dispatch at all.
///
/// Absent / wrong-kind / wrong-attempt-type / undecodable are all "no dispatch
/// lineage", never storage corruption: the queue and codec are `pub`, so any
/// attempt id can be named as a parent (the D13 non-boundary ruling).
fn record_dispatch_input(record: &AttemptRecord) -> Option<AgentDispatchInput> {
    if record.kind != crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND {
        return None;
    }
    let payload = decode_dreamer_attempt_payload(&record.payload).ok()?;
    if payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
        return None;
    }
    decode_agent_dispatch_input(&payload.input).ok()
}

/// MALFORMED IS NOT ZERO: a parent whose depth cannot be read is a schema-v1
/// (or non-dispatch) lineage, and the CONFIGURED compatibility cap answers for
/// it — bounded, not unbounded, and not a refusal. Only a STORED `Some(0)` is
/// the exhausted lineage.
fn child_depth_from(parent: Option<AgentDispatchInput>) -> Result<u8> {
    parent
        .and_then(|input| input.depth_remaining)
        .unwrap_or(AGENT_DISPATCH_COMPAT_DEPTH_CAP)
        .checked_sub(1)
        .ok_or(Error::InvalidAgentDispatchInput(
            "agent dispatch recursion depth is exhausted",
        ))
}

/// The attenuated fork's row id: deterministic in `(source row, source
/// content fingerprint, parent attempt, run)`, so a retried spawn of the same
/// source revision finds its own fork, while a source row updated in place
/// mints a DISTINCT fork instead of colliding with the stale occupant.
fn attenuated_fork_id(
    source_ref: EntityId,
    source_fingerprint: &blake3::Hash,
    parent_attempt: AttemptId,
    run_id: Option<&str>,
) -> Result<EntityId> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ATTENUATED_FORK_ID_DOMAIN);
    hasher.update(source_ref.as_bytes());
    hasher.update(source_fingerprint.as_bytes());
    hasher.update(parent_attempt.as_bytes());
    hasher.update(run_id.unwrap_or_default().as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    EntityId::from_bytes(bytes).map_err(|_| {
        Error::InvalidAgentDispatchInput("attenuated fork id collided with a reserved id")
    })
}

/// The content fingerprint that joins fork identity: the canonical encoding
/// of the REQUESTED source definition, hashed. Recorded in fork provenance,
/// so the revision a fork was minted from is always auditable.
fn source_content_fingerprint(source: &AgentDefinition) -> Result<blake3::Hash> {
    let encoded = encode_agent_definition(source).map_err(|_| {
        Error::InvalidAgentDispatchInput("source definition does not encode as an AGENT_DEF body")
    })?;
    Ok(blake3::hash(&encoded))
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

    /// ONE-1896 §12: a LANDING spawner is live work and keeps its standing.
    ///
    /// The live-parent allow-list decides whether the killer is a real parent
    /// or an unconfirmable one; omitting `Landing` read a spawner that was
    /// tidying up as DEAD and downgraded its ask to a proposal — exactly when
    /// it needed to stop the children it was landing away from.
    #[test]
    fn a_landing_spawner_keeps_its_live_parent_standing() -> Result<()> {
        use crate::attempt_queue::{
            AcceptAttemptLanding, LandingOutcome, LandingTrigger, RejectAttemptCancel,
            RequestAttemptCancel,
        };

        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let dispatcher = AgentDispatcher::new(&vault);
        let spawner = dispatched_status(dispatcher.dispatch_default_base(None, None, None, 1)?);
        let queued_child = dispatch_child(
            &dispatcher,
            seeded_target(&vault, "sys.scout"),
            spawner.attempt.id,
            2,
        )?;
        let running_child = dispatch_child(
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
        assert_eq!(claimed_spawner.id, spawner.attempt.id);

        // The spawner accepts a stop of its own and enters LANDING.
        queue.request_cancel(RequestAttemptCancel {
            id: spawner.attempt.id,
            actor: "peer-1".to_owned(),
            standing: CancelStanding::PeerAgent,
            trigger: LandingTrigger::CancelRequest,
            reason: None,
            now: 5,
        })?;
        let LandingOutcome::Landing(landing) = queue.accept_landing(AcceptAttemptLanding {
            id: spawner.attempt.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: claimed_spawner.attempt_count,
            trigger: LandingTrigger::CancelRequest,
            status: None,
            resume_point: None,
            request_sequence: None,
            now: 6,
        })?
        else {
            panic!("expected a fresh landing");
        };
        assert_eq!(landing.state, AttemptState::Landing);

        // Pre-lease child: stopped outright, exactly as a leased parent's is.
        assert_eq!(
            dispatcher.kill_spawn(&queued_child.attempt.id, &spawner.attempt.id, 7)?,
            KillOutcome::Killed
        );
        assert_eq!(
            queue
                .get(queued_child.attempt.id)?
                .expect("child exists")
                .state,
            AttemptState::Cancelled
        );

        // Running child: ASKED, never killed — peer standing is standing to ask.
        let ClaimOutcome::Claimed(claimed_child) = queue.claim(ClaimAttempt {
            lease_owner: "worker-b".to_owned(),
            now: 8,
        })?
        else {
            panic!("expected running child lease");
        };
        assert_eq!(claimed_child.id, running_child.attempt.id);
        assert_eq!(
            dispatcher.kill_spawn(&running_child.attempt.id, &spawner.attempt.id, 9)?,
            KillOutcome::CancellationRequested,
            "a landing parent may still ask its running child to stop"
        );
        let asked = queue
            .get(running_child.attempt.id)?
            .expect("running child exists");
        assert_eq!(asked.state, AttemptState::Leased);
        assert_eq!(asked.cancel_pressure().pending, 1);

        // Stale-generation completion stays typed and idempotent while the
        // sticky child answers with a refusal instead.
        let err = queue
            .complete(CompleteAttempt {
                id: running_child.attempt.id,
                lease_owner: "worker-b".to_owned(),
                attempt_count: claimed_child.attempt_count + 1,
                now: 10,
            })
            .expect_err("a stale generation cannot complete");
        assert!(matches!(
            err,
            Error::InvalidAttemptQueueTransition { action, state }
                if action == "complete" && state == "stale_attempt"
        ));
        let refusal = queue.reject_cancel(RejectAttemptCancel {
            id: running_child.attempt.id,
            lease_owner: "worker-b".to_owned(),
            attempt_count: claimed_child.attempt_count,
            reason: "mid-write".to_owned(),
            status: None,
            request_sequence: None,
            now: 11,
        })?;
        assert_eq!(refusal.record.state, AttemptState::Leased);
        assert_eq!(refusal.pressure.rejections, 1);
        // And the bound executor still completes its own current generation.
        let CompleteOutcome::Completed(done) = queue.complete(CompleteAttempt {
            id: running_child.attempt.id,
            lease_owner: "worker-b".to_owned(),
            attempt_count: claimed_child.attempt_count,
            now: 12,
        })?
        else {
            panic!("the bound executor completes its own attempt");
        };
        assert_eq!(done.state, AttemptState::Completed);
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
