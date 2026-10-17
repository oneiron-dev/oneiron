//! One named verb registry for validated UI events and agent calls.
//! Host factories build existing SelfCalls; only GatedActorWrite executes them.
//!
//! One action layer, two callers (OF-181): the app's buttons and an agent's
//! calls name the same verbs, every row of the SDK verb table among them, and
//! each runs through the one gated SDK the agent writes code against.
use super::{
    AgentVerbDoor, CodeRunBridgeCall, CodeRunDeterminism, CodeRunReplayRecord, GatedActorWrite,
    SelfAgentVerbCall, SelfCall, SelfDeniedResult, SelfDispatchOutcome, SelfDispatcher,
    SelfFailedResult,
};
use crate::agent_def::AgentCeiling;
use crate::claim::{PointRead, ScopedReadReceipt};
use crate::consent::AuthenticatedOwner;
use crate::error::GateError;

use crate::lens::{
    FiniteF64, GeneratedUiValidatedAction, LensActingPrincipalKind, LensApprovedActionArg,
    LensPrincipalBinding, LensText, SelfUiActionId, SelfUiOptionValue,
};
use crate::task_verb::sdk::{AgentVerb, RunVerb};
use crate::{EdgeActorClass, EntityId, Error, Result, Vault, WriteActor};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionArgKind {
    Bool,
    Number,
    Text,
    Token,
    Entity,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ActionArgument {
    Bool(bool),
    Number(FiniteF64),
    Text(LensText),
    Token(SelfUiOptionValue),
    Entity {
        #[serde(with = "crate::serialize::entity_ref")]
        id: EntityId,
    },
}
impl ActionArgument {
    fn kind(&self) -> ActionArgKind {
        match self {
            Self::Bool(_) => ActionArgKind::Bool,
            Self::Number(_) => ActionArgKind::Number,
            Self::Text(_) => ActionArgKind::Text,
            Self::Token(_) => ActionArgKind::Token,
            Self::Entity { .. } => ActionArgKind::Entity,
        }
    }
    fn from_ui(arg: &LensApprovedActionArg) -> Self {
        match arg {
            LensApprovedActionArg::Bool(v) => Self::Bool(*v),
            LensApprovedActionArg::Number(v) => Self::Number(*v),
            LensApprovedActionArg::Text(v) => Self::Text(v.clone()),
            LensApprovedActionArg::Token(v) => Self::Token(v.clone()),
            LensApprovedActionArg::BackingRef(reference) => Self::Entity {
                id: *reference.target().entity_id(),
            },
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionVerbDefinition {
    pub id: SelfUiActionId,
    pub args_schema: Vec<ActionArgKind>,
    #[serde(with = "ceiling_wire")]
    pub required_ceiling: AgentCeiling,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentActionCall {
    pub verb_id: SelfUiActionId,
    pub args: Vec<ActionArgument>,
    pub idempotency_key: String,
}
/// A dispatched action and the principal's scoped read of its entity
/// arguments. A withheld argument refuses the action before any effect.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionDispatch {
    pub outcome: SelfDispatchOutcome,
    pub read_receipt: ScopedReadReceipt,
}
impl ActionDispatch {
    /// The outcome as the run's replay record spells it, as JSON for a host
    /// reply.
    pub fn outcome_value(&self) -> Result<serde_json::Value> {
        let value = super::payload::self_dispatch_outcome_value(&self.outcome)?;
        rmpv::ext::from_value(value).map_err(|_| invalid("action outcome encoding"))
    }
}
/// What the host binds onto one action call, never the call's own body: the
/// door its credential opens onto the SDK verb table, when the host
/// authenticated the owner on its own that proof, and when the call acts for
/// a live agent run that run's lease. Unbound, a verb-table or run-row action
/// is refused, a live-run row asks for the lease and an owner action asks
/// for the proof.
#[derive(Clone, Default)]
pub struct ActionHostBinding<'a> {
    pub verb_door: Option<Arc<dyn AgentVerbDoor>>,
    pub owner: Option<&'a AuthenticatedOwner>,
    /// The live agent run the call acts for, as the host that runs it sealed
    /// its lease (`HostSelfDispatcher::task_host_binding`). Read live again
    /// at every call, and before any replay answers.
    pub live_run: Option<crate::task_verb::HostBinding>,
}
#[derive(Debug, Clone, Copy)]
pub struct ActionBuildContext {
    pub effect_id: EntityId,
    pub actor: WriteActor,
    pub frozen_unix_ms: u64,
}
pub type ActionFactory = fn(ActionBuildContext, &[ActionArgument]) -> Result<SelfCall>;
/// How a registered verb becomes its call: a host factory, a row of the
/// SDK verb table at its own name, or a run row as the typed call a code run
/// makes.
#[derive(Clone, Copy)]
enum ActionBuild {
    Factory(ActionFactory),
    Verb(AgentVerb),
    Run(RunVerb),
}
struct RegisteredVerb {
    definition: ActionVerbDefinition,
    build: ActionBuild,
}
#[derive(Default)]
pub struct ActionRegistry {
    verbs: BTreeMap<String, RegisteredVerb>,
}
impl ActionRegistry {
    /// Registers the host-governed v1 policy action. Registration offers the
    /// verb to agents; execution still requires an independent owner proof.
    pub fn register_dreamer_wake_policy(&mut self) -> Result<()> {
        self.register(
            ActionVerbDefinition {
                id: SelfUiActionId::new("dreamer.wake_policy.set")?,
                args_schema: vec![ActionArgKind::Text],
                required_ceiling: AgentCeiling::Proposed,
            },
            build_wake_policy_action,
        )
    }

    pub fn register(
        &mut self,
        definition: ActionVerbDefinition,
        factory: ActionFactory,
    ) -> Result<()> {
        self.insert(definition, ActionBuild::Factory(factory))
    }
    fn insert(&mut self, definition: ActionVerbDefinition, build: ActionBuild) -> Result<()> {
        if self.verbs.contains_key(definition.id.as_str()) {
            return Err(invalid("duplicate action verb"));
        }
        self.verbs.insert(
            definition.id.as_str().to_owned(),
            RegisteredVerb { definition, build },
        );
        Ok(())
    }
    /// The app's whole table: the owner's wake policy, the resident's two
    /// inference-policy actions, every row of the SDK verb table, the four
    /// memory run rows and the live-run rows. A host serves its buttons and
    /// its agents' calls from this one table.
    pub fn app() -> Result<Self> {
        let mut registry = Self::default();
        registry.register_dreamer_wake_policy()?;
        registry.register_inference_defaults()?;
        registry.register_sdk_verbs()?;
        registry.register_memory_run_verbs()?;
        registry.register_live_run_verbs()?;
        Ok(registry)
    }
    /// Offers every row of the SDK verb table a host door answers, under the
    /// row's own name. Each takes the row's whole JSON input as one text
    /// argument and runs as [`SelfCall::AgentVerb`] through the door the host
    /// binds, under that row's own scope, ceiling and gate, so an action holds
    /// no authority the row's direct call lacks. Board, browser and
    /// definition-only rows need a run or a socket of their own, and a row
    /// whose name is no action id is one no lens can name; none is offered.
    pub fn register_sdk_verbs(&mut self) -> Result<()> {
        for verb in AgentVerb::ALL
            .iter()
            .copied()
            .filter(|verb| verb.is_facade())
        {
            let Ok(id) = SelfUiActionId::new(verb.as_str()) else {
                continue;
            };
            self.insert(
                ActionVerbDefinition {
                    id,
                    args_schema: vec![ActionArgKind::Text],
                    required_ceiling: AgentCeiling::Proposed,
                },
                ActionBuild::Verb(verb),
            )?;
        }
        Ok(())
    }
    /// Offers the memory run rows (`vault.search`, `vault.claims.put`,
    /// `vault.claims.supersede`, `vault.edges.put`) under their own names.
    /// Each takes the row's whole JSON input as one text argument and runs as
    /// the typed call a code run makes, at the action's frozen clock, under
    /// the door the host binds: a search reads, and an edge's target is
    /// checked, with the credential's read key, and claims and edges meet
    /// their own gates.
    pub fn register_memory_run_verbs(&mut self) -> Result<()> {
        self.register_run_verbs(&super::run_verb_call::MEMORY_RUN_VERBS)
    }
    /// Offers the run rows that act on their caller's live agent run
    /// (`tasks.refuse`, `self.agents.spawn`, `self.team.start`,
    /// `self.team.record`) under their own names, as the memory rows are
    /// offered. Each runs only when the host binds the run's lease
    /// ([`ActionHostBinding::live_run`]), read live, so the call is the run's
    /// own: its parent, actor and lease are the run's, never the body's.
    pub fn register_live_run_verbs(&mut self) -> Result<()> {
        self.register_run_verbs(&super::run_verb_call::LIVE_RUN_VERBS)
    }
    fn register_run_verbs(&mut self, verbs: &[RunVerb]) -> Result<()> {
        for verb in verbs.iter().copied() {
            self.insert(
                ActionVerbDefinition {
                    id: SelfUiActionId::new(verb.as_str())?,
                    args_schema: vec![ActionArgKind::Text],
                    required_ceiling: AgentCeiling::Proposed,
                },
                ActionBuild::Run(verb),
            )?;
        }
        Ok(())
    }
    /// Install the resident's two governed inference-policy actions. Hosts opt
    /// in by registering them for an agent whose Auto ceiling was approved.
    pub fn register_inference_defaults(&mut self) -> Result<()> {
        self.register(
            ActionVerbDefinition {
                id: SelfUiActionId::new("inference.defaults.read")?,
                args_schema: vec![],
                required_ceiling: AgentCeiling::Auto,
            },
            build_inference_defaults_read,
        )?;
        self.register(
            ActionVerbDefinition {
                id: SelfUiActionId::new("inference.defaults.replace")?,
                args_schema: vec![ActionArgKind::Text],
                required_ceiling: AgentCeiling::Auto,
            },
            build_inference_defaults_replace,
        )
    }
    pub fn definitions(&self) -> impl Iterator<Item = &ActionVerbDefinition> {
        self.verbs.values().map(|v| &v.definition)
    }
    pub fn resolve(&self, id: &str) -> Result<&ActionVerbDefinition> {
        Ok(&self.registered(id)?.definition)
    }
    fn registered(&self, id: &str) -> Result<&RegisteredVerb> {
        self.verbs
            .get(id)
            .ok_or_else(|| invalid("unknown action verb"))
    }
    pub fn resolve_ui(&self, action: &GeneratedUiValidatedAction) -> Result<&ActionVerbDefinition> {
        let GeneratedUiValidatedAction::DeterministicTool { action, .. } = action else {
            return Err(invalid("UI action is not a deterministic tool"));
        };
        self.resolve(action.command().as_str())
    }
    pub fn execute_ui(
        &self,
        vault: &Vault,
        actor: WriteActor,
        action: &GeneratedUiValidatedAction,
        idempotency_key: &str,
    ) -> Result<ActionDispatch> {
        self.execute_ui_bound(
            vault,
            actor,
            action,
            idempotency_key,
            ActionHostBinding::default(),
        )
    }
    /// [`Self::execute_ui`] under the host's binding: its verb door and,
    /// when it authenticated the owner on its own, that proof.
    pub fn execute_ui_bound(
        &self,
        vault: &Vault,
        actor: WriteActor,
        action: &GeneratedUiValidatedAction,
        idempotency_key: &str,
        binding: ActionHostBinding<'_>,
    ) -> Result<ActionDispatch> {
        let GeneratedUiValidatedAction::DeterministicTool { emitter, action } = action else {
            return Err(invalid("UI action is not a deterministic tool"));
        };
        let call = AgentActionCall {
            verb_id: action.command().clone(),
            args: action.args().iter().map(ActionArgument::from_ui).collect(),
            idempotency_key: idempotency_key.to_owned(),
        };
        self.execute(vault, actor, emitter, &call, binding)
    }
    /// One call from either caller, as the host authenticated it: a person's
    /// own app button (a human view) or an agent's call (an agent task). The
    /// credential binds actor, principal and binding; the call names only
    /// the verb, its arguments and its idempotency key.
    pub fn execute_call(
        &self,
        vault: &Vault,
        actor: WriteActor,
        principal: &LensPrincipalBinding,
        call: &AgentActionCall,
        binding: ActionHostBinding<'_>,
    ) -> Result<ActionDispatch> {
        self.execute(vault, actor, principal, call, binding)
    }
    pub fn execute_agent(
        &self,
        vault: &Vault,
        actor: WriteActor,
        principal: &LensPrincipalBinding,
        call: &AgentActionCall,
    ) -> Result<ActionDispatch> {
        if principal.kind() != LensActingPrincipalKind::AgentTask {
            return Err(invalid("agent action requires an agent principal"));
        }
        self.execute(vault, actor, principal, call, ActionHostBinding::default())
    }
    /// Executes an agent chat action under an INDEPENDENT authenticated-owner
    /// witness bound by the host, never by a transcript or action argument.
    pub fn execute_agent_with_owner(
        &self,
        vault: &Vault,
        actor: WriteActor,
        principal: &LensPrincipalBinding,
        call: &AgentActionCall,
        owner: &AuthenticatedOwner,
    ) -> Result<ActionDispatch> {
        if principal.kind() != LensActingPrincipalKind::AgentTask {
            return Err(invalid("agent action requires an agent principal"));
        }
        let binding = ActionHostBinding {
            verb_door: None,
            owner: Some(owner),
            live_run: None,
        };
        self.execute(vault, actor, principal, call, binding)
    }
    fn execute<'a>(
        &self,
        vault: &'a Vault,
        actor: WriteActor,
        principal: &LensPrincipalBinding,
        request: &AgentActionCall,
        binding: ActionHostBinding<'a>,
    ) -> Result<ActionDispatch> {
        let ActionHostBinding {
            verb_door,
            owner,
            live_run,
        } = binding;
        let registered = self.registered(request.verb_id.as_str())?;
        // Unbound, a run row would read past the caller's own read key.
        if matches!(registered.build, ActionBuild::Run(_)) && verb_door.is_none() {
            return Err(invalid("a run-row action runs only under a host's door"));
        }
        if let ActionBuild::Run(verb) = registered.build
            && super::run_verb_call::LIVE_RUN_VERBS.contains(&verb)
            && live_run.is_none()
        {
            return Err(invalid("this run row needs its caller's live run"));
        }
        // The run's lease, read live: a lapsed one acts and replays nothing.
        let leased = live_run
            .as_ref()
            .map(|run| run.leased_record(vault))
            .transpose()?;
        let expected_kind = if actor.actor_class() == EdgeActorClass::Agent {
            LensActingPrincipalKind::AgentTask
        } else {
            LensActingPrincipalKind::HumanView
        };
        if principal.principal_ref() != actor.entity_ref().to_hex()
            || principal.kind() != expected_kind
        {
            return Err(invalid("action principal does not match host actor"));
        }
        if request.idempotency_key.trim().is_empty()
            || request.idempotency_key.len() > 256
            || registered.definition.args_schema.len() != request.args.len()
            || request
                .args
                .iter()
                .zip(&registered.definition.args_schema)
                .any(|(arg, kind)| arg.kind() != *kind)
        {
            return Err(invalid("action arguments do not match declared schema"));
        }
        let targets: Vec<_> = request
            .args
            .iter()
            .filter_map(|arg| match arg {
                ActionArgument::Entity { id } => Some(PointRead::id(*id)),
                _ => None,
            })
            .collect();
        let targets = vault
            .scoped_read(principal.selected_read_key().clone())
            .read(&targets, None)?;
        if targets.value.iter().any(Option::is_none) {
            return Err(invalid("action target is outside principal read scope"));
        }
        let read_receipt = targets.receipt;
        check_ceiling(vault, actor, registered.definition.required_ceiling)?;
        let mut hash = blake3::Hasher::new();
        hash.update(b"oneiron:shared-action:v1");
        for part in [
            actor.entity_ref().as_bytes().as_slice(),
            request.verb_id.as_str().as_bytes(),
            request.idempotency_key.as_bytes(),
        ] {
            hash.update(&(part.len() as u64).to_be_bytes());
            hash.update(part);
        }
        // A live run's action is that try's own: another try, or another
        // lease of it, never replays its answer.
        if let Some(record) = &leased {
            hash.update(b"live-run");
            hash.update(record.id.as_bytes());
            hash.update(&record.attempt_count.to_be_bytes());
        }
        let digest = hash.finalize();
        let run_id = EntityId::from_bytes(
            digest.as_bytes()[..16]
                .try_into()
                .map_err(|_| invalid("action identity"))?,
        )?;
        let seed = *blake3::hash(
            &serde_json::to_vec(&(&registered.definition, &request.args))
                .map_err(|_| invalid("action encoding"))?,
        )
        .as_bytes();
        let previous = vault.get_code_run_replay_record(&run_id)?;
        let frozen = previous.as_ref().map_or_else(
            || crate::unix_seconds_now().saturating_mul(1000),
            |record| record.determinism.frozen_unix_ms,
        );
        let call = match registered.build {
            ActionBuild::Factory(factory) => factory(
                ActionBuildContext {
                    effect_id: run_id,
                    actor,
                    frozen_unix_ms: frozen,
                },
                &request.args,
            )?,
            ActionBuild::Verb(verb) => build_sdk_verb(verb, &request.args)?,
            ActionBuild::Run(verb) => build_run_verb(verb, &request.args, frozen)?,
        }
        .with_bridge_stamp(0, frozen);
        if matches!(call, SelfCall::WakePolicyWrite(_)) {
            let proof = owner.ok_or(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "wake policy action needs host owner proof",
            )))?;
            let txn = vault.store.env.read_txn()?;
            crate::dreamer_runner::maintenance::validate_owner_in_txn(vault, &txn, proof)?;
        }
        if let Some(record) = previous {
            if record.determinism.rng_seed != seed {
                return Err(invalid("idempotency key reused with changed action"));
            }
            if record.bridge_calls.is_empty() {
                return Err(Error::ConcurrentWrite(
                    "shared action is in flight or needs reconciliation",
                ));
            }
            return record
                .replay_cursor()
                .dispatch(call)
                .map(|outcome| ActionDispatch {
                    outcome,
                    read_receipt,
                });
        }
        // Reserve the EXISTING replay record before effects. A crash or racing
        // caller sees an incomplete record and fails closed, never re-dispatches.
        let mut record = CodeRunReplayRecord::new(run_id, CodeRunDeterminism::new(frozen, seed));
        let generation = vault.put_code_run_replay_record_if_generation(&record, None)?;
        let dispatcher = match &leased {
            Some(record) => {
                GatedActorWrite::for_action_attempt(vault, actor, run_id.to_hex(), record)?
            }
            None => GatedActorWrite::new(vault, actor, run_id.to_hex())?,
        };
        let dispatcher = match owner {
            Some(proof) => dispatcher.with_authenticated_owner(proof),
            None => dispatcher,
        };
        let dispatcher = match verb_door {
            Some(door) => dispatcher.with_agent_verb_door(door),
            None => dispatcher,
        };
        let result = dispatcher.dispatch_for_executor_run(
            super::ExecutorCallSite {
                run_id,
                seq: 0,
                step_start: 0,
                earlier: &[],
            },
            call.clone(),
        );
        let recorded = match &result {
            Ok(outcome) => outcome.clone(),
            Err(Error::Gate(crate::error::GateError::GateWriteRejected {
                outcome,
                reason_codes,
            })) => SelfDispatchOutcome::Denied(SelfDeniedResult {
                effect: call.effect(),
                outcome: (*outcome).to_owned(),
                reason_codes: reason_codes.iter().map(|r| (*r).to_owned()).collect(),
            }),
            Err(error) => SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: call.effect(),
                error: error.to_string(),
            }),
        };
        record.bridge_calls.push(CodeRunBridgeCall::record(
            0, &call, &recorded, frozen, frozen,
        )?);
        vault.put_code_run_replay_record_if_generation(&record, Some(generation))?;
        result.map(|outcome| ActionDispatch {
            outcome,
            read_receipt,
        })
    }
}
fn build_sdk_verb(verb: AgentVerb, args: &[ActionArgument]) -> Result<SelfCall> {
    let [ActionArgument::Text(input)] = args else {
        return Err(invalid(
            "verb-table action takes its JSON input as one text",
        ));
    };
    let input = serde_json::from_str(input.as_str())
        .map_err(|_| invalid("verb-table action input is not JSON"))?;
    Ok(SelfCall::AgentVerb(SelfAgentVerbCall { verb, input }))
}
/// A run row's typed call, its defaults on the action's frozen clock in unix
/// seconds, as a code run's own clock is.
fn build_run_verb(verb: RunVerb, args: &[ActionArgument], frozen_unix_ms: u64) -> Result<SelfCall> {
    let [ActionArgument::Text(input)] = args else {
        return Err(invalid("run-row action takes its JSON input as one text"));
    };
    let input = serde_json::from_str(input.as_str())
        .map_err(|_| invalid("run-row action input is not JSON"))?;
    super::run_verb_call::run_verb_call(verb, input, frozen_unix_ms / 1000)
}
fn build_inference_defaults_read(
    _: ActionBuildContext,
    args: &[ActionArgument],
) -> Result<SelfCall> {
    if !args.is_empty() {
        return Err(invalid("inference defaults read takes no arguments"));
    }
    Ok(SelfCall::InferenceDefaultsRead)
}
fn build_inference_defaults_replace(
    _: ActionBuildContext,
    args: &[ActionArgument],
) -> Result<SelfCall> {
    let [ActionArgument::Text(value)] = args else {
        return Err(invalid("inference defaults replace requires JSON text"));
    };
    crate::llm::PurposeDefaultTable::from_json(value.as_str().as_bytes())?;
    Ok(SelfCall::InferenceDefaultsReplace(
        value.as_str().to_owned(),
    ))
}
fn build_wake_policy_action(_ctx: ActionBuildContext, args: &[ActionArgument]) -> Result<SelfCall> {
    let [ActionArgument::Text(value)] = args else {
        return Err(invalid("wake policy action needs one row"));
    };
    let policy: crate::dreamer_wake::DreamerWakePolicy = serde_json::from_str(value.as_str())
        .map_err(|_| invalid("wake policy action row does not decode"))?;
    Ok(SelfCall::WakePolicyWrite(
        crate::code_run::SelfWakePolicyWriteCall::new(policy.validate()?),
    ))
}

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.to_owned())
}
pub(super) fn check_ceiling(
    vault: &Vault,
    actor: WriteActor,
    required: AgentCeiling,
) -> Result<()> {
    if required == AgentCeiling::Proposed {
        return Ok(());
    }
    let txn = vault.store.env.read_txn()?;
    check_ceiling_in_txn(vault, &txn, actor, required)
}
/// [`check_ceiling`] in the caller's transaction, for a door that must judge
/// the ceiling in the snapshot it writes.
pub(super) fn check_ceiling_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: WriteActor,
    required: AgentCeiling,
) -> Result<()> {
    if required == AgentCeiling::Proposed {
        return Ok(());
    }
    let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
    let class = match actor.actor_class() {
        EdgeActorClass::Agent => "agent",
        EdgeActorClass::Human => "human",
        _ => return Err(invalid("unsupported action principal class")),
    };
    let ceiling = policy.actor_ceiling(class, Some(&actor.entity_ref().to_hex()));
    let definition = crate::gate::agent_definition_ceiling_for_actor(&vault.store, txn, actor);
    if ceiling != crate::gate::PolicyApprovalCeiling::Auto
        || definition == Some(crate::gate::PolicyApprovalCeiling::Proposed)
    {
        return Err(Error::Gate(crate::error::GateError::GateWriteRejected {
            outcome: "pending",
            reason_codes: vec!["gate.pending.actor_ceiling"],
        }));
    }
    Ok(())
}
mod ceiling_wire {
    use super::*;
    pub(super) fn serialize<S: serde::Serializer>(
        value: &AgentCeiling,
        s: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        value.as_str().serialize(s)
    }
    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> std::result::Result<AgentCeiling, D::Error> {
        AgentCeiling::parse(&String::deserialize(d)?)
            .ok_or_else(|| serde::de::Error::custom("unknown action ceiling"))
    }
}
#[cfg(test)]
mod tests;
