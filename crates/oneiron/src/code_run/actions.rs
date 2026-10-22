//! One named verb registry for validated UI events and agent calls.
//! Entry type: `ActionRegistry`.
//! This root owns action values; the execution and build children use code_run calls.
//!
//! Host factories build existing SelfCalls; only GatedActorWrite executes them.
//!
//! One action layer, two callers (OF-181): the app's buttons and an agent's
//! calls name the same verbs, every row of the SDK verb table among them, and
//! each runs through the one gated SDK the agent writes code against.
use self::build::{
    build_inference_defaults_read, build_inference_defaults_replace, build_run_verb,
    build_sdk_verb, build_wake_policy_action,
};
use super::{
    AgentVerbDoor, AgentVerbRefusalWords, CodeRunBridgeCall, CodeRunDeterminism,
    CodeRunReplayRecord, GatedActorWrite, SelfAgentVerbCall, SelfCall, SelfDeniedResult,
    SelfDispatchOutcome, SelfDispatcher, SelfFailedResult,
};
use super::{ExecutorCallSite, payload, run_verb_call};
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
    Json,
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
    /// A verb-table or run row's whole input, structured, past what one text
    /// holds: a host's REST write carries its full body here.
    Json(ActionJson),
}
impl ActionArgument {
    fn kind(&self) -> ActionArgKind {
        match self {
            Self::Bool(_) => ActionArgKind::Bool,
            Self::Number(_) => ActionArgKind::Number,
            Self::Text(_) => ActionArgKind::Text,
            Self::Token(_) => ActionArgKind::Token,
            Self::Entity { .. } => ActionArgKind::Entity,
            Self::Json(_) => ActionArgKind::Json,
        }
    }
    /// Whether this argument fills a `kind` slot of a verb built by `build`.
    /// A verb-table or run row's one text is its whole JSON input, so that
    /// slot takes the input structured too.
    fn fits(&self, kind: ActionArgKind, build: ActionBuild) -> bool {
        self.kind() == kind
            || (matches!(self, Self::Json(_))
                && kind == ActionArgKind::Text
                && matches!(build, ActionBuild::Verb(_) | ActionBuild::Run(_)))
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
/// One structured JSON argument, at most [`MAX_ACTION_JSON_BYTES`] encoded:
/// the most a verb-table row's own facade route reads.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "serde_json::Value", into = "serde_json::Value")]
pub struct ActionJson(serde_json::Value);
/// The most one [`ActionJson`] holds, encoded, in bytes.
pub const MAX_ACTION_JSON_BYTES: usize = crate::memory::caps::MAX_REMOTE_REQUEST_BYTES;
impl ActionJson {
    /// # Errors
    /// A value that encodes past [`MAX_ACTION_JSON_BYTES`].
    pub fn new(value: serde_json::Value) -> Result<Self> {
        let bytes = serde_json::to_vec(&value).map_err(|_| invalid("action JSON encoding"))?;
        if bytes.len() > MAX_ACTION_JSON_BYTES {
            return Err(invalid("action JSON argument is too large"));
        }
        Ok(Self(value))
    }
    /// The structured value.
    #[must_use]
    pub const fn value(&self) -> &serde_json::Value {
        &self.0
    }
}
impl TryFrom<serde_json::Value> for ActionJson {
    type Error = Error;
    fn try_from(value: serde_json::Value) -> Result<Self> {
        Self::new(value)
    }
}
impl From<ActionJson> for serde_json::Value {
    fn from(json: ActionJson) -> Self {
        json.0
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
    /// A refused verb-table row's own words, as its route answered them and
    /// its replay record keeps them; `None` for every other outcome.
    pub refusal: Option<AgentVerbRefusalWords>,
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
    /// Where the owner's say-so reached the host, beside `owner`: an owner
    /// setting records it in the owner's act (WILL-PLAN L13 row 01), audit
    /// only. Unset, the setting keeps no act record.
    pub owner_surface: Option<crate::authority::ActSurface>,
    /// The live agent run the call acts for, as the host that runs it sealed
    /// its lease (`HostSelfDispatcher::task_host_binding`). Read live again
    /// at every call, and before any replay answers.
    pub live_run: Option<crate::task_verb::HostBinding>,
    /// The host's planner that run reads, lent beside its lease: the
    /// leader's rows (`self.leader.advice`, `self.leader.pattern`) ask it.
    /// Unset, they answer `planner_unbound`.
    pub planner: Option<super::HostPlannerBinding<'a>>,
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
    /// A row that is also a memory or live run row is offered once, as the
    /// run row registered below.
    pub fn register_sdk_verbs(&mut self) -> Result<()> {
        for verb in AgentVerb::ALL.iter().copied().filter(|verb| {
            verb.is_facade()
                && !super::live_run::is_live_run_verb(verb.as_str())
                && !RunVerb::from_name(verb.as_str())
                    .is_some_and(|run| super::run_verb_call::MEMORY_RUN_VERBS.contains(&run))
        }) {
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
    /// `self.team.record`, `self.team.submit`, the leader's
    /// `self.leader.advice` and `self.leader.pattern` on the planner the host
    /// lends beside it, and the fold rows on the run's own log) under
    /// their own names, as the memory rows are offered. Each runs only when the host binds the run's lease
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
mod build;
mod execution;
mod replay_read;
#[cfg(test)]
mod tests;
