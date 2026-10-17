//! The app's policy actions as host verbs (OF-181). The action table holds
//! three policy actions no SDK row named: `dreamer.wake_policy.set`,
//! `inference.defaults.read` and `inference.defaults.replace`. The host verbs
//! `vault.settings.wake_policy.set`, `vault.settings.inference_defaults` and
//! `.replace` run them, so code mode, MCP and the SDK clients reach the same
//! actions the app's buttons do. Each door runs the table's own action under
//! the caller's credential: the wake policy still needs the host's owner
//! proof, and the inference defaults the caller's Auto ceiling. Nothing here
//! writes a policy itself.

use serde::{Deserialize, Serialize};

use crate::claim::ScopedReadActorKey;
use crate::code_run::actions::{
    ActionArgument, ActionDispatch, ActionHostBinding, ActionRegistry, AgentActionCall,
};
use crate::consent::AuthenticatedOwner;
use crate::lens::{LensPrincipalBinding, LensText, SelfUiActionId};
use crate::memory::{Memory, MemoryResult};
use crate::{EdgeActorClass, EntityId, Error, Result, WriteActor};

/// `vault.settings.wake_policy.set`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WakePolicySetRequest {
    /// The dreamer wake policy row, as `dreamer.wake_policy.set` takes it.
    pub policy: serde_json::Value,
    /// The call's idempotency key, at most 256 bytes: a retry with the same
    /// key and policy gets the first call's answer.
    pub idempotency_key: String,
}

/// `vault.settings.inference_defaults.replace`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InferenceDefaultsReplaceRequest {
    /// The whole per-purpose default table, as `inference.defaults.replace`
    /// takes it.
    pub defaults: serde_json::Value,
    /// The call's idempotency key, at most 256 bytes.
    pub idempotency_key: String,
}

/// A policy action's answer: its outcome as the action's replay record
/// spells it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PolicyActionOutcome {
    pub outcome: serde_json::Value,
}

impl PolicyActionOutcome {
    /// # Errors
    /// An outcome that does not encode.
    pub fn from_dispatch(dispatch: &ActionDispatch) -> Result<Self> {
        Ok(Self {
            outcome: dispatch.outcome_value()?,
        })
    }
}

fn action(id: &str, args: Vec<ActionArgument>, idempotency_key: String) -> Result<AgentActionCall> {
    Ok(AgentActionCall {
        verb_id: SelfUiActionId::new(id)?,
        args,
        idempotency_key,
    })
}

fn json_text(value: &serde_json::Value) -> Result<ActionArgument> {
    let text = serde_json::to_string(value)
        .map_err(|_| Error::InvalidConfig("policy action input does not encode".to_owned()))?;
    Ok(ActionArgument::Text(LensText::new(text)?))
}

impl WakePolicySetRequest {
    /// The table's `dreamer.wake_policy.set` call.
    /// # Errors
    /// A policy past the action's text bound.
    pub fn into_action(self) -> Result<AgentActionCall> {
        action(
            "dreamer.wake_policy.set",
            vec![json_text(&self.policy)?],
            self.idempotency_key,
        )
    }
}

impl InferenceDefaultsReplaceRequest {
    /// The table's `inference.defaults.replace` call.
    /// # Errors
    /// A table past the action's text bound.
    pub fn into_action(self) -> Result<AgentActionCall> {
        action(
            "inference.defaults.replace",
            vec![json_text(&self.defaults)?],
            self.idempotency_key,
        )
    }
}

/// The table's `inference.defaults.read` call. A read takes no key from its
/// caller: each read gets a fresh one, so it never answers from an earlier
/// read's record.
/// # Errors
/// None in practice; the action id is fixed.
pub fn inference_defaults_read_action() -> Result<AgentActionCall> {
    action(
        "inference.defaults.read",
        Vec::new(),
        format!("read/{}", EntityId::now().to_hex()),
    )
}

/// The principal an action call runs as: `actor` itself, reading under its
/// credential's `key`, as a human view or an agent task by its class.
/// # Errors
/// A key that does not belong to `actor`.
pub fn action_principal(
    actor: WriteActor,
    key: ScopedReadActorKey,
) -> Result<LensPrincipalBinding> {
    let id = actor.entity_ref().to_hex();
    match actor.actor_class() {
        EdgeActorClass::Agent => LensPrincipalBinding::agent_task(id, key.clone(), vec![key]),
        _ => LensPrincipalBinding::human_view(id, key.clone(), vec![key]),
    }
}

/// An embedded call: the handle's own actor and read key, and the owner's
/// proof when the action needs it.
fn run_embedded(
    memory: &Memory<'_>,
    call: AgentActionCall,
    owner: Option<&AuthenticatedOwner>,
) -> MemoryResult<PolicyActionOutcome> {
    let actor = WriteActor::new(memory.actor(), memory.actor_class());
    let principal = action_principal(actor, memory.read_key()?)?;
    let dispatch = ActionRegistry::app()?.execute_call(
        memory.vault(),
        actor,
        &principal,
        &call,
        ActionHostBinding {
            verb_door: None,
            owner,
            live_run: None,
            planner: None,
        },
    )?;
    Ok(PolicyActionOutcome::from_dispatch(&dispatch)?)
}

/// `vault.settings.wake_policy.set` on an embedded handle: the owner's own.
/// # Errors
/// A handle that is not the owner's, or the action's refusal.
pub fn wake_policy_set_embedded(
    memory: &Memory<'_>,
    input: WakePolicySetRequest,
) -> MemoryResult<PolicyActionOutcome> {
    let owner = memory.embedded_owner("vault.settings.wake_policy.set")?;
    run_embedded(memory, input.into_action()?, Some(&owner))
}

/// `vault.settings.inference_defaults` on an embedded handle.
/// # Errors
/// The action's refusal: the handle's actor needs an Auto ceiling.
pub fn inference_defaults_embedded(memory: &Memory<'_>) -> MemoryResult<PolicyActionOutcome> {
    run_embedded(memory, inference_defaults_read_action()?, None)
}

/// `vault.settings.inference_defaults.replace` on an embedded handle.
/// # Errors
/// The action's refusal: the handle's actor needs an Auto ceiling, and the
/// table must validate.
pub fn inference_defaults_replace_embedded(
    memory: &Memory<'_>,
    input: InferenceDefaultsReplaceRequest,
) -> MemoryResult<PolicyActionOutcome> {
    run_embedded(memory, input.into_action()?, None)
}
