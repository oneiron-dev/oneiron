//! Door for `tests/action_replay_custody.rs` (FIX REPLAY-COMPARE-KNOWN-MATCHER):
//! one agent's action called twice under one idempotency key, as a host
//! serves it. The first call records its row in the vault, through the
//! side-row wall; the second meets that row by its request and answers from
//! it, with no effect of its own.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use rmpv::Value;

use crate::agent_def::AgentCeiling;
use crate::claim::ScopedReadActorKey;
use crate::code_run::actions::{
    ActionArgKind, ActionArgument, ActionBuildContext, ActionDispatch, ActionRegistry,
    ActionVerbDefinition, AgentActionCall,
};
use crate::code_run::{SelfCall, SelfMemoryPutClaimCall};
use crate::error::{Error, Result};
use crate::lens::{LensPrincipalBinding, LensText, SelfUiActionId};
use crate::{ClaimCandidate, ClaimSubject, EdgeActorClass, EntityId, TimeRange, Vault, WriteActor};

/// The action's one verb.
const REMEMBER: &str = "remember";

/// The remember action: its one text, as the acting agent's name claim.
fn remember(context: ActionBuildContext, args: &[ActionArgument]) -> Result<SelfCall> {
    let [ActionArgument::Text(text)] = args else {
        return Err(Error::InvalidConfig(
            "the remember action takes one text".to_owned(),
        ));
    };
    let candidate = ClaimCandidate::new(
        "profile.name",
        ClaimSubject::Entity(context.actor.entity_ref()),
        Value::from(text.as_str()),
        1.0,
    );
    let at = context.frozen_unix_ms / 1000;
    Ok(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
        context.effect_id,
        candidate,
        TimeRange { start: at, end: at },
        at,
    )))
}

/// Calls the remember action with `text` twice under `idempotency_key`, as
/// one new agent: the answer of each call, in order. The first call runs and
/// records its row, whatever it answers; the second answers from that row
/// when its request meets the row's.
///
/// # Errors
///
/// The agent, its principal or the action cannot be set up.
pub fn remember_twice(
    vault: &Vault,
    text: &str,
    idempotency_key: &str,
) -> Result<[Result<ActionDispatch>; 2]> {
    let agent = EntityId::now();
    vault.put_entity(
        &agent,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"agent",
    )?;
    let actor = WriteActor::new(agent, EdgeActorClass::Agent);
    let key = ScopedReadActorKey::with_actor_class(actor.entity_ref().to_hex(), "agent")
        .ok_or(Error::InvalidConfig("the agent has no read key".to_owned()))?;
    let principal =
        LensPrincipalBinding::agent_task(actor.entity_ref().to_hex(), key.clone(), vec![key])?;
    let mut registry = ActionRegistry::default();
    registry.register(
        ActionVerbDefinition {
            id: SelfUiActionId::new(REMEMBER)?,
            args_schema: vec![ActionArgKind::Text],
            required_ceiling: AgentCeiling::Proposed,
        },
        remember,
    )?;
    let call = AgentActionCall {
        verb_id: SelfUiActionId::new(REMEMBER)?,
        args: vec![ActionArgument::Text(LensText::new(text)?)],
        idempotency_key: idempotency_key.to_owned(),
    };
    let first = registry.execute_agent(vault, actor, &principal, &call);
    let second = registry.execute_agent(vault, actor, &principal, &call);
    Ok([first, second])
}
