//! One named verb registry for validated UI events and agent calls.
//! Host factories build existing SelfCalls; only GatedActorWrite executes them.
use super::{
    CodeRunBridgeCall, CodeRunDeterminism, CodeRunReplayRecord, GatedActorWrite, SelfCall,
    SelfDeniedResult, SelfDispatchOutcome, SelfDispatcher, SelfFailedResult,
};
use crate::agent_def::AgentCeiling;
use crate::lens::{
    FiniteF64, GeneratedUiValidatedAction, LensActingPrincipalKind, LensApprovedActionArg,
    LensPrincipalBinding, LensText, SelfUiActionId, SelfUiOptionValue,
};
use crate::{EdgeActorClass, EntityId, Error, Result, Vault, WriteActor};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
#[derive(Debug, Clone, Copy)]
pub struct ActionBuildContext {
    pub effect_id: EntityId,
    pub actor: WriteActor,
    pub frozen_unix_ms: u64,
}
pub type ActionFactory = fn(ActionBuildContext, &[ActionArgument]) -> Result<SelfCall>;
struct RegisteredVerb {
    definition: ActionVerbDefinition,
    factory: ActionFactory,
}
#[derive(Default)]
pub struct ActionRegistry {
    verbs: BTreeMap<String, RegisteredVerb>,
}
impl ActionRegistry {
    pub fn register(
        &mut self,
        definition: ActionVerbDefinition,
        factory: ActionFactory,
    ) -> Result<()> {
        if self.verbs.contains_key(definition.id.as_str()) {
            return Err(invalid("duplicate action verb"));
        }
        self.verbs.insert(
            definition.id.as_str().to_owned(),
            RegisteredVerb {
                definition,
                factory,
            },
        );
        Ok(())
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
    ) -> Result<SelfDispatchOutcome> {
        let GeneratedUiValidatedAction::DeterministicTool { emitter, action } = action else {
            return Err(invalid("UI action is not a deterministic tool"));
        };
        let call = AgentActionCall {
            verb_id: action.command().clone(),
            args: action.args().iter().map(ActionArgument::from_ui).collect(),
            idempotency_key: idempotency_key.to_owned(),
        };
        self.execute(vault, actor, emitter, &call)
    }
    pub fn execute_agent(
        &self,
        vault: &Vault,
        actor: WriteActor,
        principal: &LensPrincipalBinding,
        call: &AgentActionCall,
    ) -> Result<SelfDispatchOutcome> {
        if principal.kind() != LensActingPrincipalKind::AgentTask {
            return Err(invalid("agent action requires an agent principal"));
        }
        self.execute(vault, actor, principal, call)
    }
    fn execute(
        &self,
        vault: &Vault,
        actor: WriteActor,
        principal: &LensPrincipalBinding,
        request: &AgentActionCall,
    ) -> Result<SelfDispatchOutcome> {
        let registered = self.registered(request.verb_id.as_str())?;
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
        let scoped = vault.scoped_read(principal.selected_read_key().clone());
        for arg in &request.args {
            if let ActionArgument::Entity { id } = arg
                && !scoped.is_entity_readable(id)?
            {
                return Err(invalid("action target is outside principal read scope"));
            }
        }
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
        let call = (registered.factory)(
            ActionBuildContext {
                effect_id: run_id,
                actor,
                frozen_unix_ms: frozen,
            },
            &request.args,
        )?
        .with_bridge_stamp(0, frozen);
        if let Some(record) = previous {
            if record.determinism.rng_seed != seed {
                return Err(invalid("idempotency key reused with changed action"));
            }
            if record.bridge_calls.is_empty() {
                return Err(Error::ConcurrentWrite(
                    "shared action is in flight or needs reconciliation",
                ));
            }
            return record.replay_cursor().dispatch(call);
        }
        // Reserve the EXISTING replay record before effects. A crash or racing
        // caller sees an incomplete record and fails closed, never re-dispatches.
        let mut record = CodeRunReplayRecord::new(run_id, CodeRunDeterminism::new(frozen, seed));
        let generation = vault.put_code_run_replay_record_if_generation(&record, None)?;
        let dispatcher = GatedActorWrite::new(vault, actor, run_id.to_hex())?;
        let result = dispatcher.dispatch_for_executor_run(run_id, call.clone());
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
        result
    }
}
fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.to_owned())
}
fn check_ceiling(vault: &Vault, actor: WriteActor, required: AgentCeiling) -> Result<()> {
    if required == AgentCeiling::Proposed {
        return Ok(());
    }
    let txn = vault.store.env.read_txn()?;
    let policy = crate::gate::resolve_policy_manifest(&vault.store, &txn)?;
    let class = match actor.actor_class() {
        EdgeActorClass::Agent => "agent",
        EdgeActorClass::Human => "human",
        _ => return Err(invalid("unsupported action principal class")),
    };
    let ceiling = policy.actor_ceiling(class, Some(&actor.entity_ref().to_hex()));
    let definition = crate::gate::agent_definition_ceiling_for_actor(&vault.store, &txn, actor);
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
