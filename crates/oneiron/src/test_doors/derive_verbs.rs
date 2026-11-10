//! Doors to the derivation verbs' typed host entries (untangle 6.7d): an
//! agent's live run, leased as a host holds the run a credential attached
//! to, and `vault.derive.commit` and `vault.derive.revert` called on it with
//! their wire input, as the served door calls them. The owner's side of
//! `vault.derive.revert` is called with the embedded owner's proof.

use serde_json::Value;

use crate::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DispatchAgent,
};
use crate::attempt_queue::{AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use crate::code_run::HostSelfDispatcher;
use crate::derive::DeriveCommitInput;
use crate::error::{Error, Result};
use crate::memory::{MemoryError, MemoryResult};
use crate::write_envelope::WriteActor;
use crate::{EdgeActorClass, EntityId, TimeRange, Vault};

/// Writes a minimal human-authored agent definition named `name`, with a
/// Proposed ceiling, as the owner's own agent; its id.
///
/// # Errors
///
/// The vault's.
pub fn define_agent(vault: &Vault, name: &str) -> Result<EntityId> {
    use crate::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
    use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
    let definition = AgentDefinition::new(
        name,
        "Derivation verbs fixture agent",
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
        rmpv::Value::Map(vec![(
            rmpv::Value::from("definedVia"),
            rmpv::Value::from("define_agent"),
        )]),
        None,
        true,
        None,
    );
    let id = EntityId::now();
    vault.put_agent_definition(&id, &definition, TimeRange { start: 1, end: 1 }, 1)?;
    Ok(id)
}

/// Writes the shipped policy with, for each of `agents`, the rows an
/// owner's policy gives an ordinary agent that derives: its `core:read`
/// grant, an `agent` Auto ceiling and the actor-bound `generated` permit.
///
/// # Errors
///
/// The vault's.
pub fn grant_derive_rows(vault: &Vault, agents: &[EntityId]) -> Result<()> {
    let mut body = crate::gate::default_policy_manifest()?;
    for agent in agents {
        body = crate::gate::body_with_agent_derive_rows(&body, &agent.to_hex())?;
    }
    crate::test_support::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id()?,
        &body,
    )
}

/// A live run of a defined agent: its dispatched attempt, leased.
#[derive(Debug, Clone)]
pub struct LiveRun {
    agent: EntityId,
    leased: AttemptRecord,
}

/// Dispatches a run of the defined agent `agent` and leases it, as a host
/// holds the run a credential attached to.
///
/// # Errors
///
/// The vault's, and a run that is not dispatched or leased.
pub fn lease_run(vault: &Vault, agent: EntityId) -> Result<LiveRun> {
    let now = vault.now_recorded_at();
    let AgentDispatchOutcome::Dispatched(status) =
        AgentDispatcher::new(vault).dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(agent),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now,
        })?
    else {
        return Err(Error::InvalidConfig(
            "the agent's run was not dispatched".into(),
        ));
    };
    let ClaimOutcome::Claimed(leased) = AttemptQueue::new(vault).claim(ClaimAttempt {
        lease_owner: "test-door".into(),
        now,
    })?
    else {
        return Err(Error::InvalidConfig(
            "the agent's run was not leased".into(),
        ));
    };
    if leased.id != status.attempt.id {
        return Err(Error::InvalidConfig(
            "another attempt was leased first".into(),
        ));
    }
    Ok(LiveRun { agent, leased })
}

fn wire<T: serde::Serialize>(view: T) -> MemoryResult<Value> {
    serde_json::to_value(view).map_err(|error| MemoryError::bad_request(error.to_string()))
}

impl LiveRun {
    fn dispatcher<'a>(&self, vault: &'a Vault) -> Result<HostSelfDispatcher<'a>> {
        HostSelfDispatcher::for_leased_agent_attempt(
            vault,
            WriteActor::new(self.agent, EdgeActorClass::Agent),
            &self.leased,
        )
    }

    /// `vault.derive.commit` on this run: `input` is the verb's wire `spec`,
    /// decoded as the served door decodes it; the verb's wire answer.
    ///
    /// # Errors
    ///
    /// A bad request for an input the wire form refuses, and the verb's.
    pub fn commit(&self, vault: &Vault, input: Value) -> MemoryResult<Value> {
        let input: DeriveCommitInput = serde_json::from_value(input)
            .map_err(|error| MemoryError::bad_request(error.to_string()))?;
        wire(self.dispatcher(vault)?.derive_commit_from_host(input)?)
    }

    /// `vault.derive.revert` on this run, naming `batch`; the verb's wire
    /// answer.
    ///
    /// # Errors
    ///
    /// The verb's: a batch that is not this run's actor's is refused.
    pub fn revert(&self, vault: &Vault, batch: EntityId) -> MemoryResult<Value> {
        wire(self.dispatcher(vault)?.derive_revert_from_host(batch)?)
    }
}

/// `vault.derive.revert` as the vault's embedded owner, who names no run;
/// the verb's wire answer.
///
/// # Errors
///
/// The verb's.
pub fn revert_as_owner(vault: &Vault, batch: EntityId) -> MemoryResult<Value> {
    let owner = super::steward::owner(vault)?;
    wire(vault.derive_revert_as_owner(&owner, batch)?)
}
