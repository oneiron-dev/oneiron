//! A TASK with one live realizing attempt, for force-cancel tests: the
//! seeded agent's dispatched run creates it through the engine's own doors,
//! as `run_tree_reader` does.

use crate::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext,
    DEFAULT_BASE_LOGICAL_ID, DispatchAgent,
};
use crate::attempt_queue::{AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use crate::error::{Error, Result};
use crate::memory::MemoryError;
use crate::policy_manifest_doors::{
    ActorCeiling, PolicyCeiling, PolicyManifestPut, PolicyManifestRead, policy_manifests_as_owner,
    put_policy_manifest_as_owner,
};
use crate::store::GateDecisionId;
use crate::task_verb::{HostBinding, TaskAssignee, TaskCreateSpec, TaskRouteOutcome};
use crate::{AttemptId, EdgeActorClass, EntityId, Vault};

/// Plants a TASK with one live realizing attempt: the seeded agent is
/// granted an Auto ceiling, its root run is dispatched and claimed, and it
/// creates a TASK assigned to its own agent definition. Answers the TASK
/// ref. The realizing attempt stays queued, so a force stops it.
///
/// # Errors
///
/// A vault without the seeded agent or policy manifest; a dispatch, claim
/// or create the engine refuses; a store failure.
pub fn plant_task_with_live_attempt_for_test(vault: &Vault) -> Result<EntityId> {
    let (agent, _) = vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)?
        .ok_or_else(|| Error::InvalidConfig("the default agent is seeded".into()))?;
    let owner = vault.ensure_embedded_owner_actor().map_err(refused)?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let policy = policy_manifests_as_owner(vault, &proof, &PolicyManifestRead::default())?;
    let mut default = policy
        .manifests
        .into_iter()
        .find(|manifest| manifest.manifest_ref == policy.default_manifest_ref)
        .ok_or_else(|| Error::InvalidConfig("the default policy manifest is seeded".into()))?;
    default.manifest.actor_ceilings.push(ActorCeiling {
        actor_class: "agent".to_owned(),
        actor_ref: Some(agent.to_hex()),
        ceiling: PolicyCeiling::Auto,
    });
    put_policy_manifest_as_owner(
        vault,
        &proof,
        PolicyManifestPut {
            manifest_ref: Some(default.manifest_ref),
            expected_body_hash: Some(default.body_hash),
            manifest: default.manifest,
        },
    )?;

    let AgentDispatchOutcome::Dispatched(parent) = AgentDispatcher::new(vault)
        .dispatch_with_context(
            DispatchAgent {
                target: AgentDispatchTarget::Custom(agent),
                parent_attempt: None,
                dedupe_key: None,
                run_id: Some("live-task-planter".to_owned()),
                now: 1,
            },
            AgentSpawnContext::default().with_depth_remaining(1),
        )?
    else {
        return Err(Error::InvalidConfig("expected one fresh parent run".into()));
    };
    let queue = AttemptQueue::new(vault);
    let parent = claim_attempt(&queue, parent.attempt.id)?;
    let receipt = vault
        .memory(agent, EdgeActorClass::Agent)
        .with_task_host(HostBinding::from_leased(&parent, None).map_err(refused)?)
        .tasks_create(
            &TaskCreateSpec::new(
                rmpv::Value::Nil,
                Some("a TASK with one live attempt".to_owned()),
                Some(agent),
                None,
            )
            .with_assignee(TaskAssignee::AgentDef {
                agent_def_ref: agent,
            }),
        )
        .map_err(refused)?;
    let task_ref = receipt
        .task_ref
        .ok_or_else(|| Error::InvalidConfig("the TASK is minted".into()))?;
    let Some(TaskRouteOutcome::AgentDispatch { .. }) = receipt.route else {
        return Err(Error::InvalidConfig(
            "an agent-definition assignee routes to an agent dispatch".into(),
        ));
    };
    Ok(task_ref)
}

/// A memory door's refusal, as this planter's error.
fn refused(error: MemoryError) -> Error {
    Error::InvalidConfig(error.to_string())
}

/// Claims `attempt_ref` past the runner rows a fresh vault queued.
fn claim_attempt(queue: &AttemptQueue<'_>, attempt_ref: AttemptId) -> Result<AttemptRecord> {
    for _ in 0..32 {
        let ClaimOutcome::Claimed(row) = queue.claim_kind(
            DREAMER_RUNNER_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "live-task-planter".to_owned(),
                now: u64::MAX,
            },
        )?
        else {
            break;
        };
        if row.id == attempt_ref {
            return Ok(row);
        }
    }
    Err(Error::InvalidConfig(
        "the run's attempt is ready to claim".into(),
    ))
}
