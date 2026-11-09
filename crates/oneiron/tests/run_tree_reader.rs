//! Primitive D, slice 6.5a (SLICE6-MAP row D; ENGINE CALLS S65-NAMES and
//! S65-BUDGET = A): `vault.runs.branches.get` and `vault.budgets.lease` keep
//! their names, and their admission widens from the owner alone to the owner
//! and the run's own actor, plus a Steward for branches. On 6.4f an agent
//! asking for its own TASK's branches or its own run's lease is refused as the
//! owner's door. Here it reads them; a caller that is not the run's actor
//! stays refused; a Steward reads another agent's branch without its text;
//! no one but the owner reads a launch root.
//!
//! The Steward grant and the child spend scopes are stood through the
//! `oneiron_test_support` doors (`oneiron::test_doors`):
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test run_tree_reader`.
#![cfg(oneiron_test_support)]

use oneiron::agent_dispatch::budget_doors::{OpenSpendLeaseRequest, SpendScopeRequest};
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatcher, DEFAULT_BASE_LOGICAL_ID, SpendScopeId,
};
use oneiron::attempt_queue::{ClaimAttempt, ClaimOutcome, FailAttempt};
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::federation::FederationGrantRole;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::run_doors::RunBranchesRequest;
use oneiron::task_verb::{TaskAssignee, TaskCreateSpec, TaskRouteOutcome};
use oneiron::test_doors::membership::stand_member_grant;
use oneiron::test_doors::spend::reserve_child_scope;
use oneiron::{AttemptId, AttemptQueue, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SHARED: u64 = 42;
/// The first-party actor the default policy manifest grants an Auto
/// ceiling, so its TASK create takes direct effect.
const CREATOR_BYTES: [u8; 16] = [0xE1; 16];
const AGENT_ERROR: &str = "the agent's own words about its failure";

/// A process-owned vault, as an embedded owner opens it: it holds the
/// writer lease, so the embedded owner's doors admit the owner.
fn open_vault() -> Result<(tempfile::TempDir, Vault), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.map_size = 32 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_owned(dir.path(), config)?;
    Ok((dir, vault))
}

fn person(vault: &Vault, id: EntityId) -> Result<EntityId, Box<dyn std::error::Error>> {
    vault.put_entity(
        &id,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"a person of the shared vault",
    )?;
    Ok(id)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn an_agent_reads_its_own_branch_and_a_steward_reads_it_without_text() -> TestResult {
    let (_dir, vault) = open_vault()?;
    // A TASK assigned to the seeded default agent runs as that agent.
    let (agent, _) = vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)?
        .ok_or("the default agent is seeded")?;
    let creator = person(&vault, EntityId::from_bytes(CREATOR_BYTES)?)?;
    let receipt = vault.memory(creator, EdgeActorClass::Agent).tasks_create(
        &TaskCreateSpec::new(
            rmpv::Value::Nil,
            Some("read the run tree".to_owned()),
            Some(creator),
            None,
        )
        .with_assignee(TaskAssignee::AgentDef {
            agent_def_ref: agent,
        }),
    )?;
    let task_ref = receipt.task_ref.ok_or("the TASK is minted")?;
    let Some(TaskRouteOutcome::AgentDispatch { attempt_ref, .. }) = receipt.route else {
        return Err("an agent-definition assignee routes to an agent dispatch".into());
    };

    // The branch fails with the agent's own words. The dispatch rides the
    // runner's queue kind; other rows the fresh vault queued are claimed past.
    let queue = AttemptQueue::new(&vault);
    let mut claimed = None;
    for _ in 0..32 {
        let ClaimOutcome::Claimed(row) = queue.claim_kind(
            DREAMER_RUNNER_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "run-tree-reader".to_owned(),
                now: u64::MAX,
            },
        )?
        else {
            break;
        };
        if row.id == attempt_ref {
            claimed = Some(row);
            break;
        }
    }
    let claimed = claimed.ok_or("the TASK's attempt is ready to claim")?;
    queue.fail(FailAttempt {
        id: claimed.id,
        lease_owner: "run-tree-reader".to_owned(),
        attempt_count: claimed.attempt_count,
        reason: AGENT_ERROR.to_owned(),
        now: claimed.claimed_at.ok_or("a claim records its time")?,
    })?;
    let request = RunBranchesRequest { task_ref };
    let branch = hex(attempt_ref.as_bytes());

    // The vault is shared; one member is its Steward.
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    vault.initialize_shared_vault(&proof, SHARED, None, &[], 1)?;
    let steward = person(&vault, EntityId::now())?;
    let member = person(&vault, EntityId::now())?;
    stand_member_grant(&vault, steward, SHARED, FederationGrantRole::Steward)?;
    stand_member_grant(&vault, member, SHARED, FederationGrantRole::Member)?;

    // The run's own actor reads its branch, its words included.
    let own = oneiron::verbs::vault_runs_branches_get(
        &vault.memory(agent, EdgeActorClass::Agent),
        request.clone(),
    )?;
    assert_eq!(own.branches.len(), 1);
    assert_eq!(own.branches[0].branch, branch);
    assert_eq!(own.branches[0].last_error.as_deref(), Some(AGENT_ERROR));

    // A Steward, no actor of the run, reads the branch without its text.
    let as_steward = vault.memory(steward, EdgeActorClass::Human);
    assert!(
        as_steward.get_entity(&task_ref.to_hex())?.value.is_some(),
        "the TASK reads on the Steward's lane"
    );
    let stewarded = oneiron::verbs::vault_runs_branches_get(&as_steward, request.clone())?;
    assert_eq!(stewarded.branches.len(), 1);
    assert_eq!(stewarded.branches[0].branch, branch);
    assert_eq!(stewarded.branches[0].state, own.branches[0].state);
    assert_eq!(stewarded.branches[0].last_error, None);
    assert!(stewarded.branches[0].asks.is_empty());
    assert!(stewarded.branches[0].signals.is_empty());

    // A member without the role, and another agent, stay refused.
    assert!(
        oneiron::verbs::vault_runs_branches_get(
            &vault.memory(member, EdgeActorClass::Human),
            request.clone()
        )
        .is_err()
    );
    assert!(
        oneiron::verbs::vault_runs_branches_get(
            &vault.memory(EntityId::now(), EdgeActorClass::Agent),
            request.clone()
        )
        .is_err()
    );

    // The owner reads every branch with its text, as before.
    let as_owner = oneiron::verbs::vault_runs_branches_get(
        &vault.memory(owner, EdgeActorClass::Human),
        request,
    )?;
    assert_eq!(as_owner.branches.len(), 1);
    assert_eq!(
        as_owner.branches[0].last_error.as_deref(),
        Some(AGENT_ERROR)
    );
    Ok(())
}

#[test]
fn an_agent_reads_the_leases_of_its_own_scope_tree_and_no_other() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let as_owner = vault.memory(owner, EdgeActorClass::Human);
    oneiron::verbs::vault_budgets_lease_open(
        &as_owner,
        OpenSpendLeaseRequest {
            launch: "launch-6-5a".to_owned(),
            cap_units: 1_000,
            unit: "units".to_owned(),
            shown_at_ms: 1,
            funding_grant_ref: None,
        },
    )?;
    let launch = SpendScopeId::launch("launch-6-5a")?;

    let AgentDispatchOutcome::Dispatched(status) =
        AgentDispatcher::new(&vault).dispatch_default_base(None, None, None, 1)?
    else {
        return Err("expected one fresh spawn".into());
    };
    let agent = status.input.target.agent_definition_ref()?;
    let run = status.attempt.id;
    // The agent's run spends under the launch; it reserved a child below it.
    // A sibling no actor runs spends under the same launch.
    reserve_child_scope(&vault, &launch, &run, 100, 1)?;
    let child = AttemptId::now();
    reserve_child_scope(&vault, &SpendScopeId::for_attempt(&run), &child, 10, 1)?;
    let sibling = AttemptId::now();
    reserve_child_scope(&vault, &launch, &sibling, 10, 1)?;
    let lease = |scope: String| SpendScopeRequest { scope };

    // The run's own actor reads its run's lease and the one its run reserved.
    let as_agent = vault.memory(agent, EdgeActorClass::Agent);
    let own = oneiron::verbs::vault_budgets_lease(&as_agent, lease(hex(run.as_bytes())))?;
    assert_eq!(own.lease.scope, SpendScopeId::for_attempt(&run));
    assert_eq!(own.lease.parent, Some(launch.clone()));
    let below = oneiron::verbs::vault_budgets_lease(&as_agent, lease(hex(child.as_bytes())))?;
    assert_eq!(below.lease.scope, SpendScopeId::for_attempt(&child));

    // Not the launch root above it, nor a sibling run's lease.
    assert!(
        oneiron::verbs::vault_budgets_lease(&as_agent, lease("launch-6-5a".to_owned())).is_err()
    );
    assert!(
        oneiron::verbs::vault_budgets_lease(&as_agent, lease(hex(sibling.as_bytes()))).is_err()
    );

    // A person who is not the run's actor stays refused.
    let stranger = person(&vault, EntityId::now())?;
    assert!(
        oneiron::verbs::vault_budgets_lease(
            &vault.memory(stranger, EdgeActorClass::Human),
            lease(hex(run.as_bytes()))
        )
        .is_err()
    );

    // The owner reads any lease, as before.
    assert_eq!(
        oneiron::verbs::vault_budgets_lease(&as_owner, lease("launch-6-5a".to_owned()))?
            .lease
            .scope,
        launch
    );
    assert!(oneiron::verbs::vault_budgets_lease(&as_owner, lease(hex(sibling.as_bytes()))).is_ok());
    Ok(())
}
