//! Primitive D, slice 6.5a (SLICE6-MAP row D; ENGINE CALLS S65-NAMES and
//! S65-BUDGET = A): `vault.runs.branches.get` and `vault.budgets.lease` keep
//! their names, and their admission widens from the owner alone to the owner
//! and the run's own actor, plus a Steward for branches. On 6.4f an agent
//! asking for its own TASK's branches or its own run's lease is refused as the
//! owner's door. Here it reads them; a caller that is not the run's actor
//! stays refused; a Steward reads another agent's branch without its text,
//! the words in its cancel state included; no one but the owner reads a
//! launch root; and a caller bound to a credential reads only while that
//! credential holds.
//!
//! The Steward grant and the child spend scopes are stood through the
//! `oneiron_test_support` doors (`oneiron::test_doors`):
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test run_tree_reader`.
#![cfg(oneiron_test_support)]

use ed25519_dalek::{Signer, SigningKey};
use oneiron::agent_dispatch::budget_doors::{OpenSpendLeaseRequest, SpendScopeRequest};
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatcher, DEFAULT_BASE_LOGICAL_ID, SpendScopeId,
};
use oneiron::attempt_queue::{ClaimAttempt, ClaimOutcome, RetryAttempt};
use oneiron::authority::HostSlipIssuer;
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::federation::FederationGrantRole;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::run_doors::{
    CancelForceRequest, RunBranchView, RunBranchesRequest, RunBranchesView,
};
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
/// What the owner says as it stops the TASK: kept on the cancelled branch.
const OWNER_REASON: &str = "the owner's own words about the stop";
/// The challenge the agent's credential is verified on.
const CHALLENGE: &[u8] = b"oneiron-request:run-tree-reader";

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

fn branch_of<'v>(
    view: &'v RunBranchesView,
    branch: &str,
) -> Result<&'v RunBranchView, Box<dyn std::error::Error>> {
    Ok(view
        .branches
        .iter()
        .find(|read| read.branch == branch)
        .ok_or("the read holds the failed try")?)
}

/// The branch of `view` a cancel stopped.
fn cancelled_branch(view: &RunBranchesView) -> Result<&RunBranchView, Box<dyn std::error::Error>> {
    Ok(view
        .branches
        .iter()
        .find(|read| read.cancel_state.cancellation.is_some())
        .ok_or("the read holds the cancelled branch")?)
}

#[test]
fn an_agent_reads_its_own_branch_and_a_steward_reads_it_without_text() -> TestResult {
    use oneiron::agent_dispatch::{AgentDispatchTarget, AgentSpawnContext, DispatchAgent};
    use oneiron::attempt_queue::AttemptRecord;
    use oneiron::policy_manifest_doors::{
        ActorCeiling, PolicyCeiling, PolicyManifestPut, PolicyManifestRead,
        policy_manifests_as_owner, put_policy_manifest_as_owner,
    };
    use oneiron::run_tree::{RunAskQuestion, RunSignalInput, RunSignalKind, RunTreeAdapter};
    use oneiron::task_verb::HostBinding;

    const ASK_PROMPT: &str = "Which branch should the run keep?";
    const SIGNAL_INSTRUCTION: &str = "Keep the current branch until the owner answers.";

    let (_dir, vault) = open_vault()?;
    let (agent, _) = vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)?
        .ok_or("the default agent is seeded")?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    // The creating run must be the default agent itself, not the unrelated
    // first-party creator: grant that agent direct TASK creation explicitly.
    let policy = policy_manifests_as_owner(&vault, &proof, &PolicyManifestRead::default())?;
    let mut default = policy
        .manifests
        .into_iter()
        .find(|manifest| manifest.manifest_ref == policy.default_manifest_ref)
        .ok_or("the default policy manifest is seeded")?;
    default.manifest.actor_ceilings.push(ActorCeiling {
        actor_class: "agent".to_owned(),
        actor_ref: Some(agent.to_hex()),
        ceiling: PolicyCeiling::Auto,
    });
    put_policy_manifest_as_owner(
        &vault,
        &proof,
        PolicyManifestPut {
            manifest_ref: Some(default.manifest_ref),
            expected_body_hash: Some(default.body_hash),
            manifest: default.manifest,
        },
    )?;

    // A root dispatch carries the run tag. Its leased host binding makes
    // the TASK's realizing attempt inherit that tag and its parent lineage.
    let AgentDispatchOutcome::Dispatched(parent) = AgentDispatcher::new(&vault)
        .dispatch_with_context(
            DispatchAgent {
                target: AgentDispatchTarget::Custom(agent),
                parent_attempt: None,
                dedupe_key: None,
                run_id: Some("run-tree-reader".to_owned()),
                now: 1,
            },
            AgentSpawnContext::default().with_depth_remaining(1),
        )?
    else {
        return Err("expected one fresh parent run".into());
    };
    let queue = AttemptQueue::new(&vault);
    // Other runner rows the fresh vault queued are claimed past.
    let claim_attempt =
        |attempt_ref: AttemptId| -> Result<AttemptRecord, Box<dyn std::error::Error>> {
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
                    return Ok(row);
                }
            }
            Err("the run's attempt is ready to claim".into())
        };
    let parent = claim_attempt(parent.attempt.id)?;
    let receipt = vault
        .memory(agent, EdgeActorClass::Agent)
        .with_task_host(HostBinding::from_leased(&parent, None)?)
        .tasks_create(
            &TaskCreateSpec::new(
                rmpv::Value::Nil,
                Some("read the run tree".to_owned()),
                Some(agent),
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

    // The try fails with the agent's own words and is retried: the TASK has
    // two branches, the failed try and its scheduled retry. The parent run
    // has no backlink to this TASK. A retry retains the failed try's inbox.
    let claimed = claim_attempt(attempt_ref)?;
    let claimed_at = claimed.claimed_at.ok_or("a claim records its time")?;
    let run_id = claimed
        .run_id
        .as_deref()
        .ok_or("the attempt has a run tag")?;
    let run_tree = RunTreeAdapter::new(&vault);
    let ask = run_tree.open_ask(
        claimed.id,
        run_id,
        "run-tree-reader",
        claimed.attempt_count,
        "branch-question",
        vec![RunAskQuestion {
            who: owner.to_hex(),
            prompt: ASK_PROMPT.to_owned(),
            options: Vec::new(),
            deadline: None,
        }],
    )?;
    let signal = run_tree.signal(RunSignalInput {
        branch: claimed.id,
        run_id: run_id.to_owned(),
        key: "branch-steer".to_owned(),
        actor: owner.to_hex(),
        kind: RunSignalKind::Steer {
            instruction: SIGNAL_INSTRUCTION.to_owned(),
        },
    })?;
    queue.retry(RetryAttempt {
        id: claimed.id,
        lease_owner: "run-tree-reader".to_owned(),
        attempt_count: claimed.attempt_count,
        backoff_until: claimed_at + 3_600_000,
        last_error: Some(AGENT_ERROR.to_owned()),
        now: claimed_at,
    })?;
    let request = RunBranchesRequest { task_ref };
    let branch = hex(attempt_ref.as_bytes());

    // The vault is shared; one member is its Steward.
    vault.initialize_shared_vault(&proof, SHARED, None, &[], 1)?;
    let steward = person(&vault, EntityId::now())?;
    let member = person(&vault, EntityId::now())?;
    let other_agent = person(&vault, EntityId::now())?;
    stand_member_grant(&vault, steward, SHARED, FederationGrantRole::Steward)?;
    stand_member_grant(&vault, member, SHARED, FederationGrantRole::Member)?;

    // The run's own actor reads its branch, its words included.
    let own = oneiron::verbs::vault_runs_branches_get(
        &vault.memory(agent, EdgeActorClass::Agent),
        request.clone(),
    )?;
    assert_eq!(own.branches.len(), 2);
    let own_try = branch_of(&own, &branch)?;
    assert_eq!(own_try.last_error.as_deref(), Some(AGENT_ERROR));
    assert_eq!(own_try.asks, vec![ask.clone()]);
    assert_eq!(own_try.asks[0].questions[0].prompt, ASK_PROMPT);
    assert_eq!(own_try.signals, vec![signal.clone()]);
    assert_eq!(
        own_try.signals[0].kind,
        RunSignalKind::Steer {
            instruction: SIGNAL_INSTRUCTION.to_owned(),
        }
    );

    // A Steward, no actor of the run, reads the branch by its role, without
    // its text.
    let as_steward = vault.memory(steward, EdgeActorClass::Human);
    let stewarded = oneiron::verbs::vault_runs_branches_get(&as_steward, request.clone())?;
    assert_eq!(stewarded.branches.len(), 2);
    let stewarded_try = branch_of(&stewarded, &branch)?;
    assert_eq!(stewarded_try.state, own_try.state);
    assert_eq!(stewarded_try.attempt_count, own_try.attempt_count);
    assert_eq!(stewarded_try.last_error, None);
    assert!(stewarded_try.asks.is_empty());
    assert!(stewarded_try.signals.is_empty());

    // A member without the role, and another agent, stay refused.
    let refused = oneiron::verbs::vault_runs_branches_get(
        &vault.memory(member, EdgeActorClass::Human),
        request.clone(),
    )
    .expect_err("a member without the role stays refused");
    assert_eq!(refused.code, oneiron::MEMORY_CODE_FORBIDDEN);
    let refused = oneiron::verbs::vault_runs_branches_get(
        &vault.memory(other_agent, EdgeActorClass::Agent),
        request.clone(),
    )
    .expect_err("another agent stays refused");
    assert_eq!(refused.code, oneiron::MEMORY_CODE_FORBIDDEN);

    // The owner reads every branch with its text, as before.
    let as_owner = oneiron::verbs::vault_runs_branches_get(
        &vault.memory(owner, EdgeActorClass::Human),
        request,
    )?;
    assert_eq!(as_owner.branches.len(), 2);
    assert_eq!(
        branch_of(&as_owner, &branch)?.last_error.as_deref(),
        Some(AGENT_ERROR)
    );
    let owner_try = branch_of(&as_owner, &branch)?;
    assert_eq!(owner_try.asks, vec![ask]);
    assert_eq!(owner_try.asks[0].questions[0].prompt, ASK_PROMPT);
    assert_eq!(owner_try.signals, vec![signal]);
    assert_eq!(
        owner_try.signals[0].kind,
        RunSignalKind::Steer {
            instruction: SIGNAL_INSTRUCTION.to_owned(),
        }
    );

    // The owner stops the TASK with words of its own, which the cancelled
    // branch keeps on its cancellation and its cancel receipt (review 6976
    // P1). The run's own actor reads them. A Steward reads that the branch
    // was cancelled, by whom and when, without the words.
    let stopped = oneiron::verbs::vault_tasks_cancel_force(
        &vault.memory(owner, EdgeActorClass::Human),
        CancelForceRequest {
            task_ref,
            reason: Some(OWNER_REASON.to_owned()),
        },
    )?;
    assert!(stopped.effected);
    let request = RunBranchesRequest { task_ref };
    let own = oneiron::verbs::vault_runs_branches_get(
        &vault.memory(agent, EdgeActorClass::Agent),
        request.clone(),
    )?;
    let own_stop = cancelled_branch(&own)?;
    let own_cancellation = own_stop
        .cancel_state
        .cancellation
        .clone()
        .ok_or("the run's own actor reads the cancellation")?;
    assert_eq!(own_cancellation.reason.as_deref(), Some(OWNER_REASON));
    let stewarded = oneiron::verbs::vault_runs_branches_get(&as_steward, request)?;
    let seen = cancelled_branch(&stewarded)?;
    assert_eq!(seen.branch, own_stop.branch);
    assert_eq!(seen.state, own_stop.state);
    // The cancellation as the run's own actor reads it, less its reason.
    let mut without_reason = own_cancellation;
    without_reason.reason = None;
    assert_eq!(
        seen.cancel_state.cancellation.as_ref(),
        Some(&without_reason)
    );
    assert_eq!(
        seen.cancel_state.receipts.len(),
        own_stop.cancel_state.receipts.len()
    );
    assert!(!seen.cancel_state.receipts.is_empty());
    assert!(
        seen.cancel_state
            .receipts
            .iter()
            .all(|receipt| receipt.reason.is_none() && receipt.status.is_none())
    );
    // Neither the owner's words nor the agent's are anywhere in what the
    // Steward was served; the run's own actor is served both.
    let served = serde_json::to_string(&stewarded)?;
    assert!(!served.contains(OWNER_REASON));
    assert!(!served.contains(AGENT_ERROR));
    let served_own = serde_json::to_string(&own)?;
    assert!(served_own.contains(OWNER_REASON));
    assert!(served_own.contains(AGENT_ERROR));
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

/// A caller bound to a verified credential reads its run's branches and its
/// run's lease only while that credential holds (review 6976 P1): each
/// reader proves the bound credential in the snapshot it serves from, so a
/// revoked one reads nothing.
#[test]
fn a_revoked_credential_reads_no_branch_and_no_lease() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    oneiron::verbs::vault_budgets_lease_open(
        &vault.memory(owner, EdgeActorClass::Human),
        OpenSpendLeaseRequest {
            launch: "launch-revoked".to_owned(),
            cap_units: 1_000,
            unit: "units".to_owned(),
            shown_at_ms: 1,
            funding_grant_ref: None,
        },
    )?;
    let launch = SpendScopeId::launch("launch-revoked")?;

    // A TASK the default agent runs, and a run of the same agent that
    // spends under the launch.
    let (agent, _) = vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)?
        .ok_or("the default agent is seeded")?;
    let creator = person(&vault, EntityId::from_bytes(CREATOR_BYTES)?)?;
    let receipt = vault.memory(creator, EdgeActorClass::Agent).tasks_create(
        &TaskCreateSpec::new(
            rmpv::Value::Nil,
            Some("read the run tree on a credential".to_owned()),
            Some(creator),
            None,
        )
        .with_assignee(TaskAssignee::AgentDef {
            agent_def_ref: agent,
        }),
    )?;
    let task_ref = receipt.task_ref.ok_or("the TASK is minted")?;
    let AgentDispatchOutcome::Dispatched(status) =
        AgentDispatcher::new(&vault).dispatch_default_base(None, None, None, 1)?
    else {
        return Err("expected one fresh spawn".into());
    };
    let run = status.attempt.id;
    reserve_child_scope(&vault, &launch, &run, 100, 1)?;

    // The host roots the vault and mints the agent a credential of its own,
    // which the agent proves with its key.
    let issuer = HostSlipIssuer::from_secret(b"oneiron-test-run-tree-reader")?;
    let root = vault.ensure_host_root_slip(&issuer)?;
    let key = SigningKey::from_bytes(&[0x65; 32]);
    let mut claims = root.claims;
    claims.slip_id = [0x65; 32];
    claims.parent_id = None;
    claims.holder_ref = agent.to_hex();
    claims.binding_key = key.verifying_key().to_bytes();
    claims.actor_class = Some("agent".to_owned());
    let slip = vault.mint_capability_slip(&issuer, claims)?;
    let signature = key.sign(&slip.binding_transcript(CHALLENGE)?).to_bytes();
    let proof = vault.verify_capability_slip(&issuer.public_key(), &slip, CHALLENGE, &signature)?;
    let bound = vault
        .memory(agent, EdgeActorClass::Agent)
        .with_read_proof(&proof);
    let branches = RunBranchesRequest { task_ref };
    let lease = SpendScopeRequest {
        scope: hex(run.as_bytes()),
    };

    // While the credential holds, the run's own actor reads both.
    let read = oneiron::verbs::vault_runs_branches_get(&bound, branches.clone())?;
    assert_eq!(read.branches.len(), 1);
    let own = oneiron::verbs::vault_budgets_lease(&bound, lease.clone())?;
    assert_eq!(own.lease.scope, SpendScopeId::for_attempt(&run));

    // Revoked, it reads neither: the same handle, the same requests.
    vault.revoke_capability_slip(&issuer, slip.claims.slip_id)?;
    let refused = oneiron::verbs::vault_runs_branches_get(&bound, branches)
        .expect_err("a revoked credential reads no branch");
    assert_eq!(refused.code, "FORBIDDEN");
    assert!(refused.message.contains("no longer holds"), "{refused:?}");
    let refused = oneiron::verbs::vault_budgets_lease(&bound, lease)
        .expect_err("a revoked credential reads no lease");
    assert_eq!(refused.code, "FORBIDDEN");
    assert!(refused.message.contains("no longer holds"), "{refused:?}");
    Ok(())
}
