//! `self.workflows.dispatch_bound` scoped reads through the code-mode door.
//! Proves `refs_readable` in `task_verb/run_rows/workflow_dispatch.rs`.
//! A leased agent run binds an idle TASK when the admitted key reads the
//! TASK, saved workflow and every step's agent definition.
//! A TASK born in a world outside that key's Grant withholds the binding
//! at preflight, leaving its bytes and the attempt count unchanged.
//!
//! Part 2b of FIX [RUN-ROW-DOOR-TESTS-ABSENT]
#![cfg(all(oneiron_test_support, feature = "test-support"))]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::attempt_queue::{AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole, PairingPrincipal, VerifiedSlip};
use oneiron::claim::{ScopedReadActorKey, base_world_id};
use oneiron::code_run::workflow_operations::{
    WorkflowBoundDispatchRequest, WorkflowRunView, WorkflowSaveRequest, save_workflow_as,
};
use oneiron::code_run::{
    AGENT_VERB_DOOR_UNBOUND, AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, HostSelfDispatcher,
    RunCall, SelfAgentVerbCall, SelfCall, SelfDispatchOutcome, SelfDispatcher, SelfEffect,
    SelfFailedResult,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::federation::record_scope::BirthPosition;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::Memory;
use oneiron::task_verb::{TaskAssignee, TaskCreateSpec, TaskRouteOutcome};
use oneiron::test_doors::authority_view_grant::bind_agent;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_support::provision_engine_machines;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};
use rmpv::Value;
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// When the fixture's claims were written and learned.
const OCCURRED_AT: u64 = 1_769_947_200;
const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:run-row-door-scoped-reads-workflow-dispatch";

/// Maps any error into the test's error with the step that failed.
fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
    move |error| format!("{step}: {error:?}").into()
}

/// The host's door for a run's own calls: every call is admitted on this
/// key's lane, as a host admits its caller on the caller's credential.
struct KeyedDoor(ScopedReadActorKey);

impl AgentVerbDoor for KeyedDoor {
    fn call(
        &self,
        _: &SelfAgentVerbCall,
        _: &oneiron::memory::HostWriteOrigin,
        _: oneiron::runtime_hooks::InvocationId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        Ok(Err(AgentVerbRefusal {
            code: AGENT_VERB_DOOR_UNBOUND.to_owned(),
            hook_notice: None,
        }))
    }

    fn admit_run_call(&self, _: RunCall) -> Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        Ok(Some(self.0.clone()))
    }
}

/// The dispatcher of `actor`'s run on its claimed try `leased`, each call
/// admitted on `key`.
fn leased_dispatcher<'v>(
    vault: &'v Vault,
    actor: WriteActor,
    leased: &AttemptRecord,
    key: ScopedReadActorKey,
) -> TestResult<HostSelfDispatcher<'v>> {
    Ok(
        HostSelfDispatcher::for_leased_agent_attempt(vault, actor, leased)
            .map_err(at("the leased run's dispatcher"))?
            .with_agent_verb_door(Arc::new(KeyedDoor(key))),
    )
}

fn paired_agent_slip(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    owner: &AuthenticatedOwner,
    agent: EntityId,
    binding_seed: u8,
) -> VerifiedSlip {
    // Only the verbs axis narrows the pairing Scope: the Grant, not the
    // pairing request, imposes the agent's world ceiling.
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "core:read".to_owned(),
        "core:write".to_owned(),
    ]));
    let holder = agent.to_hex();
    let link = vault
        .issue_owner_pairing_link(
            issuer,
            owner,
            scope,
            3_600,
            PairingPrincipal {
                holder_ref: Some(holder.clone()),
                actor_class: Some("agent".to_owned()),
                ..PairingPrincipal::default()
            },
        )
        .expect("owner issues the agent's pairing link");
    let signing_key = SigningKey::from_bytes(&[binding_seed; 32]);
    let binding_key = signing_key.verifying_key().to_bytes();
    let transcript = oneiron::authority::pairing_binding_transcript_pinned(
        &link.code,
        &binding_key,
        &holder,
        link.pin.as_ref(),
    )
    .expect("agent pairing transcript");
    let slip = vault
        .redeem_pairing_link(
            issuer,
            &link.code,
            &holder,
            binding_key,
            &signing_key.sign(&transcript).to_bytes(),
        )
        .expect("agent redeems its pairing link");
    let signature = signing_key
        .sign(
            &slip
                .binding_transcript(REQUEST_CHALLENGE)
                .expect("agent request transcript"),
        )
        .to_bytes();
    vault
        .verify_capability_slip(&issuer.public_key(), &slip, REQUEST_CHALLENGE, &signature)
        .expect("paired agent proves possession of its credential")
}

/// An enabled, active agent definition the owner creates as `agent_id`.
fn create_enabled_agent(
    vault: &Vault,
    owner_proof: &AuthenticatedOwner,
    agent_id: &str,
) -> EntityId {
    let agent = EntityId::now();
    create_agent_definition_as(
        vault,
        owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": agent_id,
                "desc": "Run row door reader",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("owner creates an enabled, active agent definition");
    agent
}

/// The owner's TASK for `agent`, and its claimed agent try.
fn leased_try(
    vault: &Vault,
    owner_memory: &Memory<'_>,
    owner: EntityId,
    agent: EntityId,
    label: &str,
) -> TestResult<(EntityId, WriteActor, AttemptRecord)> {
    let created = owner_memory.tasks_create(
        &TaskCreateSpec::new(rmpv::Value::Nil, Some(label.to_owned()), Some(owner), None)
            .with_assignee(TaskAssignee::AgentDef {
                agent_def_ref: agent,
            }),
    )?;
    let task = created
        .task_ref
        .ok_or("the owner's TASK lands, not a proposal")?;
    let Some(TaskRouteOutcome::AgentDispatch { attempt_ref, .. }) = created.route else {
        return Err("an agent-definition assignee routes to an agent dispatch".into());
    };
    // The dispatch rides the runner's queue kind; other rows the fresh vault
    // queued are claimed past.
    let queue = AttemptQueue::new(vault);
    for _ in 0..64 {
        let ClaimOutcome::Claimed(row) = queue.claim_kind(
            DREAMER_RUNNER_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: format!("run-row-door-{}", agent.to_hex()),
                now: u64::MAX,
            },
        )?
        else {
            break;
        };
        if row.id == attempt_ref {
            let leased = queue.get(row.id)?.ok_or("a claimed try reads back")?;
            assert_eq!(leased.task_ref.as_deref(), Some(task.to_hex().as_str()));
            return Ok((task, WriteActor::new(agent, EdgeActorClass::Agent), leased));
        }
    }
    Err("the TASK's agent try is ready to claim".into())
}

/// An owner-rooted vault whose paired agent holds one Grant, to read and
/// write in the base world alone; `other_world` is a second world that Grant
/// does not name.
struct TaskRun {
    vault: Vault,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    /// The host slip issuer the agent is bound under.
    issuer: HostSlipIssuer,
    agent: EntityId,
    /// The read lane of the agent's own credential.
    agent_key: ScopedReadActorKey,
    other_world: EntityId,
    _dir: tempfile::TempDir,
}

fn task_run() -> TestResult<TaskRun> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device()).map_err(at("open"))?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = provision_engine_machines(&vault);
    // The owner's agent Grant act is carried by this install's live machine
    // profile, as a serving start or `init` enrols it (FIX 4648).
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .map_err(at("this install's live machine profile"))?;
    let (owner, owner_proof) =
        embedded_owner(&vault).map_err(at("authenticated embedded owner"))?;
    let other_world = vault
        .create_world(&owner_proof, "Grant-excluded world", OCCURRED_AT)
        .map_err(at("owner creates the second world"))?;

    let agent = create_enabled_agent(&vault, &owner_proof, "run_row_door_task_reader");
    let mut authority_scope = Scope::top();
    authority_scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())]));
    // The agent acts in these tests (a refusal writes her diary note), so
    // the Grant carries both verbs; only its world axis decides the reads.
    authority_scope.verbs =
        ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    let minted = mint_agent_grant_as(
        &vault,
        &owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .map_err(at("owner mints the agent a base-world Grant"))?;
    assert!(minted.grant.confers, "the agent's base-world Grant is live");
    let slip = paired_agent_slip(&vault, &issuer, &owner_proof, agent, 0x47);
    let agent_key = vault
        .credential_read_key(&slip)
        .map_err(at("agent credential read key"))?
        .ok_or("the agent's credential grants no read")?;
    Ok(TaskRun {
        vault,
        owner,
        owner_proof,
        issuer,
        agent,
        agent_key,
        other_world,
        _dir: dir,
    })
}

impl TaskRun {
    /// A new TASK of the owner's for the agent, on the agent's claimed try.
    fn leased(&self, label: &str) -> TestResult<(EntityId, WriteActor, AttemptRecord)> {
        let owner_memory = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .with_owner_authorship(&self.owner_proof);
        leased_try(&self.vault, &owner_memory, self.owner, self.agent, label)
    }
}

/// The preflight's refusal (code_run/dispatcher/workflow_dispatch.rs:34-36).
const PREFLIGHT_UNREADABLE: &str = "self.workflows.dispatch_bound reads its TASK, its workflow \
                          and each step's definition on its run's read lane, and one is not \
                          readable there; bind only a TASK and a workflow your Grant reads";
/// The binder's shorter text (workflow_try/binder.rs:34-37): the same words up to the semicolon.
const BINDER_UNREADABLE: &str = "self.workflows.dispatch_bound reads its TASK, its workflow \
                          and each step's definition on its run's read lane, and one is not \
                          readable there";

/// A saved workflow, two idle TASKs the agent owns (one in the Grant's world, one outside it),
/// and the agent's leased run.
struct WorkflowRun {
    run: TaskRun,
    actor: WriteActor,
    leased: AttemptRecord,
    leased_task: EntityId,
    workflow: EntityId,
    step: EntityId,
    task_in_grant: EntityId,
    task_outside_grant: EntityId,
}

impl WorkflowRun {
    fn dispatcher(&self) -> TestResult<HostSelfDispatcher<'_>> {
        leased_dispatcher(
            &self.run.vault,
            self.actor,
            &self.leased,
            self.run.agent_key.clone(),
        )
    }

    fn bind(&self, task_ref: EntityId, intent_key: &str) -> SelfCall {
        SelfCall::WorkflowDispatch(Box::new(WorkflowBoundDispatchRequest {
            workflow_ref: self.workflow,
            intent_key: intent_key.to_owned(),
            briefing: "bind the run".to_owned(),
            context_spec: None,
            task_ref,
        }))
    }

    fn refusal(&self, error: &str) -> SelfDispatchOutcome {
        SelfDispatchOutcome::Failed(SelfFailedResult {
            effect: SelfEffect::WorkflowDispatch,
            error: error.to_owned(),
            code: None,
            disk_floor: None,
        })
    }
}

fn workflow_run() -> TestResult<WorkflowRun> {
    let run = task_run()?;
    // Owner steps first: `bind_agent` rebinds the host key away from the owner.
    let step = create_enabled_agent(&run.vault, &run.owner_proof, "run_row_door_workflow_step");
    let workflow = EntityId::now();
    save_workflow_as(
        &run.vault,
        &run.owner_proof,
        WorkflowSaveRequest {
            workflow_ref: workflow,
            name: "run row door workflow".to_owned(),
            steps: vec![step],
        },
    )
    .map_err(at("the owner saves the workflow"))?;
    // An idle standard TASK on the runner lane with no try: a watch TASK queues no work.
    let idle_task = |position: BirthPosition, label: &str| -> TestResult<EntityId> {
        let due_at = run.vault.now_recorded_at() + 3_600;
        let created = run
            .vault
            .memory(run.owner, EdgeActorClass::Human)
            .with_owner_authorship(&run.owner_proof)
            .with_birth_position(position)
            .tasks_create(
                &TaskCreateSpec::new(Value::Nil, Some(label.to_owned()), Some(run.agent), None)
                    .with_watch(true)
                    .with_due_at(due_at),
            )
            .map_err(at("the owner's idle TASK"))?;
        Ok(created
            .task_ref
            .ok_or("the owner's TASK lands, not a proposal")?)
    };
    let task_in_grant = idle_task(BirthPosition::default(), "idle-task-in-grant")?;
    let task_outside_grant = idle_task(
        BirthPosition {
            world: Some(run.other_world),
            facet: None,
        },
        "idle-task-outside-grant",
    )?;
    let (leased_task, actor, leased) = run.leased("workflow-binding-run")?;
    bind_agent(&run.vault, &run.issuer, run.agent)
        .map_err(at("bind the agent under the host key"))?;
    Ok(WorkflowRun {
        run,
        actor,
        leased,
        leased_task,
        workflow,
        step,
        task_in_grant,
        task_outside_grant,
    })
}

#[test]
fn a_workflow_run_binds_a_task_when_its_door_key_reads_the_task_the_workflow_and_its_steps()
-> TestResult {
    let flow = workflow_run()?;

    let outcome = flow
        .dispatcher()?
        .dispatch(flow.bind(flow.task_in_grant, "bind-readable-task"))
        .map_err(at("the keyed workflow binding"))?;

    let answer = match outcome {
        SelfDispatchOutcome::AgentVerb(answer) => answer,
        other => return Err(format!("the binding answered {other:?}").into()),
    };
    let view: WorkflowRunView = serde_json::from_value(answer.output.clone())?;
    assert_eq!(view.workflow_ref, flow.workflow);
    assert_eq!(view.task_ref, Some(flow.task_in_grant));
    assert_eq!(
        view.steps
            .iter()
            .map(|step| step.requested_agent_ref)
            .collect::<Vec<_>>(),
        vec![flow.step]
    );
    let rows = answer.rows.ok_or("the answer names the rows it served")?;
    assert!(
        rows.contains(&flow.task_in_grant) && rows.contains(&flow.workflow),
        "the answer serves the TASK and the workflow; seen {rows:?}"
    );
    Ok(())
}

#[test]
fn a_workflow_run_binding_a_task_outside_the_readers_grant_binds_nothing() -> TestResult {
    let flow = workflow_run()?;
    let vault = &flow.run.vault;
    let dispatcher = flow.dispatcher()?;
    let queue = AttemptQueue::new(vault);

    // The control: the same key reads this TASK, the workflow and the step, so the preflight
    // passes; the binder then refuses a TASK that is not idle and not the agent's own.
    let control = dispatcher
        .dispatch(flow.bind(flow.leased_task, "bind-control"))
        .map_err(at("the control binding"))?;
    assert!(
        matches!(&control, SelfDispatchOutcome::Failed(failed)
            if failed.effect == SelfEffect::WorkflowDispatch
                && !failed.error.starts_with(BINDER_UNREADABLE)),
        "the control passes the read and fails for another reason; seen {control:?}"
    );

    let attempts_before = queue.list().map_err(at("list the attempts"))?.len();
    let task_before = vault
        .get(&flow.task_outside_grant)
        .map_err(at("read the TASK"))?;
    // Exactly one ref differs: the TASK was born in a world the Grant does not name.
    let withheld = dispatcher
        .dispatch(flow.bind(flow.task_outside_grant, "bind-withheld-task"))
        .map_err(at("the withheld binding"))?;

    assert_eq!(withheld, flow.refusal(PREFLIGHT_UNREADABLE));
    assert_eq!(
        queue.list().map_err(at("list the attempts again"))?.len(),
        attempts_before,
        "a refused binding starts no attempt"
    );
    assert_eq!(
        vault
            .get(&flow.task_outside_grant)
            .map_err(at("read the TASK again"))?,
        task_before,
        "a refused binding leaves the TASK as it was"
    );
    Ok(())
}
