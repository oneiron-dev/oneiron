//! The task-bound run rows' scoped reads, through the code-mode door: a
//! `HostSelfDispatcher` bound to an agent's leased try, whose host door admits
//! each call on one read key.
//!
//! Part 2 of FIX [RUN-ROW-DOOR-TESTS-ABSENT] (part 1 is
//! `run_row_door_scoped_reads_memory.rs`): the reads moved to
//! `task_verb/run_rows` as code moves, with no behaviour test.
//!
//! - `tasks.refuse`: a declining refusal releases its reason's body to the
//!   run only on a key that reads the reason. The refusal itself lands either
//!   way: its landing checks that the reason exists, under no reader (FIX
//!   [TASKS-REFUSE-REASON-REF-NOT-READ-CHECKED]). A refusal that only objects
//!   releases nothing.
//!
//! The fixture joins two of main's: the owner's TASK for a paired agent on a
//! claimed try (`repo_run/fixture.rs`), in an owner-rooted vault whose agent
//! holds a Grant that names one world of two (`agent_grant_read_ceiling.rs`).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test run_row_door_scoped_reads_tasks`
#![cfg(all(oneiron_test_support, feature = "test-support"))]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::agent_def::{RefusalDomain, RefusalLevel};
use oneiron::attempt_queue::{AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole, PairingPrincipal, VerifiedSlip};
use oneiron::claim::{ScopedReadActorKey, base_world_id, default_project_id};
use oneiron::code_run::{
    AGENT_VERB_DOOR_UNBOUND, AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, HostSelfDispatcher,
    RunCall, SelfAgentVerbCall, SelfCall, SelfDispatchOutcome, SelfDispatcher,
    SelfTaskRefusalResult, SelfTaskRefuseCall,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::{AllRelationships, ClaimRelationships, ClaimScope, Memory, ScopedClaimInput};
use oneiron::task_verb::{ConsultPayloadRef, TaskAssignee, TaskCreateSpec, TaskRouteOutcome};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::task_refusal_output::take_released_reason;
use oneiron::test_support::provision_engine_machines;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// When the fixture's claims were written and learned.
const OCCURRED_AT: u64 = 1_769_947_200;
const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:run-row-door-scoped-reads-tasks";

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
    /// The owner's own read lane: it reads both worlds.
    owner_key: ScopedReadActorKey,
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
    let owner_key = vault
        .memory(owner, EdgeActorClass::Human)
        .read_key()
        .map_err(at("owner read key"))?;
    Ok(TaskRun {
        vault,
        owner,
        owner_proof,
        owner_key,
        agent,
        agent_key,
        other_world,
        _dir: dir,
    })
}

impl TaskRun {
    /// The owner's claim in `world`, stating `value`.
    fn owner_claim(&self, world: EntityId, value: &str) -> EntityId {
        let id = EntityId::now();
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .with_owner_authorship(&self.owner_proof)
            .claim_upsert_scoped(&ScopedClaimInput {
                id: Some(id.to_hex()),
                predicate: "profile.preference".to_owned(),
                subject_ref: self.owner.to_hex(),
                value: json!(value),
                confidence: 1.0,
                source: "user_stated".to_owned(),
                scope: ClaimScope {
                    world_id: world.to_hex(),
                    scope_facet_id: self
                        .vault
                        .default_facet()
                        .expect("owner default facet")
                        .to_hex(),
                    scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
                    scope_project_id: default_project_id().to_hex(),
                },
                sensitivity: None,
                evidence_turn_refs: Vec::new(),
                valid_from: None,
                valid_to: None,
                occurred_at: Some(OCCURRED_AT),
                learned_at: Some(OCCURRED_AT),
                salience: None,
            })
            .expect("owner writes a claim in the requested world");
        id
    }

    /// A new TASK of the owner's for the agent, on the agent's claimed try.
    fn leased(&self, label: &str) -> TestResult<(EntityId, WriteActor, AttemptRecord)> {
        let owner_memory = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .with_owner_authorship(&self.owner_proof);
        leased_try(&self.vault, &owner_memory, self.owner, self.agent, label)
    }

    /// A key that reads no row, for the agent as its holder.
    fn key_that_reads_nothing(&self) -> TestResult<ScopedReadActorKey> {
        Ok(
            ScopedReadActorKey::read_nothing(self.agent.to_hex(), "agent")
                .ok_or("a key that reads nothing")?,
        )
    }
}

// ---------------------------------------------------------------------------
// tasks.refuse: the released reason body.
// ---------------------------------------------------------------------------

/// What one `tasks.refuse` became: the TASK it refused, the run's reply, and
/// the reason body the call released to its host.
struct Refused {
    task: EntityId,
    reply: SelfDispatchOutcome,
    released: Option<Vec<u8>>,
}

impl TaskRun {
    /// The agent's run of a new TASK refuses it in `domain`, naming the claim
    /// `reason`, through a door that admits the call on `key`.
    fn refuse_naming(
        &self,
        domain: RefusalDomain,
        reason: EntityId,
        key: ScopedReadActorKey,
    ) -> TestResult<Refused> {
        let (task, actor, leased) = self.leased("a task its agent refuses")?;
        let dispatcher = leased_dispatcher(&self.vault, actor, &leased, key)?;
        let reply = dispatcher
            .dispatch(SelfCall::TasksRefuse(SelfTaskRefuseCall {
                task_ref: Some(task),
                domain,
                reason_ref: ConsultPayloadRef::Claim(reason).short_ref(),
                at: self.vault.now_recorded_at(),
            }))
            .map_err(at("the run's tasks.refuse"))?;
        let released = take_released_reason(&dispatcher);
        Ok(Refused {
            task,
            reply,
            released,
        })
    }
}

/// The reply of a refusal that landed at `level`, first time.
fn refused_at(task: EntityId, level: RefusalLevel) -> SelfDispatchOutcome {
    SelfDispatchOutcome::TaskRefusal(SelfTaskRefusalResult {
        task_ref: task,
        level,
        replay: false,
    })
}

#[test]
fn a_declining_refusal_releases_its_reason_to_a_door_key_that_reads_it() -> TestResult {
    let run = task_run()?;
    let reason = run.owner_claim(base_world_id(), "a reason in the base world");

    // A personal vault's bond default is a veto: the refusal declines.
    let refused = run.refuse_naming(RefusalDomain::Bond, reason, run.agent_key.clone())?;

    assert_eq!(
        refused.reply,
        refused_at(refused.task, RefusalLevel::Veto),
        "the agent's veto declines her TASK"
    );
    let released = refused
        .released
        .ok_or("the key reads the reason, so its body is released to the run")?;
    let row: serde_json::Value = serde_json::from_slice(&released)?;
    assert_eq!(
        row["id"],
        json!(ConsultPayloadRef::Claim(reason).short_ref()),
        "the released row is the reason the refusal named: {row}"
    );
    assert_eq!(
        row["val"],
        json!("a reason in the base world"),
        "the released row carries the reason's own value: {row}"
    );
    Ok(())
}

#[test]
fn a_declining_refusal_releases_a_second_world_reason_to_a_door_key_that_reads_it() -> TestResult {
    let run = task_run()?;
    let reason = run.owner_claim(run.other_world, "a reason in the grant-excluded world");

    // The owner's key reads the second world, which the agent's Grant leaves
    // out: the reason is one a refusal releases.
    let refused = run.refuse_naming(RefusalDomain::Bond, reason, run.owner_key.clone())?;

    assert_eq!(
        refused.reply,
        refused_at(refused.task, RefusalLevel::Veto),
        "the agent's veto declines her TASK"
    );
    let released = refused
        .released
        .ok_or("the key reads the reason's world, so its body is released to the run")?;
    let row: serde_json::Value = serde_json::from_slice(&released)?;
    assert_eq!(
        row["id"],
        json!(ConsultPayloadRef::Claim(reason).short_ref()),
        "the released row is the reason the refusal named: {row}"
    );
    assert_eq!(
        row["val"],
        json!("a reason in the grant-excluded world"),
        "the released row carries the reason's own value: {row}"
    );
    Ok(())
}

#[test]
fn a_declining_refusal_releases_no_reason_its_door_keys_grant_leaves_out() -> TestResult {
    let run = task_run()?;
    let reason = run.owner_claim(run.other_world, "a reason in the grant-excluded world");

    let refused = run.refuse_naming(RefusalDomain::Bond, reason, run.agent_key.clone())?;

    // The landing checks that the reason exists, under no reader, so the
    // refusal lands as it does for a reason the key reads
    // (`a_declining_refusal_releases_a_second_world_reason_to_a_door_key_that_reads_it`
    // is this test on the owner's key).
    assert_eq!(
        refused.reply,
        refused_at(refused.task, RefusalLevel::Veto),
        "the agent's veto declines her TASK"
    );
    assert_eq!(
        refused.released, None,
        "a reason outside the key's Grant is released to no run"
    );
    Ok(())
}

#[test]
fn a_declining_refusal_releases_no_reason_to_a_door_key_that_reads_nothing() -> TestResult {
    let run = task_run()?;
    let reason = run.owner_claim(base_world_id(), "a reason in the base world");

    let refused = run.refuse_naming(RefusalDomain::Bond, reason, run.key_that_reads_nothing()?)?;

    assert_eq!(
        refused.reply,
        refused_at(refused.task, RefusalLevel::Veto),
        "the agent's veto declines her TASK"
    );
    assert_eq!(
        refused.released, None,
        "a key that reads no row is released no reason"
    );
    Ok(())
}

#[test]
fn a_refusal_that_only_objects_releases_no_reason() -> TestResult {
    let run = task_run()?;
    let reason = run.owner_claim(base_world_id(), "a reason in the base world");

    // A personal vault's logistics default is voice: one objection, and the
    // TASK goes on.
    let refused = run.refuse_naming(RefusalDomain::Logistics, reason, run.agent_key.clone())?;

    assert_eq!(
        refused.reply,
        refused_at(refused.task, RefusalLevel::Voice),
        "the agent's voice objects and declines nothing"
    );
    assert_eq!(
        refused.released, None,
        "only a decline releases its reason, even to a key that reads it"
    );
    Ok(())
}
