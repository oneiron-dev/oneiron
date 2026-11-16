//! `tasks.consult.result` scoped reads through the code-mode door.
//! Proves `refs_readable` in `task_verb/run_rows/consult_result.rs`.
//! A leased agent run lands its answer when the admitted key reads the
//! consult TASK, result and every evidence claim it names.
//! Evidence in a world outside that key's Grant withholds the landing and
//! leaves the consult TASK unchanged; a readable control reaches validation.
//!
//! Part 2b of FIX [RUN-ROW-DOOR-TESTS-ABSENT]
#![cfg(all(oneiron_test_support, feature = "test-support"))]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::attempt_queue::{AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole, PairingPrincipal, VerifiedSlip};
use oneiron::claim::{ScopedReadActorKey, base_world_id, default_project_id};
use oneiron::code_run::{
    AGENT_VERB_DOOR_UNBOUND, AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, HostSelfDispatcher,
    JS_SAFE_INTEGER, RunCall, SelfAgentVerbCall, SelfCall, SelfDispatchOutcome, SelfDispatcher,
    SelfEffect, SelfFailedResult,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::{
    AllRelationships, ClaimRelationships, ClaimScope, MEMORY_CODE_BAD_REQUEST,
    MEMORY_CODE_FORBIDDEN, Memory, ScopedClaimInput,
};
use oneiron::task_verb::run_doors::{
    ConsultDisposition, ConsultLandKind, ConsultLandReply, ConsultLandRequest, ConsultSummaryView,
    ConsultTerminalView,
};
use oneiron::task_verb::{
    ConsultPayload, ConsultPayloadRef, TaskAssignee, TaskCreateSpec, TaskKind, TaskRouteOutcome,
    TaskTtl,
};
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
const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:run-row-door-scoped-reads-consult-result";

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
}

const CONSULT_WINDOW_SECONDS: u64 = 3_600;

/// A run row whose engine landing refuses with `code`: the code alone.
fn failed_with_code(effect: SelfEffect, code: &str) -> SelfDispatchOutcome {
    SelfDispatchOutcome::Failed(SelfFailedResult {
        effect,
        error: code.to_owned(),
        code: None,
        disk_floor: None,
    })
}

/// A consult TASK addressed to the agent, the agent's leased run, and the records an answer names.
struct ConsultRun {
    run: TaskRun,
    actor: WriteActor,
    leased: AttemptRecord,
    consult: EntityId,
    result: EntityId,
    evidence_in_grant: EntityId,
    evidence_outside_grant: EntityId,
}

impl ConsultRun {
    fn dispatcher(&self) -> TestResult<HostSelfDispatcher<'_>> {
        leased_dispatcher(
            &self.run.vault,
            self.actor,
            &self.leased,
            self.run.agent_key.clone(),
        )
    }

    fn answer_citing(&self, evidence: EntityId, completed_at: u64) -> SelfCall {
        SelfCall::ConsultResult(ConsultLandRequest {
            task_ref: self.consult,
            kind: ConsultLandKind::Answer {
                result_ref: self.result,
                option: None,
                evidence_refs: vec![ConsultPayloadRef::Claim(evidence)],
            },
            completed_at,
            measured_spend: None,
        })
    }
}

fn consult_run() -> TestResult<ConsultRun> {
    let run = task_run()?;
    // Owner steps first: `bind_agent` rebinds the host key away from the owner.
    let claim = |world, text| run.owner_claim(world, text);
    let question = claim(base_world_id(), "consult question");
    let result = claim(base_world_id(), "consult result");
    let evidence_in_grant = claim(base_world_id(), "evidence in the Grant's world");
    let evidence_outside_grant = claim(run.other_world, "evidence outside the Grant");
    let (_own_task, actor, leased) = run.leased("consult-answering-run")?;
    // Minted after the bind, so the consult records the agent's binding generation.
    bind_agent(&run.vault, &run.issuer, run.agent)
        .map_err(at("bind the agent under the host key"))?;
    let created = run
        .vault
        .memory(run.owner, EdgeActorClass::Human)
        .tasks_create(
            &TaskCreateSpec::new(
                Value::Nil,
                Some("consult".to_owned()),
                Some(run.owner),
                None,
            )
            .with_kind(TaskKind::Consult)
            .with_consult(ConsultPayload::question(
                ConsultPayloadRef::Claim(question),
                Vec::new(),
                EntityId::now(),
            ))
            .with_assignee(TaskAssignee::Peer {
                actor_ref: run.agent,
            })
            .with_ttl(TaskTtl::after(
                run.vault.now_recorded_at(),
                CONSULT_WINDOW_SECONDS,
            )),
        )
        .map_err(at("the owner's consult"))?;
    let consult = created
        .task_ref
        .ok_or("the consult lands, not a proposal")?;
    let stamp = run
        .vault
        .record_scope(&consult)
        .map_err(at("the consult's birth stamp"))?
        .ok_or("the consult carries a birth stamp")?;
    assert_eq!(
        stamp.worlds,
        ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())])),
        "the consult is born in the world the Grant names"
    );
    Ok(ConsultRun {
        run,
        actor,
        leased,
        consult,
        result,
        evidence_in_grant,
        evidence_outside_grant,
    })
}

#[test]
fn a_consult_answer_lands_when_its_door_key_reads_the_task_and_every_ref_it_names() -> TestResult {
    let consult = consult_run()?;
    let vault = &consult.run.vault;
    let before = vault
        .get(&consult.consult)
        .map_err(at("read the consult TASK"))?;
    let completed_at = vault.now_recorded_at();

    let landed = consult
        .dispatcher()?
        .dispatch(consult.answer_citing(consult.evidence_in_grant, completed_at))
        .map_err(at("the keyed consult landing"))?;

    let reply = ConsultLandReply {
        task_ref: consult.consult,
        terminal: ConsultTerminalView {
            disposition: ConsultDisposition::Completed,
            result_ref: Some(consult.result),
            summary: Some(ConsultSummaryView::Answer {
                evidence_refs: vec![ConsultPayloadRef::Claim(consult.evidence_in_grant)],
            }),
            finished_at: completed_at,
            ladder: None,
            counter_task_ref: None,
        },
        idempotent_replay: false,
    };
    assert_eq!(
        landed,
        SelfDispatchOutcome::AgentVerb(AgentVerbAnswer::new(
            serde_json::to_value(&reply)?,
            Some(vec![
                consult.consult,
                consult.result,
                consult.evidence_in_grant
            ]),
        ))
    );
    assert_ne!(
        vault
            .get(&consult.consult)
            .map_err(at("read the consult TASK again"))?,
        before,
        "the landing wrote the consult's terminal record"
    );
    Ok(())
}

#[test]
fn a_consult_answer_citing_evidence_outside_the_readers_grant_lands_nothing() -> TestResult {
    let consult = consult_run()?;
    let vault = &consult.run.vault;
    let dispatcher = consult.dispatcher()?;
    let before = vault
        .get(&consult.consult)
        .map_err(at("read the consult TASK"))?;

    // The control: every ref is readable on this key, so the read passes and the engine
    // refuses the completion time (later than its clock) before it writes anything.
    let control = dispatcher
        .dispatch(consult.answer_citing(consult.evidence_in_grant, JS_SAFE_INTEGER))
        .map_err(at("the control landing"))?;
    assert_eq!(
        control,
        failed_with_code(SelfEffect::ConsultResult, MEMORY_CODE_BAD_REQUEST)
    );

    // Exactly one ref differs: the evidence claim lies in a world the Grant does not name.
    let withheld = dispatcher
        .dispatch(consult.answer_citing(consult.evidence_outside_grant, vault.now_recorded_at()))
        .map_err(at("the withheld landing"))?;

    assert_eq!(
        withheld,
        failed_with_code(SelfEffect::ConsultResult, MEMORY_CODE_FORBIDDEN)
    );
    assert_eq!(
        vault
            .get(&consult.consult)
            .map_err(at("read the consult TASK again"))?,
        before,
        "a refused landing leaves the consult TASK as it was"
    );
    Ok(())
}
