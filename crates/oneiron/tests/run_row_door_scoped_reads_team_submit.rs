//! `self.team.submit` scoped reads through the code-mode door.
//! Proves `claim_revision_scope_in_txn` in
//! `task_verb/run_rows/team_submit/entity.rs` on the run's admitted key.
//! A team's leased leader submits a pinned claim the key reads and files
//! an owner acceptance review in the output's scope.
//! A pinned claim in a world outside that key's Grant withholds the submit
//! as missing and files no review, after a readable control succeeds.
//!
//! Part 2b of FIX [RUN-ROW-DOOR-TESTS-ABSENT]
#![cfg(all(oneiron_test_support, feature = "test-support"))]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole, PairingPrincipal, VerifiedSlip};
use oneiron::claim::{ScopedReadActorKey, base_world_id, default_project_id};
use oneiron::code_run::{
    AGENT_VERB_DOOR_UNBOUND, AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, HostSelfDispatcher,
    RunCall, SelfAgentVerbCall, SelfCall, SelfDispatchOutcome, SelfDispatcher, SelfEffect,
    SelfFailedResult, TeamSubmitInput,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::{AllRelationships, ClaimRelationships, ClaimScope, Memory, ScopedClaimInput};
use oneiron::task_type::type_tree;
use oneiron::task_verb::{TaskAssignee, TaskCreateSpec, TaskRouteOutcome};
use oneiron::team::{
    DecidedBy, TeamAxis, TeamPattern, TeamReceipt, TeamShape, record_team_receipt,
};
use oneiron::test_doors::authority_view_grant::bind_agent;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_support::provision_engine_machines;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{
    ClaimApprovalStatus, ClaimSubject, EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor,
};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// When the fixture's claims were written and learned.
const OCCURRED_AT: u64 = 1_769_947_200;
const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:run-row-door-scoped-reads-team-submit";

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

/// The review predicate (gate/team_review.rs:4; the constant is crate-private).
const TEAM_REVIEW_PREDICATE: &str = "team.deliverable.acceptance";

fn attempt_hex(id: AttemptId) -> String {
    id.as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A team the agent leads, and one pinned claim output in the Grant's world and one outside it.
struct TeamRun {
    run: TaskRun,
    actor: WriteActor,
    leased: AttemptRecord,
    team: String,
    claim_in_grant: EntityId,
    output_in_grant: String,
    output_outside_grant: String,
}

impl TeamRun {
    fn dispatcher(&self) -> TestResult<HostSelfDispatcher<'_>> {
        leased_dispatcher(
            &self.run.vault,
            self.actor,
            &self.leased,
            self.run.agent_key.clone(),
        )
    }

    fn submit(&self, output_revision: &str) -> SelfCall {
        SelfCall::TeamSubmit(TeamSubmitInput {
            team: self.team.clone(),
            output_revision: output_revision.to_owned(),
        })
    }
}

fn team_run() -> TestResult<TeamRun> {
    let run = task_run()?;
    // Owner steps first: `bind_agent` rebinds the host key away from the owner.
    let claim_in_grant = run.owner_claim(base_world_id(), "team output in the Grant's world");
    let claim_outside_grant = run.owner_claim(run.other_world, "team output outside the Grant");
    let pinned = |claim: EntityId| -> TestResult<String> {
        let revision = run
            .vault
            .pin_entity_revision(&claim)
            .map_err(at("pin the claim's revision"))?;
        Ok(format!("claim:{}@{}", claim.to_hex(), revision.to_hex()))
    };
    let output_in_grant = pinned(claim_in_grant)?;
    let output_outside_grant = pinned(claim_outside_grant)?;
    let (_own_task, actor, leased) = run.leased("team-leading-run")?;
    // The leader's own team: its ref carries the leader's attempt id (team_submit.rs:90-93).
    let team = format!("team:{}:run-row-door-team", attempt_hex(leased.id));
    record_team_receipt(
        &run.vault,
        &TeamReceipt {
            team_ref: team.clone(),
            project: None,
            type_ref: type_tree(&run.vault, None)
                .map_err(at("the type tree"))?
                .root(),
            pattern: TeamPattern::Solo,
            pattern_skill: None,
            axis: TeamAxis::Converge,
            models: Vec::new(),
            shape: TeamShape {
                width: 1,
                roles: BTreeMap::from([("solo".to_owned(), 1)]),
            },
            decided_by: DecidedBy::Leader { actor: run.agent },
            coverage: None,
            confessions: None,
            spend: None,
            spend_cap: None,
            elapsed_secs: 0,
            calls: None,
            outcome: None,
            at: run.vault.now_recorded_at(),
        },
    )
    .map_err(at("record the team receipt"))?;
    bind_agent(&run.vault, &run.issuer, run.agent)
        .map_err(at("bind the agent under the host key"))?;
    Ok(TeamRun {
        run,
        actor,
        leased,
        team,
        claim_in_grant,
        output_in_grant,
        output_outside_grant,
    })
}

#[test]
fn a_team_submit_files_an_owner_review_when_its_door_key_reads_the_pinned_output() -> TestResult {
    let team = team_run()?;
    let vault = &team.run.vault;
    let consents_before = vault
        .pending_gate_consents(100)
        .map_err(at("pending consents"))?;

    let outcome = team
        .dispatcher()?
        .dispatch(team.submit(&team.output_in_grant))
        .map_err(at("the keyed team submit"))?;

    let answer = match outcome {
        SelfDispatchOutcome::TeamSubmitted(answer) => answer,
        other => return Err(format!("the team submit answered {other:?}").into()),
    };
    assert_eq!(answer.team, team.team);
    assert_eq!(answer.output_revision, team.output_in_grant);
    assert!(!answer.already_submitted);
    let review_id = EntityId::from_hex(&answer.review_claim).map_err(at("the review claim id"))?;
    let review = vault
        .get_claim(&review_id)
        .map_err(at("read the review claim"))?
        .ok_or("the review claim reads nothing")?;
    assert_eq!(review.predicate, TEAM_REVIEW_PREDICATE);
    assert_eq!(review.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(review.subject, ClaimSubject::Entity(team.claim_in_grant));
    assert!(
        vault
            .pending_gate_consents(100)
            .map_err(at("pending consents again"))?
            .len()
            > consents_before.len(),
        "the Gate parked the review for the owner"
    );
    Ok(())
}

#[test]
fn a_team_submit_naming_an_output_outside_the_readers_grant_files_no_review() -> TestResult {
    let team = team_run()?;
    let vault = &team.run.vault;
    let dispatcher = team.dispatcher()?;

    // The control: on the same key and team, the output the Grant covers is submitted.
    let control = dispatcher
        .dispatch(team.submit(&team.output_in_grant))
        .map_err(at("the control submit"))?;
    assert!(
        matches!(control, SelfDispatchOutcome::TeamSubmitted(_)),
        "the control submit files its review; seen {control:?}"
    );
    let consents = vault
        .pending_gate_consents(100)
        .map_err(at("pending consents"))?;

    // Exactly one input differs: the pinned claim lies in a world the Grant does not name.
    let withheld = dispatcher
        .dispatch(team.submit(&team.output_outside_grant))
        .map_err(at("the withheld submit"))?;

    assert_eq!(
        withheld,
        SelfDispatchOutcome::Failed(SelfFailedResult {
            effect: SelfEffect::Team,
            error: "team_submit_output_missing".to_owned(),
            code: None,
            disk_floor: None,
        })
    );
    assert_eq!(
        vault
            .pending_gate_consents(100)
            .map_err(at("pending consents again"))?,
        consents,
        "a refused submit parks no review"
    );
    Ok(())
}
