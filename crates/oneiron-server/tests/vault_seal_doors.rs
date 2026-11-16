//! Owner-door promise tests for the `vault.seal` family (ARCH-0079 P1/P2/P3).
//!
//! Every case drives the real routes in process (`build_app` + `oneshot`):
//! `POST /v1/core/facade/<verb>` for `vault.seal.run`, `.pending`,
//! `.confess`, `.complete`, `.audit` and `.receipt`, plus
//! `vault.learning.read` where a promise is about measured state. Callers:
//! the vault's embedded owner on the host root credential, and two
//! strangers: a second live person on a minted human credential and another
//! live person on a minted agent-class credential. Each case owns its
//! wall-clock vault; the sealed tries are hosted `tasks.update` DONEs,
//! confessed through the doors.
//!
//! The promises, with their canon (oneiron-arch-0079
//! `generated/oneiron/agents/oneiron-arch-0079-agent-coordination-v1.md`):
//! - a confession names its flaw without moving any score, and its
//!   uncertainty queues a directed recheck (P1+P2+P3);
//! - the confession leaves the measured learning cell untested (P1+P2);
//! - strangers are refused at all six verbs and write nothing (the door);
//! - only completed findings move the score the confession left alone (P2);
//! - completing refuses the executor's own model, and a completion replays
//!   identically (complete admission);
//! - a passing seal draws its audit once (audit-once);
//! - run queues a job, and pending filters by attempt (Q2 shapes);
//! - the receipt is null before the seal and shaped after it (Q5 shape).
//!
//! These promises hold on main. Their red proof is a seeded fault (Test rules
//! v2, rule 5), named in `seed_seal_faults.py`.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --no-fail-fast --test vault_seal_doors`. The test calls no test door; it
//! needs `oneiron/test-support` for `MemoryKeystore`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode},
};
use ed25519_dalek::SigningKey;
use engine_stack::run_on_engine_stack;
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DispatchAgent,
};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptState, ClaimAttempt, ClaimOutcome};
use oneiron::authority::{
    ActSurface, AgentTier, CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof,
};
use oneiron::claim::base_world_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::Memory;
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::task_verb::{AttemptHandle, HostBinding, TaskHandle};
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const SEAL_RUN: &str = "vault.seal.run";
const SEAL_PENDING: &str = "vault.seal.pending";
const SEAL_CONFESS: &str = "vault.seal.confess";
const SEAL_COMPLETE: &str = "vault.seal.complete";
const SEAL_AUDIT: &str = "vault.seal.audit";
const SEAL_RECEIPT: &str = "vault.seal.receipt";
const LEARNING_READ: &str = "vault.learning.read";

/// The model and revision the host ran the executor's run on.
const RUN_MODEL: &str = "fixture/run-model@rev-a";
/// An independent judge: another model than the executor's.
const JUDGE_MODEL: &str = "fixture/judge-model@rev-j";
const RUN_LEASE_OWNER: &str = "seal-doors-host";
const OBJECTIVE: &str = "summarize the week's notes";
const SECOND_OBJECTIVE: &str = "name every source note";

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The key every minted credential here binds; the holder proves it per
/// request.
fn holder_key() -> SigningKey {
    SigningKey::from_bytes(&[0x6D; 32])
}

/// A served wall-clock vault: its embedded owner, the executor agent with a
/// base-reach grant, and two live stranger persons, each caller on their own
/// credential.
struct Served {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_slip: CapabilitySlip,
    owner_token: String,
    executor: EntityId,
    stranger: EntityId,
    agent_person: EntityId,
    stranger_slip: CapabilitySlip,
    stranger_token: String,
    agent_slip: CapabilitySlip,
    agent_token: String,
}

/// Who sends a request.
#[derive(Clone, Copy, Debug)]
enum Caller {
    /// The embedded owner on the host root credential.
    Owner,
    /// A second live person on their own human credential.
    Person,
    /// A live person on a minted agent-class credential.
    Agent,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn attempt_value(attempt: AttemptId) -> Value {
    serde_json::to_value(&attempt).expect("attempt wire")
}

fn attempt_hex(attempt: AttemptId) -> String {
    hex(attempt.as_bytes())
}

fn error_code(body: &Value) -> Option<&str> {
    body["error"]["code"].as_str()
}

fn person(vault: &Vault, id: EntityId) {
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
}

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// The executor agent: an enabled definition with the owner's live grant of
/// base-world reach, so its task calls read the TASK they name.
fn executor_agent(vault: &Vault, owner: &AuthenticatedOwner) -> EntityId {
    let agent = EntityId::now();
    create_agent_definition_as(
        vault,
        owner,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": "seal-doors-executor",
                "desc": "seal doors fixture",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("the owner creates the executor agent");
    let mut authority_scope = Scope::top();
    authority_scope.worlds = [ScopeId(base_world_id())].into_iter().collect();
    authority_scope.verbs = AgentTier::FullAccess
        .grant_verbs()
        .iter()
        .map(|verb| (*verb).to_owned())
        .collect();
    let minted = mint_agent_grant_as(
        vault,
        owner,
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
    .expect("the owner grants the executor base reach");
    assert!(minted.grant.confers, "the executor's grant confers");
    agent
}

/// A served wall-clock vault with its executor and its two strangers.
fn served() -> Served {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("vault-seal-doors".into()),
                ..Default::default()
            },
        )
        .expect("create server"),
    );
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let owner_slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    let owner_token = owner_slip.to_token().expect("owner slip token");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machine identities");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("serving install profile");
    let owner_proof = proof(&vault, owner);
    let executor = executor_agent(&vault, &owner_proof);
    let stranger = EntityId::now();
    let agent_person = EntityId::now();
    for id in [stranger, agent_person] {
        person(&vault, id);
    }
    let app = build_app(server);
    let (stranger_slip, stranger_token) = credential(&vault, &issuer, stranger, Some("human"));
    let (agent_slip, agent_token) = credential(&vault, &issuer, agent_person, Some("agent"));
    Served {
        _dir: dir,
        vault,
        app,
        issuer,
        owner,
        owner_slip,
        owner_token,
        executor,
        stranger,
        agent_person,
        stranger_slip,
        stranger_token,
        agent_slip,
        agent_token,
    }
}

/// A credential this host mints `who` at `class`, holding `read` and
/// `write`: a holder's own slip, not owner-grade. Answers the slip and its
/// token.
fn credential(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    who: EntityId,
    class: Option<&str>,
) -> (CapabilitySlip, String) {
    let mut claims = vault
        .ensure_host_root_slip(issuer)
        .expect("the host root slip")
        .claims;
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = who.to_hex();
    claims.actor_class = class.map(str::to_owned);
    claims.binding_key = holder_key().verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    let slip = vault
        .mint_capability_slip(issuer, claims)
        .expect("a credential");
    let token = slip.to_token().expect("token");
    (slip, token)
}

/// A confession of `attempt` naming `subject` at the root type, over
/// `objectives`.
fn confess_body(attempt: AttemptId, subject: EntityId, objectives: Value) -> Value {
    json!({
        "attempt": attempt_value(attempt),
        "subject": subject.to_hex(),
        "type_ref": {"node_id": "root", "tree_version": 1},
        "objectives": objectives,
    })
}

/// One objective confessing a flaw outright.
fn flaw_objectives() -> Value {
    json!([{
        "objective": OBJECTIVE,
        "met": false,
        "flaw": "omitted a source note",
        "uncertainty": null,
    }])
}

/// One uncertain objective: no flaw claimed, examination asked.
fn uncertain_objectives() -> Value {
    json!([{
        "objective": SECOND_OBJECTIVE,
        "met": true,
        "flaw": null,
        "uncertainty": "the summary may omit a note",
    }])
}

/// One clean objective: met, with nothing to examine.
fn clean_objectives() -> Value {
    json!([{
        "objective": OBJECTIVE,
        "met": true,
        "flaw": null,
        "uncertainty": null,
    }])
}

/// A completion of `attempt`'s directed recheck by `judge` at `checked_at`.
fn complete_body(attempt: AttemptId, judge: &str, checked_at: u64, findings: Value) -> Value {
    json!({
        "attempt": attempt_value(attempt),
        "kind": "confession_recheck",
        "outcome": {
            "judge_revision": judge,
            "checked_at": checked_at,
            "findings": findings,
        },
    })
}

/// A seal view whose assessment and reward are all zero: nothing judged.
fn assert_assessment_zero(view: &Value) {
    assert_eq!(view["assessment"]["weighted_flaws"], json!(0.0), "{view}");
    assert_eq!(
        view["assessment"]["weighted_hidden_flaws"],
        json!(0.0),
        "{view}"
    );
    assert_eq!(view["assessment"]["confirmed_confessions"], 0, "{view}");
    assert_eq!(view["assessment"]["false_confessions"], 0, "{view}");
    assert_eq!(view["honesty_reward"], json!(0.0), "{view}");
}

/// A learning cell with no runs: untested, unattributed, without evidence.
fn assert_cell_empty(cell: &Value) {
    assert_eq!(cell["view"]["estimate"]["untested"], true, "{cell}");
    assert_eq!(
        cell["view"]["attributed_outcome_receipts"],
        json!([]),
        "{cell}"
    );
    assert_eq!(cell["view"]["provenance"]["evidence"], json!([]), "{cell}");
}

impl Served {
    fn slip(&self, caller: Caller) -> Option<&CapabilitySlip> {
        match caller {
            Caller::Owner => None,
            Caller::Person => Some(&self.stranger_slip),
            Caller::Agent => Some(&self.agent_slip),
        }
    }

    /// The request binding `caller` signs afresh for one request: the owner
    /// on the host root, anyone else on their own holder key.
    fn binding(&self, caller: Caller) -> String {
        match self.slip(caller) {
            None => {
                let timestamp = self.vault.now_recorded_at();
                let nonce = EntityId::now().to_hex();
                let challenge = format!("oneiron-request:{timestamp}:{nonce}");
                let signature = hex(&self
                    .issuer
                    .binding_proof(&self.owner_slip, challenge.as_bytes())
                    .expect("owner holder proof"));
                json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
            }
            Some(slip) => holder_proof(slip, &holder_key(), self.vault.now_recorded_at())
                .expect("holder proof")
                .to_string(),
        }
    }

    fn token(&self, caller: Caller) -> &str {
        match caller {
            Caller::Owner => self.owner_token.as_str(),
            Caller::Person => self.stranger_token.as_str(),
            Caller::Agent => self.agent_token.as_str(),
        }
    }

    /// `caller` sends `method` to `uri` with an optional JSON `body`: the
    /// status and the body.
    async fn send(
        &self,
        caller: Caller,
        method: Method,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {}", self.token(caller)))
            .header("x-oneiron-binding", self.binding(caller));
        let request = match body {
            Some(body) => builder
                .header("content-type", "application/json")
                .body(Body::from(body.to_string())),
            None => builder.body(Body::empty()),
        }
        .expect("request");
        let response = self.app.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 16 * 1024 * 1024)
            .await
            .expect("response body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// `caller` posts `verb` with `input` to its facade door.
    async fn post(&self, caller: Caller, verb: &str, input: Value) -> (StatusCode, Value) {
        self.send(
            caller,
            Method::POST,
            &format!("/v1/core/facade/{verb}"),
            Some(input),
        )
        .await
    }

    /// `caller` posts `verb` and expects a 200: the answer.
    async fn ok(&self, caller: Caller, verb: &str, input: Value) -> Value {
        let (status, body) = self.post(caller, verb, input).await;
        assert_eq!(status, StatusCode::OK, "{caller:?} at {verb}: {body}");
        body
    }

    fn owner_memory(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    /// A durable row the DONE names as its result.
    fn result_row(&self, text: &str) -> EntityId {
        let id = EntityId::now();
        let at = self.vault.now_recorded_at();
        let body = rmp_serde::to_vec_named(&json!({"text": text})).expect("a TURN body");
        self.vault
            .put_entity(
                &id,
                ENTITY_TYPE_TURN,
                TimeRange { start: at, end: at },
                at,
                &body,
            )
            .expect("the result row");
        id
    }

    /// The executor's met DONE of an owner TASK, through a host-bound run,
    /// naming a fresh TURN as its result: the completed try and its result.
    /// `tag` keeps this try's intent and report keys its own.
    fn completed_try(&self, tag: &str) -> (AttemptId, EntityId) {
        let now = self.vault.now_recorded_at();
        let AgentDispatchOutcome::Dispatched(status) = AgentDispatcher::new(&self.vault)
            .dispatch(DispatchAgent {
                target: AgentDispatchTarget::Custom(self.executor),
                parent_attempt: None,
                dedupe_key: None,
                run_id: None,
                now,
            })
            .expect("dispatch the executor's run")
        else {
            panic!("the executor's run was not dispatched");
        };
        let ClaimOutcome::Claimed(run) = AttemptQueue::new(&self.vault)
            .claim(ClaimAttempt {
                lease_owner: RUN_LEASE_OWNER.into(),
                now,
            })
            .expect("claim the run")
        else {
            panic!("the executor's run was not leased");
        };
        assert_eq!(run.id, status.attempt.id, "the dispatched run is leased");
        let run = AttemptQueue::new(&self.vault)
            .set_executor_model(run.id, RUN_LEASE_OWNER, run.attempt_count, RUN_MODEL)
            .expect("the host stamps its run's model");
        let created = invoke(
            &self.owner_memory(),
            "tasks.create",
            json!({
                "spec": {"summary": format!("seal doors task {tag}")},
                "assignee": {"child": {"actor_ref": self.executor.to_hex()}},
            }),
        )
        .expect("the owner creates the task");
        let task: EntityId = serde_json::from_value(created["task_ref"].clone())
            .unwrap_or_else(|error| panic!("no created task ({error}): {created}"));
        let memory = self
            .vault
            .memory(self.executor, EdgeActorClass::Agent)
            .with_task_host(HostBinding::from_leased(&run, None).expect("host binding"));
        let accepted = invoke(
            &memory,
            "tasks.accept",
            json!({"task_ref": task.to_hex(), "intent_key": format!("take-the-task-{tag}")}),
        )
        .expect("the executor accepts");
        let handle: AttemptHandle =
            match serde_json::from_value::<TaskHandle>(accepted["handle"].clone()) {
                Ok(TaskHandle::Attempt(handle)) => handle,
                other => panic!("the accept named no try ({other:?}): {accepted}"),
            };
        let result = self.result_row(&format!("seal doors result {tag}"));
        invoke(
            &memory,
            "tasks.update",
            json!({
                "task_ref": task.to_hex(),
                "report_key": format!("done-{tag}"),
                "attempt": serde_json::to_value(&handle).expect("handle wire"),
                "report": {"done": {"result_ref": result.to_hex()}},
            }),
        )
        .expect("the DONE lands");
        let record = AttemptQueue::new(&self.vault)
            .get(handle.attempt_ref)
            .expect("read the try")
            .expect("the try exists");
        assert_eq!(
            record.state,
            AttemptState::Completed,
            "the DONE completes the try"
        );
        assert_eq!(
            record.executor_model.as_deref(),
            Some(RUN_MODEL),
            "the try carries the host run's model"
        );
        (handle.attempt_ref, result)
    }

    /// The measured cell the seal projects this vault's tries into.
    async fn learning_cell(&self) -> Value {
        self.ok(
            Caller::Owner,
            LEARNING_READ,
            json!({"cell": {
                "subject": self.executor.to_hex(),
                "predicate": "learning.reliability",
                "executor": RUN_MODEL,
                "typeRef": {"node_id": "root", "tree_version": 1},
                "axis": "seal_flaw_free",
            }}),
        )
        .await
    }
}

/// A confession names its flaw without moving any score, and uncertainty
/// queues its directed recheck: both seals answer zero assessment and zero
/// reward, and pending holds one confession recheck per seal at rate 1.0.
/// (P1+P2: a report is not an outcome; P3: doubt asks for a recheck.)
#[test]
fn confess_names_a_flaw_without_moving_any_score_and_queues_its_recheck() {
    run_on_engine_stack("seal-confess-queues-recheck", || async {
        let served = served();
        let (a, _) = served.completed_try("t1a");
        let (b, _) = served.completed_try("t1b");

        let sealed_a = served
            .ok(
                Caller::Owner,
                SEAL_CONFESS,
                confess_body(a, served.executor, flaw_objectives()),
            )
            .await;
        assert_assessment_zero(&sealed_a);
        assert_eq!(
            sealed_a["receipt"]["checks"][0]["request"]["reference"],
            format!("seal:recheck:{}", attempt_hex(a)),
            "{sealed_a}"
        );

        let sealed_b = served
            .ok(
                Caller::Owner,
                SEAL_CONFESS,
                confess_body(b, served.executor, uncertain_objectives()),
            )
            .await;
        assert_assessment_zero(&sealed_b);

        let pending = served.ok(Caller::Owner, SEAL_PENDING, json!({})).await;
        let list = pending.as_array().expect("a pending list");
        assert_eq!(list.len(), 2, "both rechecks wait: {pending}");
        for (attempt, objective) in [(a, OBJECTIVE), (b, SECOND_OBJECTIVE)] {
            let check = list
                .iter()
                .find(|check| check["attempt"] == attempt_value(attempt))
                .expect("one recheck per seal");
            assert_eq!(check["kind"], "confession_recheck", "{check}");
            assert_eq!(check["rate"], json!(1.0), "{check}");
            assert_eq!(
                check["reference"],
                format!("seal:recheck:{}", attempt_hex(attempt)),
                "{check}"
            );
            let objectives = check["objectives"].as_array().expect("objectives");
            assert_eq!(objectives.len(), 1, "{check}");
            assert_eq!(objectives[0]["objective"], objective, "{check}");
        }
    });
}

/// Confessing a flaw leaves the measured learning cell untested: no
/// evidence, no attributed receipts, before and after the seal. (P1+P2 in
/// measured state: the projector reads findings, never the report.)
#[test]
fn confession_leaves_the_learning_cell_untested() {
    run_on_engine_stack("seal-confession-leaves-cell", || async {
        let served = served();
        let (a, _) = served.completed_try("t2a");
        let (_, _) = served.completed_try("t2b");

        let before = served.learning_cell().await;
        assert_cell_empty(&before);

        let sealed = served
            .ok(
                Caller::Owner,
                SEAL_CONFESS,
                confess_body(a, served.executor, flaw_objectives()),
            )
            .await;
        assert_assessment_zero(&sealed);

        let after = served.learning_cell().await;
        assert_cell_empty(&after);
    });
}

/// Strangers are refused at all six verbs and write nothing: the person and
/// the agent each meet FORBIDDEN at run, pending, confess, complete, audit
/// and receipt, and the owner's pending and receipt read back unchanged.
/// (The door: every seal verb is the vault owner's.)
#[test]
fn strangers_are_refused_at_all_six_verbs_and_nothing_is_written() {
    run_on_engine_stack("seal-strangers-refused", || async {
        let served = served();
        assert_ne!(served.stranger, served.owner);
        assert_ne!(served.agent_person, served.owner);
        assert_ne!(served.stranger, served.agent_person);
        let (a, _) = served.completed_try("t3");
        let sealed = served
            .ok(
                Caller::Owner,
                SEAL_CONFESS,
                confess_body(a, served.executor, flaw_objectives()),
            )
            .await;
        let created_at = sealed["receipt"]["checks"][0]["request"]["created_at"]
            .as_u64()
            .expect("the recheck's request time");

        let pending_before = served.ok(Caller::Owner, SEAL_PENDING, json!({})).await;
        let receipt_before = served
            .ok(
                Caller::Owner,
                SEAL_RECEIPT,
                json!({"attempt": attempt_value(a)}),
            )
            .await;

        let confess = confess_body(a, served.executor, flaw_objectives());
        let complete = complete_body(
            a,
            JUDGE_MODEL,
            created_at,
            json!([{
                "objective": OBJECTIVE,
                "flaw_present": true,
                "evidence_ref": "independent-recheck-1",
            }]),
        );
        let attempt_only = json!({"attempt": attempt_value(a)});
        for caller in [Caller::Person, Caller::Agent] {
            for (verb, input) in [
                (SEAL_RUN, json!({})),
                (SEAL_PENDING, json!({})),
                (SEAL_CONFESS, confess.clone()),
                (SEAL_COMPLETE, complete.clone()),
                (SEAL_AUDIT, attempt_only.clone()),
                (SEAL_RECEIPT, attempt_only.clone()),
            ] {
                let (status, body) = served.post(caller, verb, input).await;
                assert_eq!(
                    status,
                    StatusCode::FORBIDDEN,
                    "{caller:?} at {verb}: {body}"
                );
                assert_eq!(
                    error_code(&body),
                    Some("FORBIDDEN"),
                    "{caller:?} at {verb}: {body}"
                );
            }
        }

        let pending_after = served.ok(Caller::Owner, SEAL_PENDING, json!({})).await;
        assert_eq!(pending_after, pending_before, "no stranger wrote a check");
        let receipt_after = served
            .ok(
                Caller::Owner,
                SEAL_RECEIPT,
                json!({"attempt": attempt_value(a)}),
            )
            .await;
        assert_eq!(receipt_after, receipt_before, "no stranger wrote the seal");
    });
}

/// Only completed findings move the score the confession left alone: the
/// recheck's found flaw lands one weighted flaw, one confirmed confession
/// and one unit of reward, and the learning cell gains its evidence. (P2's
/// contrast: anchored findings project; the report never did.)
#[test]
fn findings_move_the_score_that_confession_left_alone() {
    run_on_engine_stack("seal-findings-move-score", || async {
        let served = served();
        let (a, _) = served.completed_try("t4");
        let sealed = served
            .ok(
                Caller::Owner,
                SEAL_CONFESS,
                confess_body(a, served.executor, flaw_objectives()),
            )
            .await;
        assert_assessment_zero(&sealed);
        assert_cell_empty(&served.learning_cell().await);
        let created_at = sealed["receipt"]["checks"][0]["request"]["created_at"]
            .as_u64()
            .expect("the recheck's request time");

        let judged = served
            .ok(
                Caller::Owner,
                SEAL_COMPLETE,
                complete_body(
                    a,
                    JUDGE_MODEL,
                    created_at,
                    json!([{
                        "objective": OBJECTIVE,
                        "flaw_present": true,
                        "evidence_ref": "independent-recheck-1",
                    }]),
                ),
            )
            .await;
        assert_eq!(
            judged["assessment"]["weighted_flaws"],
            json!(1.0),
            "{judged}"
        );
        assert_eq!(
            judged["assessment"]["weighted_hidden_flaws"],
            json!(0.0),
            "{judged}"
        );
        assert_eq!(judged["assessment"]["confirmed_confessions"], 1, "{judged}");
        assert_eq!(judged["assessment"]["false_confessions"], 0, "{judged}");
        assert_eq!(judged["honesty_reward"], json!(1.0), "{judged}");

        let cell = served.learning_cell().await;
        let evidence = cell["view"]["provenance"]["evidence"]
            .as_array()
            .expect("evidence");
        assert_eq!(evidence.len(), 1, "the finding projects: {cell}");
        let attributed = cell["view"]["attributed_outcome_receipts"]
            .as_array()
            .expect("attributed receipts");
        assert_eq!(attributed.len(), 1, "{cell}");
    });
}

/// Completing refuses the executor's own model and replays identically: a
/// judge of the executor's model is BAD_REQUEST, the independent judge lands,
/// and the same completion again answers the same receipt. (Complete
/// admission: a check needs another mind, and delivery is idempotent.)
#[test]
fn complete_refuses_the_executors_own_model_and_replays_identically() {
    run_on_engine_stack("seal-complete-admission", || async {
        let served = served();
        let (a, _) = served.completed_try("t5");
        let sealed = served
            .ok(
                Caller::Owner,
                SEAL_CONFESS,
                confess_body(a, served.executor, uncertain_objectives()),
            )
            .await;
        let created_at = sealed["receipt"]["checks"][0]["request"]["created_at"]
            .as_u64()
            .expect("the recheck's request time");
        let findings = json!([{
            "objective": SECOND_OBJECTIVE,
            "flaw_present": false,
            "evidence_ref": "independent-recheck-1",
        }]);

        let (status, body) = served
            .post(
                Caller::Owner,
                SEAL_COMPLETE,
                complete_body(a, RUN_MODEL, created_at, findings.clone()),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "the executor's own model judges: {body}"
        );
        assert_eq!(error_code(&body), Some("BAD_REQUEST"), "{body}");
        assert!(
            body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("judge")),
            "{body}"
        );

        let first = served
            .ok(
                Caller::Owner,
                SEAL_COMPLETE,
                complete_body(a, JUDGE_MODEL, created_at, findings.clone()),
            )
            .await;
        let replay = served
            .ok(
                Caller::Owner,
                SEAL_COMPLETE,
                complete_body(a, JUDGE_MODEL, created_at, findings),
            )
            .await;
        assert_eq!(replay, first, "an identical completion replays");
    });
}

/// A passing seal draws its audit once: the first audit stores the draw, the
/// second answers the identical receipt, and a random audit waits exactly
/// when the draw selected. (Audit-once: one draw per seal, kept.)
#[test]
fn audit_draws_a_passing_seal_once() {
    run_on_engine_stack("seal-audit-once", || async {
        let served = served();
        let (a, _) = served.completed_try("t6");
        let run = served.ok(Caller::Owner, SEAL_RUN, json!({})).await;
        assert_eq!(
            run["job"]["bytes"].as_array().expect("job bytes").len(),
            16,
            "{run}"
        );
        let sealed = served
            .ok(
                Caller::Owner,
                SEAL_CONFESS,
                confess_body(a, served.executor, uncertain_objectives()),
            )
            .await;
        let created_at = sealed["receipt"]["checks"][0]["request"]["created_at"]
            .as_u64()
            .expect("the recheck's request time");
        let _ = served
            .ok(
                Caller::Owner,
                SEAL_COMPLETE,
                complete_body(
                    a,
                    JUDGE_MODEL,
                    created_at,
                    json!([{
                        "objective": SECOND_OBJECTIVE,
                        "flaw_present": false,
                        "evidence_ref": "independent-recheck-1",
                    }]),
                ),
            )
            .await;

        let first = served
            .ok(
                Caller::Owner,
                SEAL_AUDIT,
                json!({"attempt": attempt_value(a)}),
            )
            .await;
        let draw = &first["receipt"]["draw"];
        assert!(draw.is_object(), "the first audit draws: {first}");
        let rate = draw["rate"].as_f64().expect("rate");
        let sample = draw["sample"].as_f64().expect("sample");
        assert!(draw["at"].is_u64(), "{first}");
        let second = served
            .ok(
                Caller::Owner,
                SEAL_AUDIT,
                json!({"attempt": attempt_value(a)}),
            )
            .await;
        assert_eq!(second, first, "the second audit answers the stored draw");
        let checks = first["receipt"]["checks"].as_array().expect("checks");
        let recheck = checks
            .iter()
            .find(|check| check["request"]["kind"] == "confession_recheck")
            .expect("the completed recheck");
        assert!(!recheck["outcome"].is_null(), "{first}");
        let pending_audits = checks
            .iter()
            .filter(|check| {
                check["request"]["kind"] == "random_audit" && check["outcome"].is_null()
            })
            .count();
        assert_eq!(pending_audits, if sample < rate { 1 } else { 0 }, "{first}");
    });
}

/// Run queues a job and pending filters by attempt: the run answers a job
/// id, the unfiltered pending lists only the directed recheck, and the clean
/// try's filter and an unknown try's filter answer empty. (Q2 shapes: one
/// queue, one filter, never a lookup.)
#[test]
fn run_queues_a_job_and_pending_filters_by_attempt() {
    run_on_engine_stack("seal-run-pending-filter", || async {
        let served = served();
        let (a, _) = served.completed_try("t7a");
        let (b, _) = served.completed_try("t7b");
        let _ = served
            .ok(
                Caller::Owner,
                SEAL_CONFESS,
                confess_body(a, served.executor, uncertain_objectives()),
            )
            .await;
        let _ = served
            .ok(
                Caller::Owner,
                SEAL_CONFESS,
                confess_body(b, served.executor, clean_objectives()),
            )
            .await;

        let run = served.ok(Caller::Owner, SEAL_RUN, json!({})).await;
        assert_eq!(
            run["job"]["bytes"].as_array().expect("job bytes").len(),
            16,
            "{run}"
        );

        let all = served.ok(Caller::Owner, SEAL_PENDING, json!({})).await;
        let list = all.as_array().expect("a pending list");
        assert_eq!(list.len(), 1, "only the directed recheck waits: {all}");
        assert_eq!(list[0]["attempt"], attempt_value(a), "{all}");
        assert_eq!(list[0]["kind"], "confession_recheck", "{all}");

        let clean = served
            .ok(
                Caller::Owner,
                SEAL_PENDING,
                json!({"attempt": attempt_value(b)}),
            )
            .await;
        assert_eq!(clean, json!([]), "the clean try waits for nothing");
        let unknown = served
            .ok(
                Caller::Owner,
                SEAL_PENDING,
                json!({"attempt": attempt_value(AttemptId::now())}),
            )
            .await;
        assert_eq!(unknown, json!([]), "an unknown try waits for nothing");
        let named = served
            .ok(
                Caller::Owner,
                SEAL_PENDING,
                json!({"attempt": attempt_value(a)}),
            )
            .await;
        assert_eq!(
            named.as_array().expect("a pending list").len(),
            1,
            "{named}"
        );
    });
}

/// The receipt is null before the seal and shaped after it: an unsealed try
/// answers null, and the sealed try answers its receipt, its zero assessment
/// and its zero reward, with no outcome and no draw yet. (Q5 shape: the seal
/// is the receipt's birth.)
#[test]
fn receipt_is_null_before_the_seal_and_shaped_after() {
    run_on_engine_stack("seal-receipt-shape", || async {
        let served = served();
        let (a, _) = served.completed_try("t8");
        let (status, body) = served
            .post(
                Caller::Owner,
                SEAL_RECEIPT,
                json!({"attempt": attempt_value(a)}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.is_null(), "{body}");

        let _ = served
            .ok(
                Caller::Owner,
                SEAL_CONFESS,
                confess_body(a, served.executor, flaw_objectives()),
            )
            .await;
        let view = served
            .ok(
                Caller::Owner,
                SEAL_RECEIPT,
                json!({"attempt": attempt_value(a)}),
            )
            .await;
        assert!(
            view["receipt"].is_object()
                && view["assessment"].is_object()
                && view["honesty_reward"].is_number(),
            "{view}"
        );
        assert_eq!(view["receipt"]["passing"], true, "{view}");
        assert_eq!(view["receipt"]["executor"], RUN_MODEL, "{view}");
        assert!(view["receipt"]["checks"][0]["outcome"].is_null(), "{view}");
        assert!(view["receipt"]["draw"].is_null(), "{view}");
        assert_assessment_zero(&view);
    });
}
