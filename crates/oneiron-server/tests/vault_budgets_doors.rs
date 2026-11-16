//! Public-door promise tests for the `vault.budgets` family (ARCH-0079
//! #budget: the runtime enforces only the cap; a suspension is a hold,
//! never DONE or abandonment; width has no count cap).
//!
//! Every case drives the real routes in process (`build_app` + `oneshot`):
//! `POST /v1/core/facade/<verb>` for `vault.budgets.lease.open`, `.lease`,
//! `.lease.top_up`, `.hold`, `.hold.resume`, `.settlements`, `.rsi`,
//! `.rsi.configure`, `.rsi.hold`, `.rsi.hold.resume`, `.rsi.top_up`,
//! `.resident_shares`, `.resident_shares.set`, `self.budget`,
//! `self.budget.land` and `self.billing.account.file`, plus
//! `vault.runs.job` and `vault.runs.branches.get` for the attempt reads.
//! Callers: the vault's embedded owner on the host root credential; the
//! run's own agent (the seeded agent definition's id) on a minted
//! agent-class credential; a stranger person on a minted human credential;
//! and a second stranger person on a minted agent-class credential. Each
//! case owns its wall-clock vault; the fixture spends, reserves, settles
//! and claims through public engine paths only, never a test door.
//!
//! The promises, one per test:
//! - the cap refuses spend past it and records nothing (the lease tree's
//!   one refusal, `OverCap`);
//! - raising a lease is the owner's act alone (a top-up stays with the
//!   owner; strangers are refused and write nothing);
//! - a depleted run holds `Paused`, never DONE, and resumes `Queued` once
//!   its lease is topped up (a suspension is a hold);
//! - width has no count cap: any number of reservations hold under one
//!   root without a count refusal;
//! - a second settle moves nothing and reports `already_settled`, and the
//!   settlements door reads one row per settled call;
//! - the RSI line configures, holds and resumes with no provider, and a
//!   top-up never resumes held work by itself;
//! - a resident share sets and reads back, and strangers are refused;
//! - `self.budget` serves only the run's dispatch actor, and a billing
//!   account files only the caller's own.
//!
//! These promises hold on main. Their red proof is a seeded fault (Test rules
//! v2, rule 5), named in `seed_budgets_faults.py`.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --no-fail-fast --test vault_budgets_doors`. The test calls no test door; it
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
use oneiron::agent_dispatch::{AgentDispatcher, ChildSpend, DEFAULT_BASE_LOGICAL_ID, SpendScopeId};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, holder_proof};
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::federation::ScopeAxis;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::task_verb::{TaskAssignee, TaskCreateSpec, TaskRouteOutcome};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const LEASE_OPEN: &str = "vault.budgets.lease.open";
const LEASE: &str = "vault.budgets.lease";
const LEASE_TOP_UP: &str = "vault.budgets.lease.top_up";
const HOLD: &str = "vault.budgets.hold";
const HOLD_RESUME: &str = "vault.budgets.hold.resume";
const SETTLEMENTS: &str = "vault.budgets.settlements";
const RSI: &str = "vault.budgets.rsi";
const RSI_CONFIGURE: &str = "vault.budgets.rsi.configure";
const RSI_HOLD: &str = "vault.budgets.rsi.hold";
const RSI_HOLD_RESUME: &str = "vault.budgets.rsi.hold.resume";
const RSI_TOP_UP: &str = "vault.budgets.rsi.top_up";
const RESIDENT_SHARES: &str = "vault.budgets.resident_shares";
const RESIDENT_SHARES_SET: &str = "vault.budgets.resident_shares.set";
const SELF_BUDGET: &str = "self.budget";
const SELF_BUDGET_LAND: &str = "self.budget.land";
const BILLING_FILE: &str = "self.billing.account.file";
const RUNS_JOB: &str = "vault.runs.job";
const RUNS_BRANCHES: &str = "vault.runs.branches.get";

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

/// Wall-clock milliseconds for a cap the owner is shown now.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("wall clock")
        .as_millis() as u64
}

/// A served vault with a dispatched run: its embedded owner, the seeded
/// agent definition the run dispatches as, the run-actor agent credential
/// on that definition's id, a stranger person on a human credential, a
/// second stranger person on an agent-class credential, and the run's task
/// and attempt.
struct Served {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    owner: EntityId,
    agent_def: EntityId,
    run_agent_slip: CapabilitySlip,
    run_agent_token: String,
    stranger_slip: CapabilitySlip,
    stranger_token: String,
    stranger: EntityId,
    stranger_agent_slip: CapabilitySlip,
    stranger_agent_token: String,
    stranger_agent: EntityId,
    task_ref: EntityId,
    attempt: AttemptId,
    attempt_hex: String,
}

/// Who sends a request.
#[derive(Clone, Copy, Debug)]
enum Caller {
    /// The embedded owner on the host root credential.
    Owner,
    /// The run's dispatch actor (the seeded agent definition's id) on its
    /// own agent-class credential.
    RunAgent,
    /// A stranger person on their own human credential.
    Stranger,
    /// A second stranger person on their own agent-class credential: an
    /// agent that is no run's actor.
    StrangerAgent,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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

/// A self-hosted served vault on the wall clock, with one task dispatched
/// to the seeded default agent.
fn served() -> Served {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let mut config = VaultConfig::device();
    config.map_size = 32 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Arc::new(Vault::open(dir.path(), config).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("vault-budgets-doors".into()),
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
    let (agent_def, _) = vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)
        .expect("seeded agent lookup")
        .expect("the default agent is seeded");
    let creator = EntityId::now();
    let stranger = EntityId::now();
    let stranger_agent = EntityId::now();
    for id in [creator, stranger, stranger_agent] {
        person(&vault, id);
    }
    let receipt = vault
        .memory(creator, EdgeActorClass::Agent)
        .tasks_create(
            &TaskCreateSpec::new(
                rmpv::Value::Nil,
                Some("spend under a lease".to_owned()),
                Some(creator),
                None,
            )
            .with_assignee(TaskAssignee::AgentDef {
                agent_def_ref: agent_def,
            }),
        )
        .expect("create the task");
    let task_ref = receipt.task_ref.expect("the task is minted");
    let attempt = match receipt.route {
        Some(TaskRouteOutcome::AgentDispatch { attempt_ref, .. }) => attempt_ref,
        _ => panic!("an agent-definition assignee routes to an agent dispatch"),
    };
    let attempt_hex = hex(attempt.as_bytes());
    let app = build_app(server);
    let (run_agent_slip, run_agent_token) = credential(&vault, &issuer, agent_def, Some("agent"));
    let (stranger_slip, stranger_token) = credential(&vault, &issuer, stranger, Some("human"));
    let (stranger_agent_slip, stranger_agent_token) =
        credential(&vault, &issuer, stranger_agent, Some("agent"));
    Served {
        _dir: dir,
        vault,
        app,
        issuer,
        owner_slip,
        owner_token,
        owner,
        agent_def,
        run_agent_slip,
        run_agent_token,
        stranger_slip,
        stranger_token,
        stranger,
        stranger_agent_slip,
        stranger_agent_token,
        stranger_agent,
        task_ref,
        attempt,
        attempt_hex,
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

/// Reserves a child scope for `child` under `parent` in one write: a carve
/// or a hold, as asked.
fn reserve(vault: &Vault, parent: &SpendScopeId, child: &AttemptId, ask: ChildSpend) {
    let dispatcher = AgentDispatcher::new(vault);
    let now = vault.now_recorded_at();
    vault
        .with_write_txn(|txn| Ok(dispatcher.reserve_child_in_txn(txn, parent, child, ask, now)?))
        .expect("reserve the child scope");
}

/// Claims the task's attempt for the test lease and answers its row.
fn claim_attempt(vault: &Vault, attempt: AttemptId) -> AttemptRecord {
    let queue = AttemptQueue::new(vault);
    for _ in 0..32 {
        let ClaimOutcome::Claimed(row) = queue
            .claim_kind(
                DREAMER_RUNNER_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: "budget-doors".to_owned(),
                    now: u64::MAX,
                },
            )
            .expect("claim")
        else {
            break;
        };
        if row.id == attempt {
            return row;
        }
    }
    panic!("the task attempt is ready to claim");
}

impl Served {
    fn slip(&self, caller: Caller) -> Option<&CapabilitySlip> {
        match caller {
            Caller::Owner => None,
            Caller::RunAgent => Some(&self.run_agent_slip),
            Caller::Stranger => Some(&self.stranger_slip),
            Caller::StrangerAgent => Some(&self.stranger_agent_slip),
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
            Caller::RunAgent => self.run_agent_token.as_str(),
            Caller::Stranger => self.stranger_token.as_str(),
            Caller::StrangerAgent => self.stranger_agent_token.as_str(),
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
}

/// The cap refuses spend past it and records nothing: an over-cap charge
/// fails with the lease tree's one refusal, the lease re-read shows spend
/// and room unchanged, and a charge within the cap still lands. (The
/// runtime enforces only the cap, a BudgetGuard lease.)
#[test]
fn cap_refuses_spend_past_it_and_records_nothing() {
    run_on_engine_stack("budgets-cap-refuses", || async {
        let served = served();
        let launch = "cap-refuses-overspend";
        let opened = served
            .ok(
                Caller::Owner,
                LEASE_OPEN,
                json!({
                    "launch": launch,
                    "cap_units": 100,
                    "unit": "tokens",
                    "shown_at_ms": now_ms(),
                }),
            )
            .await;
        assert_eq!(opened["lease"]["scope"], launch, "{opened}");
        assert_eq!(opened["lease"]["cap_units"], 100, "{opened}");
        assert_eq!(opened["lease"]["hard"], true, "{opened}");
        assert_eq!(opened["lease"]["state"], "open", "{opened}");
        assert_eq!(opened["spend"]["available_units"], 100, "{opened}");

        let root = SpendScopeId::launch(launch).expect("the launch id");
        reserve(
            &served.vault,
            &root,
            &served.attempt,
            ChildSpend::Carve { cap_units: 100 },
        );
        let child = SpendScopeId::for_attempt(&served.attempt);
        let dispatcher = AgentDispatcher::new(&served.vault);
        let refused = dispatcher
            .charge(&child, 101)
            .expect_err("an over-cap charge is refused");
        assert!(
            refused.to_string().contains("cannot cover"),
            "the one refusal: {refused}"
        );

        let reread = served
            .ok(
                Caller::Owner,
                LEASE,
                json!({"scope": served.attempt_hex.clone()}),
            )
            .await;
        assert_eq!(reread["lease"]["spent_units"], 0, "{reread}");
        assert_eq!(reread["spend"]["spent_units"], 0, "{reread}");
        assert_eq!(reread["spend"]["available_units"], 100, "{reread}");

        dispatcher.charge(&child, 100).expect("the cap still holds");
        let spent = served
            .ok(
                Caller::Owner,
                LEASE,
                json!({"scope": served.attempt_hex.clone()}),
            )
            .await;
        assert_eq!(spent["lease"]["spent_units"], 100, "{spent}");
        assert_eq!(spent["spend"]["available_units"], 0, "{spent}");
        assert_eq!(
            spent["spend"]["signal"],
            json!({"signal": "at_cap", "cap_units": 100}),
            "{spent}"
        );
    });
}

/// Raising a lease is the owner's act alone: the owner tops up, the run's
/// agent and a stranger are refused at the top-up with the owner refusal,
/// and the lease still shows the owner's cap. (A top-up stays with the
/// vault owner.)
#[test]
fn top_up_is_the_owners_act_strangers_are_refused() {
    run_on_engine_stack("budgets-top-up-owner", || async {
        let served = served();
        let launch = "top-up-is-the-owners-act";
        served
            .ok(
                Caller::Owner,
                LEASE_OPEN,
                json!({
                    "launch": launch,
                    "cap_units": 100,
                    "unit": "tokens",
                    "shown_at_ms": now_ms(),
                }),
            )
            .await;
        let raised = served
            .ok(
                Caller::Owner,
                LEASE_TOP_UP,
                json!({
                    "scope": launch,
                    "expected_cap_units": 100,
                    "cap_units": 200,
                    "unit": "tokens",
                    "shown_at_ms": now_ms(),
                }),
            )
            .await;
        assert_eq!(raised["lease"]["cap_units"], 200, "{raised}");

        for caller in [Caller::RunAgent, Caller::Stranger] {
            let (status, body) = served
                .post(
                    caller,
                    LEASE_TOP_UP,
                    json!({
                        "scope": launch,
                        "expected_cap_units": 200,
                        "cap_units": 300,
                        "unit": "tokens",
                        "shown_at_ms": now_ms(),
                    }),
                )
                .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{caller:?}: {body}");
            assert_eq!(error_code(&body), Some("FORBIDDEN"), "{body}");
            assert_eq!(
                body["error"]["message"],
                format!("{LEASE_TOP_UP} is the vault owner's"),
                "{body}"
            );
        }

        let reread = served
            .ok(Caller::Owner, LEASE, json!({"scope": launch}))
            .await;
        assert_eq!(reread["lease"]["cap_units"], 200, "{reread}");
    });
}

/// A depleted run holds `Paused`, never DONE, and resumes `Queued` once
/// its lease is topped up: the worker parks through its own land door, the
/// hold reads `held` with its checkpoint, the run reads `Paused`, resume
/// is refused until the top-up, then the hold reads `resumed` and the run
/// reads `Queued`. (A suspension is a hold, never DONE or abandonment.)
#[test]
fn depleted_run_holds_paused_never_done_then_resumes() {
    run_on_engine_stack("budgets-hold-resume", || async {
        let served = served();
        let launch = "depleted-run-holds";
        served
            .ok(
                Caller::Owner,
                LEASE_OPEN,
                json!({
                    "launch": launch,
                    "cap_units": 200,
                    "unit": "tokens",
                    "shown_at_ms": now_ms(),
                }),
            )
            .await;
        let root = SpendScopeId::launch(launch).expect("the launch id");
        reserve(
            &served.vault,
            &root,
            &served.attempt,
            ChildSpend::Carve { cap_units: 100 },
        );
        let child = SpendScopeId::for_attempt(&served.attempt);
        let dispatcher = AgentDispatcher::new(&served.vault);
        dispatcher.charge(&child, 100).expect("spend to the cap");
        let claimed = claim_attempt(&served.vault, served.attempt);

        let marker = "wrap-up-checkpoint";
        let landed = served
            .ok(
                Caller::RunAgent,
                SELF_BUDGET_LAND,
                json!({
                    "attempt": served.attempt_hex.clone(),
                    "run": served.attempt_hex.clone(),
                    "lease_owner": "budget-doors",
                    "attempt_count": claimed.attempt_count,
                    "marker": marker,
                    "reason": "the lease is spent",
                }),
            )
            .await;
        assert_eq!(landed["state"], "held", "{landed}");
        assert_eq!(landed["resume_ready"], false, "{landed}");
        let attempt_value = serde_json::to_value(&served.attempt).expect("attempt id");
        assert_eq!(landed["root_attempt"], attempt_value, "{landed}");
        let held = landed["held"].as_array().expect("held attempts");
        assert_eq!(held.len(), 1, "{landed}");
        assert_eq!(held[0]["attempt"], attempt_value, "{landed}");
        assert_eq!(held[0]["resume_point"]["marker"], marker, "{landed}");

        let hold = served
            .ok(
                Caller::Owner,
                HOLD,
                json!({"run": served.attempt_hex.clone()}),
            )
            .await;
        assert_eq!(hold["state"], "held", "{hold}");

        let job = served
            .ok(
                Caller::Owner,
                RUNS_JOB,
                json!({"job": served.attempt_hex.clone()}),
            )
            .await;
        assert_eq!(job["job"]["state"], "Paused", "{job}");
        assert_eq!(job["job"]["branch"], served.attempt_hex, "{job}");
        let branches = served
            .ok(
                Caller::Owner,
                RUNS_BRANCHES,
                json!({"task_ref": served.task_ref.to_hex()}),
            )
            .await;
        let branch = branches["branches"]
            .as_array()
            .expect("branches")
            .iter()
            .find(|branch| branch["branch"] == served.attempt_hex)
            .expect("the parked branch")
            .clone();
        assert_eq!(branch["state"], "Paused", "{branches}");

        let (status, body) = served
            .post(
                Caller::Owner,
                HOLD_RESUME,
                json!({"run": served.attempt_hex.clone()}),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "resume too soon: {body}");
        assert_eq!(error_code(&body), Some("BAD_REQUEST"), "{body}");
        assert_eq!(
            body["error"]["message"],
            "invalid config: top up the held run's binding lease before resuming",
            "{body}"
        );

        let raised = served
            .ok(
                Caller::Owner,
                LEASE_TOP_UP,
                json!({
                    "scope": served.attempt_hex.clone(),
                    "expected_cap_units": 100,
                    "cap_units": 200,
                    "unit": "tokens",
                    "shown_at_ms": now_ms(),
                }),
            )
            .await;
        assert_eq!(raised["lease"]["cap_units"], 200, "{raised}");

        let resumed = served
            .ok(
                Caller::Owner,
                HOLD_RESUME,
                json!({"run": served.attempt_hex.clone()}),
            )
            .await;
        assert_eq!(resumed["state"], "resumed", "{resumed}");
        assert!(resumed["resumed_at"].is_u64(), "{resumed}");
        assert!(resumed["resumed_by"].is_string(), "{resumed}");

        let job = served
            .ok(
                Caller::Owner,
                RUNS_JOB,
                json!({"job": served.attempt_hex.clone()}),
            )
            .await;
        assert_eq!(job["job"]["state"], "Queued", "{job}");
    });
}

/// Width has no count cap: twenty-five holds reserve under one root with
/// no count refusal, and the root holds their sum. (Count is never the
/// cap; the only refusal is `OverCap`.)
#[test]
fn width_has_no_count_cap_on_reservations() {
    run_on_engine_stack("budgets-no-count-cap", || async {
        let served = served();
        let launch = "no-count-cap";
        served
            .ok(
                Caller::Owner,
                LEASE_OPEN,
                json!({
                    "launch": launch,
                    "cap_units": 1000,
                    "unit": "tokens",
                    "shown_at_ms": now_ms(),
                }),
            )
            .await;
        let root = SpendScopeId::launch(launch).expect("the launch id");
        for _ in 0..25 {
            let child = AttemptId::from_bytes(EntityId::now().as_bytes()).expect("a child id");
            reserve(
                &served.vault,
                &root,
                &child,
                ChildSpend::Hold { expected_units: 10 },
            );
        }
        let reread = served
            .ok(Caller::Owner, LEASE, json!({"scope": launch}))
            .await;
        assert_eq!(reread["lease"]["held_units"], 250, "{reread}");
        assert_eq!(reread["spend"]["available_units"], 750, "{reread}");
    });
}

/// A second settle moves nothing and the settlements door reads one row
/// per settled call: the replay reports `already_settled` with the same
/// spend, the child reads closed, and owner and agent read no metering
/// and no rows on an unbound host. (One attempt holds one lease and
/// settles once.)
#[test]
fn second_settle_moves_nothing_and_settlements_read_once() {
    run_on_engine_stack("budgets-settle-once", || async {
        let served = served();
        let launch = "settle-once";
        served
            .ok(
                Caller::Owner,
                LEASE_OPEN,
                json!({
                    "launch": launch,
                    "cap_units": 100,
                    "unit": "tokens",
                    "shown_at_ms": now_ms(),
                }),
            )
            .await;
        let root = SpendScopeId::launch(launch).expect("the launch id");
        reserve(
            &served.vault,
            &root,
            &served.attempt,
            ChildSpend::Carve { cap_units: 100 },
        );
        let child = SpendScopeId::for_attempt(&served.attempt);
        let dispatcher = AgentDispatcher::new(&served.vault);
        dispatcher.charge(&child, 40).expect("spend before settle");
        let now = served.vault.now_recorded_at();
        let first = dispatcher
            .settle_child(&served.attempt, now)
            .expect("settle")
            .expect("the metered attempt settles");
        assert!(!first.already_settled, "the first settle moves spend");
        assert_eq!(first.spent_units, 40, "the first settle moves spend");
        assert_eq!(first.released_units, 60, "the first settle moves spend");
        let second = dispatcher
            .settle_child(&served.attempt, now)
            .expect("re-settle")
            .expect("the replay answers");
        assert!(second.already_settled, "the replay moves nothing");
        assert_eq!(second.spent_units, 40, "the replay moves nothing");
        assert_eq!(second.released_units, 0, "the replay moves nothing");
        assert!(second.charged_to.is_none(), "the replay moves nothing");

        let reread = served
            .ok(
                Caller::Owner,
                LEASE,
                json!({"scope": served.attempt_hex.clone()}),
            )
            .await;
        assert_eq!(reread["lease"]["state"], "closed", "{reread}");
        assert_eq!(reread["lease"]["spent_units"], 40, "{reread}");
        let root_read = served
            .ok(Caller::Owner, LEASE, json!({"scope": launch}))
            .await;
        assert_eq!(root_read["lease"]["spent_units"], 40, "{root_read}");

        for caller in [Caller::Owner, Caller::RunAgent] {
            let settlements = served
                .ok(
                    caller,
                    SETTLEMENTS,
                    json!({"run": served.attempt_hex.clone()}),
                )
                .await;
            assert_eq!(settlements["run"], served.attempt_hex, "{settlements}");
            assert_eq!(settlements["metering_enabled"], false, "{settlements}");
            assert_eq!(settlements["settlements"], json!([]), "{settlements}");
        }
    });
}

/// The RSI line configures, holds and resumes with no provider: it reads
/// unconfigured until configured, a stranger cannot configure it, the
/// hold reads `suspended`, a top-up raises the line without resuming, and
/// the resume clears the hold. (A hold reads as suspended, never as a
/// terminal failure.)
#[test]
fn rsi_line_configures_holds_resumes_without_provider() {
    run_on_engine_stack("budgets-rsi-hold", || async {
        let served = served();
        let (status, body) = served.post(Caller::Owner, RSI, json!({})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unconfigured: {body}");
        assert_eq!(error_code(&body), Some("BAD_REQUEST"), "{body}");
        assert_eq!(
            body["error"]["message"], "invalid config: RSI budget is not configured",
            "{body}"
        );

        let configured = served
            .ok(
                Caller::Owner,
                RSI_CONFIGURE,
                json!({
                    "limit": 1000,
                    "exploration_exposure_limit": 50,
                    "shares": {"loop": {"units": 600, "pinned": false}},
                }),
            )
            .await;
        assert_eq!(configured["work_line"]["unit"], "tokens", "{configured}");
        assert_eq!(configured["work_line"]["limit"], 1000, "{configured}");
        assert_eq!(configured["work_line"]["spent"], 0, "{configured}");
        assert_eq!(configured["exposure_line"]["limit"], 50, "{configured}");
        assert_eq!(configured["suspended"], false, "{configured}");
        let shares = configured["shares"].as_array().expect("shares");
        assert_eq!(shares.len(), 1, "{configured}");
        assert_eq!(shares[0]["label"], "loop", "{configured}");
        assert_eq!(shares[0]["units"], 600, "{configured}");

        let (status, body) = served
            .post(
                Caller::RunAgent,
                RSI_CONFIGURE,
                json!({
                    "limit": 1,
                    "exploration_exposure_limit": 1,
                    "shares": {},
                }),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a stranger configures: {body}"
        );
        assert_eq!(error_code(&body), Some("FORBIDDEN"), "{body}");
        assert_eq!(
            body["error"]["message"],
            format!("{RSI_CONFIGURE} is the vault owner's"),
            "{body}"
        );

        let held = served.ok(Caller::Owner, RSI_HOLD, json!({})).await;
        assert_eq!(held["suspended"], true, "{held}");

        let raised = served
            .ok(
                Caller::Owner,
                RSI_TOP_UP,
                json!({"line": "tokens", "units": 500}),
            )
            .await;
        assert_eq!(raised["work_line"]["limit"], 1500, "{raised}");
        assert_eq!(raised["suspended"], true, "{raised}");

        let resumed = served.ok(Caller::Owner, RSI_HOLD_RESUME, json!({})).await;
        assert_eq!(resumed["suspended"], false, "{resumed}");
        assert_eq!(resumed["work_line"]["limit"], 1500, "{resumed}");
    });
}

/// A resident share sets and reads back, and strangers are refused: the
/// owner sets a pinned and a default share, the agent and a stranger are
/// refused at the set with the owner refusal, and the shares still show
/// the owner's rows. (Only the owner sets a resident's share.)
#[test]
fn resident_share_set_reads_and_strangers_refused() {
    run_on_engine_stack("budgets-resident-shares", || async {
        let served = served();
        let empty = served.ok(Caller::Owner, RESIDENT_SHARES, json!({})).await;
        assert_eq!(empty["residents"], json!([]), "{empty}");

        let stranger_hex = served.stranger.to_hex();
        let set = served
            .ok(
                Caller::Owner,
                RESIDENT_SHARES_SET,
                json!({
                    "resident": stranger_hex.clone(),
                    "units": 500,
                    "pinned": true,
                }),
            )
            .await;
        let rows = set["residents"].as_array().expect("residents");
        assert_eq!(rows.len(), 1, "{set}");
        assert_eq!(rows[0]["resident"], stranger_hex, "{set}");
        assert_eq!(rows[0]["units"], 500, "{set}");
        assert_eq!(rows[0]["pinned"], true, "{set}");
        assert_eq!(rows[0]["used_units"], 0, "{set}");

        let other = EntityId::now().to_hex();
        let soft = served
            .ok(
                Caller::Owner,
                RESIDENT_SHARES_SET,
                json!({"resident": other.clone(), "pinned": false}),
            )
            .await;
        let rows = soft["residents"].as_array().expect("residents");
        assert_eq!(rows.len(), 2, "{soft}");
        let row = rows
            .iter()
            .find(|row| row["resident"] == other)
            .expect("the soft row");
        assert!(row["units"].is_null(), "{soft}");
        assert_eq!(row["pinned"], false, "{soft}");

        for caller in [Caller::RunAgent, Caller::Stranger] {
            let (status, body) = served
                .post(
                    caller,
                    RESIDENT_SHARES_SET,
                    json!({
                        "resident": stranger_hex.clone(),
                        "units": 1,
                        "pinned": false,
                    }),
                )
                .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{caller:?}: {body}");
            assert_eq!(error_code(&body), Some("FORBIDDEN"), "{body}");
            assert_eq!(
                body["error"]["message"],
                format!("{RESIDENT_SHARES_SET} is the vault owner's"),
                "{body}"
            );
        }

        let reread = served.ok(Caller::Owner, RESIDENT_SHARES, json!({})).await;
        let rows = reread["residents"].as_array().expect("residents");
        assert_eq!(rows.len(), 2, "{reread}");
        let row = rows
            .iter()
            .find(|row| row["resident"] == stranger_hex)
            .expect("the pinned row");
        assert_eq!(row["units"], 500, "{reread}");
        assert_eq!(row["pinned"], true, "{reread}");
    });
}

/// `self.budget` serves only the run's dispatch actor, and a billing
/// account files only the caller's own: the actor reads its lease, every
/// other caller is refused at the actor gate, the stranger files and
/// withdraws its own account, an over-long account is refused, and the
/// actor cannot top up its own lease. (An agent reads its own budget and
/// files its own billing; the cap stays the owner's.)
#[test]
fn self_budget_serves_only_the_run_actor_and_billing_files_self_only() {
    run_on_engine_stack("budgets-self-budget", || async {
        let served = served();
        let launch = "self-budget-actor";
        served
            .ok(
                Caller::Owner,
                LEASE_OPEN,
                json!({
                    "launch": launch,
                    "cap_units": 100,
                    "unit": "tokens",
                    "shown_at_ms": now_ms(),
                }),
            )
            .await;
        let root = SpendScopeId::launch(launch).expect("the launch id");
        reserve(
            &served.vault,
            &root,
            &served.attempt,
            ChildSpend::Carve { cap_units: 100 },
        );

        let read = served
            .ok(
                Caller::RunAgent,
                SELF_BUDGET,
                json!({"attempt": served.attempt_hex.clone()}),
            )
            .await;
        assert_eq!(read["attempt"], served.attempt_hex, "{read}");
        assert_eq!(read["lease"]["lease"]["cap_units"], 100, "{read}");
        assert!(read["hold"].is_null(), "{read}");

        for caller in [Caller::Owner, Caller::Stranger, Caller::StrangerAgent] {
            let (status, body) = served
                .post(
                    caller,
                    SELF_BUDGET,
                    json!({"attempt": served.attempt_hex.clone()}),
                )
                .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{caller:?}: {body}");
            assert_eq!(error_code(&body), Some("FORBIDDEN"), "{body}");
            assert_eq!(
                body["error"]["message"],
                "a self budget door acts only on the caller's own dispatched attempt",
                "{body}"
            );
        }

        let filed = served
            .ok(Caller::Stranger, BILLING_FILE, json!({"account": "acct-1"}))
            .await;
        assert_eq!(filed["account"], "acct-1", "{filed}");
        let withdrawn = served
            .ok(Caller::Stranger, BILLING_FILE, json!({"account": ""}))
            .await;
        assert!(withdrawn.is_null(), "{withdrawn}");

        let long = "a".repeat(257);
        let (status, body) = served
            .post(Caller::Stranger, BILLING_FILE, json!({"account": long}))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "over-long: {body}");
        assert_eq!(error_code(&body), Some("BAD_REQUEST"), "{body}");
        assert_eq!(
            body["error"]["message"],
            "invalid config: a billing account is at most 256 bytes with no control character",
            "{body}"
        );

        let (status, body) = served
            .post(
                Caller::RunAgent,
                LEASE_TOP_UP,
                json!({
                    "scope": served.attempt_hex.clone(),
                    "expected_cap_units": 100,
                    "cap_units": 200,
                    "unit": "tokens",
                    "shown_at_ms": now_ms(),
                }),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "an agent tops up: {body}");
        assert_eq!(error_code(&body), Some("FORBIDDEN"), "{body}");
        assert_eq!(
            body["error"]["message"],
            format!("{LEASE_TOP_UP} is the vault owner's"),
            "{body}"
        );
    });
}
