#![cfg(oneiron_test_support)]
//! L1-03 PR 2 (canon ARCH-0028 `#mcp-tasks`, owner ruling ONEIRON-MCP-TASKS =
//! AB; Engine ruling L1-03-TTL = A): the MCP Tasks extension of the
//! 2026-07-28 revision as an adapter over a saved-workflow run.
//!
//! - The server advertises `io.modelcontextprotocol/tasks`.
//! - A `vault.workflows.dispatch` call whose own request declares the
//!   extension answers a stored task; one that does not (or declared it only
//!   on an earlier `initialize`) answers the ordinary run, as before.
//! - `tasks/get` reads the run through `vault.workflows.status` as the poller:
//!   after a new server over the same vault too, and to its end. A failed run
//!   ends `completed` with `isError`. `tasks/cancel` runs
//!   `vault.workflows.cancel`, and the task ends `cancelled`.
//! - The task states its starting call's receipt.
//! - An expired handle, another actor's and an unknown id answer alike as
//!   missing to every task method, and the run goes on. A repeated call
//!   starts one run. A `tasks/*` request that does not declare the extension
//!   is refused with `-32021`.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test mcp_tasks_adapter`.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use ed25519_dalek::{Signer, SigningKey};
use oneiron::agent_def::workflow::WorkflowDefinition;
use oneiron::agent_dispatch::{AgentDispatcher, WorkflowProgress};
use oneiron::attempt_queue::{
    AttemptId, AttemptInterventionKind, AttemptQueue, AttemptResultRef, AttemptState,
    InterveneAttempt,
};
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, SlipCaveat, holder_proof_challenge,
};
use oneiron::claim::base_world_id;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::mcp::MCP_TOOL_ARGS_SCHEMA_VERSION;
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const MCP_PROTOCOL_VERSION: &str = "2026-07-28";
const TOOL_FIRST: &str = "/mcp/tool-first";
const TASKS: &str = "io.modelcontextprotocol/tasks";
const CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
/// The default retention (L1-03-TTL = A): 24 hours.
const DAY_MS: u64 = 86_400_000;

/// Who sends a request.
#[derive(Clone, Copy, Debug)]
enum Caller {
    /// The self-hosted root slip, proved by the vault's issuer: the owner.
    Owner,
    /// A distinct person's `core:read` slip, narrowed to the base world.
    Reader,
}

/// A rooted vault behind the MCP gateway, its owner's saved two-step
/// workflow, and a distinct reader's slip.
struct Fixture {
    app: Router,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
    reader: CapabilitySlip,
    reader_key: SigningKey,
    workflow: EntityId,
    ttl_ms: Option<u64>,
    _dir: tempfile::TempDir,
}

impl Fixture {
    /// The fixture with the server's default handle retention.
    fn new() -> TestResult<Self> {
        Self::with_ttl(None)
    }

    /// The fixture with `mcp_task_ttl_ms` set to `ttl_ms` when it names one.
    fn with_ttl(ttl_ms: Option<u64>) -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let (_owner, _owner_proof) = embedded_owner(&vault)?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        let reader_person = EntityId::now();
        vault.put_entity(
            &reader_person,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"a distinct reader",
        )?;
        let reader_key = SigningKey::from_bytes(&[0x65; 32]);
        let mut claims = root.claims.clone();
        claims.parent_id = None;
        claims.slip_id = [0x65; 32];
        claims.holder_ref = reader_person.to_hex();
        claims.binding_key = reader_key.verifying_key().to_bytes();
        claims.actor_class = Some("human".to_owned());
        claims.scope = Scope::top();
        claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["core:read".to_owned()]));
        let mut reader = vault.mint_capability_slip(&issuer, claims)?;
        let mut ceiling = Scope::top();
        ceiling.worlds = ScopeAxis::Some(
            [base_world_id()]
                .iter()
                .map(|world| ScopeId(*world))
                .collect(),
        );
        reader.attenuate(
            SlipCaveat {
                scope: Some(ceiling),
                ..Default::default()
            },
            &reader_key,
        )?;
        let first = saved_agent(&vault, "tasks.first")?;
        let second = saved_agent(&vault, "tasks.second")?;
        let workflow = EntityId::now();
        vault.save_workflow(
            &workflow,
            &WorkflowDefinition::new("mcp tasks", vec![first, second])?,
            2,
        )?;
        let app = app(&vault, ttl_ms)?;
        Ok(Self {
            app,
            vault,
            issuer,
            root,
            reader,
            reader_key,
            workflow,
            ttl_ms,
            _dir: dir,
        })
    }

    /// A new server over the same vault: the old one's memory is gone, and
    /// only what the vault stores carries over.
    fn restart(&mut self) -> TestResult {
        self.app = app(&self.vault, self.ttl_ms)?;
        Ok(())
    }

    /// One JSON-RPC request to the tool-first endpoint as `caller`, under its
    /// slip and a fresh holder proof: the HTTP status and the parsed reply.
    async fn rpc(&self, caller: Caller, method: &str, params: Value) -> TestResult<(u16, Value)> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let (slip, signature) = match caller {
            Caller::Owner => (
                &self.root,
                self.issuer.binding_proof(&self.root, &challenge)?,
            ),
            Caller::Reader => (
                &self.reader,
                self.reader_key
                    .sign(&self.reader.binding_transcript(&challenge)?)
                    .to_bytes()
                    .to_vec(),
            ),
        };
        let binding = json!({
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": hex(&signature),
        });
        let request = Request::post(TOOL_FIRST)
            .header("content-type", "application/json")
            .header("mcp-protocol-version", MCP_PROTOCOL_VERSION)
            .header("authorization", format!("Bearer {}", slip.to_token()?))
            .header("x-oneiron-binding", binding.to_string())
            .body(Body::from(
                json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
                    .to_string(),
            ))?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        let body = String::from_utf8_lossy(&bytes);
        Ok((
            status,
            serde_json::from_str(&body).unwrap_or_else(|_| Value::String(body.into_owned())),
        ))
    }

    /// The owner's `vault.workflows.dispatch` under `intent_key`; with the
    /// Tasks extension declared on this request when `declared`.
    async fn dispatch(&self, intent_key: &str, declared: bool) -> TestResult<Value> {
        let mut params = json!({
            "name": "vault.workflows.dispatch",
            "arguments": verb_arguments(json!({
                "workflow_ref": self.workflow.to_hex(),
                "intent_key": intent_key,
                "briefing": "Write the two notes.",
            })),
        });
        if declared {
            params["_meta"] = declaration();
        }
        let (status, reply) = self.rpc(Caller::Owner, "tools/call", params).await?;
        assert_eq!(status, 200, "{reply}");
        Ok(reply)
    }

    /// A declared dispatch's task id.
    async fn task(&self, intent_key: &str) -> TestResult<String> {
        let reply = self.dispatch(intent_key, true).await?;
        Ok(reply["result"]["taskId"]
            .as_str()
            .ok_or_else(|| format!("a declared dispatch answers a task: {reply}"))?
            .to_owned())
    }

    /// A declared `tasks/<method>` on `task_id` as `caller`.
    async fn tasks(&self, caller: Caller, method: &str, task_id: &str) -> TestResult<Value> {
        let (status, reply) = self
            .rpc(
                caller,
                &format!("tasks/{method}"),
                json!({ "taskId": task_id, "_meta": declaration() }),
            )
            .await?;
        assert_eq!(status, 200, "{reply}");
        Ok(reply)
    }

    /// The one open run's root.
    fn open_root(&self) -> TestResult<AttemptId> {
        let roots = AgentDispatcher::new(&self.vault).open_workflow_roots()?;
        let [root] = roots[..] else {
            return Err(format!("expected one open run, found {}", roots.len()).into());
        };
        Ok(root)
    }

    /// Runs the run's active step as a host does, delivering `result`.
    fn run_step(&self, root: AttemptId, result: &str) -> TestResult<WorkflowProgress> {
        Ok(AgentDispatcher::new(&self.vault).run_workflow_step(
            root,
            "test-host",
            self.vault.now_recorded_at(),
            |_status, _context| AttemptResultRef::new(result),
        )?)
    }
}

fn app(vault: &Arc<Vault>, ttl_ms: Option<u64>) -> TestResult<Router> {
    let mut config = SyncServerConfig {
        auth_secret: Some("mcp-tasks-adapter".into()),
        ..Default::default()
    };
    if ttl_ms.is_some() {
        config.mcp_task_ttl_ms = ttl_ms;
    }
    Ok(build_app(Arc::new(SyncServer::new(vault.clone(), config)?)))
}

/// A custom agent definition the pump can dispatch.
fn saved_agent(vault: &Vault, name: &str) -> TestResult<EntityId> {
    let (_, mut definition) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")?
        .ok_or("the default agent is seeded")?;
    definition.logical_id = None;
    definition.agent_id = format!("test.{name}");
    definition.instructions = Some("Write one note.".to_owned());
    definition.skills.clear();
    let id = EntityId::now();
    vault.put_agent_definition(&id, &definition, TimeRange { start: 1, end: 1 }, 1)?;
    Ok(id)
}

/// A generated verb's tool-first arguments over its typed `input`.
fn verb_arguments(input: Value) -> Value {
    json!({
        "schema_version": MCP_TOOL_ARGS_SCHEMA_VERSION,
        "consent": {
            "policy_ref": "policy:agent-session",
            "purpose": "run the owner's saved workflow",
        },
        "arguments": { "spec": input },
    })
}

/// A request's `_meta` declaring the Tasks extension.
fn declaration() -> Value {
    json!({ CLIENT_CAPABILITIES: { "extensions": { TASKS: {} } } })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A run's view inside a completed task's result.
fn task_run(reply: &Value) -> &Value {
    &reply["result"]["result"]["structuredContent"]["output"]["value"]
}

/// Runs `test` as the server's binary runs its app, on the engine's stack.
fn on_engine_stack<F, Fut>(test: F) -> TestResult
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = TestResult>,
{
    let driver = std::thread::Builder::new()
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || -> Result<(), String> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?
                .block_on(test())
                .map_err(|error| error.to_string())
        })?;
    match driver.join() {
        Ok(outcome) => Ok(outcome?),
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[test]
fn discover_advertises_the_tasks_extension() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new()?;
        let (status, reply) = fixture
            .rpc(Caller::Owner, "server/discover", json!({}))
            .await?;
        assert_eq!(status, 200, "{reply}");
        assert_eq!(
            reply["result"]["capabilities"]["extensions"][TASKS],
            json!({}),
            "the server advertises the Tasks extension: {reply}"
        );
        Ok(())
    })
}

#[test]
fn a_declared_workflow_dispatch_returns_a_stored_task() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new()?;
        let reply = fixture.dispatch("declared", true).await?;
        let task = &reply["result"];
        assert_eq!(task["resultType"], "task", "{reply}");
        assert_eq!(task["status"], "working", "{reply}");
        let id = task["taskId"].as_str().ok_or("a taskId")?;
        assert_eq!(id.len(), 64, "the taskId is 32 bytes as hex: {id}");
        assert!(
            id.bytes()
                .all(|digit| digit.is_ascii_hexdigit() && !digit.is_ascii_uppercase())
        );
        assert_eq!(task["pollIntervalMs"], 2000);
        assert_eq!(
            task["ttlMs"], DAY_MS,
            "the handle keeps the server's retention"
        );
        assert_eq!(task["statusMessage"], "step 1 of 2");
        assert_eq!(task["_meta"]["cacheScope"], "private");
        assert!(
            task["_meta"]["receipt_ref"].is_string(),
            "the task states its starting call's receipt: {reply}"
        );

        let got = fixture.tasks(Caller::Owner, "get", id).await?;
        assert_eq!(got["result"]["status"], "working", "{got}");
        assert_eq!(got["result"]["taskId"], id);
        assert_eq!(got["result"]["resultType"], "complete");
        assert!(
            got["result"].get("result").is_none(),
            "a working task has no result yet"
        );
        Ok(())
    })
}

#[test]
fn an_undeclared_call_keeps_the_plain_handle() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new()?;
        let reply = fixture.dispatch("plain", false).await?;
        assert!(reply["result"].get("resultType").is_none(), "{reply}");
        assert!(
            reply["result"]["structuredContent"]["output"]["value"]["root_attempt_ref"].is_string(),
            "the undeclared call answers the run itself: {reply}"
        );

        // A declaration on an earlier initialize does not count.
        let (status, init) = fixture
            .rpc(
                Caller::Owner,
                "initialize",
                json!({
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": { "extensions": { TASKS: {} } },
                    "clientInfo": { "name": "mcp-tasks-adapter", "version": "1" },
                }),
            )
            .await?;
        assert_eq!(status, 200, "{init}");
        let reply = fixture.dispatch("plain-after-initialize", false).await?;
        assert!(reply["result"].get("resultType").is_none(), "{reply}");
        assert!(reply["result"].get("taskId").is_none(), "{reply}");
        Ok(())
    })
}

#[test]
fn the_task_resumes_after_a_disconnect_and_a_server_restart() -> TestResult {
    on_engine_stack(|| async {
        let mut fixture = Fixture::new()?;
        let id = fixture.task("restart").await?;
        let root = fixture.open_root()?;

        // The client went away; the server is replaced by a new one over the
        // same vault.
        fixture.restart()?;
        let got = fixture.tasks(Caller::Owner, "get", &id).await?;
        assert_eq!(got["result"]["status"], "working", "{got}");

        assert!(matches!(
            fixture.run_step(root, "artifact:first")?,
            WorkflowProgress::Advanced(_)
        ));
        assert_eq!(
            fixture.run_step(root, "artifact:second")?,
            WorkflowProgress::Completed
        );

        let done = fixture.tasks(Caller::Owner, "get", &id).await?;
        assert_eq!(done["result"]["status"], "completed", "{done}");
        let run = task_run(&done);
        assert_eq!(run["state"], "completed", "{done}");
        assert_eq!(
            run["results"]
                .as_array()
                .ok_or("results")?
                .iter()
                .map(|step| step["result_ref"].clone())
                .collect::<Vec<_>>(),
            vec![json!("artifact:first"), json!("artifact:second")],
            "the result carries the run's result refs"
        );
        assert_eq!(
            done["result"]["result"]["isError"], false,
            "a completed run's result is no error: {done}"
        );
        Ok(())
    })
}

#[test]
fn tasks_cancel_stops_the_run_and_ends_the_task_cancelled() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new()?;
        let id = fixture.task("cancel").await?;
        let root = fixture.open_root()?;
        let leaf = AgentDispatcher::new(&fixture.vault)
            .workflow_status(root)?
            .active_step;

        let cancelled = fixture.tasks(Caller::Owner, "cancel", &id).await?;
        assert_eq!(cancelled["result"]["resultType"], "complete", "{cancelled}");

        let got = fixture.tasks(Caller::Owner, "get", &id).await?;
        assert_eq!(got["result"]["status"], "cancelled", "{got}");
        assert_eq!(
            AttemptQueue::new(&fixture.vault)
                .get(leaf)?
                .ok_or("the step is stored")?
                .state,
            AttemptState::Cancelled,
            "the run's waiting step was cancelled"
        );
        assert!(
            AgentDispatcher::new(&fixture.vault)
                .open_workflow_roots()?
                .is_empty(),
            "the run ended"
        );
        Ok(())
    })
}

#[test]
fn an_expired_task_is_missing_and_its_run_goes_on() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::with_ttl(Some(1))?;
        let id = fixture.task("expire").await?;
        let root = fixture.open_root()?;
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        let (status, got) = fixture
            .rpc(
                Caller::Owner,
                "tasks/get",
                json!({ "taskId": id, "_meta": declaration() }),
            )
            .await?;
        assert_eq!(status, 200, "{got}");
        assert_eq!(
            got["error"]["code"], -32602,
            "an expired task is missing: {got}"
        );

        let (status, run) = fixture
            .rpc(
                Caller::Owner,
                "tools/call",
                json!({
                    "name": "vault.workflows.status",
                    "arguments": verb_arguments(json!({
                        "root_attempt_ref": EntityId::from_bytes(root.as_bytes())?.to_hex(),
                    })),
                }),
            )
            .await?;
        assert_eq!(status, 200, "{run}");
        assert_eq!(
            run["result"]["structuredContent"]["output"]["value"]["state"], "running",
            "the run goes on after its handle ends: {run}"
        );
        Ok(())
    })
}

#[test]
fn another_actor_gets_task_not_found() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new()?;
        let id = fixture.task("hidden").await?;
        let unknown = fixture
            .tasks(Caller::Reader, "get", &"0".repeat(64))
            .await?;
        assert_eq!(unknown["error"]["code"], -32602, "{unknown}");

        for method in ["get", "update", "cancel"] {
            let reply = fixture.tasks(Caller::Reader, method, &id).await?;
            assert_eq!(reply["error"]["code"], -32602, "{method}: {reply}");
            assert_eq!(
                reply["error"]["message"], unknown["error"]["message"],
                "{method}: another actor's task answers as an unknown one: {reply}"
            );
        }
        assert_eq!(
            AgentDispatcher::new(&fixture.vault)
                .open_workflow_roots()?
                .len(),
            1,
            "the run was not cancelled"
        );
        Ok(())
    })
}

#[test]
fn a_repeated_dispatch_starts_one_run() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new()?;
        let first = fixture.task("again").await?;
        let second = fixture.task("again").await?;
        assert_ne!(first, second, "each call gets its own handle");
        let root = fixture.open_root()?;

        fixture.run_step(root, "artifact:first")?;
        fixture.run_step(root, "artifact:second")?;
        let one = fixture.tasks(Caller::Owner, "get", &first).await?;
        let two = fixture.tasks(Caller::Owner, "get", &second).await?;
        assert_eq!(one["result"]["status"], "completed", "{one}");
        assert_eq!(
            task_run(&one)["root_attempt_ref"],
            task_run(&two)["root_attempt_ref"],
            "both handles wrap the one run"
        );
        Ok(())
    })
}

#[test]
fn tasks_methods_refuse_a_request_that_does_not_declare() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new()?;
        let id = fixture.task("undeclared-poll").await?;
        let (status, reply) = fixture
            .rpc(Caller::Owner, "tasks/get", json!({ "taskId": id }))
            .await?;
        assert_eq!(status, 200, "{reply}");
        assert_eq!(reply["error"]["code"], -32021, "{reply}");
        assert_eq!(
            reply["error"]["data"]["requiredCapabilities"]["extensions"][TASKS],
            json!({}),
            "the refusal names the extension to declare: {reply}"
        );
        Ok(())
    })
}

#[test]
fn a_failed_run_ends_completed_with_is_error() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new()?;
        let id = fixture.task("fails").await?;
        let root = fixture.open_root()?;
        let dispatcher = AgentDispatcher::new(&fixture.vault);
        let leaf = dispatcher.workflow_status(root)?.active_step;
        // The step is stopped outside the run's own cancel, so the run fails.
        AttemptQueue::new(&fixture.vault).intervene(InterveneAttempt {
            id: leaf,
            kind: AttemptInterventionKind::Cancel,
            actor: "test-operator".to_owned(),
            note: None,
            now: fixture.vault.now_recorded_at(),
        })?;
        dispatcher.advance_workflow(root, fixture.vault.now_recorded_at())?;

        let got = fixture.tasks(Caller::Owner, "get", &id).await?;
        assert_eq!(got["result"]["status"], "completed", "{got}");
        assert_eq!(got["result"]["result"]["isError"], true, "{got}");
        assert_eq!(task_run(&got)["state"], "failed", "{got}");
        Ok(())
    })
}
