//! L8-29 (canon agent-runtime-v1 `#mcp-tasks-outbound`, ONEIRON-MCP-TASKS =
//! AB; ruling L8-29-CANCEL-TRIGGER = B): the owner stops a remote MCP task
//! with one `tasks/cancel`, which undoes nothing already done. The owner asks
//! on the call (`POST /v1/owner/connectors/remote-tasks/{intent}/cancel`) or
//! stops the try that made it; the served poll sends the stop once, records
//! how it went, never sends it again, and leaves the send Deferred until a
//! poll reads the task's end. A send whose task keeps no poll is refused as
//! `remote_task_unpollable`. On main nothing sends `tasks/cancel`: the route
//! does not exist and the owner's Stop leaves a Deferred send as it is.
//!
//! The Deferred sends are written through `oneiron::test_doors`, as a
//! connector's task answer leaves one; the connector is a stub MCP endpoint on
//! loopback that records each JSON-RPC method it is sent. The poll pass runs
//! through `oneiron_server::test_doors`, as the connector settler runs it.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support
//! --test remote_task_cancel`.
#![cfg(oneiron_test_support)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::body::{Body, Bytes, to_bytes};
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use engine_stack::run_on_engine_stack;
use oneiron::attempt_queue::AttemptId;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer};
use oneiron::connector_key::{
    ConnectorCallClass, ConnectorCatalogEntry, ConnectorKeySpec, SlateDataClass, SlateToolManifest,
    draft_connector_slate,
};
use oneiron::outbound_intent_ledger::{IntentState, RemoteTaskCredential, RemoteTaskPoll};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::remote_task_cancel::{
    DeferredConnectorSend, defer_connector_send, intent_state, stop_try_sends,
};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::config::{ConnectorHostConfig, ConnectorTransport, SyncServerConfig};
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::remote_task_poll::poll_remote_tasks_once;
use serde_json::{Value, json};
use tower::ServiceExt;

const TASK_CONNECTOR: &str = "taskstub";
const TASK_TOOL: &str = "long_report";
const TASK_ID: &str = "task-report-1";
const TASK_PROTOCOL: &str = "2025-11-25";
const CONNECTOR_REVISION: &str = "2026-09-01";
const NOW_SECS: u64 = 1_700_000_000;

/// The stub connector: every JSON-RPC method it was sent, with the task id
/// its params named, and the HTTP status it answers `tasks/cancel` with.
struct TaskStub {
    seen: Mutex<Vec<(String, Option<String>)>>,
    cancel_status: StatusCode,
}

impl TaskStub {
    fn methods(&self) -> Vec<String> {
        self.seen
            .lock()
            .expect("the stub's record")
            .iter()
            .map(|(method, _)| method.clone())
            .collect()
    }

    /// The task id of each `tasks/cancel` the stub was sent.
    fn cancels(&self) -> Vec<Option<String>> {
        self.seen
            .lock()
            .expect("the stub's record")
            .iter()
            .filter(|(method, _)| method == "tasks/cancel")
            .map(|(_, task)| task.clone())
            .collect()
    }
}

/// One MCP POST to the stub: recorded, then answered as a task that is
/// still working, or, for `tasks/cancel`, cancelled under the stub's status.
async fn stub_answer(State(stub): State<Arc<TaskStub>>, body: Bytes) -> Response {
    let message: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let method = message
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let task = message
        .pointer("/params/taskId")
        .and_then(Value::as_str)
        .map(str::to_owned);
    stub.seen
        .lock()
        .expect("the stub's record")
        .push((method.clone(), task.clone()));
    let id = message.get("id").cloned().unwrap_or(Value::Null);
    let (status, state) = if method == "tasks/cancel" {
        (stub.cancel_status, "cancelled")
    } else {
        (StatusCode::OK, "working")
    };
    (
        status,
        Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "taskId": task, "status": state },
        })),
    )
        .into_response()
}

/// A session end (`DELETE`) to the stub: recorded and taken.
async fn stub_end(State(stub): State<Arc<TaskStub>>) -> StatusCode {
    stub.seen
        .lock()
        .expect("the stub's record")
        .push(("DELETE".to_owned(), None));
    StatusCode::OK
}

/// Serves the stub on loopback: its endpoint.
async fn serve_stub(stub: &Arc<TaskStub>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the stub connector");
    let address = listener.local_addr().expect("the stub's address");
    let app = Router::new()
        .route("/mcp", post(stub_answer).delete(stub_end))
        .with_state(Arc::clone(stub));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve the stub");
    });
    format!("http://{address}/mcp")
}

/// The catalog connector `taskstub`, admitted Active by the owner's
/// attestation, so its calls route, as `tests/verb_connector_call_source_rows.rs`
/// admits one.
fn admit_connector(vault: &Vault) {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("the owner's proof");
    let manifest = vec![SlateToolManifest {
        name: TASK_TOOL.to_owned(),
        data_class: SlateDataClass::Personal,
        header_parameters: Vec::new(),
        resolved_input_schema: Some(json!({ "type": "object" })),
        trigger: None,
        destroys: false,
        spends: false,
        sends_outward: false,
        legacy_ask: false,
        read_only: false,
        idempotent: false,
        price: None,
    }];
    let slate = vault
        .store_connector_slate(
            &manifest,
            &serde_json::to_string(&draft_connector_slate(&manifest)).expect("draft slate"),
        )
        .expect("the owner stores the connector slate");
    let (key, _pending) = vault
        .register_connector(
            ConnectorCatalogEntry {
                name: TASK_CONNECTOR.to_owned(),
                connector: TASK_CONNECTOR.to_owned(),
                summary: "Long report connector".to_owned(),
                verbs: vec!["report".to_owned()],
                call_class: ConnectorCallClass::ScopedMcp,
                registered_at: 0,
            },
            ConnectorKeySpec {
                slate_ref: Some(slate),
                protocol_revision: Some(CONNECTOR_REVISION.to_owned()),
                ..ConnectorKeySpec::new(TASK_CONNECTOR)
            },
            NOW_SECS,
        )
        .expect("the owner registers the catalog connector");
    vault
        .override_connector_slate(&proof, slate, 0, &BTreeMap::new())
        .expect("the owner stamps the slate");
    vault
        .attest_connector_key(&proof, &key, CONNECTOR_REVISION, NOW_SECS + 1)
        .expect("the owner attests the connector active");
    assert!(
        vault
            .route_connector_call(TASK_CONNECTOR)
            .expect("the route reads")
            .is_some(),
        "the attested connector routes"
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// A served vault whose `[connectors]` install the stub, and the owner's
/// client for its routes.
struct CancelFixture {
    vault: Arc<Vault>,
    server: Arc<SyncServer>,
    app: Router,
    issuer: HostSlipIssuer,
    slip: CapabilitySlip,
    token: String,
    endpoint: String,
    stub: Arc<TaskStub>,
    // Dropped after the vault.
    _dir: tempfile::TempDir,
}

impl CancelFixture {
    async fn new(cancel_status: StatusCode) -> Self {
        let stub = Arc::new(TaskStub {
            seen: Mutex::new(Vec::new()),
            cancel_status,
        });
        let endpoint = serve_stub(&stub).await;
        let dir = tempfile::tempdir().expect("a temp dir");
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open a vault"));
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        vault.prepare_install_signing().expect("install signing");
        admit_connector(&vault);
        let mut connectors = BTreeMap::new();
        connectors.insert(
            TASK_CONNECTOR.to_owned(),
            ConnectorHostConfig {
                transport: ConnectorTransport::McpHttp,
                endpoint: endpoint.clone(),
            },
        );
        let server = Arc::new(
            SyncServer::new(
                Arc::clone(&vault),
                SyncServerConfig {
                    auth_secret: Some("remote-task-cancel-owner".into()),
                    connectors,
                    ..Default::default()
                },
            )
            .expect("serve the vault"),
        );
        let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
        let slip = vault
            .ensure_host_root_slip(&issuer)
            .expect("the owner's root slip");
        let token = slip.to_token().expect("the owner's slip token");
        Self {
            app: oneiron_server::build_app(Arc::clone(&server)),
            vault,
            server,
            issuer,
            slip,
            token,
            endpoint,
            stub,
            _dir: dir,
        }
    }

    /// A Deferred send of `attempt` whose task the stub runs, polled with
    /// the route's own credential in the stub's session, or kept with no
    /// poll when `polled` is false.
    fn deferred_send(&self, attempt: u8, polled: bool) -> [u8; 32] {
        let poll = polled.then(|| RemoteTaskPoll {
            session: Some("stub-session".to_owned()),
            protocol: TASK_PROTOCOL.to_owned(),
            credential: RemoteTaskCredential::Route,
            form_elicitation: false,
        });
        let intent = defer_connector_send(
            &self.vault,
            DeferredConnectorSend {
                attempt: AttemptId::from_bytes(&[attempt; 16]).expect("an attempt id"),
                server: TASK_CONNECTOR,
                tool: TASK_TOOL,
                endpoint: &self.endpoint,
                task_id: TASK_ID,
                poll,
                now_ms: now_ms(),
            },
        )
        .expect("the connector's task answer defers the send");
        assert_eq!(self.state(&intent), Some(IntentState::Deferred));
        intent
    }

    fn state(&self, intent: &[u8; 32]) -> Option<IntentState> {
        intent_state(&self.vault, intent).expect("the send's state reads")
    }

    /// One pass of the served poll, on a blocking worker.
    async fn poll_once(&self) {
        let server = Arc::clone(&self.server);
        tokio::task::spawn_blocking(move || poll_remote_tasks_once(&server))
            .await
            .expect("the poll pass");
    }

    /// The task's next poll due now, however long its backoff.
    async fn poll_again(&self, intent: &[u8; 32]) {
        self.vault
            .remote_task_polls_due_at(&[*intent], now_ms())
            .expect("the poll made due");
        self.poll_once().await;
    }

    /// The owner's `POST .../remote-tasks/{intent}/cancel`.
    async fn cancel(&self, intent: &[u8; 32]) -> (StatusCode, Value) {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature = hex(&self
            .issuer
            .binding_proof(&self.slip, challenge.as_bytes())
            .expect("a fresh owner holder proof"));
        let request = Request::post(format!(
            "/v1/owner/connectors/remote-tasks/{}/cancel",
            hex(intent)
        ))
        .header("authorization", format!("Bearer {}", self.token))
        .header(
            "x-oneiron-binding",
            json!({ "timestamp": timestamp, "nonce": nonce, "signature": signature }).to_string(),
        )
        .body(Body::empty())
        .expect("the owner's request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("the owner's response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("the owner's response body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn cancel_phase(&self, intent: &[u8; 32]) -> String {
        let (status, body) = self.cancel(intent).await;
        assert_eq!(status, StatusCode::OK, "the owner's cancel: {body}");
        body["phase"]
            .as_str()
            .unwrap_or_else(|| panic!("a phase in {body}"))
            .to_owned()
    }
}

#[test]
fn the_owners_cancel_sends_one_tasks_cancel_and_the_send_stays_deferred() {
    run_on_engine_stack("remote_task_cancel_owner", || async {
        let fixture = CancelFixture::new(StatusCode::OK).await;
        let intent = fixture.deferred_send(0x29, true);
        assert_eq!(fixture.cancel_phase(&intent).await, "requested");

        fixture.poll_once().await;
        assert_eq!(
            fixture.stub.cancels(),
            vec![Some(TASK_ID.to_owned())],
            "one tasks/cancel names the task: {:?}",
            fixture.stub.methods()
        );
        assert_eq!(
            fixture.state(&intent),
            Some(IntentState::Deferred),
            "a stop undoes nothing: only the task's end settles the send"
        );
        assert_eq!(fixture.cancel_phase(&intent).await, "sent");

        fixture.poll_again(&intent).await;
        assert_eq!(
            fixture.stub.cancels().len(),
            1,
            "the stop is never sent again"
        );
        assert!(
            !fixture
                .stub
                .methods()
                .iter()
                .any(|method| method == "tools/call"),
            "the call itself is never sent again"
        );
    });
}

#[test]
fn a_cancel_whose_outcome_is_unknown_is_never_sent_again() {
    run_on_engine_stack("remote_task_cancel_uncertain", || async {
        let fixture = CancelFixture::new(StatusCode::INTERNAL_SERVER_ERROR).await;
        let intent = fixture.deferred_send(0x2A, true);
        assert_eq!(fixture.cancel_phase(&intent).await, "requested");

        fixture.poll_once().await;
        assert_eq!(fixture.stub.cancels(), vec![Some(TASK_ID.to_owned())]);
        assert_eq!(fixture.cancel_phase(&intent).await, "uncertain");

        fixture.poll_again(&intent).await;
        assert_eq!(
            fixture.stub.cancels().len(),
            1,
            "an uncertain stop is never sent again"
        );
        assert_eq!(fixture.state(&intent), Some(IntentState::Deferred));
    });
}

#[test]
fn a_cancel_the_connector_refused_stays_claimed_and_is_never_sent_again() {
    run_on_engine_stack("remote_task_cancel_refused", || async {
        let fixture = CancelFixture::new(StatusCode::BAD_REQUEST).await;
        let intent = fixture.deferred_send(0x2B, true);
        assert_eq!(fixture.cancel_phase(&intent).await, "requested");

        fixture.poll_once().await;
        assert_eq!(fixture.stub.cancels(), vec![Some(TASK_ID.to_owned())]);
        assert_eq!(
            fixture.cancel_phase(&intent).await,
            "sending",
            "a claimed stop the connector did not take stays claimed"
        );

        fixture.poll_again(&intent).await;
        assert_eq!(
            fixture.stub.cancels().len(),
            1,
            "a claimed stop is never sent again"
        );
        assert_eq!(fixture.state(&intent), Some(IntentState::Deferred));
    });
}

#[test]
fn the_owners_stop_of_a_try_sends_tasks_cancel_for_its_deferred_send() {
    run_on_engine_stack("remote_task_cancel_stop", || async {
        let fixture = CancelFixture::new(StatusCode::OK).await;
        let intent = fixture.deferred_send(0x2C, true);
        stop_try_sends(
            &fixture.vault,
            AttemptId::from_bytes(&[0x2C; 16]).expect("the try's id"),
            NOW_SECS + 2,
        )
        .expect("the owner's Stop writes");

        fixture.poll_once().await;
        assert_eq!(
            fixture.stub.cancels(),
            vec![Some(TASK_ID.to_owned())],
            "the stopped try's task is asked to stop: {:?}",
            fixture.stub.methods()
        );
        assert_eq!(fixture.state(&intent), Some(IntentState::Deferred));
        assert_eq!(fixture.cancel_phase(&intent).await, "sent");
    });
}

#[test]
fn a_cancel_of_a_send_whose_task_keeps_no_poll_is_refused_unpollable() {
    run_on_engine_stack("remote_task_cancel_unpollable", || async {
        let fixture = CancelFixture::new(StatusCode::OK).await;
        let intent = fixture.deferred_send(0x2D, false);
        let (status, body) = fixture.cancel(&intent).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(
            body.to_string().contains("remote_task_unpollable"),
            "the refusal names the unpollable task: {body}"
        );

        fixture.poll_once().await;
        assert!(
            fixture.stub.cancels().is_empty(),
            "nothing carries the stop"
        );
        assert_eq!(fixture.state(&intent), Some(IntentState::Deferred));
    });
}
