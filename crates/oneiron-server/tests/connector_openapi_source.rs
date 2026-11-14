//! An HTTP API its OpenAPI document describes is a connector (L8-31 PR 2,
//! canon agent-runtime `#translator-inputs`): `[connectors.<name>]` with
//! `transport = "http_api"` and a `document`, registered, stamped and
//! attested through the owner's routes, consented, and called through
//! `connector.call` on the core action door. The API is a loopback fixture
//! on a std `TcpListener` thread that records every request it receives.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support --test
//! connector_openapi_source`.
#![cfg(oneiron_test_support)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal, pairing_binding_transcript,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::secret_custody::{
    CustodyClass, CustodyTier, OwnerSecretRegistration, RequestedBinding,
};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_server::config::{ConnectorHostConfig, ConnectorTransport, SyncServerConfig};
use oneiron_server::{build_app, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const CONNECTOR: &str = "notes";
const SECRET_NAME: &str = "notes-api-token";
/// The custody value; the fixture echoes it back in its replies, so a reply
/// field that still holds it was not cleared.
const SECRET_VALUE: &str = "owen-notes-token-7f3a";
const CREATED_AT: u64 = 1_769_947_200;

/// One request the fixture API received.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

/// The loopback API: `GET /api/notes/{id}` answers a note whose text
/// echoes the bearer it was sent, `POST /api/notes` answers the note it
/// was given with 201, anything else 404.
struct NotesApi {
    endpoint: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl NotesApi {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture API");
        let port = listener.local_addr().expect("fixture address").port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let kept = Arc::clone(&seen);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let kept = Arc::clone(&kept);
                std::thread::spawn(move || answer(stream, &kept));
            }
        });
        Self {
            endpoint: format!("http://127.0.0.1:{port}/api"),
            seen,
        }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("fixture record").clone()
    }
}

fn answer(stream: TcpStream, seen: &Mutex<Vec<Seen>>) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone the fixture stream"));
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() || line.is_empty() {
        return;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let target = parts.next().unwrap_or_default().to_owned();
    let mut headers = BTreeMap::new();
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).is_err() || header.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let length = headers
        .get("content-length")
        .and_then(|length| length.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0; length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    let bearer = headers.get("authorization").cloned().unwrap_or_default();
    let (status, reply) = if method == "GET" && target.starts_with("/api/notes/") {
        (
            "200 OK",
            json!({"id": "n1", "text": format!("read with {bearer}")}),
        )
    } else if method == "POST" && target == "/api/notes" {
        let note: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        ("201 Created", note)
    } else {
        ("404 Not Found", json!({"error": "no such route"}))
    };
    seen.lock().expect("fixture record").push(Seen {
        method,
        target,
        headers,
        body,
    });
    let reply = reply.to_string();
    let mut stream = stream;
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
         connection: close\r\n\r\n{reply}",
        reply.len()
    );
}

/// The notes API's OpenAPI 3.1 document: two reads, a create that takes
/// an `Idempotency-Key` header, and a delete, under bearer security.
fn notes_document() -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {"title": "Notes", "version": "1"},
        "security": [{"bearer": []}],
        "components": {
            "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
            "schemas": {
                "Note": {
                    "type": "object",
                    "properties": {"id": {"type": "string"}, "text": {"type": "string"}},
                    "required": ["id"]
                }
            }
        },
        "paths": {
            "/notes/{id}": {
                "parameters": [
                    {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}
                ],
                "get": {
                    "operationId": "getNote",
                    "summary": "Read one note.",
                    "responses": {"200": {"description": "ok", "content": {"application/json": {
                        "schema": {"$ref": "#/components/schemas/Note"}}}}}
                },
                "delete": {
                    "operationId": "deleteNote",
                    "responses": {"204": {"description": "gone"}}
                }
            },
            "/notes": {
                "get": {
                    "operationId": "listNotes",
                    "parameters": [{"name": "tag", "in": "query", "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "ok", "content": {"application/json": {
                        "schema": {"type": "array", "items": {"$ref": "#/components/schemas/Note"}}}}}}
                },
                "post": {
                    "operationId": "createNote",
                    "x-oneiron-destructive": false,
                    "parameters": [
                        {"name": "Idempotency-Key", "in": "header", "required": true,
                         "schema": {"type": "string"}}
                    ],
                    "requestBody": {"required": true, "content": {"application/json": {
                        "schema": {"$ref": "#/components/schemas/Note"}}}},
                    "responses": {"201": {"description": "made", "content": {"application/json": {
                        "schema": {"$ref": "#/components/schemas/Note"}}}}}
                }
            }
        }
    })
}

/// One paired agent credential (as `consent_revoke_grantee_renounce.rs`
/// pairs one).
struct Agent {
    principal: EntityId,
    holder: SigningKey,
    slip: CapabilitySlip,
    token: String,
}

struct Fixture {
    app: Router,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
    root_token: String,
    api: NotesApi,
    _dir: tempfile::TempDir,
    _documents: tempfile::TempDir,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl Fixture {
    /// A rooted, profiled vault (as `mcp_server_discover.rs` builds one)
    /// whose server installs `[connectors.notes]` as an HTTP API at the
    /// fixture's endpoint, with `document` written to a file, and the
    /// API's bearer token in owner custody for `connector:notes`.
    fn new(document: &Value) -> Self {
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("serving profile");
        let (_, owner) = embedded_owner(&vault).expect("embedded owner");
        vault
            .register_secret_as_owner(
                &owner,
                &OwnerSecretRegistration {
                    name: SECRET_NAME,
                    class: CustodyClass::CustodyDeviceBound,
                    device_only: true,
                    rung: CustodyTier::T0Doored,
                    bindings: vec![RequestedBinding {
                        effector: format!("connector:{CONNECTOR}"),
                        tier_ceiling: None,
                        scopes: vec!["read".to_owned()],
                    }],
                    manifest: None,
                    value: SECRET_VALUE.as_bytes(),
                },
                CREATED_AT,
            )
            .expect("register the API token");
        let root = vault.ensure_host_root_slip(&issuer).expect("root slip");
        let root_token = root.to_token().expect("root token");
        let api = NotesApi::start();
        let documents = tempfile::tempdir().expect("temporary document directory");
        let document_path = documents.path().join("notes-openapi.json");
        std::fs::write(&document_path, document.to_string()).expect("write the document");
        let mut connectors = BTreeMap::new();
        connectors.insert(
            CONNECTOR.to_owned(),
            ConnectorHostConfig {
                transport: ConnectorTransport::HttpApi,
                endpoint: api.endpoint.clone(),
                document: Some(document_path.to_string_lossy().into_owned()),
            },
        );
        let server = Arc::new(
            SyncServer::new(
                Arc::clone(&vault),
                SyncServerConfig {
                    auth_secret: Some("connector-openapi-source".into()),
                    connectors,
                    ..Default::default()
                },
            )
            .expect("create server"),
        );
        Self {
            app: build_app(server),
            vault,
            issuer,
            root,
            root_token,
            api,
            _dir: dir,
            _documents: documents,
        }
    }

    fn owner_binding(&self) -> String {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature = hex(&self
            .issuer
            .binding_proof(&self.root, challenge.as_bytes())
            .expect("owner holder proof"));
        json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
    }

    fn agent_binding(&self, agent: &Agent) -> String {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let transcript = agent
            .slip
            .binding_transcript(challenge.as_bytes())
            .expect("agent binding transcript");
        let signature = hex(&agent.holder.sign(&transcript).to_bytes());
        json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
    }

    async fn post(
        &self,
        path: &str,
        token: &str,
        binding: Option<String>,
        body: &Value,
    ) -> (StatusCode, Value) {
        let mut request = Request::post(path)
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json");
        if let Some(binding) = binding {
            request = request.header("x-oneiron-binding", binding);
        }
        let response = self
            .app
            .clone()
            .oneshot(request.body(Body::from(body.to_string())).expect("request"))
            .await
            .expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .expect("response body");
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        (status, body)
    }

    /// One owner route, under the root slip and a fresh holder proof.
    async fn owner(&self, route: &str, body: &Value) -> (StatusCode, Value) {
        let binding = self.owner_binding();
        self.post(
            &format!("/v1/owner/connectors/{route}"),
            &self.root_token,
            Some(binding),
            body,
        )
        .await
    }

    /// One `connector.call` on the core action door, as `agent`, under the
    /// action idempotency key `key`.
    async fn call(&self, agent: &Agent, key: &str, call: Value) -> (StatusCode, Value) {
        let binding = self.agent_binding(agent);
        self.post(
            "/v1/core/actions/connector.call",
            &agent.token,
            Some(binding),
            &json!({"args": [{"kind": "json", "value": call}], "idempotencyKey": key}),
        )
        .await
    }

    /// Pairs one agent over the real pairing route with `core:read` and
    /// `core:write`.
    async fn pair_agent(&self, name: &str, seed: [u8; 32]) -> Agent {
        let principal = self
            .vault
            .ensure_agent_principal(name)
            .expect("agent principal");
        let holder = SigningKey::from_bytes(&seed);
        let binding_key = holder.verifying_key().to_bytes();
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(BTreeSet::from([
            "core:read".to_owned(),
            "core:write".to_owned(),
        ]));
        let link = self
            .vault
            .issue_pairing_link_for_principal(
                &self.issuer,
                scope,
                3600,
                PairingPrincipal {
                    holder_ref: Some(principal.to_hex()),
                    actor_class: Some("agent".to_owned()),
                    org_ref: None,
                    write_facet: None,
                    ..Default::default()
                },
            )
            .expect("pairing link");
        let transcript = pairing_binding_transcript(&link.code, &binding_key, &principal.to_hex())
            .expect("pairing transcript");
        let request = Request::post("/v1/core/pairing/redeem")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "code": link.code,
                    "holder_ref": principal.to_hex(),
                    "binding_key": hex(&binding_key),
                    "signature": hex(&holder.sign(&transcript).to_bytes()),
                })
                .to_string(),
            ))
            .expect("pairing redeem request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("pairing redeem response");
        assert_eq!(response.status(), StatusCode::OK, "pairing redeem status");
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("pairing redeem body");
        let body: Value = serde_json::from_slice(&bytes).expect("pairing redeem JSON");
        let token = body["token"].as_str().expect("paired token").to_owned();
        let slip = CapabilitySlip::from_token(&token).expect("paired slip");
        Agent {
            principal,
            holder,
            slip,
            token,
        }
    }

    /// Registers the connector, stamps `getNote` and `createNote` always
    /// allowed, attests it, pairs an agent and consents both tools to it.
    async fn admitted(&self) -> Agent {
        let (status, registered) = self
            .owner(
                "register",
                &json!({"connector": CONNECTOR, "summary": "Notes API", "secret_ref": SECRET_NAME}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "register: {registered}");
        let revision = registered["slate"]["revision"]
            .as_u64()
            .expect("slate revision");
        let (status, accepted) = self
            .owner(
                "slate/accept",
                &json!({"connector": CONNECTOR, "revision": revision,
                        "rows": {"getNote": "always_allow", "createNote": "always_allow"}}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "slate accept: {accepted}");
        let (status, attested) = self.owner("attest", &json!({"connector": CONNECTOR})).await;
        assert_eq!(status, StatusCode::OK, "attest: {attested}");
        let agent = self.pair_agent("notes-agent", [0x31; 32]).await;
        let (status, consented) = self
            .owner(
                "consent",
                &json!({
                    "connector": CONNECTOR,
                    "actor": agent.principal.to_hex(),
                    "endpoint": self.api.endpoint,
                    "rows": [
                        {"tool": "getNote", "ceiling": "personal", "headers": false},
                        {"tool": "createNote", "ceiling": "personal", "headers": false}
                    ]
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "consent: {consented}");
        agent
    }
}

/// The first value under `key` anywhere in `value`, depth first.
fn find<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    match value {
        Value::Object(map) => map
            .get(key)
            .or_else(|| map.values().find_map(|inner| find(inner, key))),
        Value::Array(items) => items.iter().find_map(|inner| find(inner, key)),
        _ => None,
    }
}

/// The slate row named `tool` in a register reply.
fn slate_row<'a>(registered: &'a Value, tool: &str) -> &'a Value {
    registered["slate"]["manifest"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["name"] == tool))
        .unwrap_or_else(|| panic!("no slate row {tool}: {registered}"))
}

#[test]
fn register_translates_each_operation_into_a_slate_row() {
    run_on_engine_stack("register-translates-each-operation", || async {
        let fixture = Fixture::new(&notes_document());
        let (status, registered) = fixture
            .owner(
                "register",
                &json!({"connector": CONNECTOR, "summary": "Notes API", "secret_ref": SECRET_NAME}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "register: {registered}");
        assert_eq!(
            registered["protocol_revision"], "openapi-3.1",
            "{registered}"
        );
        let names: BTreeSet<&str> = registered["slate"]["manifest"]
            .as_array()
            .expect("slate manifest")
            .iter()
            .filter_map(|row| row["name"].as_str())
            .collect();
        assert_eq!(
            names,
            BTreeSet::from(["createNote", "deleteNote", "getNote", "listNotes"])
        );

        let get = slate_row(&registered, "getNote");
        assert_eq!(
            (get["read_only"].as_bool(), get["destroys"].as_bool()),
            (Some(true), Some(false))
        );
        assert_eq!(get["http"]["method"], "GET");
        assert_eq!(get["http"]["path"], "/notes/{id}");
        assert_eq!(
            get["resolved_output_schema"]["properties"]["id"]["type"], "string",
            "the 200 reply's schema rides the row: {get}"
        );
        assert_eq!(slate_row(&registered, "listNotes")["read_only"], true);
        assert_eq!(
            slate_row(&registered, "listNotes")["http"]["query"],
            json!(["tag"])
        );

        let delete = slate_row(&registered, "deleteNote");
        assert_eq!(
            (delete["read_only"].as_bool(), delete["destroys"].as_bool()),
            (Some(false), Some(true))
        );
        assert_eq!(delete["http"]["method"], "DELETE");

        // The intent key fills the create's Idempotency-Key: no argument
        // sets it, so no header data class is asked, and a resend after an
        // ambiguous reply is safe.
        let create = slate_row(&registered, "createNote");
        assert_eq!(create["read_only"], false);
        assert_eq!(
            create["destroys"], false,
            "x-oneiron-destructive: false: {create}"
        );
        assert_eq!(create["idempotent"], true, "{create}");
        assert_eq!(create["header_parameters"], json!([]), "{create}");
        assert_eq!(create["http"]["method"], "POST");
        assert_eq!(
            create["http"]["idempotency_header"], "Idempotency-Key",
            "{create}"
        );
        assert_eq!(create["http"]["json_body"], true);
        assert!(
            create["resolved_input_schema"]["properties"]["body"].is_object(),
            "the request body is the `body` argument: {create}"
        );
        assert!(
            fixture.api.seen().is_empty(),
            "registration never calls the API"
        );
    });
}

#[test]
fn a_get_call_sends_one_request_to_the_installed_endpoint_with_the_held_token() {
    run_on_engine_stack("get-call-sends-one-request", || async {
        let fixture = Fixture::new(&notes_document());
        let agent = fixture.admitted().await;
        let (status, answer) = fixture
            .call(
                &agent,
                "get-note-1",
                json!({"name": CONNECTOR, "source": "catalog", "tool": "getNote",
                       "arguments": {"id": "n 1/.."}, "mutation": "preview"}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "connector.call: {answer}");
        let seen = fixture.api.seen();
        assert_eq!(seen.len(), 1, "one request: {seen:?}");
        assert_eq!(seen[0].method, "GET");
        assert_eq!(
            seen[0].target, "/api/notes/n%201%2F..",
            "the id is one segment under the installed endpoint"
        );
        assert_eq!(
            seen[0].headers.get("authorization").map(String::as_str),
            Some(format!("Bearer {SECRET_VALUE}").as_str())
        );
        let structured = find(&answer, "structured_content")
            .or_else(|| find(&answer, "structuredContent"))
            .unwrap_or_else(|| panic!("no structured content: {answer}"));
        assert_eq!(structured["id"], "n1", "{answer}");
        assert!(
            !answer.to_string().contains(SECRET_VALUE),
            "the reply echoed the token, and every field was cleared of it: {answer}"
        );
    });
}

#[test]
fn a_post_carries_the_intent_key_and_a_replay_sends_nothing() {
    run_on_engine_stack("post-carries-the-intent-key", || async {
        let fixture = Fixture::new(&notes_document());
        let agent = fixture.admitted().await;
        let create = json!({"name": CONNECTOR, "source": "catalog", "tool": "createNote",
                            "arguments": {"body": {"id": "n2", "text": "made by owen"}},
                            "mutation": "explicit_mutation"});
        let (status, first) = fixture.call(&agent, "create-note-1", create.clone()).await;
        assert_eq!(status, StatusCode::OK, "first create: {first}");
        let (status, second) = fixture.call(&agent, "create-note-1", create).await;
        assert_eq!(status, StatusCode::OK, "replayed create: {second}");
        let seen = fixture.api.seen();
        assert_eq!(seen.len(), 1, "the replay sent nothing: {seen:?}");
        assert_eq!(
            (seen[0].method.as_str(), seen[0].target.as_str()),
            ("POST", "/api/notes")
        );
        let key = seen[0]
            .headers
            .get("idempotency-key")
            .unwrap_or_else(|| panic!("no Idempotency-Key: {:?}", seen[0]));
        assert!(
            key.len() == 64 && key.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "the call's 32-byte intent key in hex: {key}"
        );
        let body: Value = serde_json::from_slice(&seen[0].body).expect("JSON body");
        assert_eq!(body, json!({"id": "n2", "text": "made by owen"}));
        let structured = find(&second, "structured_content")
            .or_else(|| find(&second, "structuredContent"))
            .unwrap_or_else(|| panic!("no structured content in the replay: {second}"));
        assert_eq!(structured["id"], "n2", "{second}");
    });
}

#[test]
fn the_document_cannot_send_calls_elsewhere() {
    run_on_engine_stack("document-cannot-send-elsewhere", || async {
        let mut document = notes_document();
        document["servers"] = json!([{"url": "https://other.example/api"}]);
        let fixture = Fixture::new(&document);
        let (status, refused) = fixture
            .owner(
                "register",
                &json!({"connector": CONNECTOR, "summary": "Notes API", "secret_ref": SECRET_NAME}),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "register: {refused}");
        assert!(
            refused.to_string().contains("https://other.example"),
            "{refused}"
        );
    });
}

#[test]
fn qualify_refuses_an_http_api_key_and_names_attest() {
    run_on_engine_stack("qualify-refuses-http-api", || async {
        let fixture = Fixture::new(&notes_document());
        let (status, registered) = fixture
            .owner(
                "register",
                &json!({"connector": CONNECTOR, "summary": "Notes API", "secret_ref": SECRET_NAME}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "register: {registered}");
        let case = json!({"call": {"id": "u1", "name": "getNote", "arguments": {}},
                          "in_scope": true, "allowed_predicates": []});
        let kit = json!({
            "plan": {"reads": [], "unanswerable": case, "injections": [], "scope_escape": [],
                     "write": null, "timeout_retry": null, "handled_result_types": [],
                     "limits": {"tokens": 1000, "latency_ms": 1000, "budget_units": 1}},
            "effect_state_uri": format!("{}/state", fixture.api.endpoint),
        });
        let (status, refused) = fixture
            .owner("qualify", &json!({"connector": CONNECTOR, "kit": kit}))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "qualify: {refused}");
        assert!(
            refused.to_string().contains("/v1/owner/connectors/attest"),
            "{refused}"
        );

        let revision = registered["slate"]["revision"]
            .as_u64()
            .expect("slate revision");
        let (status, accepted) = fixture
            .owner(
                "slate/accept",
                &json!({"connector": CONNECTOR, "revision": revision, "rows": {}}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "slate accept: {accepted}");
        let (status, attested) = fixture
            .owner("attest", &json!({"connector": CONNECTOR}))
            .await;
        assert_eq!(status, StatusCode::OK, "attest: {attested}");
        assert_eq!(
            find(&attested, "status").and_then(Value::as_str),
            Some("active"),
            "{attested}"
        );
        assert!(fixture.api.seen().is_empty(), "neither door calls the API");
    });
}

#[test]
fn an_operation_without_an_operation_id_or_with_an_external_ref_is_refused() {
    run_on_engine_stack("operation-id-and-external-ref", || async {
        let mut nameless = notes_document();
        nameless["paths"]["/notes/{id}"]["delete"]
            .as_object_mut()
            .expect("delete operation")
            .remove("operationId");
        let mut external = notes_document();
        external["paths"]["/notes"]["post"]["requestBody"]["content"]["application/json"]["schema"] =
            json!({"$ref": "https://schemas.example/note.json"});
        for (document, names) in [
            (nameless, "DELETE /notes/{id} has no operationId"),
            (external, "operation createNote"),
        ] {
            let fixture = Fixture::new(&document);
            let (status, refused) = fixture
                .owner(
                    "register",
                    &json!({"connector": CONNECTOR, "summary": "Notes API",
                            "secret_ref": SECRET_NAME}),
                )
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "register: {refused}");
            assert!(refused.to_string().contains(names), "{names}: {refused}");
        }
    });
}
