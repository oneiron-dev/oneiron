//! A Google API its Discovery document describes is a connector (L8-31
//! PR 3, canon agent-runtime `#translator-inputs`: "The Google pack starts
//! typed from Google's Discovery documents"): `[connectors.<name>]` with
//! `transport = "http_api"` and the document, registered, stamped and
//! attested through the owner's routes, consented, and called through
//! `connector.call` on the core action door. The API is a loopback fixture
//! on a std `TcpListener` thread that records every request it receives.
//!
//! The document is Google's own: the Docs v1 Discovery document (revision
//! 20261109, `https://docs.googleapis.com/$discovery/rest?version=v1`) cut
//! to `documents.get` and `documents.batchUpdate` and the schemas they
//! reach, in `fixtures/discovery/docs-v1-trimmed.json`. Each test points its
//! `rootUrl` and `baseUrl` at the fixture's origin, as an owner installing
//! it would point the endpoint at Google's.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support --test
//! connector_discovery_source`.
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

const CONNECTOR: &str = "docs";
const SECRET_NAME: &str = "docs-api-token";
const SECRET_VALUE: &str = "owen-docs-token-5c2e";
const CREATED_AT: u64 = 1_769_947_200;

/// One request the fixture API received.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

/// The loopback API: `GET /v1/documents/{id}` answers a document,
/// anything else 404.
struct DocsApi {
    endpoint: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl DocsApi {
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
            endpoint: format!("http://127.0.0.1:{port}/"),
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
    let path = target.split('?').next().unwrap_or_default();
    let document = path.strip_prefix("/v1/documents/").unwrap_or_default();
    let (status, reply) = if method == "GET" && !document.is_empty() && !document.contains(':') {
        (
            "200 OK",
            json!({"documentId": document, "title": "Plan", "revisionId": "r1"}),
        )
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

/// Google's Docs v1 Discovery document, its root moved to `endpoint`.
fn docs_document(endpoint: &str) -> Value {
    let mut document: Value =
        serde_json::from_str(include_str!("fixtures/discovery/docs-v1-trimmed.json"))
            .expect("the fixture document is JSON");
    document["rootUrl"] = json!(endpoint);
    document["baseUrl"] = json!(endpoint);
    document
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
    api: DocsApi,
    _dir: tempfile::TempDir,
    _documents: tempfile::TempDir,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl Fixture {
    /// A rooted, profiled vault (as `mcp_server_discover.rs` builds one)
    /// whose server installs `[connectors.docs]` as an HTTP API at the
    /// fixture's endpoint, with Google's document (as `edit` changes it)
    /// written to a file, and the API's bearer token in owner custody for
    /// `connector:docs`.
    fn new(edit: impl FnOnce(&mut Value)) -> Self {
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
        let api = DocsApi::start();
        let mut document = docs_document(&api.endpoint);
        edit(&mut document);
        let documents = tempfile::tempdir().expect("temporary document directory");
        let document_path = documents.path().join("docs-v1-discovery.json");
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
                    auth_secret: Some("connector-discovery-source".into()),
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

    /// Registers the connector, stamps `documents.get` always allowed,
    /// attests it, pairs an agent and consents the tool to it.
    async fn admitted(&self) -> Agent {
        let (status, registered) = self
            .owner(
                "register",
                &json!({"connector": CONNECTOR, "summary": "Google Docs", "secret_ref": SECRET_NAME}),
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
                        "rows": {"documents.get": "always_allow"}}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "slate accept: {accepted}");
        let (status, attested) = self.owner("attest", &json!({"connector": CONNECTOR})).await;
        assert_eq!(status, StatusCode::OK, "attest: {attested}");
        let agent = self.pair_agent("docs-agent", [0x32; 32]).await;
        let (status, consented) = self
            .owner(
                "consent",
                &json!({
                    "connector": CONNECTOR,
                    "actor": agent.principal.to_hex(),
                    "endpoint": self.api.endpoint,
                    "rows": [
                        {"tool": "documents.get", "ceiling": "personal", "headers": false}
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

/// Registers the connector as the owner; the reply's status and body.
async fn register(fixture: &Fixture) -> (StatusCode, Value) {
    fixture
        .owner(
            "register",
            &json!({"connector": CONNECTOR, "summary": "Google Docs", "secret_ref": SECRET_NAME}),
        )
        .await
}

#[test]
fn register_names_each_method_by_its_discovery_id() {
    run_on_engine_stack("register-names-each-discovery-method", || async {
        let fixture = Fixture::new(|_| {});
        let (status, registered) = register(&fixture).await;
        assert_eq!(status, StatusCode::OK, "register: {registered}");
        assert_eq!(
            registered["protocol_revision"], "discovery-v1",
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
            BTreeSet::from(["documents.batchUpdate", "documents.get"])
        );

        let get = slate_row(&registered, "documents.get");
        assert_eq!(
            (get["read_only"].as_bool(), get["destroys"].as_bool()),
            (Some(true), Some(false))
        );
        assert_eq!(get["http"]["method"], "GET");
        assert_eq!(get["http"]["path"], "/v1/documents/{documentId}");
        assert_eq!(
            get["http"]["query"],
            json!([
                "suggestionsViewMode",
                "commentsViewMode",
                "includeTabsContent"
            ])
        );
        // `Document`, reached through `response.$ref`, types the reply.
        let output = &get["resolved_output_schema"];
        for field in ["documentId", "title", "revisionId", "body"] {
            assert!(
                output["properties"][field].is_object(),
                "Document.{field} rides the row: {output}"
            );
        }
        let typescript = oneiron::connector_key::typescript::output_typescript(output);
        assert!(
            typescript.contains("documentId?: string;"),
            "the reply's signature: {typescript}"
        );

        let batch = slate_row(&registered, "documents.batchUpdate");
        assert_eq!(
            (batch["read_only"].as_bool(), batch["destroys"].as_bool()),
            (Some(false), Some(true))
        );
        assert_eq!(batch["http"]["method"], "POST");
        assert_eq!(
            batch["http"]["path"],
            "/v1/documents/{documentId}:batchUpdate"
        );
        assert_eq!(batch["http"]["json_body"], true);
        assert_eq!(
            batch["resolved_input_schema"]["properties"]["body"]["properties"]["requests"]["type"],
            "array",
            "BatchUpdateDocumentRequest is the `body` argument: {batch}"
        );
        assert!(
            fixture.api.seen().is_empty(),
            "registration never calls the API"
        );
    });
}

#[test]
fn a_method_call_fills_its_path_and_query_parameters() {
    run_on_engine_stack("discovery-call-fills-path-and-query", || async {
        let fixture = Fixture::new(|_| {});
        let agent = fixture.admitted().await;
        let (status, answer) = fixture
            .call(
                &agent,
                "documents-get-1",
                json!({"name": CONNECTOR, "source": "catalog", "tool": "documents.get",
                       "arguments": {"documentId": "d1",
                                     "suggestionsViewMode": "PREVIEW_WITHOUT_SUGGESTIONS"},
                       "mutation": "preview"}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "connector.call: {answer}");
        let seen = fixture.api.seen();
        assert_eq!(seen.len(), 1, "one request: {seen:?}");
        assert_eq!(
            (seen[0].method.as_str(), seen[0].target.as_str()),
            (
                "GET",
                "/v1/documents/d1?suggestionsViewMode=PREVIEW_WITHOUT_SUGGESTIONS"
            )
        );
        assert_eq!(
            seen[0].headers.get("authorization").map(String::as_str),
            Some(format!("Bearer {SECRET_VALUE}").as_str())
        );
        assert!(seen[0].body.is_empty(), "a GET sends no body");
        let structured = find(&answer, "structured_content")
            .or_else(|| find(&answer, "structuredContent"))
            .unwrap_or_else(|| panic!("no structured content: {answer}"));
        assert_eq!(structured["documentId"], "d1", "{answer}");
    });
}

#[test]
fn a_media_upload_method_is_no_tool() {
    run_on_engine_stack("discovery-media-upload-is-no-tool", || async {
        // Docs v1 has no media method; this one is shaped as Google's
        // upload-only methods are: `mediaUpload` and no JSON request.
        let fixture = Fixture::new(|document| {
            document["resources"]["documents"]["methods"]["upload"] = json!({
                "id": "docs.documents.upload",
                "path": "v1/documents/{documentId}:upload",
                "flatPath": "v1/documents/{documentId}:upload",
                "httpMethod": "POST",
                "parameters": {"documentId": {"type": "string", "required": true,
                                              "location": "path"}},
                "parameterOrder": ["documentId"],
                "supportsMediaUpload": true,
                "mediaUpload": {"accept": ["*/*"], "maxSize": "10485760",
                                "protocols": {"simple": {"multipart": true,
                                    "path": "/upload/v1/documents/{documentId}:upload"}}}
            });
        });
        let (status, registered) = register(&fixture).await;
        assert_eq!(status, StatusCode::OK, "register: {registered}");
        let rows = registered["slate"]["manifest"]
            .as_array()
            .expect("slate manifest");
        assert!(
            rows.iter().all(|row| row["name"] != "documents.upload"),
            "{registered}"
        );
        assert_eq!(
            registered["skipped"],
            json!(["documents.upload: uploads media only, and code mode carries no binary body"]),
            "{registered}"
        );
    });
}
