//! The public path and signing API are separate from hosted device leases.
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use std::sync::Arc;
use tower::ServiceExt;

#[tokio::test]
async fn public_path_signing_bypasses_hosted_lease_but_not_capability_admission() {
    let dir = tempfile::tempdir().expect("create device vault directory");
    let vault = Arc::new(
        oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device())
            .expect("open device vault"),
    );
    let server = Arc::new(
        SyncServer::new(
            vault,
            SyncServerConfig {
                lease_vault_id: 1,
                auth_secret: Some("editor-owner-issuer".into()),
                ..Default::default()
            },
        )
        .expect("create device sync server"),
    );
    let app = build_app(server.clone());
    let token = "11".repeat(32);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/sign/{token}"))
                .body(Body::empty())
                .expect("build signing page request"),
        )
        .await
        .expect("serve signing page request");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
    assert!(
        response
            .headers()
            .contains_key(header::CONTENT_SECURITY_POLICY)
    );
    assert!(!response.headers().contains_key(header::LOCATION));
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    let body = to_bytes(response.into_body(), 128 * 1024)
        .await
        .expect("read signing page body");
    assert!(!String::from_utf8_lossy(&body).contains(&token));

    let malformed = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/sign/not-a-token")
                .body(Body::empty())
                .expect("build malformed-token request"),
        )
        .await
        .expect("serve malformed-token request");
    assert_eq!(malformed.status(), StatusCode::NOT_FOUND);
    assert_eq!(malformed.headers()[header::CACHE_CONTROL], "no-store");
    let unavailable = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/sign/action")
                .extension(axum::extract::ConnectInfo(
                    "127.0.0.1:12345"
                        .parse::<std::net::SocketAddr>()
                        .expect("parse loopback peer address"),
                ))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({"token":token,"action":{"action":"load"}}).to_string(),
                ))
                .expect("build signing action request"),
        )
        .await
        .expect("serve signing action request");
    assert_eq!(unavailable.status(), StatusCode::FORBIDDEN);
    assert_eq!(unavailable.headers()[header::CACHE_CONTROL], "no-store");
    // Bypassing the device lease is scoped to the ceremony, not its
    // owner-side geometry editor or the rest of the hosted API.
    for path in ["/sign/editor", "/api/openapi.json"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("build protected-path request"),
            )
            .await
            .expect("serve protected-path request");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
    // A logged owner slip, not a historical lease, reaches the editor shell.
    let issuer = oneiron::authority::HostSlipIssuer::from_secret(b"editor-owner-issuer").unwrap();
    let slip = server.vault().ensure_host_root_slip(&issuer).unwrap();
    let timestamp = server.vault().capability_slip_now().unwrap();
    let nonce = oneiron::EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature: String = issuer
        .binding_proof(&slip, challenge.as_bytes())
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let proof = serde_json::json!({"timestamp":timestamp,"nonce":nonce,"signature":signature});
    let editor = app
        .oneshot(
            Request::builder()
                .uri("/sign/editor")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", slip.to_token().unwrap()),
                )
                .header("x-oneiron-binding", proof.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(editor.status(), StatusCode::OK);
}

/// Seed a real sent request through the owner-authored send gate, not by
/// inventing a viewed/sent claim or bypassing the capability store.
fn sent_request() -> (
    tempfile::TempDir,
    Arc<SyncServer>,
    String,
    String,
    oneiron::EntityId,
) {
    use oneiron::blob_artifact::esign::{
        DocumentKind, EsignAuditActor, EsignDocument, EsignField, EsignItem, EsignOutboundCommand,
        EsignOutboundVerb, EsignRecipient, FieldGeometry, FieldMeta, RecipientRole,
    };
    use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
    use oneiron::federation::{Scope, ScopeAxis};
    use oneiron::outbound::{
        OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
        OutboundDispatchOutcome, OutboundDispatchRequest, OutboundIntent, OutboundIntentDraft,
        OutboundIntentSource, OutboundIntentTrigger,
    };
    use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

    let dir = tempfile::tempdir().expect("create signing fixture directory");
    let vault = Arc::new(
        Vault::open(dir.path(), VaultConfig::server()).expect("open signing fixture vault"),
    );
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("create embedded owner actor");
    let artifact = EntityId::now();
    let when = TimeRange { start: 1, end: 1 };
    vault
        .put_blob_artifact(
            &artifact,
            &BlobArtifactBody::new("agreement.pdf", "application/pdf"),
            when,
            1,
        )
        .expect("store signing PDF artifact");
    vault
        .append_blob_artifact_version(
            &artifact,
            include_bytes!("../../oneiron-seal/tests/fixtures/pdf-input/classic_1page.pdf"),
            &BlobVersionProvenance::UserUpload,
            WriteActor::new(owner, EdgeActorClass::Human),
            when,
            1,
        )
        .expect("append signing PDF version");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("read system time after Unix epoch")
        .as_secs();
    let recipient = EntityId::now().to_hex();
    let field = EntityId::now().to_hex();
    let document = EsignDocument {
        schema_version: 1,
        kind: DocumentKind::Document,
        title: "Agreement".into(),
        sequential: true,
        expires_at: now + 3600,
        items: vec![EsignItem {
            artifact_ref: artifact.to_hex(),
            original_version: 1,
        }],
        recipients: vec![EsignRecipient {
            id: recipient.clone(),
            email: "signer@example.test".into(),
            name: "Signer".into(),
            role: RecipientRole::Signer,
            order: 0,
            expires_at: now + 3600,
            principal_ref: None,
            automated: false,
        }],
        fields: vec![EsignField {
            id: field.clone(),
            item: 0,
            recipient,
            required: true,
            geometry: FieldGeometry {
                page: 1,
                x_percent: 10.0,
                y_percent: 10.0,
                width_percent: 50.0,
                height_percent: 20.0,
            },
            meta: FieldMeta::Text { max_bytes: 50 },
        }],
        full_trail_appendix: false,
    };
    vault
        .create_esign_document(
            artifact,
            &document,
            EsignAuditActor {
                actor: owner.to_hex(),
                ip: None,
                user_agent: None,
            },
            now,
        )
        .expect("create signing document");
    let mut effect = Scope::top();
    effect.verbs = ScopeAxis::Some(["effect".to_owned()].into());
    oneiron::conversation_dag::test_support::put_test_policy_manifest(
        &vault,
        WriteActor::new(owner, EdgeActorClass::Human),
        EntityId::now(),
        &serde_json::json!({
            "schema_version":"1.2", "pack_id":"esign-http-test", "pack_version":"v1",
            "min_engine_version":"0.0.0",
            "defaults":{"criticality":"normal","sensitivity":"normal"},
            "rules":[],
            "actor_ceilings":[{"actor_class":"human","actor_ref":owner.to_hex(),"ceiling":"auto"}],
            "scoped_grants":[{"actor_ref":owner.to_hex(),"effector":"external:send_for_signature",
                "scope":effect,"selectors":{"channel":"esign"}}]
        }),
    )
    .expect("install signing policy manifest");
    let authenticated = vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .expect("authenticate signing owner");
    let token = vault
        .issue_esign_capabilities(&authenticated, artifact)
        .expect("issue signer capability")
        .remove(0)
        .1
        .expose_for_delivery()
        .to_owned();
    let verb = EsignOutboundVerb::SendForSignature;
    let command = EsignOutboundCommand {
        document: artifact.to_hex(),
        recipient_count: 1,
        verb,
        reason: None,
    };
    let request = OutboundDispatchRequest::new(
        "receipt:public-sign",
        "public-sign",
        OutboundIntent::from_trigger(
            OutboundIntentDraft {
                actor: owner.to_hex(),
                on_behalf_of: None,
                verb: verb.as_str().into(),
                channel: "esign".into(),
                target: artifact.to_hex(),
                content_ref: None,
                idempotency_key: Some("public-sign".into()),
                dedupe_key: Some("public-sign".into()),
            },
            OutboundIntentTrigger {
                source: OutboundIntentSource::AgentImmediate,
                trigger_ref: "public-sign".into(),
                job_ref: None,
            },
        ),
        OutboundDispatchActor {
            actor_class: "human".into(),
            actor_ref: Some(owner.to_hex()),
            actor_entity_ref: Some(owner),
        },
        OutboundDispatchGate::allow_when_policy_grants(),
        now,
        OutboundDeliveryWindowDecision::DeliverNow,
    );
    let sent = vault
        .dispatch_esign(request, &command, None, None)
        .expect("dispatch signing request");
    assert_eq!(
        sent.outcome,
        OutboundDispatchOutcome::DeliveredToChannel,
        "{sent:?}"
    );
    let server = Arc::new(
        SyncServer::new(
            vault,
            SyncServerConfig {
                lease_vault_id: 1,
                ..Default::default()
            },
        )
        .expect("create signing sync server"),
    );
    (dir, server, token, field, artifact)
}

#[tokio::test]
async fn real_managed_tcp_listener_loads_saves_and_reads_without_device_lease() {
    use oneiron_server::managed::{BoundServeListener, ManagedShutdown, ServeListener};
    let (_dir, server, token, field, document) = sent_request();
    let listener = ServeListener::Tcp("127.0.0.1:0".parse().expect("parse TCP listener address"))
        .bind()
        .await
        .expect("bind TCP listener");
    let BoundServeListener::Tcp(ref tcp) = listener else {
        panic!("tcp bind");
    };
    let address = tcp.local_addr().expect("read TCP listener address");
    let shutdown = ManagedShutdown::new();
    let signal = shutdown.triggered();
    let app = build_app(Arc::clone(&server));
    let served = tokio::spawn(async move { listener.serve_until(app, signal).await });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("build TCP signing client");
    let url = format!("http://{address}");
    let page = client
        .get(format!("{url}/sign/{token}"))
        .send()
        .await
        .expect("fetch public signing page");
    assert_eq!(page.status(), StatusCode::OK);
    let load = client
        .post(format!("{url}/sign/action"))
        .header("x-forwarded-for", "203.0.113.9")
        .json(&serde_json::json!({"token": token, "action":{"action":"load"}}))
        .send()
        .await
        .expect("load signer action over TCP");
    assert_eq!(load.status(), StatusCode::OK);
    assert_eq!(
        load.json::<serde_json::Value>()
            .await
            .expect("decode TCP load response")["outcome"],
        "page"
    );
    let saved = client
        .post(format!("{url}/sign/action"))
        .json(&serde_json::json!({"token": token, "action":{
            "action":"save_field", "field":field, "value":{"kind":"text","value":"Accepted"}
        }}))
        .send()
        .await
        .expect("save signer field over TCP");
    assert_eq!(saved.status(), StatusCode::OK);
    let saved: serde_json::Value = saved.json().await.expect("decode TCP save response");
    assert_eq!(
        saved["data"]["values"][&field]["value"]["value"],
        "Accepted"
    );
    let preview = client
        .post(format!("{url}/sign/preview"))
        .json(&serde_json::json!({"token":token,"item":0}))
        .send()
        .await
        .expect("preview signing document over TCP");
    assert_eq!(preview.status(), StatusCode::OK);
    assert_eq!(
        preview
            .json::<serde_json::Value>()
            .await
            .expect("decode TCP preview response")["fields"]
            .as_array()
            .expect("preview fields are an array")
            .len(),
        1
    );
    let pdf = client
        .post(format!("{url}/sign/pdf"))
        .json(&serde_json::json!({"token":token,"item":0}))
        .send()
        .await
        .expect("fetch signing PDF over TCP");
    assert_eq!(pdf.status(), StatusCode::OK);
    assert_eq!(
        pdf.bytes()
            .await
            .expect("read signing PDF over TCP")
            .as_ref(),
        include_bytes!("../../oneiron-seal/tests/fixtures/pdf-input/classic_1page.pdf")
    );
    let audit = server
        .vault()
        .esign_audit(document)
        .expect("read signing audit");
    assert!(
        audit
            .iter()
            .any(|row| row.actor.ip.as_deref() == Some("127.0.0.1"))
    );
    assert!(
        !audit
            .iter()
            .any(|row| row.actor.ip.as_deref() == Some("203.0.113.9"))
    );
    shutdown.trigger();
    served
        .await
        .expect("join TCP signing server task")
        .expect("finish TCP signing server");
}

async fn over_unix(path: &std::path::Path, method: &str, target: &str, body: &str) -> Vec<u8> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::UnixStream::connect(path)
        .await
        .expect("connect to signing Unix socket");
    let request = format!(
        "{method} {target} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nX-Forwarded-For: 203.0.113.9\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write Unix signing request");
    let mut response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stream.read_to_end(&mut response),
    )
    .await
    .expect("finish Unix signing response before timeout")
    .expect("read Unix signing response");
    response
}

fn http_body(response: &[u8]) -> &[u8] {
    assert!(
        response.starts_with(b"HTTP/1.1 200 OK"),
        "{}",
        String::from_utf8_lossy(response)
    );
    let end = response
        .windows(4)
        .position(|chunk| chunk == b"\r\n\r\n")
        .expect("find end of HTTP response headers")
        + 4;
    &response[end..]
}

#[tokio::test]
async fn real_managed_unix_listener_uses_kernel_peer_not_forwarded_caller_ip() {
    use oneiron_server::managed::{ManagedShutdown, ServeListener};
    let (_dir, server, token, field, document) = sent_request();
    let run = tempfile::tempdir().expect("create signing Unix socket directory");
    let socket = run.path().join("signing.sock");
    let listener = ServeListener::UnixPath(socket.clone())
        .bind()
        .await
        .expect("bind Unix signing listener");
    let shutdown = ManagedShutdown::new();
    let signal = shutdown.triggered();
    let app = build_app(Arc::clone(&server));
    let served = tokio::spawn(async move { listener.serve_until(app, signal).await });
    let page = over_unix(&socket, "GET", &format!("/sign/{token}"), "").await;
    assert!(!http_body(&page).is_empty());
    let load = over_unix(
        &socket,
        "POST",
        "/sign/action",
        &serde_json::json!({"token":token,"action":{"action":"load"}}).to_string(),
    )
    .await;
    let load: serde_json::Value =
        serde_json::from_slice(http_body(&load)).expect("decode Unix load response");
    assert_eq!(load["outcome"], "page");
    let save = over_unix(
        &socket,
        "POST",
        "/sign/action",
        &serde_json::json!({"token":token,"action":{
            "action":"save_field", "field":field, "value":{"kind":"text","value":"Accepted"}
        }})
        .to_string(),
    )
    .await;
    let save: serde_json::Value =
        serde_json::from_slice(http_body(&save)).expect("decode Unix save response");
    assert_eq!(save["data"]["values"][&field]["value"]["value"], "Accepted");
    let preview = over_unix(
        &socket,
        "POST",
        "/sign/preview",
        &serde_json::json!({"token":token,"item":0}).to_string(),
    )
    .await;
    let preview: serde_json::Value =
        serde_json::from_slice(http_body(&preview)).expect("decode Unix preview response");
    assert_eq!(
        preview["fields"]
            .as_array()
            .expect("Unix preview fields are an array")
            .len(),
        1
    );
    let pdf = over_unix(
        &socket,
        "POST",
        "/sign/pdf",
        &serde_json::json!({"token":token,"item":0}).to_string(),
    )
    .await;
    assert_eq!(
        http_body(&pdf),
        include_bytes!("../../oneiron-seal/tests/fixtures/pdf-input/classic_1page.pdf")
    );
    // The kernel identifies only the local proxy process. Its UID is not
    // an external signer IP, and an HTTP forwarding header cannot become one.
    let audit = server
        .vault()
        .esign_audit(document)
        .expect("read Unix signing audit");
    let saved = audit
        .iter()
        .find(|row| {
            matches!(
                row.event,
                oneiron::blob_artifact::esign::EsignEvent::FieldSaved { .. }
            )
        })
        .expect("find saved-field audit event");
    assert_eq!(saved.actor.ip, None);
    shutdown.trigger();
    served
        .await
        .expect("join Unix signing server task")
        .expect("finish Unix signing server");
}

#[tokio::test]
async fn signing_routes_keep_matched_wire_receipts_and_threshold_questions() {
    use oneiron_server::wire_telemetry::{WireTelemetry, WireThresholds};

    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let observer = WireTelemetry::new(vault.clone());
    let window_secs = 604_800;
    observer
        .set_thresholds(&WireThresholds {
            window_secs,
            per_verb: 1,
            per_actor: u64::MAX,
        })
        .unwrap();
    drop(observer);
    let server = Arc::new(
        SyncServer::new(
            vault.clone(),
            SyncServerConfig {
                lease_vault_id: 1,
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let app = build_app(server.clone());
    let token = "ab".repeat(32);
    for _ in 0..2 {
        let page = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/sign/{token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(page.status(), StatusCode::OK);
        let action = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/sign/action")
                    .extension(axum::extract::ConnectInfo(
                        "127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
                    ))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({"token":token,"action":{"action":"load"}}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(action.status(), StatusCode::FORBIDDEN);
    }
    let denied = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/entity/00112233445566778899aabbccddeeff")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    drop(app);
    drop(server); // flush the active receipt through the real owner of that counter

    let observer = WireTelemetry::new(vault);
    let now = oneiron_vault_contract::now_ts();
    let start = now / window_secs * window_secs;
    let receipt = observer
        .receipt(start, start + window_secs)
        .unwrap()
        .unwrap();
    assert_eq!(receipt.by_verb["GET /sign/{token}"], 2);
    assert_eq!(receipt.by_verb["POST /sign/action"], 2);
    assert_eq!(receipt.by_verb["GET /api/entity/{id}"], 1);
    assert_eq!(receipt.by_actor["unauthenticated"], 5);
    assert!(receipt.by_verb.keys().all(|key| !key.contains(&token)));
    let question = observer
        .question(start, start + window_secs)
        .unwrap()
        .unwrap();
    assert_eq!(question.evidence.by_verb["GET /sign/{token}"], 2);
}

#[tokio::test]
async fn hosted_burst_keeps_a_live_ceremony_writable_and_raises_a_typed_check() {
    let (_dir, server, token, field, id) = sent_request();
    let app = build_app(Arc::clone(&server));
    let page = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/sign/{token}"))
                .body(Body::empty())
                .expect("page request"),
        )
        .await
        .expect("page response");
    assert_eq!(page.status(), StatusCode::OK);

    let post = |action: serde_json::Value| {
        let app = app.clone();
        let token = token.clone();
        async move {
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/sign/action")
                        .extension(axum::extract::ConnectInfo(
                            "127.0.0.1:12345"
                                .parse::<std::net::SocketAddr>()
                                .expect("loopback peer"),
                        ))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            serde_json::json!({"token":token,"action":action}).to_string(),
                        ))
                        .expect("signing action request"),
                )
                .await
                .expect("signing action response");
            let status = response.status();
            let body = to_bytes(response.into_body(), 16 * 1024)
                .await
                .expect("signing action body");
            let body: serde_json::Value =
                serde_json::from_slice(&body).expect("typed signing outcome");
            (status, body)
        }
    };
    // More than two full former 120/minute windows, so even a minute boundary
    // cannot hide the crossing. None of these legitimate refreshes may drop.
    for _ in 0..300 {
        let (status, body) = post(serde_json::json!({"action":"load"})).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["outcome"], "page");
    }
    let (status, saved) = post(serde_json::json!({
        "action":"save_field", "field":field,
        "value":{"kind":"text", "value":"approved"}
    }))
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(saved["outcome"], "page");
    assert_eq!(
        saved["data"]["values"][&field]["value"]["value"],
        "approved"
    );
    let (status, completed) = post(serde_json::json!({
        "action":"complete", "consent":true, "next":null
    }))
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(completed["outcome"], "awaiting_seal");
    let recipient = &server
        .vault()
        .esign_document(id)
        .expect("signing state")
        .document
        .recipients[0]
        .id;
    let checks = server
        .vault()
        .esign_rate_checks(id)
        .expect("local typed checks");
    assert!(checks.iter().any(|check| {
        check.receipt.recipient.as_deref() == Some(recipient.as_str())
            && check.receipt.count == 121
            && check.threshold == 120
    }));
}
