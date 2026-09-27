//! The public path and signing API are separate from hosted device leases.
#![expect(
    clippy::unwrap_used,
    reason = "integration fixture unwraps only setup and response assertions"
)]
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use std::sync::Arc;
use tower::ServiceExt;

#[tokio::test]
async fn public_path_signing_bypasses_hosted_lease_but_not_capability_admission() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let server = Arc::new(
        SyncServer::new(
            vault,
            SyncServerConfig {
                lease_vault_id: 1,
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let app = build_app(server);
    let token = "11".repeat(32);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/sign/{token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
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
    let body = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
    assert!(!String::from_utf8_lossy(&body).contains(&token));

    let malformed = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/sign/not-a-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(malformed.status(), StatusCode::NOT_FOUND);
    assert_eq!(malformed.headers()[header::CACHE_CONTROL], "no-store");
    let unavailable = app
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
    assert_eq!(unavailable.status(), StatusCode::FORBIDDEN);
    assert_eq!(unavailable.headers()[header::CACHE_CONTROL], "no-store");
    // Bypassing the device lease is scoped to the ceremony, not its
    // owner-side geometry editor or the rest of the hosted API.
    for path in ["/sign/editor", "/api/openapi.json"] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
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

    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::server()).unwrap());
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let artifact = EntityId::now();
    let when = TimeRange { start: 1, end: 1 };
    vault
        .put_blob_artifact(
            &artifact,
            &BlobArtifactBody::new("agreement.pdf", "application/pdf"),
            when,
            1,
        )
        .unwrap();
    vault
        .append_blob_artifact_version(
            &artifact,
            include_bytes!("../../oneiron-seal/tests/fixtures/pdf-input/classic_1page.pdf"),
            &BlobVersionProvenance::UserUpload,
            WriteActor::new(owner, EdgeActorClass::Human),
            when,
            1,
        )
        .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
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
        .unwrap();
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
    .unwrap();
    let authenticated = vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .unwrap();
    let token = vault
        .issue_esign_capabilities(&authenticated, artifact)
        .unwrap()
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
    let sent = vault.dispatch_esign(request, &command, None, None).unwrap();
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
        .unwrap(),
    );
    (dir, server, token, field, artifact)
}

#[tokio::test]
async fn real_managed_tcp_listener_loads_saves_and_reads_without_device_lease() {
    use oneiron_server::managed::{BoundServeListener, ManagedShutdown, ServeListener};
    let (_dir, server, token, field, document) = sent_request();
    let listener = ServeListener::Tcp("127.0.0.1:0".parse().unwrap())
        .bind()
        .await
        .unwrap();
    let BoundServeListener::Tcp(ref tcp) = listener else {
        panic!("tcp bind");
    };
    let address = tcp.local_addr().unwrap();
    let shutdown = ManagedShutdown::new();
    let signal = shutdown.triggered();
    let app = build_app(Arc::clone(&server));
    let served = tokio::spawn(async move { listener.serve_until(app, signal).await });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();
    let url = format!("http://{address}");
    let page = client
        .get(format!("{url}/sign/{token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    let load = client
        .post(format!("{url}/sign/action"))
        .header("x-forwarded-for", "203.0.113.9")
        .json(&serde_json::json!({"token": token, "action":{"action":"load"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(load.status(), StatusCode::OK);
    assert_eq!(
        load.json::<serde_json::Value>().await.unwrap()["outcome"],
        "page"
    );
    let saved = client
        .post(format!("{url}/sign/action"))
        .json(&serde_json::json!({"token": token, "action":{
            "action":"save_field", "field":field, "value":{"kind":"text","value":"Accepted"}
        }}))
        .send()
        .await
        .unwrap();
    assert_eq!(saved.status(), StatusCode::OK);
    let saved: serde_json::Value = saved.json().await.unwrap();
    assert_eq!(
        saved["data"]["values"][&field]["value"]["value"],
        "Accepted"
    );
    let preview = client
        .post(format!("{url}/sign/preview"))
        .json(&serde_json::json!({"token":token,"item":0}))
        .send()
        .await
        .unwrap();
    assert_eq!(preview.status(), StatusCode::OK);
    assert_eq!(
        preview.json::<serde_json::Value>().await.unwrap()["fields"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let pdf = client
        .post(format!("{url}/sign/pdf"))
        .json(&serde_json::json!({"token":token,"item":0}))
        .send()
        .await
        .unwrap();
    assert_eq!(pdf.status(), StatusCode::OK);
    assert_eq!(
        pdf.bytes().await.unwrap().as_ref(),
        include_bytes!("../../oneiron-seal/tests/fixtures/pdf-input/classic_1page.pdf")
    );
    let audit = server.vault().esign_audit(document).unwrap();
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
    served.await.unwrap().unwrap();
}

async fn over_unix(path: &std::path::Path, method: &str, target: &str, body: &str) -> Vec<u8> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::UnixStream::connect(path).await.unwrap();
    let request = format!(
        "{method} {target} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nX-Forwarded-For: 203.0.113.9\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stream.read_to_end(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
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
        .unwrap()
        + 4;
    &response[end..]
}

#[tokio::test]
async fn real_managed_unix_listener_uses_kernel_peer_not_forwarded_caller_ip() {
    use oneiron_server::managed::{ManagedShutdown, ServeListener};
    let (_dir, server, token, field, document) = sent_request();
    let run = tempfile::tempdir().unwrap();
    let socket = run.path().join("signing.sock");
    let listener = ServeListener::UnixPath(socket.clone())
        .bind()
        .await
        .unwrap();
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
    let load: serde_json::Value = serde_json::from_slice(http_body(&load)).unwrap();
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
    let save: serde_json::Value = serde_json::from_slice(http_body(&save)).unwrap();
    assert_eq!(save["data"]["values"][&field]["value"]["value"], "Accepted");
    let preview = over_unix(
        &socket,
        "POST",
        "/sign/preview",
        &serde_json::json!({"token":token,"item":0}).to_string(),
    )
    .await;
    let preview: serde_json::Value = serde_json::from_slice(http_body(&preview)).unwrap();
    assert_eq!(preview["fields"].as_array().unwrap().len(), 1);
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
    let audit = server.vault().esign_audit(document).unwrap();
    let saved = audit
        .iter()
        .find(|row| {
            matches!(
                row.event,
                oneiron::blob_artifact::esign::EsignEvent::FieldSaved { .. }
            )
        })
        .unwrap();
    assert_eq!(saved.actor.ip, None);
    shutdown.trigger();
    served.await.unwrap().unwrap();
}
