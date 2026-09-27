//! Hosted public signing links must not inherit tenant device-lease admission.
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use oneiron_server::build_app;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use std::sync::Arc;
use tower::ServiceExt;

#[tokio::test]
async fn hosted_signing_is_public_but_tenant_routes_still_require_a_lease() {
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
    let token = "ab".repeat(32);
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
    assert_eq!(page.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(page.headers()[header::REFERRER_POLICY], "no-referrer");
    assert!(page.headers().contains_key(header::CONTENT_SECURITY_POLICY));
    let bytes = to_bytes(page.into_body(), 16 * 1024).await.unwrap();
    let html = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(
        !html.contains(&token),
        "capability must not be in the HTML body"
    );
    let refusal = app
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
    assert_eq!(refusal.status(), StatusCode::FORBIDDEN);
    let invalid = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/sign/not-a-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::FORBIDDEN);
    let denied = app
        .oneshot(
            Request::builder()
                .uri("/api/entity/00112233445566778899aabbccddeeff")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
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
    assert!(receipt.by_verb.keys().all(|key| !key.contains(&token)));
    let question = observer
        .question(start, start + window_secs)
        .unwrap()
        .unwrap();
    assert_eq!(question.evidence.by_verb["GET /sign/{token}"], 2);
}

fn seed_live_signing(vault: &oneiron::Vault) -> (oneiron::EntityId, String) {
    use oneiron::blob_artifact::esign::{
        DocumentKind, EsignAuditActor, EsignDocument, EsignItem, EsignOutboundCommand,
        EsignOutboundVerb, EsignRecipient, RecipientRole,
    };
    use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
    use oneiron::outbound::{
        OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
        OutboundDispatchOutcome, OutboundDispatchRequest, OutboundIntent, OutboundIntentDraft,
        OutboundIntentSource, OutboundIntentTrigger,
    };
    use oneiron::{EntityId, TimeRange};

    let now = oneiron_vault_contract::now_ts();
    let at = TimeRange {
        start: now,
        end: now,
    };
    let owner = EntityId::now();
    vault
        .put_entity(
            &owner,
            oneiron::registry::ENTITY_TYPE_PERSON,
            at,
            now,
            b"owner",
        )
        .expect("seed live signing fixture");
    let id = EntityId::now();
    vault
        .put_blob_artifact(
            &id,
            &BlobArtifactBody::new("agreement.pdf", "application/pdf"),
            at,
            now,
        )
        .expect("seed live signing fixture");
    vault
        .append_blob_artifact_version(
            &id,
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../oneiron-seal/tests/fixtures/pdf-input/classic_1page.pdf"
            )),
            &BlobVersionProvenance::UserUpload,
            oneiron::write_envelope::WriteActor::new(owner, oneiron::edge::EdgeActorClass::Human),
            at,
            now,
        )
        .expect("seed live signing fixture");
    let recipient = EntityId::now().to_hex();
    let document = EsignDocument {
        schema_version: 1,
        kind: DocumentKind::Document,
        title: "Agreement".into(),
        sequential: false,
        expires_at: now + 3600,
        items: vec![EsignItem {
            artifact_ref: id.to_hex(),
            original_version: 1,
        }],
        recipients: vec![EsignRecipient {
            id: recipient,
            email: "signer@example.test".into(),
            name: "Signer".into(),
            role: RecipientRole::Signer,
            order: 0,
            expires_at: now + 3600,
            principal_ref: None,
            automated: false,
        }],
        fields: vec![],
        full_trail_appendix: false,
    };
    vault
        .create_esign_document(
            id,
            &document,
            EsignAuditActor {
                actor: owner.to_hex(),
                ip: None,
                user_agent: None,
            },
            now,
        )
        .expect("seed live signing fixture");
    let auth = vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .expect("seed live signing fixture");
    let capability = vault
        .issue_esign_capabilities(&auth, id)
        .expect("seed live signing fixture")
        .remove(0)
        .1;
    let mut scope = oneiron::federation::Scope::top();
    scope.verbs = oneiron::federation::ScopeAxis::Some(["effect".to_owned()].into());
    let manifest = serde_json::json!({
        "schema_version": "1.2", "pack_id": "esign-test", "pack_version": "v1",
        "min_engine_version": env!("CARGO_PKG_VERSION"),
        "defaults": {"criticality":"normal","sensitivity":"normal"},
        "rules": [],
        "actor_ceilings": [{"actor_class":"human","actor_ref":owner.to_hex(),"ceiling":"auto"}],
        "scoped_grants": [{"actor_ref":owner.to_hex(),"effector":"external:send_for_signature",
                           "scope":scope,"selectors":{"channel":"esign"}}]
    });
    oneiron::conversation_dag::test_support::put_test_policy_manifest(
        vault,
        oneiron::write_envelope::WriteActor::new(owner, oneiron::edge::EdgeActorClass::Human),
        EntityId::now(),
        &manifest,
    )
    .expect("seed live signing fixture");
    let intent_ref = format!("esign-host:{}", EntityId::now().to_hex());
    let request = OutboundDispatchRequest::new(
        format!("receipt:{intent_ref}"),
        &intent_ref,
        OutboundIntent::from_trigger(
            OutboundIntentDraft {
                actor: owner.to_hex(),
                on_behalf_of: None,
                verb: "send_for_signature".into(),
                channel: "esign".into(),
                target: id.to_hex(),
                content_ref: None,
                idempotency_key: Some(intent_ref.clone()),
                dedupe_key: Some(intent_ref.clone()),
            },
            OutboundIntentTrigger {
                source: OutboundIntentSource::AgentImmediate,
                trigger_ref: intent_ref.clone(),
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
        .dispatch_esign(
            request,
            &EsignOutboundCommand {
                document: id.to_hex(),
                recipient_count: 1,
                verb: EsignOutboundVerb::SendForSignature,
                reason: None,
            },
            None,
            None,
        )
        .expect("seed live signing fixture");
    assert_eq!(
        sent.outcome,
        OutboundDispatchOutcome::DeliveredToChannel,
        "{sent:?}"
    );
    (id, capability.expose_for_delivery().to_owned())
}

async fn http_over_unix(path: &std::path::Path, request: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::UnixStream::connect(path)
        .await
        .expect("connect and write managed signing request");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("connect and write managed signing request");
    let mut bytes = Vec::new();
    loop {
        let patience = if bytes.is_empty() {
            std::time::Duration::from_secs(5)
        } else {
            std::time::Duration::from_millis(200)
        };
        let mut chunk = [0; 4096];
        match tokio::time::timeout(patience, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(count)) => bytes.extend_from_slice(&chunk[..count]),
            Ok(Err(error)) => panic!("managed signing read failed: {error}"),
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn managed_unix_listener_serves_a_live_signing_capability_without_a_forged_ip() {
    use oneiron_server::managed::{
        ManagedShutdown, ManagedState, ServeListener, WakeLedger, build_managed_app,
    };
    use oneiron_vault_contract::{Credentials, DEK_LEN, TOKEN_LEN};

    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(
        oneiron::Vault::open(dir.path().join("vault"), oneiron::VaultConfig::device()).unwrap(),
    );
    let (id, token) = seed_live_signing(&vault);
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
    let ledger = WakeLedger::load(
        vault.clone(),
        "esign-test".into(),
        dir.path().join("supervisor.sock"),
        &Credentials {
            dek: [0; DEK_LEN],
            token: [7; TOKEN_LEN],
        },
    )
    .unwrap();
    let state = Arc::new(ManagedState::new(
        "esign-test".into(),
        server.clone(),
        ledger,
    ));
    let path = dir.path().join("sign.sock");
    let bound = ServeListener::UnixPath(path.clone()).bind().await.unwrap();
    let shutdown = ManagedShutdown::new();
    let app = build_managed_app(server, state);
    let done = shutdown.triggered();
    let task = tokio::spawn(async move { bound.serve_until(app, done).await });

    let page = http_over_unix(
        &path,
        &format!("GET /sign/{token} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(page.starts_with("HTTP/1.1 200 OK"), "{page}");
    let body = serde_json::json!({"token":token,"action":{"action":"load"}}).to_string();
    let request = format!(
        "POST /sign/action HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 192.0.2.5\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let action = http_over_unix(&path, &request).await;
    assert!(action.starts_with("HTTP/1.1 200 OK"), "{action}");
    assert!(action.contains("\"outcome\":\"page\""), "{action}");
    for endpoint in ["pdf", "preview"] {
        let body = serde_json::json!({"token":token,"item":0}).to_string();
        let request = format!(
            "POST /sign/{endpoint} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let response = http_over_unix(&path, &request).await;
        assert!(
            response.starts_with("HTTP/1.1 200 OK"),
            "{endpoint}: {response}"
        );
    }
    let audit = vault.esign_audit(id).unwrap();
    assert!(audit.iter().any(|row| matches!(
        row.event,
        oneiron::blob_artifact::esign::EsignEvent::Viewed { .. }
    ) && row.actor.ip.is_none()));
    shutdown.trigger();
    task.await.unwrap().unwrap();
}
