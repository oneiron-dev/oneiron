//! The signing lens's session (census L3-22; ARCH-0064a §6 #token-hardening
//! and [SGN-03]; RULING L3-22-SIGNING-SESSION = A, 13 Nov 21:25). The emailed
//! link is traded once for a single-use exchange, a form POST consumes it
//! and opens a Secure, HttpOnly, SameSite=Strict session on `/sign`, and the
//! ceremony doors read only that session: the emailed capability is no
//! bearer on them. One session per link; its lifetimes end the session,
//! never the link.
//!
//! Fleet command: `cargo test --locked -p oneiron-server --all-features
//! --features oneiron/test-support,oneiron/test-hooks --test
//! esign_signing_session`.
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use oneiron_server::config::{LimitsConfig, SyncServerConfig};
use oneiron_server::{build_app, server::SyncServer};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

/// Runs one case on an engine-sized stack, as the served doors need.
fn on_engine_stack<F, Fut>(case: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()>,
{
    let thread = std::thread::Builder::new()
        .stack_size(oneiron_server::ENGINE_THREAD_STACK_BYTES)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .thread_stack_size(oneiron_server::ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .expect("build engine-stack runtime")
                .block_on(case());
        })
        .expect("spawn engine-stack thread");
    if let Err(panic) = thread.join() {
        std::panic::resume_unwind(panic);
    }
}

#[test]
fn ceremony_doors_refuse_the_emailed_capability_as_a_bearer() {
    on_engine_stack(|| async {
        let (_dir, server, token) = sent_request(LimitsConfig::default());
        let app = build_app(server);
        for (path, body) in [
            (
                "/sign/action",
                serde_json::json!({"action":{"action":"load"}}),
            ),
            ("/sign/pdf", serde_json::json!({"item":0})),
            ("/sign/preview", serde_json::json!({"item":0})),
        ] {
            let response = app
                .clone()
                .oneshot(
                    ceremony_request(path)
                        .header("x-oneiron-esign-capability", token.as_str())
                        .body(Body::from(body.to_string()))
                        .expect("build header-bearer request"),
                )
                .await
                .expect("serve header-bearer request");
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "{path}: the emailed capability is no bearer on a ceremony door"
            );
        }
        // The exchange door admits only a capability the vault admits.
        let stranger = exchange_response(&app, &"11".repeat(32)).await;
        assert_eq!(stranger.status(), StatusCode::FORBIDDEN);
    });
}

#[test]
fn one_exchange_opens_one_session() {
    on_engine_stack(|| async {
        let (_dir, server, token) = sent_request(LimitsConfig::default());
        let app = build_app(server);
        let exchange = exchange(&app, &token).await;
        assert!(is_hex64(&exchange), "{exchange}");
        assert_ne!(exchange, token);

        // A browser that marks the form POST as sent from another site
        // opens nothing.
        let foreign = session_response(&app, &exchange, Some("cross-site")).await;
        assert_eq!(foreign.status(), StatusCode::FORBIDDEN);
        assert!(!foreign.headers().contains_key(header::SET_COOKIE));

        let opened = session_response(&app, &exchange, Some("same-origin")).await;
        assert_eq!(opened.status(), StatusCode::SEE_OTHER);
        assert_eq!(opened.headers()[header::LOCATION], "/sign");
        let set_cookie = opened.headers()[header::SET_COOKIE]
            .to_str()
            .expect("read session cookie")
            .to_owned();
        let attributes: Vec<&str> = set_cookie.split(';').map(str::trim).collect();
        let (name, id) = attributes[0].split_once('=').expect("cookie pair");
        assert_eq!(name, "oneiron-sign-session");
        assert!(is_hex64(id), "{set_cookie}");
        assert_ne!(id, token);
        for attribute in ["Path=/sign", "Secure", "HttpOnly", "SameSite=Strict"] {
            assert!(attributes.contains(&attribute), "{set_cookie}");
        }
        let cookie = attributes[0].to_owned();
        let (status, outcome) = load(&app, &cookie).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(outcome["outcome"], "page");

        // The exchange is single-use, and an unknown one opens nothing.
        for presented in [exchange.clone(), "00".repeat(32)] {
            let replayed = session_response(&app, &presented, None).await;
            assert_eq!(replayed.status(), StatusCode::FORBIDDEN);
            assert!(!replayed.headers().contains_key(header::SET_COOKIE));
        }
        // The session still answers after the replay was refused.
        assert_eq!(load(&app, &cookie).await.0, StatusCode::OK);
    });
}

#[test]
fn a_reopened_link_replaces_its_earlier_session() {
    on_engine_stack(|| async {
        let (_dir, server, token) = sent_request(LimitsConfig::default());
        let app = build_app(server);
        let first = open_session(&app, &token).await;
        assert_eq!(load(&app, &first).await.0, StatusCode::OK);
        let second = open_session(&app, &token).await;
        assert_ne!(first, second);
        assert_eq!(load(&app, &second).await.0, StatusCode::OK);
        assert_eq!(load(&app, &first).await.0, StatusCode::FORBIDDEN);
        // Opening the link again replaces its pending exchange too.
        let stale = exchange(&app, &token).await;
        let fresh = exchange(&app, &token).await;
        let refused = session_response(&app, &stale, None).await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        let opened = session_response(&app, &fresh, None).await;
        assert_eq!(opened.status(), StatusCode::SEE_OTHER);
    });
}

#[test]
fn session_lifetimes_end_the_session_not_the_link() {
    on_engine_stack(|| async {
        // The absolute lifetime ends a session however busy it is, and an
        // exchange past its own lifetime opens nothing.
        let (_dir, server, token) = sent_request(LimitsConfig {
            esign_exchange_seconds: 1,
            esign_session_absolute_seconds: Some(2),
            ..LimitsConfig::default()
        });
        let app = build_app(server);
        let late = exchange(&app, &token).await;
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        let refused = session_response(&app, &late, None).await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        assert!(!refused.headers().contains_key(header::SET_COOKIE));
        let cookie = open_session(&app, &token).await;
        for _ in 0..2 {
            assert_eq!(load(&app, &cookie).await.0, StatusCode::OK);
            tokio::time::sleep(Duration::from_millis(1_100)).await;
        }
        assert_eq!(load(&app, &cookie).await.0, StatusCode::FORBIDDEN);
        let reopened = open_session(&app, &token).await;
        assert_eq!(load(&app, &reopened).await.0, StatusCode::OK);

        // The idle lifetime ends only a session left unused; use keeps it.
        let (_dir, server, token) = sent_request(LimitsConfig {
            esign_session_idle_seconds: Some(2),
            ..LimitsConfig::default()
        });
        let app = build_app(server);
        let cookie = open_session(&app, &token).await;
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_millis(1_000)).await;
            assert_eq!(load(&app, &cookie).await.0, StatusCode::OK);
        }
        tokio::time::sleep(Duration::from_millis(2_200)).await;
        assert_eq!(load(&app, &cookie).await.0, StatusCode::FORBIDDEN);
        let reopened = open_session(&app, &token).await;
        assert_eq!(load(&app, &reopened).await.0, StatusCode::OK);
    });
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn ceremony_request(path: &str) -> axum::http::request::Builder {
    Request::builder()
        .method("POST")
        .uri(path)
        .extension(axum::extract::ConnectInfo(
            "127.0.0.1:12345"
                .parse::<std::net::SocketAddr>()
                .expect("parse loopback peer address"),
        ))
        .header(header::CONTENT_TYPE, "application/json")
}

async fn exchange_response(app: &Router, token: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/sign/exchange")
                .header("x-oneiron-esign-capability", token)
                .body(Body::empty())
                .expect("build exchange request"),
        )
        .await
        .expect("serve exchange request")
}

/// The single-use exchange the page trades its link for.
async fn exchange(app: &Router, token: &str) -> String {
    let response = exchange_response(app, token).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096)
        .await
        .expect("read exchange body");
    assert!(!String::from_utf8_lossy(&body).contains(token));
    let body: serde_json::Value = serde_json::from_slice(&body).expect("decode exchange body");
    body["exchange"]
        .as_str()
        .expect("exchange value")
        .to_owned()
}

/// The page's form POST that consumes `exchange`; `site` is the browser's
/// `Sec-Fetch-Site` mark, when it sends one.
async fn session_response(
    app: &Router,
    exchange: &str,
    site: Option<&str>,
) -> axum::response::Response {
    let mut request = Request::builder()
        .method("POST")
        .uri("/sign/session")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(site) = site {
        request = request.header("sec-fetch-site", site);
    }
    app.clone()
        .oneshot(
            request
                .body(Body::from(format!("exchange={exchange}")))
                .expect("build session request"),
        )
        .await
        .expect("serve session request")
}

/// Opens a session for `token` as the page does; answers its `Cookie` pair.
async fn open_session(app: &Router, token: &str) -> String {
    let exchange = exchange(app, token).await;
    let opened = session_response(app, &exchange, Some("same-origin")).await;
    assert_eq!(opened.status(), StatusCode::SEE_OTHER);
    opened.headers()[header::SET_COOKIE]
        .to_str()
        .expect("read session cookie")
        .split(';')
        .next()
        .expect("cookie pair")
        .to_owned()
}

/// One `load` act carried by the session cookie alone.
async fn load(app: &Router, cookie: &str) -> (StatusCode, serde_json::Value) {
    let body = serde_json::json!({"action":{"action":"load"}});
    let response = app
        .clone()
        .oneshot(
            ceremony_request("/sign/action")
                .header(header::COOKIE, cookie)
                .body(Body::from(body.to_string()))
                .expect("build session load request"),
        )
        .await
        .expect("serve session load request");
    let status = response.status();
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read session load body");
    (status, serde_json::from_slice(&body).unwrap_or_default())
}

/// A request sent through the owner-authored send gate (it_esign_public's
/// fixture), served with `limits`. Answers the recipient's capability.
fn sent_request(limits: LimitsConfig) -> (tempfile::TempDir, Arc<SyncServer>, String) {
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
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
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
            natural_person: None,
        }],
        fields: vec![EsignField {
            id: EntityId::now().to_hex(),
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
        lifecycle: None,
        token_expires_at: None,
        project: None,
        commitments: Vec::new(),
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
            "schema_version":"1.2", "pack_id":"esign-session-test", "pack_version":"v1",
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
        "receipt:signing-session",
        "signing-session",
        OutboundIntent::from_trigger(
            OutboundIntentDraft {
                actor: owner.to_hex(),
                on_behalf_of: None,
                verb: verb.as_str().into(),
                channel: "esign".into(),
                target: artifact.to_hex(),
                content_ref: None,
                idempotency_key: Some("signing-session".into()),
                dedupe_key: Some("signing-session".into()),
                mention: None,
            },
            OutboundIntentTrigger {
                source: OutboundIntentSource::AgentImmediate,
                trigger_ref: "signing-session".into(),
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
                limits,
                ..Default::default()
            },
        )
        .expect("create signing sync server"),
    );
    (dir, server, token)
}
