use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use oneiron::types::{
    ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_NOTIFICATION, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, ResumeBundle,
    TimeRange, VaultConfig,
};
use oneiron_server::build_app;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SKILLS_PACK: &str = include_str!("../oneiron.skills.md");

fn test_vault_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.max_readers = 32;
    config
}

fn large_test_vault_config() -> VaultConfig {
    let mut config = test_vault_config();
    config.map_size = 256 * 1024 * 1024;
    config
}

fn time_range(start: u64, end: u64) -> TimeRange {
    TimeRange { start, end }
}

fn seeded_entity_id(counter: u128) -> EntityId {
    let mut bytes = counter.to_be_bytes();
    bytes[0] = 0x7e;
    EntityId::from_bytes(bytes).expect("seeded test id should be valid")
}

fn config_with_secret(secret: &str) -> SyncServerConfig {
    SyncServerConfig {
        auth_secret: Some(secret.to_owned()),
        ..Default::default()
    }
}

async fn spawn_server(
    vault: Arc<oneiron::Vault>,
    config: SyncServerConfig,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let server = Arc::new(SyncServer::new(vault, config).unwrap());
    let app = build_app(server);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, handle)
}

async fn http_get(addr: SocketAddr, path: &str, secret: Option<&str>) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let secret_header = secret
        .map(|secret| format!("x-oneiron-secret: {secret}\r\n"))
        .unwrap_or_default();
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n{secret_header}\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
        .await
        .expect("timed out waiting for HTTP response")
        .expect("failed reading HTTP response");
    String::from_utf8(response).unwrap()
}

async fn http_post(addr: SocketAddr, path: &str, secret: Option<&str>, body: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let secret_header = secret
        .map(|secret| format!("x-oneiron-secret: {secret}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{secret_header}\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
        .await
        .expect("timed out waiting for HTTP response")
        .expect("failed reading HTTP response");
    String::from_utf8(response).unwrap()
}

fn assert_http_status(response: &str, status: u16) {
    let expected = format!("HTTP/1.1 {status} ");
    assert!(
        response.starts_with(&expected),
        "expected HTTP status {status}, got response head: {:?}",
        response.lines().next()
    );
}

fn http_headers(response: &str) -> &str {
    response
        .split_once("\r\n\r\n")
        .map(|(headers, _body)| headers)
        .expect("HTTP response should contain header/body delimiter")
}

fn http_json(response: &str) -> Value {
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_headers, body)| body)
        .expect("HTTP response should contain header/body delimiter");
    serde_json::from_str(body).expect("response body should be JSON")
}

fn http_body(response: &str) -> &str {
    response
        .split_once("\r\n\r\n")
        .map(|(_headers, body)| body)
        .expect("HTTP response should contain header/body delimiter")
}

fn str_array_set(value: &Value) -> BTreeSet<&str> {
    value
        .as_array()
        .expect("value should be an array")
        .iter()
        .map(|item| item.as_str().expect("array item should be a string"))
        .collect()
}

#[tokio::test]
async fn companion_resume_requires_auth_and_deserializes() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), test_vault_config()).unwrap());
    let (addr, handle) = spawn_server(vault, config_with_secret("secret")).await;

    let missing = http_post(addr, "/api/companion/resume", None, "{}").await;
    assert_http_status(&missing, 401);

    let wrong = http_post(addr, "/api/companion/resume", Some("wrong"), "{}").await;
    assert_http_status(&wrong, 401);

    let response = http_post(addr, "/api/companion/resume", Some("secret"), "{}").await;
    assert_http_status(&response, 200);
    let bundle: ResumeBundle =
        serde_json::from_str(http_body(&response)).expect("resume body should deserialize");
    assert_eq!(bundle.session.api_version, "v1");
    assert_eq!(bundle.notifications, Vec::new());
    assert_eq!(bundle.unprocessed, Vec::new());
    assert_eq!(bundle.budget.tokens_remaining, 0);
    assert!(http_body(&response).contains("\"notifications\":[]"));
    assert!(http_body(&response).contains("\"unprocessed\":[]"));

    handle.abort();
}

#[tokio::test]
async fn companion_resume_counts_by_type_and_reports_latest_activity() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), test_vault_config()).unwrap());

    vault
        .put_entity(
            &EntityId::now(),
            ENTITY_TYPE_PERSON,
            time_range(1, 1),
            40,
            b"person",
        )
        .unwrap();
    vault
        .put_entity(
            &EntityId::now(),
            ENTITY_TYPE_TURN,
            time_range(2, 2),
            90,
            b"turn",
        )
        .unwrap();

    let (addr, handle) = spawn_server(vault, config_with_secret("secret")).await;
    let response = http_post(addr, "/api/companion/resume", Some("secret"), "{}").await;
    assert_http_status(&response, 200);
    let bundle: ResumeBundle =
        serde_json::from_str(http_body(&response)).expect("resume body should deserialize");

    assert_eq!(
        bundle
            .session
            .counts
            .get(&ENTITY_TYPE_PERSON.to_string())
            .copied(),
        Some(1)
    );
    assert_eq!(
        bundle
            .session
            .counts
            .get(&ENTITY_TYPE_TURN.to_string())
            .copied(),
        Some(1)
    );
    assert_eq!(bundle.session.last_activity, Some(90));

    handle.abort();
}

#[tokio::test]
async fn companion_resume_filters_surfaced_notification_by_exact_id() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), test_vault_config()).unwrap());

    let surfaced = EntityId::now();
    let pending = EntityId::now();
    let surfaced_body = rmp_serde::to_vec(&serde_json::json!({
        "message": "seen",
        "surfaced_by": ["default"]
    }))
    .unwrap();
    let pending_body = rmp_serde::to_vec(&serde_json::json!({
        "message": "fresh"
    }))
    .unwrap();
    vault
        .put_entity(
            &surfaced,
            ENTITY_TYPE_NOTIFICATION,
            time_range(1, 1),
            10,
            &surfaced_body,
        )
        .unwrap();
    vault
        .put_entity(
            &pending,
            ENTITY_TYPE_NOTIFICATION,
            time_range(2, 2),
            20,
            &pending_body,
        )
        .unwrap();

    let (addr, handle) = spawn_server(vault, config_with_secret("secret")).await;
    let response = http_post(addr, "/api/companion/resume", Some("secret"), "{}").await;
    assert_http_status(&response, 200);
    let bundle: ResumeBundle =
        serde_json::from_str(http_body(&response)).expect("resume body should deserialize");

    assert_eq!(bundle.notifications.len(), 1);
    assert_eq!(bundle.notifications[0].id, pending.to_hex());
    assert_ne!(bundle.notifications[0].id, surfaced.to_hex());
    assert_eq!(bundle.unprocessed, Vec::new());

    handle.abort();
}

#[tokio::test]
async fn companion_resume_skips_malformed_and_non_object_notifications() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), test_vault_config()).unwrap());

    let malformed = EntityId::now();
    let non_object = EntityId::now();
    let valid = EntityId::now();
    let non_object_body = rmp_serde::to_vec(&serde_json::json!("hello")).unwrap();
    let valid_body = rmp_serde::to_vec(&serde_json::json!({
        "message": "fresh"
    }))
    .unwrap();

    vault
        .put_entity(
            &malformed,
            ENTITY_TYPE_NOTIFICATION,
            time_range(1, 1),
            10,
            &[0xc1],
        )
        .unwrap();
    vault
        .put_entity(
            &non_object,
            ENTITY_TYPE_NOTIFICATION,
            time_range(2, 2),
            20,
            &non_object_body,
        )
        .unwrap();
    vault
        .put_entity(
            &valid,
            ENTITY_TYPE_NOTIFICATION,
            time_range(3, 3),
            30,
            &valid_body,
        )
        .unwrap();

    let (addr, handle) = spawn_server(vault, config_with_secret("secret")).await;
    let response = http_post(addr, "/api/companion/resume", Some("secret"), "{}").await;
    assert_http_status(&response, 200);
    let bundle: ResumeBundle =
        serde_json::from_str(http_body(&response)).expect("resume body should deserialize");

    assert_eq!(bundle.notifications.len(), 1);
    assert_eq!(bundle.notifications[0].id, valid.to_hex());

    handle.abort();
}

#[tokio::test]
async fn companion_resume_requires_all_present_scope_keys_to_match() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), test_vault_config()).unwrap());

    let conflicting = EntityId::now();
    let matched = EntityId::now();
    let conflicting_body = rmp_serde::to_vec(&serde_json::json!({
        "message": "conflict",
        "caller": "default",
        "recipient": "other"
    }))
    .unwrap();
    let matched_body = rmp_serde::to_vec(&serde_json::json!({
        "message": "match",
        "caller": "default",
        "recipient": "default"
    }))
    .unwrap();

    vault
        .put_entity(
            &conflicting,
            ENTITY_TYPE_NOTIFICATION,
            time_range(1, 1),
            10,
            &conflicting_body,
        )
        .unwrap();
    vault
        .put_entity(
            &matched,
            ENTITY_TYPE_NOTIFICATION,
            time_range(2, 2),
            20,
            &matched_body,
        )
        .unwrap();

    let (addr, handle) = spawn_server(vault, config_with_secret("secret")).await;
    let response = http_post(addr, "/api/companion/resume", Some("secret"), "{}").await;
    assert_http_status(&response, 200);
    let bundle: ResumeBundle =
        serde_json::from_str(http_body(&response)).expect("resume body should deserialize");

    assert_eq!(bundle.notifications.len(), 1);
    assert_eq!(bundle.notifications[0].id, matched.to_hex());
    assert_ne!(bundle.notifications[0].id, conflicting.to_hex());

    handle.abort();
}

#[tokio::test]
async fn companion_resume_bounds_pending_notification_response_to_latest_items() {
    const PENDING_ROWS: usize = 130;
    const EXPECTED_LIMIT: usize = 128;
    const ID_BASE: u128 = 0x2142_0000;

    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), test_vault_config()).unwrap());
    let body = rmp_serde::to_vec(&serde_json::json!({
        "message": "pending"
    }))
    .unwrap();

    let mut batch = vault.batch();
    for i in 0..PENDING_ROWS {
        let id = seeded_entity_id(ID_BASE + i as u128);
        batch = batch.put(
            &id,
            ENTITY_TYPE_NOTIFICATION,
            time_range(i as u64, i as u64),
            i as u64,
            &body,
        );
    }
    batch.commit().unwrap();

    let (addr, handle) = spawn_server(vault, config_with_secret("secret")).await;
    let response = http_post(addr, "/api/companion/resume", Some("secret"), "{}").await;
    assert_http_status(&response, 200);
    let bundle: ResumeBundle =
        serde_json::from_str(http_body(&response)).expect("resume body should deserialize");

    assert_eq!(bundle.notifications.len(), EXPECTED_LIMIT);
    assert_eq!(
        bundle.notifications[0].id,
        seeded_entity_id(ID_BASE + (PENDING_ROWS - 1) as u128).to_hex()
    );
    assert!(
        bundle
            .notifications
            .iter()
            .all(|item| item.id != seeded_entity_id(ID_BASE).to_hex())
    );

    handle.abort();
}

#[tokio::test]
async fn companion_resume_returns_latest_pending_notification_over_type_cap() {
    const TYPE_CAP: usize = 100_000;
    const HISTORICAL_ROWS: usize = TYPE_CAP + 1;
    const ID_BASE: u128 = 0x2140_0000;

    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), large_test_vault_config()).unwrap());

    let acked_body = rmp_serde::to_vec(&serde_json::json!({
        "message": "old-acked",
        "acked": true
    }))
    .unwrap();
    let surfaced_body = rmp_serde::to_vec(&serde_json::json!({
        "message": "old-surfaced",
        "surfaced_by": ["default"]
    }))
    .unwrap();
    let pending = seeded_entity_id(ID_BASE + HISTORICAL_ROWS as u128);
    let pending_body = rmp_serde::to_vec(&serde_json::json!({
        "message": "fresh"
    }))
    .unwrap();

    let mut batch = vault.batch();
    for i in 0..HISTORICAL_ROWS {
        let id = seeded_entity_id(ID_BASE + i as u128);
        let body = if i % 2 == 0 {
            &acked_body
        } else {
            &surfaced_body
        };
        batch = batch.put(
            &id,
            ENTITY_TYPE_NOTIFICATION,
            time_range(i as u64, i as u64),
            i as u64,
            body,
        );
    }
    batch
        .put(
            &pending,
            ENTITY_TYPE_NOTIFICATION,
            time_range(HISTORICAL_ROWS as u64, HISTORICAL_ROWS as u64),
            HISTORICAL_ROWS as u64,
            &pending_body,
        )
        .commit()
        .unwrap();

    let (addr, handle) = spawn_server(vault, config_with_secret("secret")).await;
    let response = http_post(addr, "/api/companion/resume", Some("secret"), "{}").await;
    assert_http_status(&response, 200);
    let bundle: ResumeBundle =
        serde_json::from_str(http_body(&response)).expect("resume body should deserialize");

    assert_eq!(bundle.notifications.len(), 1);
    assert_eq!(bundle.notifications[0].id, pending.to_hex());
    assert_eq!(
        bundle.notifications[0].body["message"].as_str(),
        Some("fresh")
    );

    handle.abort();
}

#[tokio::test]
async fn discover_requires_auth_and_returns_empty_contract() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), test_vault_config()).unwrap());
    let (addr, handle) = spawn_server(vault, config_with_secret("secret")).await;

    let missing = http_get(addr, "/api/core/discover", None).await;
    assert_http_status(&missing, 401);

    let wrong = http_get(addr, "/api/core/discover", Some("wrong")).await;
    assert_http_status(&wrong, 401);

    let response = http_get(addr, "/api/core/discover", Some("secret")).await;
    assert_http_status(&response, 200);
    assert!(
        http_headers(&response)
            .to_ascii_lowercase()
            .contains("content-type: application/json"),
        "discover response should be application/json"
    );

    let body = http_json(&response);
    let object = body.as_object().expect("discover body should be an object");
    let keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    assert_eq!(
        keys,
        BTreeSet::from([
            "api_version",
            "bound",
            "conversations",
            "counts",
            "feature_flags",
            "formats",
            "last_activity",
            "personas",
            "predicate_namespaces",
            "scopes",
        ])
    );

    assert!(body["bound"]["vault"].is_null());
    assert!(body["bound"]["persona"].is_null());
    assert!(body["bound"]["conversation"].is_null());
    assert!(body["personas"].as_array().unwrap().is_empty());
    assert!(body["conversations"].as_array().unwrap().is_empty());
    assert!(body["counts"].as_object().unwrap().is_empty());
    assert!(body["predicate_namespaces"].as_array().unwrap().is_empty());
    assert!(body["last_activity"].is_null());
    assert_eq!(
        str_array_set(&body["feature_flags"]["modes"]),
        BTreeSet::from(["flash", "pro", "thinking", "ultra"])
    );

    handle.abort();
}

#[tokio::test]
async fn skills_pack_requires_auth_and_serves_static_markdown() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), test_vault_config()).unwrap());
    let (addr, handle) = spawn_server(vault, config_with_secret("secret")).await;

    let missing = http_get(addr, "/api/skills/oneiron.skills.md", None).await;
    assert_http_status(&missing, 401);

    let wrong = http_get(addr, "/api/skills/oneiron.skills.md", Some("wrong")).await;
    assert_http_status(&wrong, 401);

    let response = http_get(addr, "/api/skills/oneiron.skills.md", Some("secret")).await;
    assert_http_status(&response, 200);
    assert!(
        http_headers(&response)
            .to_ascii_lowercase()
            .contains("content-type: text/markdown; profile=agentskills.io"),
        "skills pack response should be text/markdown"
    );
    assert_eq!(http_body(&response), SKILLS_PACK);

    handle.abort();
}

#[tokio::test]
async fn discover_reports_seeded_counts_namespaces_and_health_capabilities() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), test_vault_config()).unwrap());

    let turn_a = EntityId::now();
    let turn_b = EntityId::now();
    let persona = EntityId::now();
    let conversation = EntityId::now();
    vault
        .put_entity(&turn_a, ENTITY_TYPE_TURN, time_range(1, 1), 10, b"turn-a")
        .unwrap();
    vault
        .put_entity(&turn_b, ENTITY_TYPE_TURN, time_range(2, 2), 20, b"turn-b")
        .unwrap();
    vault
        .put_entity(
            &persona,
            ENTITY_TYPE_PERSON,
            time_range(3, 3),
            30,
            b"persona",
        )
        .unwrap();
    vault
        .put_entity(
            &conversation,
            ENTITY_TYPE_CONVERSATION,
            time_range(4, 4),
            40,
            b"conversation",
        )
        .unwrap();

    let claim = EntityId::now();
    let claim_body = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(persona),
        "Ada".into(),
        0.99,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    vault
        .put_claim(&claim, &claim_body, time_range(5, 5), 50)
        .unwrap();

    let (addr, handle) = spawn_server(vault, config_with_secret("secret")).await;

    let response = http_get(addr, "/api/core/discover", Some("secret")).await;
    assert_http_status(&response, 200);
    let body = http_json(&response);

    assert_eq!(body["counts"]["0"].as_u64(), Some(1));
    assert_eq!(body["counts"]["1"].as_u64(), Some(2));
    assert_eq!(body["counts"]["4"].as_u64(), Some(1));
    assert_eq!(body["counts"]["11"].as_u64(), Some(1));
    assert_eq!(body["last_activity"].as_u64(), Some(50));
    assert_eq!(
        str_array_set(&body["predicate_namespaces"]),
        BTreeSet::from(["profile"])
    );
    assert_eq!(
        body["personas"][0]["id"].as_str(),
        Some(persona.to_hex().as_str())
    );
    assert_eq!(
        body["conversations"][0]["id"].as_str(),
        Some(conversation.to_hex().as_str())
    );
    assert_eq!(
        str_array_set(&body["feature_flags"]["modes"]),
        BTreeSet::from(["flash", "pro", "thinking", "ultra"])
    );

    let health = http_get(addr, "/api/health", None).await;
    assert_http_status(&health, 200);
    let health = http_json(&health);
    assert_eq!(health["status"].as_str(), Some("ok"));
    assert_eq!(health["service"].as_str(), Some("oneiron-server"));
    assert!(health.get("capabilities").is_some());
    assert!(health.get("formats").is_some());
    assert!(health.get("rate_limit").is_some());
    assert_eq!(
        str_array_set(&health["capabilities"]["modes"]),
        BTreeSet::from(["flash", "pro", "thinking", "ultra"])
    );
    assert_eq!(health["rate_limit"]["api_enforced"].as_bool(), Some(false));
    assert_eq!(
        health["rate_limit"]["max_messages_per_sec"].as_u64(),
        Some(SyncServerConfig::default().max_messages_per_sec.into())
    );

    handle.abort();
}
