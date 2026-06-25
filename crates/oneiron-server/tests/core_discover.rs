use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use oneiron::types::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, TimeRange,
    VaultConfig,
};
use oneiron_server::build_app;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn test_vault_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.max_readers = 32;
    config
}

fn time_range(start: u64, end: u64) -> TimeRange {
    TimeRange { start, end }
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

fn str_array_set(value: &Value) -> BTreeSet<&str> {
    value
        .as_array()
        .expect("value should be an array")
        .iter()
        .map(|item| item.as_str().expect("array item should be a string"))
        .collect()
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
