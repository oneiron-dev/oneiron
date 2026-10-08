// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oneiron::authority::{CapabilitySlip, HostSlipIssuer};
use oneiron::registry::ENTITY_TYPE_NOTIFICATION;
use oneiron::{AssembledContext, EntityId, TimeRange, VaultConfig};
use oneiron_server::build_app;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
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

struct HostRootAuth {
    issuer: HostSlipIssuer,
    slip: CapabilitySlip,
}

impl HostRootAuth {
    fn principal(&self) -> String {
        let slip_id = self
            .slip
            .claims
            .slip_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("slip:{slip_id}")
    }
}

fn host_root_auth(vault: &oneiron::Vault, secret: &str) -> HostRootAuth {
    let issuer = HostSlipIssuer::from_secret(secret.as_bytes()).unwrap();
    let slip = vault.ensure_host_root_slip(&issuer).unwrap();
    HostRootAuth { issuer, slip }
}

enum HttpAuth<'a> {
    Bearer(&'a str),
    HostRoot(&'a HostRootAuth),
}

async fn spawn_server(
    vault: Arc<oneiron::Vault>,
    config: SyncServerConfig,
) -> (SocketAddr, tokio::task::JoinHandle<()>, HostRootAuth) {
    let secret = config
        .auth_secret
        .as_deref()
        .expect("authenticated test server needs a host root secret");
    let root_auth = host_root_auth(&vault, secret);

    let server = Arc::new(SyncServer::new(vault, config).unwrap());
    let app = build_app(server);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, handle, root_auth)
}

fn auth_headers(auth: Option<HttpAuth<'_>>) -> String {
    match auth {
        None => String::new(),
        Some(HttpAuth::Bearer(token)) => format!("Authorization: Bearer {token}\r\n"),
        Some(HttpAuth::HostRoot(root)) => {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock should be after Unix epoch")
                .as_secs();
            let nonce = EntityId::now().to_hex();
            let challenge = format!("oneiron-request:{timestamp}:{nonce}");
            let signature = root
                .issuer
                .binding_proof(&root.slip, challenge.as_bytes())
                .unwrap()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            format!(
                "Authorization: Bearer {}\r\nx-oneiron-binding: {}\r\n",
                root.slip.to_token().unwrap(),
                serde_json::json!({
                    "timestamp": timestamp,
                    "nonce": nonce,
                    "signature": signature,
                })
            )
        }
    }
}

async fn http_post(addr: SocketAddr, path: &str, auth: Option<HttpAuth<'_>>, body: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let auth_headers = auth_headers(auth);
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{auth_headers}\r\n{body}",
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

fn http_body(response: &str) -> &str {
    response
        .split_once("\r\n\r\n")
        .map(|(_headers, body)| body)
        .expect("HTTP response should contain header/body delimiter")
}

#[tokio::test]
async fn context_board_requires_auth_and_deserializes() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), test_vault_config()).unwrap());
    let (addr, handle, root_auth) = spawn_server(vault, config_with_secret("secret")).await;

    let missing = http_post(addr, "/v1/core/context-board", None, "{}").await;
    assert_http_status(&missing, 401);

    let wrong = http_post(
        addr,
        "/v1/core/context-board",
        Some(HttpAuth::Bearer("wrong")),
        "{}",
    )
    .await;
    assert_http_status(&wrong, 401);

    let bare_secret = http_post(
        addr,
        "/v1/core/context-board",
        Some(HttpAuth::Bearer("secret")),
        "{}",
    )
    .await;
    assert_http_status(&bare_secret, 401);

    let response = http_post(
        addr,
        "/v1/core/context-board",
        Some(HttpAuth::HostRoot(&root_auth)),
        "{}",
    )
    .await;
    assert_http_status(&response, 200);
    let bundle: AssembledContext =
        serde_json::from_str(http_body(&response)).expect("context board should deserialize");
    assert_eq!(bundle.session.api_version, "v1");
    assert_eq!(bundle.notifications, Vec::new());
    assert_eq!(bundle.unprocessed, Vec::new());
    assert_eq!(bundle.budget.tokens_remaining, 0);
    assert!(http_body(&response).contains("\"notifications\":[]"));
    assert!(http_body(&response).contains("\"unprocessed\":[]"));

    handle.abort();
}

#[tokio::test]
async fn context_board_requires_all_present_scope_keys_to_match() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), test_vault_config()).unwrap());
    let caller = host_root_auth(&vault, "secret").principal();

    let conflicting = EntityId::now();
    let matched = EntityId::now();
    let conflicting_body = rmp_serde::to_vec(&serde_json::json!({
        "message": "conflict",
        "caller": caller,
        "recipient": "other"
    }))
    .unwrap();
    let matched_body = rmp_serde::to_vec(&serde_json::json!({
        "message": "match",
        "caller": caller,
        "recipient": caller
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

    let (addr, handle, root_auth) = spawn_server(vault, config_with_secret("secret")).await;
    let response = http_post(
        addr,
        "/v1/core/context-board",
        Some(HttpAuth::HostRoot(&root_auth)),
        "{}",
    )
    .await;
    assert_http_status(&response, 200);
    let bundle: AssembledContext =
        serde_json::from_str(http_body(&response)).expect("context board should deserialize");

    assert_eq!(bundle.notifications.len(), 1);
    assert_eq!(bundle.notifications[0].id, matched.to_hex());
    assert_ne!(bundle.notifications[0].id, conflicting.to_hex());

    handle.abort();
}
