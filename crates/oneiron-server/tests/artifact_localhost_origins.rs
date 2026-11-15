//! A local run serves apps and previews in the hosted shape on `*.localhost`
//! (APP-HOST = A, CROSS-ARCH-0019 #app-host-shape, owner 2026-10-11: "A
//! published app lives at `<app>--<name>.oneiron.page` ... A local run uses
//! the same shape on `*.localhost`"; CROSS-ARCH-0024:48: "Local serving on
//! `*.localhost` is not built").
//!
//! Red at main: `<app>--<name>.localhost` falls to local serving, whose `/`
//! has no route (404); a local preview lease answers at
//! `preview-<hex>.localhost`, which the contract's `p-<lease>` codec does not
//! read. Guards (they pass there too): the bare `localhost` and `127.0.0.1`
//! keep local `/a/`, a `*.localhost` name of another vault serves nothing,
//! and the unauthenticated `/api/health` names no vault.
//!
//! `cargo test --locked -p oneiron-server --features oneiron/test-support,oneiron/test-hooks
//! --test artifact_localhost_origins`.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(
    clippy::disallowed_methods,
    reason = "the fixture commits a bundle with the git binary; the rule covers the server's crates"
)]

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use oneiron::artifact_hosting::ArtifactServeTier;
use oneiron::{TimeRange, Vault, VaultConfig};
use oneiron_server::managed::ManagedShutdown;
use oneiron_server::managed::ShutdownSignal;
use oneiron_server::managed::preview::{
    LocalPreviewHost, PreviewConnectFuture, PreviewConnection, PreviewProcess,
};
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, build_artifact_app, config::SyncServerConfig,
    server::SyncServer,
};
use oneiron_vault_contract::artifact_origin::{PreviewOrigin, PreviewOriginRead};
use oneiron_vault_contract::host::PreviewPortHost;
use oneiron_vault_contract::preview::{PreviewPortDeclaration, PreviewSessionManifest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

const APP_PAGE: &str = "<h1>a public app</h1>\n";
const PREVIEW_PAGE: &str = "<h1>a live preview</h1>\n";
/// The artifact port a request names in its `Host`; the router reads the
/// name alone.
const ARTIFACT_PORT: u16 = 49152;

fn git(repo: &std::path::Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .args(args)
        .current_dir(repo)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("git starts");
    assert!(status.success(), "git {args:?} failed");
}

/// Commits `index.html` holding `page` to a fresh repository and publishes it
/// as the public code bundle `name`.
fn publish_public_bundle(vault: &Vault, name: &str, page: &str) {
    let repo = tempfile::tempdir().expect("artifact repo");
    std::fs::write(repo.path().join("index.html"), page).expect("write bundle file");
    git(repo.path(), &["init"]);
    git(
        repo.path(),
        &["config", "user.email", "oneiron@example.test"],
    );
    git(repo.path(), &["config", "user.name", "Oneiron Test"]);
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-m", "bundle"]);
    let ingest = oneiron::codebase::RepoIngestConfig::new(repo.path(), ["index.html"])
        .expect("ingest config");
    let result = vault
        .ingest_local_repo_at_commit(name, &ingest, "HEAD", TimeRange { start: 10, end: 10 }, 10)
        .expect("ingest bundle");
    let body = vault
        .get_code_artifact(&result.code_artifact_id)
        .expect("read code artifact")
        .expect("code artifact exists")
        .with_class(oneiron::code_artifact::CodeArtifactClass::Artifact);
    vault
        .put_code_artifact(
            &result.code_artifact_id,
            &body,
            TimeRange { start: 10, end: 10 },
            10,
        )
        .expect("mark hostable");
    vault
        .publish_artifact_pointer_with_tier(
            name,
            oneiron::ArtifactPointerChannel::Published,
            &result.snapshot.fork_hash,
            ArtifactServeTier::Public,
        )
        .expect("publish bundle");
}

/// A vault holding the public app `site`, served as a plain serve that names
/// its vault `vault_name` (none: it names no vault), with an artifact
/// listener on [`ARTIFACT_PORT`].
fn served(vault_name: Option<&str>) -> (tempfile::TempDir, Arc<SyncServer>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    let vault = Arc::new(Vault::open(dir.path(), config).expect("vault"));
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    publish_public_bundle(&vault, "site", APP_PAGE);
    let server = SyncServer::new(
        Arc::clone(&vault),
        SyncServerConfig {
            auth_secret: Some("artifact-localhost-origins".to_owned()),
            artifact_vault_name: vault_name.map(str::to_owned),
            ..Default::default()
        },
    )
    .expect("a server")
    .with_artifact_listener(ARTIFACT_PORT);
    (dir, Arc::new(server))
}

/// `GET <path>` on the artifact listener under `Host: <host>`, with no
/// credential: the status and the body.
async fn open(server: &Arc<SyncServer>, host: &str, path: &str) -> (StatusCode, String) {
    let request = Request::builder()
        .method("GET")
        .uri(path)
        .header("host", host)
        .body(Body::empty())
        .expect("request");
    let response = build_artifact_app(Arc::clone(server))
        .oneshot(request)
        .await
        .expect("response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1_048_576)
        .await
        .expect("response body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Runs `case` on a runtime whose threads have the engine's stack.
fn on_engine_stack<F>(case: impl FnOnce() -> F + Send + 'static)
where
    F: std::future::Future<Output = ()>,
{
    let thread = std::thread::Builder::new()
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(case());
        })
        .expect("engine-stack thread");
    if let Err(panic) = thread.join() {
        std::panic::resume_unwind(panic);
    }
}

#[test]
fn local_run_serves_app_shape_on_localhost() {
    on_engine_stack(|| async {
        let (_dir, server) = served(Some("vault"));
        let app_host = format!("site--vault.localhost:{ARTIFACT_PORT}");
        let (status, body) = open(&server, &app_host, "/_s/c/published/").await;
        assert_eq!(status, StatusCode::OK, "{app_host}: {body}");
        assert!(
            body.contains(APP_PAGE),
            "the app's page on {app_host}: {body}"
        );
        // The vault's own host serves its artifacts by path.
        let vault_host = format!("vault.localhost:{ARTIFACT_PORT}");
        let (status, body) = open(&server, &vault_host, "/site/_s/c/published/").await;
        assert_eq!(status, StatusCode::OK, "{vault_host}: {body}");
        assert!(
            body.contains(APP_PAGE),
            "the app's page on {vault_host}: {body}"
        );
    });
}

#[test]
fn bare_localhost_keeps_local_artifact_serving() {
    on_engine_stack(|| async {
        let (_dir, server) = served(Some("vault"));
        for host in [
            format!("localhost:{ARTIFACT_PORT}"),
            format!("127.0.0.1:{ARTIFACT_PORT}"),
        ] {
            let (status, body) = open(&server, &host, "/a/site/_s/c/published/").await;
            assert_eq!(status, StatusCode::OK, "{host}: {body}");
            assert!(body.contains(APP_PAGE), "local /a/ on {host}: {body}");
        }
    });
}

#[test]
fn a_localhost_name_of_another_vault_serves_nothing() {
    on_engine_stack(|| async {
        let (_dir, server) = served(Some("vault"));
        let host = format!("site--other.localhost:{ARTIFACT_PORT}");
        let (status, body) = open(&server, &host, "/_s/c/published/").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{host}: {body}");
        assert!(!body.contains(APP_PAGE), "{host} served the app: {body}");
    });
}

/// `/api/health` answers with no credential, so it names no vault: a client
/// that starts the serve knows its `--artifact-vault-name` and reaches
/// `<name>.localhost:<artifact_port>` from that (#8359 review T5).
#[test]
fn health_names_no_vault() {
    on_engine_stack(|| async {
        let (_dir, server) = served(Some("Quarry"));
        let request = Request::builder()
            .method("GET")
            .uri("/api/health")
            .body(Body::empty())
            .expect("request");
        let response = build_app(Arc::clone(&server))
            .oneshot(request)
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 1_048_576)
            .await
            .expect("health body");
        let health: serde_json::Value = serde_json::from_slice(&bytes).expect("health JSON");
        assert_eq!(
            health["artifact_port"].as_u64(),
            Some(u64::from(ARTIFACT_PORT)),
            "{health:#}"
        );
        assert!(
            !health.to_string().to_ascii_lowercase().contains("quarry"),
            "health names the vault: {health:#}"
        );
    });
}

/// A verified process stand-in: its declared port is a loopback server that
/// answers every request with [`PREVIEW_PAGE`].
struct ServedProcess {
    manifest: PreviewSessionManifest,
    upstream: SocketAddr,
    stop: ManagedShutdown,
}

impl PreviewProcess for ServedProcess {
    fn manifest(&self) -> &PreviewSessionManifest {
        &self.manifest
    }

    fn connect(&self, _port: u16) -> PreviewConnectFuture<'_> {
        let upstream = self.upstream;
        Box::pin(async move {
            let stream = tokio::net::TcpStream::connect(upstream).await?;
            Ok::<PreviewConnection, std::io::Error>(Box::new(stream))
        })
    }

    fn stopped(&self) -> ShutdownSignal {
        self.stop.triggered()
    }
}

/// A loopback HTTP/1.1 server that answers each request with
/// [`PREVIEW_PAGE`] and closes.
async fn spawn_upstream() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream");
    let addr = listener.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = read_head(&mut socket).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{PREVIEW_PAGE}",
                    PREVIEW_PAGE.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    addr
}

/// Reads a request or response head up to its blank line.
async fn read_head(socket: &mut tokio::net::TcpStream) -> std::io::Result<Vec<u8>> {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if socket.read(&mut byte).await? == 0 {
            break;
        }
        head.push(byte[0]);
    }
    Ok(head)
}

/// One raw HTTP/1.1 `GET <path>` to `127.0.0.1:<port>` under `Host:
/// <authority>`, with `cookie` when given: the whole response, head and
/// body.
async fn raw_get(port: u16, authority: &str, path: &str, cookie: Option<&str>) -> String {
    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("preview listener");
    let cookie = cookie.map_or_else(String::new, |cookie| format!("cookie: {cookie}\r\n"));
    let request =
        format!("GET {path} HTTP/1.1\r\nhost: {authority}\r\n{cookie}connection: close\r\n\r\n");
    socket
        .write_all(request.as_bytes())
        .await
        .expect("send request");
    let mut response = Vec::new();
    socket
        .read_to_end(&mut response)
        .await
        .expect("read response");
    String::from_utf8_lossy(&response).into_owned()
}

#[test]
fn local_run_serves_preview_shape_on_localhost() {
    on_engine_stack(|| async {
        let upstream = spawn_upstream().await;
        let manifest = PreviewSessionManifest {
            session_ref: "session-1".to_owned(),
            lease_ref: "lease-1".to_owned(),
            owner_ref: "owner-1".to_owned(),
            expires_at: oneiron_vault_contract::now_ts() + 600,
            preview: PreviewPortDeclaration {
                process_ref: "process-1".to_owned(),
                port: 3000,
            },
        };
        let process = Arc::new(ServedProcess {
            manifest: manifest.clone(),
            upstream,
            stop: ManagedShutdown::new(),
        });
        let host_stop = ManagedShutdown::new();
        let host = LocalPreviewHost::new(process, host_stop.clone());
        let lease = host.open_preview(manifest).await.expect("a live lease");

        let local_url = lease.endpoint().local_url.clone();
        let authority = local_url
            .strip_prefix("http://")
            .unwrap_or_else(|| panic!("a plain loopback origin: {local_url}"))
            .to_owned();
        let read = PreviewOrigin::read(&authority, &["localhost".to_owned()]);
        assert!(
            matches!(read, PreviewOriginRead::Named(_)),
            "the lease's origin {local_url} is not `p-<lease>.localhost`: {read:?}"
        );
        let port: u16 = authority
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse().ok())
            .unwrap_or_else(|| panic!("the origin names its port: {local_url}"));

        // The owner's access link sets the lease's cookie on that origin,
        // and the origin then answers with the process's own page.
        let access = lease
            .access_url("owner-1")
            .expect("the owner's access link");
        let path = access
            .strip_prefix(local_url.as_str())
            .unwrap_or_else(|| panic!("the access link is on the lease's origin"))
            .to_owned();
        let bootstrap = raw_get(port, &authority, &path, None).await;
        assert!(bootstrap.starts_with("HTTP/1.1 303"), "{bootstrap}");
        let cookie = bootstrap
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("set-cookie").then(|| {
                    value
                        .trim()
                        .split(';')
                        .next()
                        .unwrap_or_default()
                        .to_owned()
                })
            })
            .unwrap_or_else(|| panic!("the access link set no cookie: {bootstrap}"));
        let page = raw_get(port, &authority, "/", Some(&cookie)).await;
        assert!(page.starts_with("HTTP/1.1 200"), "{page}");
        assert!(page.contains(PREVIEW_PAGE), "the process's page: {page}");

        lease.close();
        host_stop.trigger();
    });
}
