//! The lifetime of one git exchange (C5) and the queue it waits in (the
//! rate law of ARCH-0044 C5), end to end over the real routes and a real
//! `git http-backend`: a stalled push is ended at the idle limit while the
//! next push waits its turn behind it and lands once it ends, reads go on
//! past a push that holds the repository, exchanges past the bound wait for
//! a stalled one to free its permit, a burst of callers on one credential all
//! complete, many pushes to one repository all land, and a slow transfer that
//! keeps moving is never cut.

use super::routes::git_http_routes;
use crate::config::{LimitsConfig, SyncServerConfig};
use crate::server::SyncServer;
use axum::body::Body;
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use oneiron::origin::smart_http;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Far past every idle limit these tests set: reaching it means an exchange
/// the test expected to end was still running.
const PATIENCE: Duration = Duration::from_secs(30);

struct Origin {
    addr: SocketAddr,
    server: Arc<SyncServer>,
    headers: HeaderMap,
    /// The token and binding stock git presents, as `-c` arguments.
    git_auth: [String; 2],
    oid: String,
    source: tempfile::TempDir,
    _vault_dir: tempfile::TempDir,
    _serving: tokio::task::JoinHandle<()>,
}

fn stock_git(root: &Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .current_dir(root)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("stock Git starts");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// A served `demo.git` holding one commit, behind the git routes with the
/// given limits, and a registered pusher's credential for it.
async fn origin(limits: LimitsConfig) -> Origin {
    let vault_dir = tempfile::tempdir().expect("vault");
    let vault = Arc::new(
        oneiron::Vault::open(vault_dir.path(), oneiron::VaultConfig::default())
            .expect("open vault"),
    );
    let config = SyncServerConfig {
        auth_secret: Some("trust-root-secret".to_owned()),
        limits,
        ..SyncServerConfig::default()
    };
    let token = format!(
        "{}scope=core:read,core:write;principal_ref={}",
        crate::test_credentials::RECIPE_PREFIX,
        oneiron::EntityId::now().to_hex()
    );
    let server = Arc::new(SyncServer::new(Arc::clone(&vault), config).expect("server"));
    let request = axum::http::Request::builder()
        .header(AUTHORIZATION, token)
        .body(Body::empty())
        .unwrap();
    let headers = crate::test_credentials::bind_request(&server, request)
        .headers()
        .clone();
    let git_auth = [
        format!(
            "http.extraHeader=Authorization: {}",
            headers[AUTHORIZATION].to_str().unwrap()
        ),
        format!(
            "http.extraHeader=X-Oneiron-Binding: {}",
            headers["x-oneiron-binding"].to_str().unwrap()
        ),
    ];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener");
    let addr = listener.local_addr().expect("address");
    let routes = git_http_routes().with_state(Arc::clone(&server));
    let serving = tokio::spawn(async move {
        axum::serve(listener, routes).await.expect("serve");
    });
    let (source, oid) = tokio::task::spawn_blocking(move || {
        let source = tempfile::tempdir().expect("source");
        stock_git(source.path(), &["init", "--initial-branch=main"]);
        std::fs::write(source.path().join("README.md"), "first\n").expect("readme");
        stock_git(source.path(), &["add", "README.md"]);
        commit(source.path(), "first");
        let oid = stock_git(source.path(), &["rev-parse", "HEAD"]);
        let root = smart_http::origin_serving_root(&vault).expect("serving root");
        stock_git(
            &root,
            &[
                "clone",
                "--bare",
                source.path().to_str().expect("source path"),
                "demo.git",
            ],
        );
        (source, oid)
    })
    .await
    .unwrap();
    Origin {
        addr,
        server,
        headers,
        git_auth,
        oid,
        source,
        _vault_dir: vault_dir,
        _serving: serving,
    }
}

fn commit(root: &Path, message: &str) {
    stock_git(
        root,
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-m",
            message,
        ],
    );
}

fn limits(git_exchanges: usize, idle_ms: u64) -> LimitsConfig {
    LimitsConfig {
        git_exchanges,
        transfer_idle_timeout_ms: idle_ms,
        ..LimitsConfig::default()
    }
}

/// Rule five at the git exchanges row: `callers` advertisements on one
/// credential past a bound of one are all served, and the row asks.
pub(crate) async fn cross_the_exchanges(callers: usize) -> crate::admission::Crossing {
    let origin = origin(limits(1, 30_000)).await;
    let calls: Vec<_> = (0..callers)
        .map(|_| tokio::spawn(advertisement_to(origin.addr, origin.headers.clone())))
        .collect();
    let mut refused = 0;
    for call in calls {
        if call.await.unwrap().0 != 200 {
            refused += 1;
        }
    }
    crate::admission::Crossing {
        refused,
        asked: exchanges_row_asked(&origin),
    }
}

/// Whether the git exchanges row asked whether everything is okay.
fn exchanges_row_asked(origin: &Origin) -> bool {
    origin
        .server
        .wire_telemetry
        .limit_questions()
        .latest(crate::wire_telemetry::LimitRow::GitExchanges)
        .is_some()
}

/// Says whether `stream` gets an answer within `soon`, without reading it.
async fn answered_within(stream: &mut TcpStream, soon: Duration) -> bool {
    let mut byte = [0_u8; 1];
    tokio::time::timeout(soon, stream.peek(&mut byte))
        .await
        .is_ok()
}

/// One whole git RPC to `addr`, sent by hand.
async fn rpc_to(addr: SocketAddr, headers: &HeaderMap, service: &str, body: &[u8]) -> TcpStream {
    rpc_head(addr, headers, service, body.len(), body).await
}

/// Opens one git RPC by hand and sends its head and `prefix`, declaring
/// `declared` body bytes. HTTP/1.0, so the response ends when the socket does.
async fn rpc(origin: &Origin, service: &str, declared: usize, prefix: &[u8]) -> TcpStream {
    rpc_head(origin.addr, &origin.headers, service, declared, prefix).await
}

async fn rpc_head(
    addr: SocketAddr,
    headers: &HeaderMap,
    service: &str,
    declared: usize,
    prefix: &[u8],
) -> TcpStream {
    let mut head = format!("POST /git/demo.git/{service} HTTP/1.0\r\nhost: origin\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {}\r\n", value.to_str().unwrap()));
    }
    head.push_str(&format!(
        "content-type: application/x-{service}-request\r\ncontent-length: {declared}\r\n\r\n"
    ));
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(prefix).await.unwrap();
    stream
}

/// The response's status and body, read until the server closes the socket.
async fn response(stream: &mut TcpStream) -> (u16, Vec<u8>) {
    let mut bytes = Vec::new();
    tokio::time::timeout(PATIENCE, stream.read_to_end(&mut bytes))
        .await
        .expect("the exchange ends")
        .unwrap();
    let split = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("a response head");
    let status = std::str::from_utf8(&bytes[9..12]).unwrap().parse().unwrap();
    (status, bytes[split + 4..].to_vec())
}

/// The advertisement: a fresh exchange of its own.
async fn advertisement(origin: &Origin) -> (u16, Vec<u8>) {
    advertisement_to(origin.addr, origin.headers.clone()).await
}

async fn advertisement_to(addr: SocketAddr, headers: HeaderMap) -> (u16, Vec<u8>) {
    let mut head =
        "GET /git/demo.git/info/refs?service=git-upload-pack HTTP/1.0\r\nhost: origin\r\n"
            .to_owned();
    for (name, value) in &headers {
        head.push_str(&format!("{name}: {}\r\n", value.to_str().unwrap()));
    }
    head.push_str("\r\n");
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(head.as_bytes()).await.unwrap();
    response(&mut stream).await
}

/// Commits `text` in the source and pushes it through the origin to
/// `branch` with stock git, answering the commit it pushed.
fn push_change(
    origin: &Origin,
    branch: &str,
    text: &'static str,
) -> tokio::task::JoinHandle<String> {
    let url = format!("http://{}/git/demo.git", origin.addr);
    let source = origin.source.path().to_owned();
    let [token, binding] = origin.git_auth.clone();
    let target = format!("HEAD:refs/heads/{branch}");
    tokio::task::spawn_blocking(move || {
        std::fs::write(source.join("README.md"), format!("{text}\n")).expect("readme");
        stock_git(&source, &["add", "README.md"]);
        commit(&source, text);
        stock_git(
            &source,
            &["-c", &token, "-c", &binding, "push", &url, &target],
        );
        stock_git(&source, &["rev-parse", "HEAD"])
    })
}

/// A pkt-line framing `payload`.
fn pkt(payload: &str) -> String {
    format!("{:04x}{payload}", payload.len() + 4)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stalled_push_is_ended_and_the_next_push_waits_its_turn_behind_it() {
    let origin = origin(limits(4, 1_000)).await;

    // A command line cut off mid-length: receive-pack waits for the rest,
    // holding the repository coordinator it took before the backend started.
    let mut stalled = rpc(&origin, "git-receive-pack", 4_096, b"00").await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Meanwhile another push to the same repository waits its turn: it is
    // not refused, and it is not answered while the first holds the turn.
    let mut next = rpc(&origin, "git-receive-pack", 4, b"0000").await;
    assert!(
        !answered_within(&mut next, Duration::from_millis(400)).await,
        "a push behind another waits for the repository; it is never refused"
    );

    let (status, _) = response(&mut stalled).await;
    assert_eq!(
        status, 408,
        "a push that stops sending ends at the idle limit"
    );
    // Its turn passes on once its worker has let the coordinator go.
    let (status, body) = response(&mut next).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));

    let pushed = tokio::time::timeout(PATIENCE, push_change(&origin, "next", "second"))
        .await
        .expect("the next push gets the repository once the stalled one ends")
        .unwrap();
    let [token, binding] = origin.git_auth.clone();
    let url = format!("http://{}/git/demo.git", origin.addr);
    let source = origin.source.path().to_owned();
    let refs = tokio::task::spawn_blocking(move || {
        stock_git(&source, &["-c", &token, "-c", &binding, "ls-remote", &url])
    })
    .await
    .unwrap();
    assert!(
        refs.contains(&format!("{pushed}\trefs/heads/next")),
        "{refs}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reads_never_queue_behind_a_push_that_holds_the_repository() {
    let origin = origin(limits(4, 10_000)).await;
    let published = push_change(&origin, "published", "second").await.unwrap();

    // A push that holds the repository coordinator for its idle limit.
    let _stalled = rpc(&origin, "git-receive-pack", 4_096, b"00").await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Far inside that limit, an advertisement and a fetch are both served.
    let soon = Duration::from_secs(3);
    let (status, refs) = tokio::time::timeout(soon, advertisement(&origin))
        .await
        .expect("an advertisement never waits on the push that holds the repository");
    assert_eq!(status, 200);
    // Projected without the coordinator, the ref list still carries what
    // was published.
    let refs = String::from_utf8_lossy(&refs);
    assert!(
        refs.contains(&format!("{published} refs/heads/published")),
        "{refs}"
    );
    let request = format!(
        "{}0000{}",
        pkt(&format!("want {}\n", origin.oid)),
        pkt("done\n")
    );
    let mut fetch = rpc(
        &origin,
        "git-upload-pack",
        request.len(),
        request.as_bytes(),
    )
    .await;
    let (status, body) = tokio::time::timeout(soon, response(&mut fetch))
        .await
        .expect("a fetch never waits on the push that holds the repository");
    assert_eq!(status, 200);
    assert!(
        body.windows(4).any(|window| window == b"PACK"),
        "the fetch delivers its pack"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn past_the_bound_an_exchange_waits_for_a_stalled_one_to_free_its_permit() {
    let origin = origin(limits(1, 1_000)).await;

    let want = pkt(&format!("want {}\n", origin.oid));
    let mut stalled = rpc(&origin, "git-upload-pack", 4_096, want.as_bytes()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Past the bound a new exchange waits; it is never refused.
    let started = std::time::Instant::now();
    let waiting = tokio::spawn(advertisement_to(origin.addr, origin.headers.clone()));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !waiting.is_finished(),
        "the waiting exchange is not answered yet"
    );
    assert!(exchanges_row_asked(&origin), "crossing the row asks");

    // The stalled fetch ends at its idle limit; its permit passes on only
    // once its worker has killed and reaped the backend.
    let _ = response(&mut stalled).await;
    let (status, _) = tokio::time::timeout(PATIENCE, waiting)
        .await
        .expect("the permit passes on once the stalled exchange ends")
        .unwrap();
    assert_eq!(status, 200);
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_millis(500),
        "it waited its turn: {waited:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_burst_of_two_hundred_callers_on_one_credential_all_complete() {
    const FETCHES: usize = 150;
    const PUSHES: usize = 50;
    let origin = origin(limits(4, 30_000)).await;

    // Fifty commits on top of the first, each to land on its own branch.
    let source = origin.source.path().to_owned();
    let commits = tokio::task::spawn_blocking(move || {
        (0..PUSHES)
            .map(|n| {
                stock_git(
                    &source,
                    &[
                        "commit-tree",
                        "HEAD^{tree}",
                        "-p",
                        "HEAD",
                        "-m",
                        &format!("push {n}"),
                    ],
                )
            })
            .collect::<Vec<_>>()
    })
    .await
    .unwrap();

    let request = format!(
        "{}0000{}",
        pkt(&format!("want {}\n", origin.oid)),
        pkt("done\n")
    );
    let fetches: Vec<_> = (0..FETCHES)
        .map(|_| {
            let addr = origin.addr;
            let headers = origin.headers.clone();
            let request = request.clone();
            tokio::spawn(async move {
                let mut stream =
                    rpc_to(addr, &headers, "git-upload-pack", request.as_bytes()).await;
                response(&mut stream).await
            })
        })
        .collect();
    let url = format!("http://{}/git/demo.git", origin.addr);
    let pushes: Vec<_> = commits
        .iter()
        .enumerate()
        .map(|(n, commit)| {
            let source = origin.source.path().to_owned();
            let [token, binding] = origin.git_auth.clone();
            let url = url.clone();
            let target = format!("{commit}:refs/heads/burst-{n}");
            tokio::task::spawn_blocking(move || {
                stock_git(
                    &source,
                    &["-c", &token, "-c", &binding, "push", &url, &target],
                )
            })
        })
        .collect();

    for fetch in fetches {
        let (status, body) = tokio::time::timeout(Duration::from_secs(300), fetch)
            .await
            .expect("every fetch completes")
            .unwrap();
        assert_eq!(status, 200, "a queued fetch is served, never refused");
        assert!(body.windows(4).any(|window| window == b"PACK"));
    }
    for push in pushes {
        tokio::time::timeout(Duration::from_secs(300), push)
            .await
            .expect("every push completes")
            .expect("every push to the one repository lands");
    }
    let [token, binding] = origin.git_auth.clone();
    let source = origin.source.path().to_owned();
    let refs = tokio::task::spawn_blocking(move || {
        stock_git(&source, &["-c", &token, "-c", &binding, "ls-remote", &url])
    })
    .await
    .unwrap();
    for (n, commit) in commits.iter().enumerate() {
        assert!(
            refs.contains(&format!("{commit}\trefs/heads/burst-{n}")),
            "push {n} landed: {refs}"
        );
    }
    assert!(
        exchanges_row_asked(&origin),
        "the burst crossed the row, which asked"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_fetch_that_keeps_moving_is_not_cut() {
    let origin = origin(limits(1, 600)).await;

    let request = format!(
        "{}0000{}",
        pkt(&format!("want {}\n", origin.oid)),
        pkt("done\n")
    );
    let pieces = request.as_bytes().chunks(request.len() / 4 + 1);
    let mut stream = rpc(&origin, "git-upload-pack", request.len(), &[]).await;
    // Every gap is inside the idle limit; together they are well past it.
    for piece in pieces {
        tokio::time::sleep(Duration::from_millis(350)).await;
        stream.write_all(piece).await.unwrap();
    }
    let (status, body) = response(&mut stream).await;
    assert_eq!(status, 200);
    assert!(
        body.windows(4).any(|window| window == b"PACK"),
        "the fetch delivers its pack"
    );
}
