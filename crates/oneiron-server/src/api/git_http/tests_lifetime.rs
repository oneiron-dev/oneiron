//! The lifetime of one git exchange (C5) and the queue it waits in (the
//! rate law of ARCH-0044 C5), end to end over the real routes and a real
//! `git http-backend`: a stalled push is ended at the idle limit while the
//! next push waits its turn behind it and lands once it ends, reads go on
//! past a push that holds the repository, exchanges past the bound (or past
//! the descriptors the sockets leave) wait for a stalled one to free its
//! permit, a burst of callers on one credential all complete, many pushes to
//! one repository all land, and a slow transfer that keeps moving is never
//! cut.

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
    /// The credential's recipe, which [`Origin::git_auth`] binds anew.
    token: String,
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
    let headers = bound_headers(&server, &token);
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
        token,
        oid,
        source,
        _vault_dir: vault_dir,
        _serving: serving,
    }
}

/// The credential `token` names, with a binding signed now.
fn bound_headers(server: &SyncServer, token: &str) -> HeaderMap {
    let request = axum::http::Request::builder()
        .header(AUTHORIZATION, token)
        .body(Body::empty())
        .unwrap();
    crate::test_credentials::bind_request(server, request)
        .headers()
        .clone()
}

impl Origin {
    /// The token and a binding signed now, as stock git's `-c` arguments. A
    /// binding is fresh for a minute, and a burst on a loaded host outlasts
    /// one signed when it began.
    fn git_auth(&self) -> [String; 2] {
        let headers = bound_headers(&self.server, &self.token);
        [
            format!(
                "http.extraHeader=Authorization: {}",
                headers[AUTHORIZATION].to_str().unwrap()
            ),
            format!(
                "http.extraHeader=X-Oneiron-Binding: {}",
                headers["x-oneiron-binding"].to_str().unwrap()
            ),
        ]
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
    let [token, binding] = origin.git_auth();
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

    // A command line cut off mid-length. The origin reads a push's command
    // section only once the push holds its repository's turn, its permit and
    // the coordinator, before the backend starts (#1447); it waits there for
    // the rest, and the stall ends at the idle limit, not a queue deadline.
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
    let [token, binding] = origin.git_auth();
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

/// Docs lane on #1456: maintenance took the last git permit with a try, so
/// the next push was answered 503 at its admission, before the coordinator
/// could ask the maintenance to give way. Maintenance now waits for its
/// permit behind every caller and never refuses one; a push that comes while
/// maintenance holds the last permit waits for it, and lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_push_that_finds_maintenance_holding_the_last_git_permit_waits_and_lands() {
    let origin = origin(limits(1, 30_000)).await;
    let server = Arc::clone(&origin.server);
    let maintenance =
        tokio::task::spawn_blocking(move || server.transfers.admit_git_maintenance().ok())
            .await
            .unwrap()
            .expect("maintenance takes the one git permit");

    let push = push_change(&origin, "past-maintenance", "pushed past maintenance");
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert!(
        !push.is_finished(),
        "the push waits for the permit maintenance holds; it is not answered"
    );
    drop(maintenance);
    tokio::time::timeout(PATIENCE, push)
        .await
        .expect("the push gets the permit once maintenance lets it go")
        .expect("the push lands, never refused");
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
    a_stalled_exchange_holds_the_next_one_back(origin(limits(1, 1_000)).await).await;
}

/// Review r8 (Astra R8-1, P1): a git exchange holds three pipes to its child
/// besides its socket, and nothing counted them: at a common open-file limit
/// of 1,024, exchanges well inside the 2,048 row could run the process out
/// of descriptors. The git and LFS bounds are now held to the descriptors
/// the sockets leave; past them an exchange waits its turn, as past the row.
/// The sockets are sized from the limit serving holds once it has raised it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn past_the_descriptors_the_sockets_leave_an_exchange_waits_for_a_stalled_one() {
    use crate::api::transfer::{GIT_DESCRIPTORS, OWN_DESCRIPTORS};
    // The sockets take all but the room of one exchange, half of what is
    // left being git's.
    let open_files = crate::machine::raise_open_file_limit().expect("an open-file limit");
    let sockets = open_files
        .checked_sub(OWN_DESCRIPTORS + 2 * GIT_DESCRIPTORS)
        .expect("room for the process's own descriptors");
    let limits = LimitsConfig {
        max_connections: usize::try_from(sockets).expect("a socket count"),
        transfer_idle_timeout_ms: 1_000,
        ..LimitsConfig::default()
    };
    assert!(limits.git_exchanges > 1, "the row alone would admit both");
    a_stalled_exchange_holds_the_next_one_back(origin(limits).await).await;
}

/// Review r12 (the Engine, beside Astra R12-3): counted at their peak, the
/// 1,024 descriptors a fresh login's soft limit holds leave room for 8 git
/// exchanges. Serving raises the soft limit to the hard one, at most 65,536,
/// and never lowers it. A process that starts at or above that, or a
/// platform that refuses the raise, keeps the limit it has.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serving_raises_its_soft_open_file_limit_to_the_hard_one_at_most_65_536() {
    let mut held = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `getrlimit` writes the struct on the stack and nothing else.
    let read = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut held) };
    assert_eq!(read, 0, "the open-file limit reads");
    let before = crate::machine::open_file_limit().expect("an open-file limit");
    let vault_dir = tempfile::tempdir().expect("vault");
    let vault = Arc::new(
        oneiron::Vault::open(vault_dir.path(), oneiron::VaultConfig::default())
            .expect("open vault"),
    );
    let _server = SyncServer::new(vault, SyncServerConfig::default()).expect("server");
    let after = crate::machine::open_file_limit().expect("an open-file limit");
    let wanted = held.rlim_max.min(65_536);
    if cfg!(target_os = "linux") {
        assert_eq!(after, before.max(wanted), "serving raised the soft limit");
    } else {
        assert!(after >= before, "serving never lowers the soft limit");
    }
}

/// Stores an object, then pushes a commit carrying its LFS pointer to
/// `branch` with stock git, answering whether the push succeeded and what
/// git said.
async fn push_an_lfs_pointer(origin: &Origin, branch: &str) -> (bool, String) {
    let asset = b"an asset the pushed branch carries".to_vec();
    let oid = oneiron::origin::lfs::LfsOid::digest(&asset);
    let at = oneiron::TimeRange {
        start: 1_700_000_000,
        end: 1_700_000_000,
    };
    origin
        .server
        .vault()
        .put_lfs_object(oid, &asset, at, at.start)
        .expect("the object the pointer names is stored before the push");
    let pointer = format!(
        "version https://git-lfs.github.com/spec/v1\noid sha256:{}\nsize {}\n",
        oid.to_hex(),
        asset.len()
    );
    let url = format!("http://{}/git/demo.git", origin.addr);
    let source = origin.source.path().to_owned();
    let [token, binding] = origin.git_auth();
    let target = format!("HEAD:refs/heads/{branch}");
    tokio::task::spawn_blocking(move || {
        std::fs::write(source.join("logo.bin"), pointer).expect("pointer");
        stock_git(&source, &["add", "logo.bin"]);
        commit(&source, "carry an asset");
        let pushed = std::process::Command::new("git")
            .current_dir(&source)
            .args(["-c", &token, "-c", &binding, "push", &url, &target])
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .expect("stock Git starts");
        let said = String::from_utf8_lossy(&pushed.stderr).into_owned();
        (pushed.status.success(), said)
    })
    .await
    .unwrap()
}

/// Waits until something waits on `line`, failing if `answered` finished
/// first.
async fn until_waiting_on(
    line: &crate::byte_line::ByteLine,
    answered: &tokio::task::JoinHandle<(u16, Vec<u8>)>,
) {
    let started = std::time::Instant::now();
    while line.waiting() == 0 {
        assert!(
            !answered.is_finished(),
            "the advertisement was answered without room to check the object"
        );
        assert!(started.elapsed() < PATIENCE, "the check waits on the line");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Review r12 (Astra R12-2, P1): an advertisement checks that each LFS
/// object its published refs need is readable, reading the object's whole
/// manifest, and that read took no room on the LFS reads line: past any
/// number of downloads holding the line, every advertisement could hold a
/// manifest more. The check now waits for its manifest's room on the line,
/// as a download does, and the ref is advertised once it has it.
///
/// Review r12 narrow (Astra R12n-3, P1): that wait is the server's own work,
/// and the exchange's idle limit counted it, so a wait longer than the
/// limit (1 s here) ended the advertisement though its room came within
/// the queue deadline. The idle clock holds still while it waits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_advertisement_checks_an_lfs_object_its_ref_needs_with_room_on_the_reads_line() {
    let origin = origin(limits(4, 1_000)).await;
    let (pushed, said) = push_an_lfs_pointer(&origin, "assets").await;
    assert!(pushed, "the push lands: {said}");

    // Downloads hold the whole reads line, past the idle limit.
    let transfers = &origin.server.transfers;
    let reads = transfers.lfs_reads();
    let held = reads
        .reserve(reads.total(), PATIENCE, &transfers.questions)
        .await
        .expect("the whole reads line");
    let advertised = tokio::spawn(advertisement_to(origin.addr, origin.headers.clone()));
    until_waiting_on(reads, &advertised).await;
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    drop(held);
    let (status, body) = tokio::time::timeout(PATIENCE, advertised)
        .await
        .expect("the advertisement is answered once its check has room")
        .unwrap();
    assert_eq!(status, 200);
    assert!(
        String::from_utf8_lossy(&body).contains("refs/heads/assets"),
        "the ref whose object was checked is advertised"
    );
}

/// Review r12 narrow (Astra R12n-2, P1): a push whose landing waited past
/// the queue deadline for room to check its LFS object was answered as if
/// the landing had run its course, the error swallowed, and recovery went
/// on to wait as long again for each pending ref. The push is now told to
/// retry (503); its ref stays Pending, and the next exchange that finds
/// the repository free publishes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_push_whose_lfs_check_waits_past_its_deadline_is_told_to_retry_and_lands_later() {
    let origin = origin(LimitsConfig {
        queue_wait_timeout_ms: 1_000,
        ..limits(4, 30_000)
    })
    .await;
    let transfers = &origin.server.transfers;
    let reads = transfers.lfs_reads();
    let held = reads
        .reserve(reads.total(), PATIENCE, &transfers.questions)
        .await
        .expect("the whole reads line");
    let (pushed, said) = push_an_lfs_pointer(&origin, "assets").await;
    assert!(!pushed, "the push is not told it landed: {said}");
    assert!(said.contains("503"), "it is told to retry: {said}");
    drop(held);
    let (status, body) = advertisement(&origin).await;
    assert_eq!(status, 200);
    assert!(
        String::from_utf8_lossy(&body).contains("refs/heads/assets"),
        "the next exchange publishes the pending ref"
    );
}

/// A fetch that stalls holds the only exchange its bound allows: the next
/// exchange waits, the row asks, and it is served once the stalled one ends
/// at the idle limit.
async fn a_stalled_exchange_holds_the_next_one_back(origin: Origin) {
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
                        "-c",
                        "user.name=Test",
                        "-c",
                        "user.email=test@example.invalid",
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
            let [token, binding] = origin.git_auth();
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
    let [token, binding] = origin.git_auth();
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
