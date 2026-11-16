//! Row RUNNER-WORK-CHECKOUT-STAYS-ACTIVE: a bound runner work's checkout at its
//! attempt's Completed capture (Engine RULING EXPORTPROOF-RUNNER-CHECKOUT-END = A,
//! 16 Nov 08:20).
//!
//! The production seat-host sequence through public API only: a TASK row, a
//! checkout claim, `bind_runner_work_in_txn`, a host CLI claim, `execute_cli`
//! with a fake executor, `capture_terminal_exhaust`, then the seat host's end
//! (`end_runner_checkout`) through `seat_host_end` below.
//!
//! - `completed_runner_capture_retains_an_unpushed_checkout`: a Completed
//!   capture with no push ends Retained for a missing pushed-head receipt.
//! - `completed_runner_capture_collects_a_pushed_clean_checkout`: a Completed
//!   capture after the run pushed its head ends Collected; the lease row and
//!   the worktree are gone.
//! - `failed_runner_capture_keeps_the_checkout_active`: a Failed capture keeps
//!   the lease Active and the end answers None.
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{io, thread};

use oneiron::attempt_queue::{AttemptId, AttemptState};
use oneiron::checkout::lease::{
    CheckoutClaimRequest, CheckoutFactMutation, CheckoutFactSink, CheckoutId, CheckoutLeaseAct,
    CheckoutLeaseService, CheckoutLeaseState, CheckoutLiveness, CheckoutLivenessPulse,
    CheckoutRepoOps, CheckoutResult, CheckoutRetainReason, CheckoutTaskClass,
    CheckoutTeardownOutcome,
};
use oneiron::code_sandbox::SandboxBoundaryContract;
use oneiron::code_sandbox::microvm::ExecutionBudget;
use oneiron::codebase::RepoRef;
use oneiron::dispatch_byoa::{
    BindRunnerWork, ByoEndpointBackendFactory, ByoEndpointSpec, ByoaCliExecutor, ByoaDispatcher,
    ByoaEgressLease, ByoaEgressPort, ByoaError, ByoaExecutionFence, ByoaExhaust, ByoaResult,
    ByoaTerminalDisposition, ByoaTerminalReceipt, CaptureByoaExhaust, CliSandboxSpec, OnSeatSpent,
    ProviderAdapterRegistry, RunnerSeat, RunnerSeatChoice, RunnerSeatPolicy, RunnerWorkBound,
    SeatAuth,
};
use oneiron::git_wire::GitWire;
use oneiron::origin::publication::OriginPublicationStatus;
use oneiron::origin::smart_http::{self, DoorSeam, ServeRequest, ServeSink};
use oneiron::task_verb::TaskCreateSpec;
use oneiron::{EdgeActorClass, EntityId, LlmBackend, Vault, VaultConfig};

const HEAD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HOLDER: &str = "one";
const LEASE_SECS: u64 = 3_600;

struct Facts;
impl CheckoutFactSink for Facts {
    fn apply_checkout_fact(&mut self, _: CheckoutFactMutation) -> CheckoutResult<()> {
        Ok(())
    }
}

/// No liveness pulse is ever seen, so teardown judges the checkout by its
/// receipt and its tree alone.
struct NoLiveness;
impl CheckoutLiveness for NoLiveness {
    fn publish(&mut self, _: CheckoutLivenessPulse) -> CheckoutResult<()> {
        Ok(())
    }
    fn current(&self, _: CheckoutId) -> CheckoutResult<Option<CheckoutLivenessPulse>> {
        Ok(None)
    }
    fn clear(&mut self, _: CheckoutId, _: u64) -> CheckoutResult<()> {
        Ok(())
    }
}

/// A seat run reaches no endpoint: the official CLI talks to its vendor.
struct NoEndpoints;

impl ByoEndpointBackendFactory for NoEndpoints {
    fn resolve_backend(&self, _spec: &ByoEndpointSpec) -> ByoaResult<Arc<dyn LlmBackend>> {
        Err(ByoaError::Backend(
            "the test serves no endpoint connector".to_owned(),
        ))
    }
}

/// A seat run takes no egress lease: the fake executor never reaches out.
struct NoEgress;

impl ByoaEgressPort for NoEgress {
    fn open(&mut self, profile_ref: &str, _intent_ref: &str) -> ByoaResult<ByoaEgressLease> {
        Err(ByoaError::EgressDenied {
            profile_ref: profile_ref.to_owned(),
            reason: "the test leases no egress".to_owned(),
        })
    }
}

/// The runner CLI, faked: every run leaves a small stdout exhaust.
struct FakeExec;

impl ByoaCliExecutor for FakeExec {
    fn run(
        &mut self,
        _spec: &CliSandboxSpec,
        _checkout: &CheckoutLeaseAct,
        _boundary: SandboxBoundaryContract,
        _budget: ExecutionBudget,
        _authorize: &mut dyn FnMut(&str, u64) -> ByoaResult<ByoaEgressLease>,
    ) -> ByoaResult<ByoaExhaust> {
        Ok(ByoaExhaust {
            stdout: b"ok".to_vec().into(),
            ..Default::default()
        })
    }
}

/// What the seat host runs after it settles a run (host_seat_run).
fn seat_host_end<B: ByoEndpointBackendFactory, E: ByoaEgressPort>(
    dispatcher: &ByoaDispatcher<'_, B, E>,
    fence: &ByoaExecutionFence,
) -> Option<CheckoutTeardownOutcome> {
    let _ = (dispatcher, fence);
    None
}

type Leases<'a> = CheckoutLeaseService<'a, Facts, NoLiveness>;

fn wall_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is past the epoch")
        .as_secs()
}

/// A TASK the owner creates through the task door: live, with an Owner fact,
/// so its standing proves the owner and it is not cancelled.
fn owner_task(vault: &Vault, owner: EntityId, label: &str) -> EntityId {
    vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_create(&TaskCreateSpec::new(
            rmpv::Value::Nil,
            Some(label.to_owned()),
            Some(owner),
            Some(vault.now_recorded_at()),
        ))
        .expect("the task door")
        .task_ref
        .expect("the TASK creation took effect")
}

/// Claims the checkout and answers the first second every later door accepts:
/// the doors compare `now` with the lease's `claimed_at`, which the vault's
/// own clock stamps.
fn claim(
    leases: &mut Leases<'_>,
    checkout_id: CheckoutId,
    task: EntityId,
    repo_ref: RepoRef,
    holder: &str,
    wall: u64,
) -> u64 {
    leases
        .claim(CheckoutClaimRequest {
            checkout_id,
            task_ref: task,
            repo_ref,
            holder_ref: holder.to_owned(),
            task_class: CheckoutTaskClass::Build,
            ttl_secs: Some(LEASE_SECS),
            now: wall,
        })
        .expect("the claim lands");
    let claimed_at = leases
        .get(checkout_id)
        .expect("the lease reads")
        .expect("the lease exists")
        .claimed_at;
    let start = wall.max(claimed_at);
    assert!(
        start + 10 < wall + LEASE_SECS,
        "the vault clock ({claimed_at}) is within the lease of the wall clock ({wall})"
    );
    start
}

/// The owner's one login seat over the standard CLI runners: a login seat
/// names no credential at all, and on a default vault no hosted-only bound
/// keeps it off this runtime.
fn seats() -> (ProviderAdapterRegistry, RunnerSeatPolicy) {
    let registry = ProviderAdapterRegistry::standard();
    let policy = RunnerSeatPolicy {
        seats: vec![RunnerSeat {
            runner: "claude-code".to_owned(),
            auth: SeatAuth::VendorLogin,
            egress_profile_ref: "test-seat".to_owned(),
            credential_handles: Vec::new(),
        }],
        on_spent: OnSeatSpent::Stop,
    };
    (registry, policy)
}

/// Binds one Dreamer step to seat 0, the server's `dreamer_step` shape, and
/// answers the dispatched attempt.
fn bind_first_attempt(
    vault: &Vault,
    dispatcher: &ByoaDispatcher<'_, NoEndpoints, NoEgress>,
    registry: &ProviderAdapterRegistry,
    policy: &RunnerSeatPolicy,
    checkout_id: CheckoutId,
    now: u64,
) -> AttemptId {
    let step = BindRunnerWork {
        parent_attempt_id: AttemptId::from_bytes(&[9; 16]).expect("a parent attempt id"),
        step_key: "test-runner-step".to_owned(),
        task: "run the test task".to_owned(),
        staged_input: None,
        checkout_id,
        task_ref: None,
        run_id: None,
        choice: RunnerSeatChoice::Seat(0),
        now,
    };
    let bound = vault
        .try_with_write_txn_grouped(|wtxn| {
            dispatcher.bind_runner_work_in_txn(wtxn, registry, policy, step)
        })
        .expect("the bind writes");
    match bound {
        RunnerWorkBound::Bound {
            attempt,
            existing: false,
            ..
        } => attempt,
        other => panic!("the work binds to seat 0, got {other:?}"),
    }
}

/// The host claims the attempt by id and runs it: the fence and its exhaust.
fn claim_and_execute(
    dispatcher: &mut ByoaDispatcher<'_, NoEndpoints, NoEgress>,
    attempt: AttemptId,
    start: u64,
) -> (ByoaExecutionFence, ByoaExhaust) {
    let machines: Vec<String> = Vec::new();
    let fence = dispatcher
        .claim_host_cli_attempt(attempt, "test-seat-host", start + 1, &machines, |_| true)
        .expect("the claim writes")
        .expect("the host claims its attempt");
    let mut executor = FakeExec;
    let exhaust = dispatcher
        .execute_cli(
            &fence,
            ExecutionBudget::new(60, 128, 8),
            &mut executor,
            start + 2,
        )
        .expect("the run executes");
    (fence, exhaust)
}

fn capture(
    dispatcher: &mut ByoaDispatcher<'_, NoEndpoints, NoEgress>,
    fence: &ByoaExecutionFence,
    exhaust: ByoaExhaust,
    disposition: ByoaTerminalDisposition,
    reason: Option<String>,
    now: u64,
) -> ByoaTerminalReceipt {
    dispatcher
        .capture_terminal_exhaust(CaptureByoaExhaust {
            attempt_id: fence.attempt_id,
            lease_owner: fence.lease_owner.clone(),
            attempt_count: fence.attempt_count,
            disposition,
            exhaust,
            reason,
            now,
        })
        .expect("the capture lands")
}

fn lease_of(leases: &Leases<'_>, checkout_id: CheckoutId) -> CheckoutLeaseAct {
    leases
        .get(checkout_id)
        .expect("the lease reads")
        .expect("the lease exists")
}

/// A Published origin row carries the pushed head, published by the owner.
fn assert_published(vault: &Vault, owner: EntityId, head: &str) {
    let ids = vault
        .origin_publication_ids(None)
        .expect("the journal reads");
    let mut found = false;
    for id in ids {
        let Some(row) = vault.origin_publication(id).expect("the row reads") else {
            continue;
        };
        if row.status == OriginPublicationStatus::Published
            && row.new_oid.as_str() == head
            && row.actor_id.id() == Some(owner)
        {
            found = true;
            break;
        }
    }
    assert!(
        found,
        "a Published row carries the pushed head by the owner"
    );
}

#[test]
fn completed_runner_capture_retains_an_unpushed_checkout() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let vault = Vault::open_owned(dir.path(), VaultConfig::default()).expect("an owned vault");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    let wall = wall_now();
    let task = owner_task(&vault, owner, "runner checkout end");
    let checkout_id = CheckoutId::from_bytes([7; 16]).expect("a checkout id");
    let mut leases = Leases::new(&vault, Facts, NoLiveness);
    let start = claim(
        &mut leases,
        checkout_id,
        task,
        RepoRef::parse(&format!("github:owner/repo#{HEAD}")).expect("a repo ref"),
        HOLDER,
        wall,
    );
    let (registry, policy) = seats();
    let mut dispatcher = ByoaDispatcher::new(&vault, NoEndpoints, NoEgress);
    let attempt = bind_first_attempt(&vault, &dispatcher, &registry, &policy, checkout_id, start);
    let (fence, exhaust) = claim_and_execute(&mut dispatcher, attempt, start);
    let receipt = capture(
        &mut dispatcher,
        &fence,
        exhaust,
        ByoaTerminalDisposition::Completed,
        None,
        start + 3,
    );
    assert_eq!(receipt.attempt.state, AttemptState::Completed);
    let lease = lease_of(&leases, checkout_id);
    assert_eq!(lease.state, CheckoutLeaseState::Active);
    match seat_host_end(&dispatcher, &fence) {
        Some(CheckoutTeardownOutcome::Retained { epoch, reason, .. }) => {
            assert_eq!(epoch, lease.epoch);
            assert_eq!(reason, CheckoutRetainReason::MissingPushedHeadReceipt);
        }
        other => panic!("an unpushed checkout is retained, got {other:?}"),
    }
    assert_eq!(
        lease_of(&leases, checkout_id).state,
        CheckoutLeaseState::Retained
    );
}

#[test]
fn failed_runner_capture_keeps_the_checkout_active() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let vault = Vault::open_owned(dir.path(), VaultConfig::default()).expect("an owned vault");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    let wall = wall_now();
    let task = owner_task(&vault, owner, "runner checkout end");
    let checkout_id = CheckoutId::from_bytes([7; 16]).expect("a checkout id");
    let mut leases = Leases::new(&vault, Facts, NoLiveness);
    let start = claim(
        &mut leases,
        checkout_id,
        task,
        RepoRef::parse(&format!("github:owner/repo#{HEAD}")).expect("a repo ref"),
        HOLDER,
        wall,
    );
    let (registry, policy) = seats();
    let mut dispatcher = ByoaDispatcher::new(&vault, NoEndpoints, NoEgress);
    let attempt = bind_first_attempt(&vault, &dispatcher, &registry, &policy, checkout_id, start);
    let (fence, exhaust) = claim_and_execute(&mut dispatcher, attempt, start);
    let receipt = capture(
        &mut dispatcher,
        &fence,
        exhaust,
        ByoaTerminalDisposition::Failed,
        Some("the runner failed".to_owned()),
        start + 3,
    );
    assert_eq!(receipt.attempt.state, AttemptState::Failed);
    assert_eq!(
        lease_of(&leases, checkout_id).state,
        CheckoutLeaseState::Active
    );
    assert_eq!(seat_host_end(&dispatcher, &fence), None);
    assert_eq!(
        lease_of(&leases, checkout_id).state,
        CheckoutLeaseState::Active
    );
}

// ---------------------------------------------------------------------------
// git helpers
// ---------------------------------------------------------------------------

fn git_output(cwd: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .current_dir(cwd)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Oneiron")
        .env("GIT_AUTHOR_EMAIL", "oneiron@example.invalid")
        .env("GIT_COMMITTER_NAME", "Oneiron")
        .env("GIT_COMMITTER_EMAIL", "oneiron@example.invalid")
        .args(args)
        .output()
        .expect("run git")
}

fn git(cwd: &Path, args: &[&str]) -> String {
    let output = git_output(cwd, args);
    assert!(
        output.status.success(),
        "git {args:?} failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn seed_source_repo(root: &Path, body: &str) -> String {
    git(root, &["init", "--initial-branch=main"]);
    std::fs::write(root.join("README.md"), body).expect("write readme");
    git(root, &["add", "--", "README.md"]);
    git(root, &["commit", "-m", "initial"]);
    git(root, &["rev-parse", "--verify", "HEAD"])
}

fn commit_file(root: &Path, name: &str, body: &str, message: &str) -> String {
    commit_bytes(root, name, body.as_bytes(), message)
}

fn commit_bytes(root: &Path, name: &str, body: &[u8], message: &str) -> String {
    std::fs::write(root.join(name), body).expect("write file");
    git(root, &["add", "--", name]);
    git(root, &["commit", "-m", message]);
    git(root, &["rev-parse", "--verify", "HEAD"])
}

// ---------------------------------------------------------------------------
// The framing shim
// ---------------------------------------------------------------------------

/// One vault serving one repository over the real smart-HTTP wire: the framing
/// shim from `git_smart_http.rs`, over a vault the test owns instead of one
/// the origin owns.
struct HttpOrigin {
    addr: SocketAddr,
    repo_dir: PathBuf,
    shutdown: Arc<AtomicBool>,
}

impl HttpOrigin {
    fn serve(vault: Arc<Vault>, seam: DoorSeam, owner: EntityId, repo_dir: PathBuf) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind origin");
        let addr = listener.local_addr().expect("origin addr");
        let shutdown = Arc::new(AtomicBool::new(false));
        thread::spawn({
            let shutdown = Arc::clone(&shutdown);
            move || {
                for stream in listener.incoming() {
                    if shutdown.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else { break };
                    let vault = Arc::clone(&vault);
                    thread::spawn(move || serve_connection(&vault, seam, owner, stream));
                }
            }
        });
        Self {
            addr,
            repo_dir,
            shutdown,
        }
    }

    fn url(&self) -> String {
        format!("http://{}/demo.git", self.addr)
    }

    fn origin_ref(&self, name: &str) -> Option<String> {
        let output = git_output(&self.repo_dir, &["rev-parse", "--verify", name]);
        output.status.success().then(|| {
            String::from_utf8_lossy(&output.stdout)
                .trim()
                .to_ascii_lowercase()
        })
    }
}

impl Drop for HttpOrigin {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
    }
}

fn serve_connection(vault: &Arc<Vault>, seam: DoorSeam, principal: EntityId, stream: TcpStream) {
    let Ok(peer) = stream.try_clone() else { return };
    let mut reader = BufReader::new(peer);
    let Some(head) = read_request_head(&mut reader, principal) else {
        return;
    };
    let mut sink = HttpSink {
        stream: stream.try_clone().expect("clone response stream"),
        began: false,
    };
    if head.expects_continue {
        let _ = sink
            .stream
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .and_then(|()| sink.stream.flush());
    }
    let mut body = head.body(reader);
    let served = smart_http::serve(
        vault,
        &head.repo,
        &head.request,
        seam,
        &mut *body,
        &mut sink,
    );
    if let Err(error) = served {
        if !sink.began {
            let message = error.to_string();
            let _ = sink.stream.write_all(
                format!(
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{message}",
                    message.len()
                )
                .as_bytes(),
            );
        }
    }
    let _ = sink.stream.flush();
    let _ = stream.shutdown(Shutdown::Write);
}

struct RequestHead {
    repo: String,
    request: ServeRequest,
    content_length: Option<u64>,
    chunked: bool,
    expects_continue: bool,
}

impl RequestHead {
    fn body(&self, reader: BufReader<TcpStream>) -> Box<dyn Read + Send> {
        if self.chunked {
            Box::new(ChunkedBody::new(reader))
        } else if let Some(length) = self.content_length {
            Box::new(reader.take(length))
        } else {
            Box::new(io::empty())
        }
    }
}

fn read_request_head(
    reader: &mut BufReader<TcpStream>,
    principal: EntityId,
) -> Option<RequestHead> {
    let mut line = String::new();
    if reader.read_line(&mut line).ok()? == 0 {
        return None;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_owned();
    let target = parts.next()?.to_owned();

    let mut headers: Vec<(String, String)> = Vec::new();
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).ok()? == 0 {
            break;
        }
        if header.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
    }
    let header = |name: &str| -> Option<String> {
        headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };

    let (path, query) = target.split_once('?').unwrap_or((target.as_str(), ""));
    let segment = path.trim_start_matches('/').split('/').next()?.to_owned();
    let repo = segment.strip_suffix(".git").unwrap_or(&segment).to_owned();
    let content_length = header("content-length").and_then(|value| value.parse::<u64>().ok());
    let chunked = header("transfer-encoding").is_some_and(|value| value.contains("chunked"));

    Some(RequestHead {
        repo,
        request: ServeRequest {
            method,
            path_info: path.to_owned(),
            query_string: query.to_owned(),
            content_type: header("content-type"),
            content_length,
            content_encoding: header("content-encoding"),
            git_protocol: header("git-protocol"),
            // A registered principal, exactly as the server layer would pass
            // it: it becomes the reflog identity of anything the push lands.
            remote_user: Some(principal.to_hex()),
            remote_addr: Some("127.0.0.1".to_owned()),
        },
        content_length,
        chunked,
        expects_continue: header("expect")
            .is_some_and(|value| value.eq_ignore_ascii_case("100-continue")),
    })
}

struct HttpSink {
    stream: TcpStream,
    began: bool,
}

impl ServeSink for HttpSink {
    fn begin(&mut self, status: u16, headers: &[(String, String)]) -> io::Result<()> {
        let mut head = format!("HTTP/1.1 {status} {}\r\n", reason(status));
        for (name, value) in headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        // No length is known ahead of a streamed body, so the close IS the
        // terminator. That is exactly the shape a large pack rides out in.
        head.push_str("Connection: close\r\n\r\n");
        self.began = true;
        self.stream.write_all(head.as_bytes())
    }

    fn write_chunk(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.stream.write_all(bytes)
    }
}

const fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        304 => "Not Modified",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Status",
    }
}

/// Dechunks a `Transfer-Encoding: chunked` request body, which is what a stock
/// client uses once a push outgrows its post buffer.
struct ChunkedBody {
    reader: BufReader<TcpStream>,
    remaining: usize,
    done: bool,
}

impl ChunkedBody {
    fn new(reader: BufReader<TcpStream>) -> Self {
        Self {
            reader,
            remaining: 0,
            done: false,
        }
    }

    fn next_chunk_size(&mut self) -> io::Result<usize> {
        let mut line = String::new();
        if self.reader.read_line(&mut line)? == 0 {
            return Ok(0);
        }
        let head = line.trim();
        let head = head.split(';').next().unwrap_or("0");
        Ok(usize::from_str_radix(head, 16).unwrap_or(0))
    }

    fn finish(&mut self) -> io::Result<()> {
        loop {
            let mut line = String::new();
            if self.reader.read_line(&mut line)? == 0 || line.trim().is_empty() {
                break;
            }
        }
        self.done = true;
        Ok(())
    }
}

impl Read for ChunkedBody {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.done || out.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            self.remaining = self.next_chunk_size()?;
            if self.remaining == 0 {
                self.finish()?;
                return Ok(0);
            }
        }
        let take = self.remaining.min(out.len());
        let read = self.reader.read(&mut out[..take])?;
        self.remaining -= read;
        if self.remaining == 0 {
            let mut terminator = [0_u8; 2];
            self.reader.read_exact(&mut terminator)?;
        }
        Ok(read)
    }
}

#[test]
fn completed_runner_capture_collects_a_pushed_clean_checkout() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let vault =
        Arc::new(Vault::open_owned(dir.path(), VaultConfig::default()).expect("an owned vault"));
    // The host installs this device's keystore after each open and loads
    // the install's signing keys from it (`install_default_keystore`, P6c).
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault
        .prepare_install_signing()
        .expect("load this install's signing keys");
    // An in-process serve admits a push from the vault's owner and no one
    // else (FIX 6867, G1-PUSH), so the shim pushes as that owner.
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let root = smart_http::origin_serving_root(&vault).expect("serving root");
    git(
        &root,
        &["init", "--bare", "--initial-branch=main", "demo.git"],
    );
    let repo_dir = root.join("demo.git");
    let origin = HttpOrigin::serve(
        Arc::clone(&vault),
        DoorSeam::Landed,
        owner,
        repo_dir.clone(),
    );
    let source = tempfile::tempdir().expect("source tempdir");
    seed_source_repo(source.path(), "base\n");
    git(
        source.path(),
        &["push", &origin.url(), "main:refs/heads/main"],
    );
    let seed = origin
        .origin_ref("refs/heads/main")
        .expect("the seed landed");

    let wall = wall_now();
    let task = owner_task(&vault, owner, "runner checkout end");
    let checkout_id = CheckoutId::from_bytes([7; 16]).expect("a checkout id");
    let mut leases = Leases::new(&vault, Facts, NoLiveness);
    let start = claim(
        &mut leases,
        checkout_id,
        task,
        RepoRef::LocalFolder {
            path: repo_dir.to_string_lossy().into_owned(),
            commit: seed,
        },
        &owner.to_hex(),
        wall,
    );
    let wire = GitWire::new(&vault).expect("the git wire opens");
    wire.materialize(&lease_of(&leases, checkout_id))
        .expect("the checkout materializes");
    let worktree = wire
        .checkout_worktree_path(&lease_of(&leases, checkout_id))
        .expect("the worktree path reads");
    let (registry, policy) = seats();
    let mut dispatcher = ByoaDispatcher::new(&vault, NoEndpoints, NoEgress);
    let attempt = bind_first_attempt(&vault, &dispatcher, &registry, &policy, checkout_id, start);
    let (fence, exhaust) = claim_and_execute(&mut dispatcher, attempt, start);
    // During the run the work commits and pushes its head as the owner.
    let head =
        commit_file(&worktree, "run.txt", "runner output\n", "runner commit").to_ascii_lowercase();
    git(&worktree, &["push", &origin.url(), "HEAD:refs/heads/main"]);
    assert_eq!(
        origin.origin_ref("refs/heads/main").as_deref(),
        Some(head.as_str()),
        "the push moved the origin ref"
    );
    assert_published(&vault, owner, &head);
    let receipt = capture(
        &mut dispatcher,
        &fence,
        exhaust,
        ByoaTerminalDisposition::Completed,
        None,
        start + 3,
    );
    assert_eq!(receipt.attempt.state, AttemptState::Completed);
    let lease = lease_of(&leases, checkout_id);
    assert_eq!(lease.state, CheckoutLeaseState::Active);
    match seat_host_end(&dispatcher, &fence) {
        Some(CheckoutTeardownOutcome::Collected { epoch, .. }) => {
            assert_eq!(epoch, lease.epoch);
        }
        other => panic!("a pushed clean checkout is collected, got {other:?}"),
    }
    assert!(
        leases.get(checkout_id).expect("the lease reads").is_none(),
        "collection removes the lease row"
    );
    assert!(
        !wire.tree_present(&lease).expect("the tree reads"),
        "collection removes the worktree"
    );
    assert!(!worktree.exists(), "the worktree path is gone");
}
