//! L8-51: over the vault-as-origin push, anyone but the vault's owner may
//! neither delete nor rewrite the repository's default branch.
//!
//! Canon: force-push or deletion of a protected ref, and history rewrite, are
//! the repo surface's catastrophe class (ARCH-0068 RC4: "Lease branches
//! auto-pass; the catastrophe class is enumerated"); DEC-0006 names them
//! one-way, and REV-3 = (a) (owner, 2026-10-09) puts every one-way act behind
//! the owner on every surface, the repo included. Before this, a holder of a
//! `git_push` Grant could force-push or delete the default branch like any
//! other: the door refused only names it cannot journal and its secret scan.
//!
//! The rewrite or delete asks the owner instead (DEC-0006: a one-way act
//! asks): the door puts the owner one question per exact move, and the
//! owner's leave is `vault.consent.approve_once` on the digest it shows. The
//! same push then passes the door, once. A plain "yes" to the question is no
//! leave. Git itself refuses to delete the branch HEAD names; that refusal
//! stays git's.
//!
//! The holder pushes with a stock `git` through the real smart-HTTP wire
//! ([`oneiron::origin::smart_http::serve_bounded_as`], the host's entry with
//! the pusher it authenticated), the owner through the in-process serve. The
//! door's own report is the fact under test.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test protected_ref_rewrite`.
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{io, thread};

use oneiron::authority::ActSurface;
use oneiron::consent::AuthenticatedOwner;
use oneiron::consent::lifecycle::{ApproveOnceRequest, approve_once};
use oneiron::federation::{GitPushCaller, GitPushCredential};
use oneiron::llm::decision::{DecisionAnswer, DecisionAsk};
use oneiron::origin::smart_http::{
    self, DoorSeam, DoorWindowVerdict, ExchangeBounds, SERVE_IDLE_TIMEOUT, ScanBounds, ServeReport,
    ServeRequest, ServeSink,
};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{
    GitPushGrantMintInput, RepoAnchorBindInput, bind_repo_anchor_as, mint_git_push_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

/// The typed reason the door refuses a protected-ref delete or rewrite with.
const PROTECTED_REF_REWRITE_OR_DELETE: &str = "protected_ref_rewrite_or_delete";

/// The queue the door puts the owner its question about one move on.
const PROTECTED_REF_ASK_QUEUE: &str = "origin.protected_ref_rewrite_or_delete";

/// Git's own refusal to delete the branch a repository's HEAD names.
const GIT_DELETE_CURRENT_REFUSAL: &str = "deletion of the current branch prohibited";

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
    std::fs::write(root.join(name), body).expect("write file");
    git(root, &["add", "--", name]);
    git(root, &["commit", "-m", message]);
    git(root, &["rev-parse", "--verify", "HEAD"])
}

/// Replaces the clone's tip with a commit that does not descend from it.
fn rewrite_tip(root: &Path, message: &str) -> String {
    git(root, &["commit", "--amend", "-m", message]);
    git(root, &["rev-parse", "--verify", "HEAD"])
}

// ---------------------------------------------------------------------------
// The origin
// ---------------------------------------------------------------------------

/// Who the origin serves the next connection as.
#[derive(Clone)]
enum Pusher {
    /// The vault's owner, through the in-process serve.
    Owner(EntityId),
    /// A `git_push` Grant holder, as a host transport authenticated it.
    Holder {
        principal: EntityId,
        caller: GitPushCaller,
    },
}

impl Pusher {
    const fn principal(&self) -> EntityId {
        match self {
            Self::Owner(principal) | Self::Holder { principal, .. } => *principal,
        }
    }
}

/// One vault serving one registered repository over the real smart-HTTP wire,
/// with an agent that holds a `git_push` Grant on it.
struct TestOrigin {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    proof: AuthenticatedOwner,
    addr: SocketAddr,
    repo_dir: PathBuf,
    reports: Arc<Mutex<Vec<ServeReport>>>,
    shutdown: Arc<AtomicBool>,
    pusher: Arc<Mutex<Pusher>>,
    owner: EntityId,
    holder: EntityId,
}

impl TestOrigin {
    /// Starts an origin whose `main` (its HEAD) the owner published with a
    /// real scanned push, and mints the holder's `git_push` Grant on it.
    fn start(source: &Path) -> Self {
        let dir = tempfile::tempdir().expect("vault tempdir");
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::default()).expect("open vault"));
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        vault
            .prepare_install_signing()
            .expect("load this install's signing keys");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        vault
            .register_served_origin_as_owner(&proof, "demo", "main")
            .expect("register the served repo");
        let repo_dir = smart_http::origin_repo_dir(&vault, "demo").expect("served repo dir");
        let project = vault.root_project().expect("root project");
        let anchor = bind_repo_anchor_as(
            &vault,
            &proof,
            RepoAnchorBindInput {
                repo: Some("demo".to_owned()),
                local_folder: None,
                project,
                anchor: None,
                editable: None,
            },
        )
        .expect("bind the repo's CODE anchor")
        .anchor;
        let holder = vault
            .ensure_agent_principal("pusher")
            .expect("agent principal");
        mint_git_push_grant_as(
            &vault,
            &proof,
            ActSurface::ThisInstall,
            GitPushGrantMintInput {
                member: holder,
                repos: BTreeSet::from([anchor]),
                expires_at: None,
            },
        )
        .expect("mint the holder's git_push Grant");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind origin");
        let addr = listener.local_addr().expect("origin addr");
        let reports = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(AtomicBool::new(false));
        let pusher = Arc::new(Mutex::new(Pusher::Owner(owner)));
        thread::spawn({
            let vault = Arc::clone(&vault);
            let reports = Arc::clone(&reports);
            let shutdown = Arc::clone(&shutdown);
            let pusher = Arc::clone(&pusher);
            move || {
                for stream in listener.incoming() {
                    if shutdown.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else { break };
                    let vault = Arc::clone(&vault);
                    let reports = Arc::clone(&reports);
                    let pusher = pusher.lock().expect("pusher lock").clone();
                    thread::spawn(move || serve_connection(&vault, &pusher, stream, &reports));
                }
            }
        });

        let origin = Self {
            _dir: dir,
            vault,
            proof,
            addr,
            repo_dir,
            reports,
            shutdown,
            pusher,
            owner,
            holder,
        };
        let head = git(source, &["rev-parse", "--verify", "refs/heads/main"]);
        git(source, &["push", &origin.url(), "main:refs/heads/main"]);
        assert_eq!(
            origin.origin_ref("refs/heads/main").as_deref(),
            Some(head.as_str()),
            "the owner's scanned seed reached the origin"
        );
        assert_eq!(
            git(&origin.repo_dir, &["symbolic-ref", "HEAD"]),
            "refs/heads/main",
            "the repository's HEAD names main, its protected ref"
        );
        origin.reports.lock().expect("reports lock").clear();
        origin
    }

    /// The next connections push as the Grant holder.
    fn push_as_holder(&self) {
        *self.pusher.lock().expect("pusher lock") = Pusher::Holder {
            principal: self.holder,
            caller: GitPushCaller::authenticated(
                self.holder,
                Some(EdgeActorClass::Agent),
                GitPushCredential::default(),
            ),
        };
    }

    /// The next connections push as the vault's owner.
    fn push_as_owner(&self) {
        *self.pusher.lock().expect("pusher lock") = Pusher::Owner(self.owner);
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

    fn object_present(&self, oid: &str) -> bool {
        git_output(&self.repo_dir, &["cat-file", "-e", oid])
            .status
            .success()
    }

    fn reports(&self) -> Vec<ServeReport> {
        self.reports.lock().expect("reports lock").clone()
    }

    fn landed(&self) -> Vec<ServeReport> {
        self.reports()
            .into_iter()
            .filter(|report| report.landing.is_some())
            .collect()
    }

    /// Every refusal the door published, oldest first, one joined string per
    /// refused push.
    fn door_refusals(&self) -> Vec<String> {
        self.reports()
            .into_iter()
            .filter_map(|report| match report.door.verdict {
                DoorWindowVerdict::Rejected { reasons } => Some(reasons.join("; ")),
                DoorWindowVerdict::Clean
                | DoorWindowVerdict::NotInvoked
                | DoorWindowVerdict::AdmitMarked { .. } => None,
            })
            .collect()
    }

    /// Every question the door put the owner about one protected-ref move,
    /// oldest first, open or not.
    fn protected_ref_asks(&self) -> Vec<DecisionAsk> {
        self.vault
            .decision_asks(None, 1024, false)
            .expect("read the decision asks")
            .into_iter()
            .filter(|ask| ask.queue_pin.model == PROTECTED_REF_ASK_QUEUE)
            .collect()
    }

    /// The approve-once digest the one question about a protected-ref move
    /// shows the owner.
    fn asked_digest(&self) -> String {
        let asks = self.protected_ref_asks();
        assert_eq!(asks.len(), 1, "the door asked the owner once: {asks:?}");
        asks[0]
            .pack_state
            .as_ref()
            .and_then(|state| state["approval_digest"].as_str())
            .expect("the question shows the move's approve-once digest")
            .to_owned()
    }

    /// A clone of the origin's `main`, fetched as the owner.
    fn clone_main(&self, work: &Path) -> PathBuf {
        self.push_as_owner();
        git(
            work,
            &["clone", "--branch=main", "--", &self.url(), "clone"],
        );
        work.join("clone")
    }
}

impl Drop for TestOrigin {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
    }
}

// ---------------------------------------------------------------------------
// The framing shim (as tests/git_smart_http.rs)
// ---------------------------------------------------------------------------

fn serve_connection(
    vault: &Arc<Vault>,
    pusher: &Pusher,
    stream: TcpStream,
    reports: &Arc<Mutex<Vec<ServeReport>>>,
) {
    let Ok(peer) = stream.try_clone() else { return };
    let mut reader = BufReader::new(peer);
    let Some(head) = read_request_head(&mut reader, pusher.principal()) else {
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
    let served = match pusher {
        Pusher::Owner(_) => smart_http::serve(
            vault,
            &head.repo,
            &head.request,
            DoorSeam::Landed,
            &mut *body,
            &mut sink,
        ),
        Pusher::Holder { caller, .. } => smart_http::serve_bounded_as(
            vault,
            &head.repo,
            &head.request,
            DoorSeam::Landed,
            ExchangeBounds {
                idle: SERVE_IDLE_TIMEOUT,
                repository_wait: Duration::from_secs(30),
                scan: ScanBounds::default(),
                spill_floor: None,
            },
            None,
            Some(caller),
            None,
            &mut *body,
            &mut sink,
        ),
    };
    match served {
        Ok(report) => reports.lock().expect("reports lock").push(report),
        Err(error) => {
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
            // The pusher's registered principal, as the server layer passes
            // it: a host caller must be this request's own remote user.
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

/// Dechunks a `Transfer-Encoding: chunked` request body.
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

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

/// The named red test: a Grant holder's force-push of the default branch.
/// Before L8-51 it landed and replaced the branch's history.
#[test]
fn a_grant_holders_force_push_of_the_default_branch_is_refused() {
    let source = tempfile::tempdir().expect("source tempdir");
    let seed = seed_source_repo(source.path(), "base\n");
    let origin = TestOrigin::start(source.path());
    let work = tempfile::tempdir().expect("work tempdir");
    let clone = origin.clone_main(work.path());

    let rewritten = rewrite_tip(&clone, "history rewritten");
    origin.push_as_holder();
    let push = git_output(&clone, &["push", "--force", "origin", "main"]);

    assert!(
        !push.status.success(),
        "a Grant holder's force-push of the default branch is refused"
    );
    let refusals = origin.door_refusals();
    assert!(
        refusals.last().is_some_and(|reason| {
            reason.contains("refs/heads/main") && reason.contains(PROTECTED_REF_REWRITE_OR_DELETE)
        }),
        "the door refused the rewrite with its typed reason: {refusals:?}"
    );
    assert_eq!(
        origin.origin_ref("refs/heads/main").as_deref(),
        Some(seed.as_str()),
        "main still names the owner's commit"
    );
    assert!(
        !origin.object_present(&rewritten),
        "refused pre-move: the rewritten commit never left quarantine"
    );
    assert!(origin.landed().is_empty(), "nothing moved, nothing landed");
}

/// A delete of the default branch by a Grant holder is refused by the door
/// with the same typed reason, before git decides anything, and puts the
/// owner the same one question: the move's state names no new tip.
#[test]
fn a_grant_holders_delete_of_the_default_branch_is_refused_and_asks_the_owner() {
    let source = tempfile::tempdir().expect("source tempdir");
    let seed = seed_source_repo(source.path(), "base\n");
    let origin = TestOrigin::start(source.path());
    let work = tempfile::tempdir().expect("work tempdir");
    let clone = origin.clone_main(work.path());

    origin.push_as_holder();
    let push = git_output(&clone, &["push", "origin", "--delete", "main"]);

    assert!(!push.status.success(), "the delete is refused");
    let refusals = origin.door_refusals();
    assert!(
        refusals.last().is_some_and(|reason| {
            reason.contains("refs/heads/main") && reason.contains(PROTECTED_REF_REWRITE_OR_DELETE)
        }),
        "the door refused the delete with its typed reason: {refusals:?}"
    );
    assert_eq!(
        origin.origin_ref("refs/heads/main").as_deref(),
        Some(seed.as_str()),
        "main is still there"
    );
    assert!(origin.landed().is_empty(), "nothing moved, nothing landed");

    let digest = origin.asked_digest();
    assert_eq!(digest.len(), 64, "a 64-hex approve-once digest");
    let asks = origin.protected_ref_asks();
    let state = asks[0]
        .pack_state
        .as_ref()
        .expect("the question names the delete");
    assert_eq!(state["ref"], "refs/heads/main");
    assert_eq!(state["old_oid"], seed.as_str());
    assert!(
        state["new_oid"].is_null(),
        "a delete has no new tip: {state}"
    );
    assert_eq!(state["pusher"], origin.holder.to_hex().as_str());
}

/// The owner's leave for a delete passes the door and is spent with the
/// intent, as a rewrite's is. Git itself then refuses to delete the branch
/// HEAD names, for every pusher: the refusal the holder reads is git's own,
/// and the door adds none.
#[test]
fn the_owners_approve_once_passes_a_delete_to_gits_own_refusal() {
    let source = tempfile::tempdir().expect("source tempdir");
    let seed = seed_source_repo(source.path(), "base\n");
    let origin = TestOrigin::start(source.path());
    let work = tempfile::tempdir().expect("work tempdir");
    let clone = origin.clone_main(work.path());

    origin.push_as_holder();
    let push = git_output(&clone, &["push", "origin", "--delete", "main"]);
    assert!(!push.status.success(), "refused until the owner leaves it");
    let digest = origin.asked_digest();

    approve_once(
        &origin.vault,
        &origin.proof,
        ApproveOnceRequest {
            effect_digest: digest,
        },
    )
    .expect("the owner leaves this exact delete once");
    let push = git_output(&clone, &["push", "origin", "--delete", "main"]);
    assert!(
        !push.status.success(),
        "git refuses to delete the branch HEAD names"
    );
    let stderr = String::from_utf8_lossy(&push.stderr);
    assert!(
        stderr.contains(GIT_DELETE_CURRENT_REFUSAL),
        "the refusal the holder reads is git's own: {stderr}"
    );
    assert!(
        !stderr.contains(PROTECTED_REF_REWRITE_OR_DELETE),
        "the door added no refusal of its own: {stderr}"
    );
    let asks = origin.protected_ref_asks();
    assert_eq!(asks.len(), 1, "no second question: {asks:?}");
    assert!(
        asks[0].withdrawn_at.is_some(),
        "the door let the left delete pass: its leave spent with the intent, \
         its question is withdrawn"
    );
    assert_eq!(
        origin.origin_ref("refs/heads/main").as_deref(),
        Some(seed.as_str()),
        "main is still there"
    );
}

/// The rule narrows nothing else a Grant holder does: a fast-forward of the
/// default branch, and any move of another branch (the lease working set),
/// force-push and delete included, land as before.
#[test]
fn a_grant_holders_fast_forward_and_other_branches_still_land() {
    let source = tempfile::tempdir().expect("source tempdir");
    seed_source_repo(source.path(), "base\n");
    let origin = TestOrigin::start(source.path());
    let work = tempfile::tempdir().expect("work tempdir");
    let clone = origin.clone_main(work.path());
    origin.push_as_holder();

    let advanced = commit_file(&clone, "app.txt", "one\n", "advance main");
    git(&clone, &["push", "origin", "main"]);
    assert_eq!(
        origin.origin_ref("refs/heads/main").as_deref(),
        Some(advanced.as_str()),
        "a fast-forward of the default branch lands"
    );

    git(&clone, &["push", "origin", "main:refs/heads/work"]);
    let reworked = rewrite_tip(&clone, "rework the work branch");
    git(
        &clone,
        &["push", "--force", "origin", "HEAD:refs/heads/work"],
    );
    assert_eq!(
        origin.origin_ref("refs/heads/work").as_deref(),
        Some(reworked.as_str()),
        "a force-push of another branch lands"
    );
    git(&clone, &["push", "origin", "--delete", "work"]);
    assert!(
        origin.origin_ref("refs/heads/work").is_none(),
        "a delete of another branch lands"
    );
    assert_eq!(
        origin.origin_ref("refs/heads/main").as_deref(),
        Some(advanced.as_str()),
        "main kept the holder's fast-forward"
    );
    assert!(
        origin.door_refusals().is_empty(),
        "the door refused none of these: {:?}",
        origin.door_refusals()
    );
    assert_eq!(
        origin.landed().len(),
        4,
        "each push landed and is journaled"
    );
}

/// The owner is never gated on his own vault: his force-push of the default
/// branch lands as before.
#[test]
fn the_owners_force_push_of_the_default_branch_lands() {
    let source = tempfile::tempdir().expect("source tempdir");
    seed_source_repo(source.path(), "base\n");
    let origin = TestOrigin::start(source.path());
    let work = tempfile::tempdir().expect("work tempdir");
    let clone = origin.clone_main(work.path());

    let rewritten = rewrite_tip(&clone, "the owner rewrites main");
    origin.push_as_owner();
    git(&clone, &["push", "--force", "origin", "main"]);

    assert_eq!(
        origin.origin_ref("refs/heads/main").as_deref(),
        Some(rewritten.as_str()),
        "the owner's force-push moved main"
    );
    assert!(
        origin.door_refusals().is_empty(),
        "the door refused nothing of the owner's"
    );
    assert_eq!(origin.landed().len(), 1, "and it landed");
}

/// The refused rewrite puts the owner one question, which names the exact
/// move and the digest of the leave it needs. Sent again, the same push asks
/// nothing more, and the owner's plain "yes" to the question is no leave: the
/// push is still refused.
#[test]
fn a_refused_rewrite_asks_the_owner_once_and_a_plain_yes_lands_nothing() {
    let source = tempfile::tempdir().expect("source tempdir");
    let seed = seed_source_repo(source.path(), "base\n");
    let origin = TestOrigin::start(source.path());
    let work = tempfile::tempdir().expect("work tempdir");
    let clone = origin.clone_main(work.path());

    let rewritten = rewrite_tip(&clone, "history rewritten");
    origin.push_as_holder();
    for _ in 0..2 {
        let push = git_output(&clone, &["push", "--force", "origin", "main"]);
        assert!(!push.status.success(), "the rewrite is refused");
    }

    let digest = origin.asked_digest();
    assert_eq!(digest.len(), 64, "a 64-hex approve-once digest");
    let asks = origin.protected_ref_asks();
    let ask = &asks[0];
    assert!(ask.is_open(), "the question waits for the owner");
    let state = ask
        .pack_state
        .as_ref()
        .expect("the question names the move");
    assert_eq!(state["ref"], "refs/heads/main");
    assert_eq!(state["old_oid"], seed.as_str());
    assert_eq!(state["new_oid"], rewritten.as_str());
    assert_eq!(state["pusher"], origin.holder.to_hex().as_str());

    origin
        .vault
        .answer_decision_ask(&origin.proof, ask.seq, DecisionAnswer::Noul(true))
        .expect("the owner answers yes");
    let push = git_output(&clone, &["push", "--force", "origin", "main"]);
    assert!(
        !push.status.success(),
        "a plain yes to the question lets no rewrite land"
    );
    assert_eq!(
        origin.origin_ref("refs/heads/main").as_deref(),
        Some(seed.as_str()),
        "main still names the owner's commit"
    );
    assert_eq!(
        origin.asked_digest(),
        digest,
        "the same move is never asked again"
    );
    assert!(origin.landed().is_empty(), "nothing moved, nothing landed");
}

/// The owner's leave (`vault.consent.approve_once` on the digest the question
/// shows) lands that exact rewrite once: the same push sent again lands, and
/// the question is withdrawn. The leave is then spent: once the owner has put
/// `main` back, the same move is refused again, and nothing is asked.
#[test]
fn the_owners_approve_once_lands_the_exact_rewrite_once() {
    let source = tempfile::tempdir().expect("source tempdir");
    let seed = seed_source_repo(source.path(), "base\n");
    let origin = TestOrigin::start(source.path());
    let work = tempfile::tempdir().expect("work tempdir");
    let clone = origin.clone_main(work.path());

    let rewritten = rewrite_tip(&clone, "history rewritten");
    origin.push_as_holder();
    let push = git_output(&clone, &["push", "--force", "origin", "main"]);
    assert!(!push.status.success(), "refused until the owner leaves it");
    let digest = origin.asked_digest();

    approve_once(
        &origin.vault,
        &origin.proof,
        ApproveOnceRequest {
            effect_digest: digest.clone(),
        },
    )
    .expect("the owner leaves this exact move once");
    git(&clone, &["push", "--force", "origin", "main"]);
    assert_eq!(
        origin.origin_ref("refs/heads/main").as_deref(),
        Some(rewritten.as_str()),
        "the move the owner left lands"
    );
    assert_eq!(origin.landed().len(), 1, "and it is journaled");
    let asks = origin.protected_ref_asks();
    assert_eq!(asks.len(), 1, "no second question: {asks:?}");
    assert!(
        asks[0].withdrawn_at.is_some(),
        "the leave spent, its question is withdrawn"
    );

    origin.push_as_owner();
    git(
        source.path(),
        &["push", "--force", &origin.url(), "main:refs/heads/main"],
    );
    assert_eq!(
        origin.origin_ref("refs/heads/main").as_deref(),
        Some(seed.as_str()),
        "the owner put main back"
    );
    origin.push_as_holder();
    let push = git_output(&clone, &["push", "--force", "origin", "main"]);
    assert!(!push.status.success(), "a spent leave lands nothing more");
    let refusals = origin.door_refusals();
    assert!(
        refusals.last().is_some_and(|reason| {
            reason.contains(PROTECTED_REF_REWRITE_OR_DELETE) && reason.contains("already spent")
        }),
        "the door refused the same move again, its leave spent: {refusals:?}"
    );
    assert_eq!(
        origin.origin_ref("refs/heads/main").as_deref(),
        Some(seed.as_str()),
        "main still names the owner's commit"
    );
    assert_eq!(
        origin.asked_digest(),
        digest,
        "a spent move is never asked again"
    );
}
