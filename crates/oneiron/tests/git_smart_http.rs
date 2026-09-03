//! Stock-git end-to-end coverage for the vault-as-origin serve wire
//! (ARCH-0068 Phase A, ONE-1908).
//!
//! The fixture is a minimal HTTP/1.1 shim over `std::net::TcpListener` whose
//! only job is framing: every request is handed to
//! [`oneiron::origin::smart_http::serve`], which owns the one `git
//! http-backend` child, the door window, and the single-writer landing. The
//! client is a stock `git`, unmodified and unpatched.
//!
//! The bearer gate itself lives in the server crate (`api::git_http`), where
//! `CoreAuth` lives, and is proved there: `git_smart_http_unauthenticated_
//! info_refs_is_401` and `git_smart_http_receive_pack_without_registered_
//! principal_ref_refused_even_on_loopback`. This binary proves the wire.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::{io, thread};

use oneiron::origin::smart_http::{
    self, DoorSeam, DoorWindowVerdict, ServeReport, ServeRequest, ServeSink,
};
use oneiron::{EntityId, Vault, VaultConfig};

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

/// Commits raw bytes, so a test can push content a text patch cannot carry.
fn commit_bytes(root: &Path, name: &str, body: &[u8], message: &str) -> String {
    std::fs::write(root.join(name), body).expect("write file");
    git(root, &["add", "--", name]);
    git(root, &["commit", "-m", message]);
    git(root, &["rev-parse", "--verify", "HEAD"])
}

/// A blob git handles as binary: the NUL is what makes it unscannable, and a
/// `git diff-tree -p` patch of it carries `Binary files ... differ` and no
/// content at all.
fn binary_payload() -> Vec<u8> {
    let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
    bytes.extend_from_slice(&[0x00, 0x01, 0x02, 0x03, 0xff, 0xfe]);
    bytes.extend_from_slice(b"TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz");
    bytes.extend_from_slice(&[0x00, 0x7f, 0x80]);
    bytes
}

// ---------------------------------------------------------------------------
// The framing shim
// ---------------------------------------------------------------------------

/// One vault serving one repository over the real smart-HTTP wire.
struct TestOrigin {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    addr: SocketAddr,
    repo_dir: PathBuf,
    reports: Arc<Mutex<Vec<ServeReport>>>,
    shutdown: Arc<AtomicBool>,
}

impl TestOrigin {
    /// Starts an origin whose `demo` repository is a bare clone of `source`.
    fn start(source: &Path, seam: DoorSeam) -> Self {
        let dir = tempfile::tempdir().expect("vault tempdir");
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::default()).expect("open vault"));
        let root = smart_http::origin_serving_root(&vault).expect("serving root");
        let source = source.to_string_lossy().into_owned();
        git(&root, &["clone", "--bare", "--", &source, "demo.git"]);
        let repo_dir = root.join("demo.git");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind origin");
        let addr = listener.local_addr().expect("origin addr");
        let reports = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(AtomicBool::new(false));
        thread::spawn({
            let vault = Arc::clone(&vault);
            let reports = Arc::clone(&reports);
            let shutdown = Arc::clone(&shutdown);
            move || {
                for stream in listener.incoming() {
                    if shutdown.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else { break };
                    let vault = Arc::clone(&vault);
                    let reports = Arc::clone(&reports);
                    thread::spawn(move || serve_connection(&vault, seam, stream, &reports));
                }
            }
        });

        Self {
            _dir: dir,
            vault,
            addr,
            repo_dir,
            reports,
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
}

impl Drop for TestOrigin {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
    }
}

fn serve_connection(
    vault: &Arc<Vault>,
    seam: DoorSeam,
    stream: TcpStream,
    reports: &Arc<Mutex<Vec<ServeReport>>>,
) {
    let Ok(peer) = stream.try_clone() else { return };
    let mut reader = BufReader::new(peer);
    let Some(head) = read_request_head(&mut reader) else {
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

fn read_request_head(reader: &mut BufReader<TcpStream>) -> Option<RequestHead> {
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
            remote_user: Some(EntityId::now().to_hex()),
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

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

#[test]
fn git_smart_http_clone_then_fetch_round_trips_stock_client() {
    let source = tempfile::tempdir().expect("source tempdir");
    seed_source_repo(source.path(), "base\n");
    let origin = TestOrigin::start(source.path(), DoorSeam::Noop);

    let work = tempfile::tempdir().expect("work tempdir");
    git(work.path(), &["clone", "--", &origin.url(), "clone"]);
    let clone = work.path().join("clone");
    assert_eq!(
        std::fs::read_to_string(clone.join("README.md")).expect("cloned file"),
        "base\n",
        "a stock client clones over smart-HTTP"
    );

    // A second commit lands directly in the origin, then the same clone fetches it.
    let advanced = git(
        &origin.repo_dir,
        &["rev-parse", "--verify", "refs/heads/main"],
    );
    let bump = tempfile::tempdir().expect("bump tempdir");
    git(bump.path(), &["clone", "--", &origin.url(), "bump"]);
    let bump_clone = bump.path().join("bump");
    let head = commit_file(&bump_clone, "next.txt", "second\n", "second");
    git(&bump_clone, &["push", "origin", "main"]);
    assert_ne!(head, advanced, "the origin moved");

    git(&clone, &["fetch", "origin"]);
    let fetched = git(
        &clone,
        &["rev-parse", "--verify", "refs/remotes/origin/main"],
    );
    assert_eq!(fetched, head, "a stock client fetches the advance");
}

#[test]
fn git_smart_http_noop_door_hook_clean_push_lands() {
    let source = tempfile::tempdir().expect("source tempdir");
    seed_source_repo(source.path(), "base\n");
    let origin = TestOrigin::start(source.path(), DoorSeam::Noop);

    let work = tempfile::tempdir().expect("work tempdir");
    git(work.path(), &["clone", "--", &origin.url(), "clone"]);
    let clone = work.path().join("clone");
    let head = commit_file(&clone, "app.txt", "clean\n", "clean push");
    git(&clone, &["push", "origin", "main"]);

    assert_eq!(
        origin.origin_ref("refs/heads/main").as_deref(),
        Some(head.as_str()),
        "the push moved the origin ref"
    );
    let landed = origin.landed();
    let last = landed.last().expect("the push produced a landing");
    let landing = last.landing.as_ref().expect("landing");
    assert!(!landing.replayed, "the first landing is not a replay");
    assert!(
        landing.receipt.observed_after.iter().any(|observed| {
            observed.name.as_str() == "refs/heads/main"
                && observed.oid.as_ref().map(oneiron::git_wire::GitOid::as_str)
                    == Some(head.as_str())
        }),
        "the receipt records the ref the landing certified"
    );
}

/// A delete-only push mutates the repository, so it owes a receipt.
///
/// The landing pins its repo_ref to a commit, and the pin used to be read out
/// of the post-image of whatever the push advanced — but a push that only
/// DELETES refs advances nothing. That skipped the landing entirely: refs
/// moved, the objects stayed, and no GitWire receipt recorded that anything had
/// happened. The pre-image the deletion was decided against names the same
/// object store, so the deletion is journaled like every other outcome.
#[test]
fn git_smart_http_delete_only_push_is_journaled_like_any_other_landing() {
    let source = tempfile::tempdir().expect("source tempdir");
    seed_source_repo(source.path(), "base\n");
    let origin = TestOrigin::start(source.path(), DoorSeam::Noop);

    let work = tempfile::tempdir().expect("work tempdir");
    git(work.path(), &["clone", "--", &origin.url(), "clone"]);
    let clone = work.path().join("clone");
    git(&clone, &["checkout", "-b", "feature"]);
    let tip = commit_file(&clone, "feature.txt", "branch\n", "feature commit");
    git(&clone, &["push", "origin", "feature"]);
    assert_eq!(
        origin.origin_ref("refs/heads/feature").as_deref(),
        Some(tip.as_str()),
        "the branch exists before it is deleted"
    );
    let before = origin.landed().len();

    // Nothing but a deletion: no pack, no post-image, no advanced ref.
    git(&clone, &["push", "origin", "--delete", "feature"]);

    assert!(
        origin.origin_ref("refs/heads/feature").is_none(),
        "the delete-only push removed the ref"
    );
    let landed = origin.landed();
    assert_eq!(
        landed.len(),
        before + 1,
        "a delete-only push produces a landing of its own"
    );
    let report = landed.last().expect("the deletion produced a landing");
    let outcome = report.outcome.as_ref().expect("outcome");
    assert_eq!(
        outcome.ref_updates.len(),
        1,
        "exactly the one ref the push deleted"
    );
    assert_eq!(outcome.ref_updates[0].name, "refs/heads/feature");
    assert!(
        outcome.ref_updates[0].new_oid.is_none(),
        "a deletion has no post-image, which is the whole point"
    );
    let landing = report.landing.as_ref().expect("landing");
    assert!(
        landing.receipt.observed_after.iter().any(|observed| {
            observed.name.as_str() == "refs/heads/feature" && observed.oid.is_none()
        }),
        "the receipt certifies the ref as absent, which is what the push did"
    );
    // The pin names WHICH object store the landing published into, never what
    // the push did, and the deleted tip is still in that store: a deletion
    // unlinks a name rather than removing an object.
    assert!(
        origin.object_present(&tip),
        "the deleted tip is still an object this repository carries"
    );
}

#[test]
fn git_smart_http_rejecting_door_hook_fails_before_refs_move_and_objects_stay_unreachable() {
    let source = tempfile::tempdir().expect("source tempdir");
    seed_source_repo(source.path(), "base\n");
    let origin = TestOrigin::start(source.path(), DoorSeam::Landed);
    let before = origin
        .origin_ref("refs/heads/main")
        .expect("origin starts with a tip");

    let work = tempfile::tempdir().expect("work tempdir");
    git(work.path(), &["clone", "--", &origin.url(), "clone"]);
    let clone = work.path().join("clone");
    // Secret-shaped added bytes. The door's scan is unconditional, so this is
    // refused while the objects are still quarantined.
    let head = commit_file(
        &clone,
        "config.env",
        "TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz\n",
        "carries a secret",
    );
    let push = git_output(&clone, &["push", "origin", "main"]);

    assert!(!push.status.success(), "the door refused the push");
    assert_eq!(
        origin.origin_ref("refs/heads/main").as_deref(),
        Some(before.as_str()),
        "a rejected push leaves refs unmoved"
    );
    assert!(
        !origin.object_present(&head),
        "rejected before objects become durable: the pushed commit never became reachable"
    );
    assert!(
        origin.landed().is_empty(),
        "a refused push produces no landing and no receipt"
    );
}

/// A binary push must never be answered `Clean` on bytes nobody read.
///
/// The extraction is the raw diff plus the blob's whole content, so a binary
/// entry reaches the door exactly like a text one — and the door's own rule
/// refuses unscannable bytes while the objects are still quarantined.
#[test]
fn git_smart_http_binary_push_is_refused_rather_than_admitted_unscanned() {
    let source = tempfile::tempdir().expect("source tempdir");
    seed_source_repo(source.path(), "base\n");
    let origin = TestOrigin::start(source.path(), DoorSeam::Landed);
    let before = origin
        .origin_ref("refs/heads/main")
        .expect("origin starts with a tip");

    let work = tempfile::tempdir().expect("work tempdir");
    git(work.path(), &["clone", "--", &origin.url(), "clone"]);
    let clone = work.path().join("clone");
    let head = commit_bytes(
        &clone,
        "logo.png",
        &binary_payload(),
        "carries binary bytes",
    );
    let push = git_output(&clone, &["push", "origin", "main"]);

    assert!(
        !push.status.success(),
        "binary content is decided, never skipped"
    );
    assert_eq!(
        origin.origin_ref("refs/heads/main").as_deref(),
        Some(before.as_str()),
        "a refused binary push leaves refs unmoved"
    );
    assert!(
        !origin.object_present(&head),
        "rejected before objects become durable"
    );
    assert!(
        origin.landed().is_empty(),
        "a refused push produces no landing and no receipt"
    );
}

/// The refusal above is the DOOR's rule, not the extraction's: with the no-op
/// seam the same binary push rides the same wire and lands.
#[test]
fn git_smart_http_binary_push_streams_whole_under_the_noop_seam() {
    let source = tempfile::tempdir().expect("source tempdir");
    seed_source_repo(source.path(), "base\n");
    let origin = TestOrigin::start(source.path(), DoorSeam::Noop);

    let work = tempfile::tempdir().expect("work tempdir");
    git(work.path(), &["clone", "--", &origin.url(), "clone"]);
    let clone = work.path().join("clone");
    let head = commit_bytes(&clone, "logo.png", &binary_payload(), "binary push");
    git(&clone, &["push", "origin", "main"]);

    assert_eq!(
        origin.origin_ref("refs/heads/main").as_deref(),
        Some(head.as_str()),
        "the extraction reads binary blobs without failing the push"
    );
    assert!(
        origin.object_present(&head),
        "the pushed commit became durable"
    );
}

/// Added lines that begin with `++` and `+++ b/...` are content, not headers.
///
/// A patch grammar reads the second as a file header and loses the first; the
/// framed extraction has no header a line can imitate, so the secret-shaped
/// line reaches the door and the door refuses it.
#[test]
fn git_smart_http_double_plus_added_lines_reach_the_door() {
    let source = tempfile::tempdir().expect("source tempdir");
    seed_source_repo(source.path(), "base\n");
    let origin = TestOrigin::start(source.path(), DoorSeam::Landed);
    let before = origin
        .origin_ref("refs/heads/main")
        .expect("origin starts with a tip");

    let work = tempfile::tempdir().expect("work tempdir");
    git(work.path(), &["clone", "--", &origin.url(), "clone"]);
    let clone = work.path().join("clone");
    let head = commit_file(
        &clone,
        "notes.md",
        "++ TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz\n+++ b/decoy.md\n",
        "leading plus signs",
    );
    let push = git_output(&clone, &["push", "origin", "main"]);

    assert!(
        !push.status.success(),
        "a `++`-leading added line is scanned like any other"
    );
    assert_eq!(
        origin.origin_ref("refs/heads/main").as_deref(),
        Some(before.as_str()),
        "the refused push left refs unmoved"
    );
    assert!(
        !origin.object_present(&head),
        "rejected before objects become durable"
    );
}

/// Every refusal the door published, oldest first, one joined string per
/// refused push. Read from the origin's own reports rather than the client's
/// stderr: what the door DECIDED is the fact under test.
fn door_refusals(origin: &TestOrigin) -> Vec<String> {
    origin
        .reports()
        .into_iter()
        .filter_map(|report| match report.door.verdict {
            DoorWindowVerdict::Rejected { reasons } => Some(reasons.join("; ")),
            DoorWindowVerdict::Clean | DoorWindowVerdict::NotInvoked => None,
        })
        .collect()
}

/// A planted `refs/replace/<oid>` must never decide which bytes the door reads.
///
/// Git resolves object reads through the replace table, so a
/// `refs/replace/<commit>` entry aimed at a benign commit makes the hook's own
/// `diff-tree` and `cat-file` enumerate the BENIGN commit while `receive-pack`
/// moves the ref to the real, secret-carrying one: a clean verdict on bytes
/// nobody is landing. Two layers close it, and this proves both — the wire
/// refuses a `refs/replace/*` push outright, and every git the serve path runs
/// has replacement lookup disabled, so a replacement that arrived some other
/// way still substitutes nothing the door reads.
#[test]
fn git_smart_http_planted_replace_ref_cannot_substitute_the_bytes_the_door_scans() {
    let source = tempfile::tempdir().expect("source tempdir");
    seed_source_repo(source.path(), "base\n");
    let origin = TestOrigin::start(source.path(), DoorSeam::Landed);
    let before = origin
        .origin_ref("refs/heads/main")
        .expect("origin starts with a tip");

    let work = tempfile::tempdir().expect("work tempdir");
    git(work.path(), &["clone", "--", &origin.url(), "clone"]);
    let clone = work.path().join("clone");
    // The secret commit exists locally BEFORE anything is pushed, so its oid is
    // known in advance: that is exactly what makes a replacement plantable.
    let secret = commit_file(
        &clone,
        "config.env",
        "TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz\n",
        "carries a secret",
    );
    let planted = format!("refs/replace/{secret}");

    // Layer one: the plant is refused on the wire. By every other measure it is
    // a benign push — its value is the origin's own current tip.
    let plant = git_output(&clone, &["push", "origin", &format!("{before}:{planted}")]);
    assert!(
        !plant.status.success(),
        "this origin never serves a refs/replace/* push"
    );
    let refusals = door_refusals(&origin);
    assert!(
        refusals
            .last()
            .is_some_and(|reason| reason.contains("never serves a replacement ref")),
        "the door refused on the rule, not by accident: {refusals:?}"
    );
    assert!(
        origin.origin_ref(&planted).is_none(),
        "the replacement ref never landed"
    );

    // Layer two: with the replacement planted directly in the origin — the
    // shape the wire now refuses — the door still reads the true bytes.
    git(&origin.repo_dir, &["update-ref", &planted, &before]);
    let push = git_output(&clone, &["push", "origin", "main"]);
    assert!(
        !push.status.success(),
        "the door scanned the bytes this push would make durable, not a substitute"
    );
    assert_eq!(
        origin.origin_ref("refs/heads/main").as_deref(),
        Some(before.as_str()),
        "the refused push left refs unmoved"
    );
    // Asked with replacement off, because the planted ref would otherwise
    // answer this question with the substitute's existence.
    let durable = git_output(
        &origin.repo_dir,
        &["--no-replace-objects", "cat-file", "-e", &secret],
    );
    assert!(
        !durable.status.success(),
        "the secret commit never became durable"
    );
    assert!(
        origin.landed().is_empty(),
        "a refused push produces no landing and no receipt"
    );
}

/// A name git accepts but the landing could never journal is refused pre-move.
///
/// `refs/heads/feature+foo` is a legal git ref and an illegal GitWire one. The
/// landing parses every proposed name with `GitRefName::parse_full` and
/// collects WHOLE, so before this rule the backend moved the ref and THEN the
/// whole landing errored: a mutated repository with no receipt. The door window
/// decides the name while the hook is still blocked, so git never moves what
/// the landing cannot journal.
#[test]
fn git_smart_http_ref_name_the_landing_cannot_journal_is_refused_before_refs_move() {
    let source = tempfile::tempdir().expect("source tempdir");
    seed_source_repo(source.path(), "base\n");
    let origin = TestOrigin::start(source.path(), DoorSeam::Noop);

    let work = tempfile::tempdir().expect("work tempdir");
    git(work.path(), &["clone", "--", &origin.url(), "clone"]);
    let clone = work.path().join("clone");
    let head = commit_file(&clone, "app.txt", "unjournalable\n", "illegal ref name");

    let push = git_output(&clone, &["push", "origin", "main:refs/heads/feature+foo"]);
    assert!(
        !push.status.success(),
        "a name the landing could not journal is refused"
    );
    let refusals = door_refusals(&origin);
    assert!(
        refusals
            .last()
            .is_some_and(|reason| reason.contains("not a ref name this origin can journal")),
        "the door refused the name itself, pre-move: {refusals:?}"
    );
    assert!(
        origin.origin_ref("refs/heads/feature+foo").is_none(),
        "the refusal happened before the backend moved anything"
    );
    assert!(
        !origin.object_present(&head),
        "refused pre-move: the pushed objects never left quarantine"
    );
    assert!(
        origin.landed().is_empty(),
        "nothing moved, so there is nothing to journal"
    );

    // The rule narrows nothing else: the same commit under a name the landing
    // CAN journal lands exactly as it did before.
    git(&clone, &["push", "origin", "main:refs/heads/feature-foo"]);
    assert_eq!(
        origin.origin_ref("refs/heads/feature-foo").as_deref(),
        Some(head.as_str()),
        "a legal name still lands"
    );
    assert_eq!(origin.landed().len(), 1, "and it is journaled");
}

#[test]
fn git_smart_http_repo_supplied_pre_receive_hook_never_executes() {
    let source = tempfile::tempdir().expect("source tempdir");
    seed_source_repo(source.path(), "base\n");
    let origin = TestOrigin::start(source.path(), DoorSeam::Noop);

    // A repository-supplied hook that would refuse every push and leave a
    // sentinel behind. `core.hooksPath` is pinned in argv to the door's own
    // directory, so it can never run.
    let sentinel = origin.repo_dir.join("repo-hook-ran");
    let hooks = origin.repo_dir.join("hooks");
    std::fs::create_dir_all(&hooks).expect("hooks dir");
    let hook = hooks.join("pre-receive");
    std::fs::write(
        &hook,
        format!(
            "#!/bin/sh\ntouch {}\necho repository hook refused this push >&2\nexit 1\n",
            sentinel.display()
        ),
    )
    .expect("write repo hook");
    set_executable(&hook);

    let work = tempfile::tempdir().expect("work tempdir");
    git(work.path(), &["clone", "--", &origin.url(), "clone"]);
    let clone = work.path().join("clone");
    let head = commit_file(&clone, "app.txt", "hooked\n", "hook probe");
    git(&clone, &["push", "origin", "main"]);

    assert!(
        !sentinel.exists(),
        "no repository-supplied hook can ever run"
    );
    assert_eq!(
        origin.origin_ref("refs/heads/main").as_deref(),
        Some(head.as_str()),
        "the push landed through the door's own hook"
    );
}

#[test]
fn git_smart_http_replayed_receive_pack_outcome_is_noop_without_duplicate_oplog_entry() {
    let source = tempfile::tempdir().expect("source tempdir");
    seed_source_repo(source.path(), "base\n");
    let origin = TestOrigin::start(source.path(), DoorSeam::Noop);

    let work = tempfile::tempdir().expect("work tempdir");
    git(work.path(), &["clone", "--", &origin.url(), "clone"]);
    let clone = work.path().join("clone");
    commit_file(&clone, "app.txt", "replay\n", "replayed push");
    git(&clone, &["push", "origin", "main"]);

    let landed = origin.landed();
    let report = landed.last().expect("the push produced a landing");
    let outcome = report.outcome.as_ref().expect("outcome");
    let first = report.landing.as_ref().expect("landing");
    let repo = outcome.pinned_repo_ref().expect("pinned repo ref");

    let replay = origin
        .vault
        .apply_receive_pack_update(&repo, outcome)
        .expect("replay the same outcome");
    assert!(
        replay.replayed,
        "a replayed outcome is answered from the durable record"
    );
    assert_eq!(
        replay.receipt.record_key, first.receipt.record_key,
        "the replay writes no second record"
    );
}

#[test]
fn git_smart_http_crash_window_recovery_never_half_moves_refs() {
    let source = tempfile::tempdir().expect("source tempdir");
    seed_source_repo(source.path(), "base\n");
    let origin = TestOrigin::start(source.path(), DoorSeam::Noop);
    let base = origin
        .origin_ref("refs/heads/main")
        .expect("origin starts with a tip");

    let work = tempfile::tempdir().expect("work tempdir");
    git(work.path(), &["clone", "--", &origin.url(), "clone"]);
    let clone = work.path().join("clone");
    commit_file(&clone, "app.txt", "recovered\n", "recovery probe");
    git(&clone, &["push", "origin", "main"]);

    let landed = origin.landed();
    let report = landed.last().expect("the push produced a landing");
    let outcome = report.outcome.as_ref().expect("outcome");
    let repo = outcome.pinned_repo_ref().expect("pinned repo ref");
    let advanced = origin
        .origin_ref("refs/heads/main")
        .expect("the push advanced the origin");

    // Roll-forward arm. Put the repository back in the state a crash between
    // the durable intent and the effect would leave, then re-drive the intent:
    // it lands the whole advance, never part of it.
    git(&origin.repo_dir, &["update-ref", "refs/heads/main", &base]);
    origin
        .vault
        .apply_receive_pack_update(&repo, outcome)
        .expect("the recorded intent rolls forward");
    assert_eq!(
        origin.origin_ref("refs/heads/main").as_deref(),
        Some(advanced.as_str()),
        "recovery lands the whole advance, never a half-moved ref"
    );

    // Refusal arm. Once the refs carry a value the intent was never decided
    // against, the same intent is terminally refused and moves nothing.
    let second = commit_file(&clone, "app.txt", "moved on\n", "second push");
    git(&clone, &["push", "origin", "main"]);
    assert_eq!(
        origin.origin_ref("refs/heads/main").as_deref(),
        Some(second.as_str())
    );
    let refused = origin.vault.apply_receive_pack_update(&repo, outcome);
    assert!(
        refused.is_err(),
        "an intent whose refs moved under it is refused, not re-applied"
    );
    assert_eq!(
        origin.origin_ref("refs/heads/main").as_deref(),
        Some(second.as_str()),
        "the refused landing moved no ref"
    );
}

#[test]
fn git_smart_http_large_push_streams_without_buffering() {
    let source = tempfile::tempdir().expect("source tempdir");
    seed_source_repo(source.path(), "base\n");
    let origin = TestOrigin::start(source.path(), DoorSeam::Noop);

    let work = tempfile::tempdir().expect("work tempdir");
    git(work.path(), &["clone", "--", &origin.url(), "clone"]);
    let clone = work.path().join("clone");
    let head = commit_file(&clone, "bulk.txt", &incompressible_text(), "bulk push");
    // A tiny post buffer forces the stock client onto chunked upload, so the
    // pack rides in with no declared length and is never held whole.
    git(
        &clone,
        &["-c", "http.postBuffer=16384", "push", "origin", "main"],
    );

    assert_eq!(
        origin.origin_ref("refs/heads/main").as_deref(),
        Some(head.as_str()),
        "a large streamed push lands"
    );
    let landed = origin.landed();
    let report = landed.last().expect("the push produced a landing");
    let outcome = report.outcome.as_ref().expect("outcome");
    assert!(
        outcome.pack_stats.request_bytes > 500_000,
        "the request streamed more than a megabyte"
    );
}

/// Text that does not compress away, so the pushed pack is genuinely large.
fn incompressible_text() -> String {
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    let mut out = String::with_capacity(3 * 1024 * 1024);
    while out.len() < 3 * 1024 * 1024 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        out.push_str(&format!("{state:016x}\n"));
    }
    out
}

#[cfg(unix)]
fn set_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .expect("mark hook executable");
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) {}
