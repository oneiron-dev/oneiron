//! RUN-REVEAL-BASE-HASH-DOMAIN: a run's `views.read` with a `why` asks the
//! owner for its base file's stored bytes through the ingested snapshot of
//! the work's base commit, never through the stamp's pinned-base hash,
//! which names another hash domain and selects no ingest snapshot.
//!
//! The fixture is a run repo door repo (as in `repo_run/fixture.rs`) with a
//! third file holding a pushed secret: the same bytes go through the
//! vault's served origin (the framing shim from `git_smart_http.rs`), so
//! the file carries readable marks, the owner ingests the commit, and the
//! agent's work holds its masked copy. A `views.read` that says `why` then
//! reaches the base snapshot: with no grant it still returns the masked
//! copy, but the file reveal it ran files its ask with the owner. Before
//! the fix the join selected nothing, so no ask was ever filed.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test run_reveal_base_hash_domain`.
#![cfg(oneiron_test_support)]
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

#[path = "repo_run/fixture.rs"]
mod fixture;

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::{io, thread};

use fixture::{
    LABEL_RS, MAIN, MATH_RS, RunBinding, TestResult, bind_run, create_enabled_agent, leased_try,
    mint_repo_grant, paired_agent_slip,
};
use oneiron::authority::MachineRole;
use oneiron::codebase::RepoRef;
use oneiron::consent::AuthenticatedOwner;
use oneiron::contract_oracle::{ContractOracle, ContractSpec, WorkspaceGraph};
use oneiron::federation::RepoAccessBounds;
use oneiron::memory::codebase_doors::{CodeRepoPointer, CodeSnapshotIngestRequest};
use oneiron::memory::repo_doors::{RepoViewsReadInput, RepoWorkOpenInput};
use oneiron::merge_queue::MergeQueue;
use oneiron::origin::smart_http::{
    self, DoorSeam, DoorWindowVerdict, ServeReport, ServeRequest, ServeSink,
};
use oneiron::secret_custody::{SecretRevealAsk, SecretRevealState};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

/// The marked file: its token is the fake GitHub token the secret scanner
/// names, as in `git_smart_http.rs`.
const SECRET_RS_PATH: &str = "secret.rs";
const SECRET_RS: &str =
    "pub const DEPLOY_TOKEN: &str = \"ghp_0123456789abcdefghijklmnopqrstuvwxyz\";\n";

fn git(dir: &Path, args: &[&str]) -> TestResult<String> {
    let output = Command::new("git").args(args).current_dir(dir).output()?;
    if !output.status.success() {
        return Err(format!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

// ---------------------------------------------------------------------------
// The framing shim, from `git_smart_http.rs`: stock git over plain HTTP/1.1,
// every request handed to `smart_http::serve`.
// ---------------------------------------------------------------------------

/// One vault serving one repository over the real smart-HTTP wire. The seed
/// push lands the repo's commit and plants the pushed secret's marks.
struct SecretOrigin {
    addr: SocketAddr,
    repo_dir: PathBuf,
    reports: Arc<Mutex<Vec<ServeReport>>>,
    shutdown: Arc<AtomicBool>,
}

impl SecretOrigin {
    /// Serves `vault`'s `demo.git` and pushes `source`'s `main` through the
    /// door's scan, as the origin's seed push.
    fn start(vault: Arc<Vault>, owner: EntityId, source: &Path) -> TestResult<Self> {
        let root = smart_http::origin_serving_root(&vault)?;
        git(
            &root,
            &["init", "--bare", "--initial-branch=main", "demo.git"],
        )?;
        let repo_dir = root.join("demo.git");

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
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
                    thread::spawn(move || {
                        serve_connection(&vault, DoorSeam::Landed, owner, stream, &reports)
                    });
                }
            }
        });

        let origin = Self {
            addr,
            repo_dir,
            reports,
            shutdown,
        };
        let head = git(source, &["rev-parse", "--verify", "refs/heads/main"])?;
        git(source, &["push", &origin.url(), "main:refs/heads/main"])?;
        if origin.origin_ref("refs/heads/main").as_deref() != Some(head.as_str()) {
            return Err("the scanned seed reached the origin".into());
        }
        Ok(origin)
    }

    fn url(&self) -> String {
        format!("http://{}/demo.git", self.addr)
    }

    fn origin_ref(&self, name: &str) -> Option<String> {
        git(&self.repo_dir, &["rev-parse", "--verify", name])
            .ok()
            .map(|name| name.to_ascii_lowercase())
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

impl Drop for SecretOrigin {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
    }
}

fn serve_connection(
    vault: &Arc<Vault>,
    seam: DoorSeam,
    principal: EntityId,
    stream: TcpStream,
    reports: &Arc<Mutex<Vec<ServeReport>>>,
) {
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

// ---------------------------------------------------------------------------
// The fixture
// ---------------------------------------------------------------------------

/// The repo, its served seed push, and one agent run with the work it opened
/// at the queue's green commit: `secret.rs` carries readable marks and the
/// work holds its masked copy.
struct Fixture {
    vault: Arc<Vault>,
    _vault_dir: tempfile::TempDir,
    _repo_dir: tempfile::TempDir,
    _origin: SecretOrigin,
    owner_proof: AuthenticatedOwner,
    run: RunBinding,
    work: EntityId,
    /// The ingested snapshot's fork hash: the ingest domain's selector.
    snapshot: String,
    /// The work's pinned-base hash: the repo-mutation domain's, never an
    /// ingest fork.
    base_snapshot: String,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let vault_dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.embedding_model = None;
        let vault = Arc::new(Vault::open_owned(vault_dir.path(), config)?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        vault.prepare_install_signing()?;
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let (owner, owner_proof) = embedded_owner(&vault)?;
        let project = vault.root_project()?;

        // The repo: two clean files and one holding a pushed secret.
        let repo_dir = tempfile::tempdir()?;
        git(repo_dir.path(), &["init", "--quiet"])?;
        git(repo_dir.path(), &["symbolic-ref", "HEAD", MAIN])?;
        std::fs::write(repo_dir.path().join("math.rs"), MATH_RS)?;
        std::fs::write(repo_dir.path().join("label.rs"), LABEL_RS)?;
        std::fs::write(repo_dir.path().join(SECRET_RS_PATH), SECRET_RS)?;
        git(
            repo_dir.path(),
            &["add", "--", "math.rs", "label.rs", SECRET_RS_PATH],
        )?;
        git(
            repo_dir.path(),
            &[
                "-c",
                "user.name=owen",
                "-c",
                "user.email=owen@example.com",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--quiet",
                "-m",
                "two files and a secret",
            ],
        )?;
        let commit = git(repo_dir.path(), &["rev-parse", "HEAD"])?;
        let folder = repo_dir.path().canonicalize()?;

        // The owner ingests the commit before the push plants its marks.
        let snapshot = vault
            .memory(owner, EdgeActorClass::Human)
            .with_owner_authorship(&owner_proof)
            .code_snapshot_ingest_as(
                &owner_proof,
                CodeSnapshotIngestRequest {
                    project_id: project.to_hex(),
                    pointer: CodeRepoPointer {
                        local_folder: folder.to_str().ok_or("UTF-8 repo path")?.to_owned(),
                        commit: commit.clone(),
                    },
                    repository: None,
                },
            )?;
        let repo = snapshot.repo;
        vault.put_project_member(repo, project)?;
        let queue = MergeQueue::open(&vault, RepoRef::parse(&snapshot.repo_ref)?)?;
        let spec = ContractSpec::default();
        let baseline = ContractOracle::new(&vault).record_baseline(
            spec.clone(),
            ContractOracle::capture(&spec, &folder, BTreeMap::new())?,
        )?;
        let pointers = queue.initialize(&baseline.id, WorkspaceGraph::unfiltered())?;
        assert_eq!(pointers.green, commit, "the queue is green at the commit");

        // The served seed push plants the secret's marks, by its bytes.
        let origin = SecretOrigin::start(Arc::clone(&vault), owner, repo_dir.path())?;
        let landed = origin.landed();
        assert_eq!(landed.len(), 1, "the seed push landed");
        assert!(
            matches!(
                landed[0].door.verdict,
                DoorWindowVerdict::AdmitMarked { .. }
            ),
            "the door admitted the seed push with its key marked: {:?}",
            landed[0].door.verdict
        );

        // One agent run, reading every Rust file, with its work at green.
        let agent = create_enabled_agent(&vault, &owner_proof, "reveal-base-agent")?;
        let slip = paired_agent_slip(&vault, &issuer, &owner_proof, agent, 0xA1)?;
        let bounds = RepoAccessBounds {
            repo,
            project,
            refs: BTreeSet::from([MAIN.to_owned()]),
            readable: BTreeSet::from(["*.rs".to_owned()]),
            editable: BTreeSet::from(["*.rs".to_owned()]),
        };
        mint_repo_grant(&vault, &owner_proof, agent, Some(&bounds))?;
        let owner_memory = vault
            .memory(owner, EdgeActorClass::Human)
            .with_owner_authorship(&owner_proof);
        let leased = leased_try(&vault, &owner_memory, owner, agent, "reveal base")?;
        let run = bind_run(&vault, &slip, leased)?;
        let opened = run.memory(&vault).repo_work_open_for_run(
            &run.binding,
            RepoWorkOpenInput {
                repo,
                portable_repo: None,
                git_ref: MAIN.to_owned(),
            },
        )?;
        let work = opened.output.work;
        let base_snapshot = opened.output.base_snapshot.clone();

        Ok(Self {
            vault,
            _vault_dir: vault_dir,
            _repo_dir: repo_dir,
            _origin: origin,
            owner_proof,
            run,
            work,
            snapshot: snapshot.snapshot,
            base_snapshot,
        })
    }

    /// `self.code.views.read` of the marked file, with `why` or without.
    fn read(&self, why: Option<&str>) -> TestResult<Vec<u8>> {
        let answer = self.run.memory(&self.vault).repo_views_read_for_run(
            &self.run.binding,
            RepoViewsReadInput {
                work: self.work,
                path: SECRET_RS_PATH.to_owned(),
                why: why.map(str::to_owned),
            },
        )?;
        Ok(answer.output.bytes)
    }

    /// The owner's pending reveal asks.
    fn asks(&self) -> TestResult<Vec<SecretRevealAsk>> {
        Ok(self.vault.secret_reveals(&self.owner_proof, true, 16)?)
    }
}

#[test]
fn a_views_read_with_why_reaches_the_base_snapshot_and_files_its_ask() -> TestResult {
    let fixture = Fixture::new()?;
    // The fixture's premise: two hash domains, and the file is marked.
    assert_ne!(
        fixture.base_snapshot, fixture.snapshot,
        "the pinned-base hash is another domain than the ingest fork"
    );
    let hits = oneiron::test_doors::repo_secret_marks::marked_hits(&fixture.vault)?;
    assert!(
        hits.iter()
            .any(|hit| hit.path.as_deref() == Some(SECRET_RS_PATH)),
        "a mark names the pushed file: {hits:?}"
    );
    // The work holds the masked copy, and nothing asked yet.
    let plain = fixture.read(None)?;
    assert_ne!(
        plain,
        SECRET_RS.as_bytes(),
        "the work holds the masked copy"
    );
    assert!(
        fixture.asks()?.is_empty(),
        "nothing filed an ask before the why-read"
    );
    // The why-read reaches the base snapshot: with no grant it still
    // returns the masked copy, but its file reveal filed its ask.
    let answered = fixture.read(Some(
        "the run needs this file's stored bytes to continue its task",
    ))?;
    assert_eq!(
        answered, plain,
        "with no grant the why-read still returns the masked copy"
    );
    let asks = fixture.asks()?;
    assert_eq!(
        asks.len(),
        1,
        "the why-read reached the base snapshot and filed its ask"
    );
    assert_eq!(asks[0].state, SecretRevealState::Asked);
    Ok(())
}

#[test]
fn a_views_read_without_why_files_no_ask() -> TestResult {
    let fixture = Fixture::new()?;
    let plain = fixture.read(None)?;
    assert_ne!(
        plain,
        SECRET_RS.as_bytes(),
        "the work holds the masked copy"
    );
    assert!(
        fixture.asks()?.is_empty(),
        "a read that says nothing asks nothing"
    );
    Ok(())
}
