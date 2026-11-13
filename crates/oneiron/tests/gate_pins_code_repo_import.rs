//! OPUS-T0-F gate pins, PR 8b (Engine NOTE 13 Nov 02:19): the green pin of
//! G198 `Vault::require_admitted_push` (OPUS-TRIAGECENSUS's census,
//! census/TRIAGE.md, class GAP-PASSES: real callers pass the gate today,
//! and no running test drove it from a door).
//!
//! The owner pushes a commit to the vault's served origin with a stock
//! `git` over the real smart-HTTP wire, then imports that commit through
//! `vault.code.import` (`Memory::code_repo_import_as`, the facade's door)
//! with the push's own Published publication as its admission receipt. The
//! gate admits it, and the import answers its manifest, again on a repeat.
//!
//! The framing shim is tests/git_smart_http.rs's, cut to what one push
//! needs: a loopback `TcpListener` that hands each request to
//! `smart_http::serve`, as the push's owner.
//!
//! Test door: `label_writers::embedded_owner`.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test gate_pins_code_repo_import`.
#![cfg(oneiron_test_support)]
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::{io, thread};

use oneiron::authority::MachineRole;
use oneiron::memory::origin_doors::{CodeRepoImportRequest, CodeRepoImportState};
use oneiron::origin::publication::OriginPublicationStatus;
use oneiron::origin::smart_http::{
    self, DoorSeam, DoorWindowVerdict, ServeReport, ServeRequest, ServeSink,
};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The served repository's name, and the ref the push publishes.
const REPO: &str = "demo";
const MAIN: &str = "refs/heads/main";

// ── git ─────────────────────────────────────────────────────────────────

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

/// A one-file repository on `main`; answers its head commit.
fn seed_source_repo(root: &Path) -> String {
    git(root, &["init", "--initial-branch=main"]);
    std::fs::write(root.join("README.md"), "base\n").expect("write readme");
    git(root, &["add", "--", "README.md"]);
    git(root, &["commit", "-m", "initial"]);
    git(root, &["rev-parse", "--verify", "HEAD"])
}

// ── the framing shim (tests/git_smart_http.rs) ──────────────────────────

/// One owned vault serving one bare repository over the smart-HTTP wire.
struct Origin {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    owner: EntityId,
    proof: oneiron::consent::AuthenticatedOwner,
    addr: SocketAddr,
    reports: Arc<Mutex<Vec<ServeReport>>>,
    shutdown: Arc<AtomicBool>,
}

impl Origin {
    /// An owned vault, its signing keys and install profile as a serving
    /// start provisions them, the owner authenticated, and `demo.git`
    /// served.
    fn start() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.embedding_model = None;
        let vault = Arc::new(Vault::open_owned(dir.path(), config)?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        vault.prepare_install_signing()?;
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        // An in-process serve admits a push from the vault's owner and no
        // one else (FIX 6867, G1-PUSH), so the shim pushes as that owner.
        let (owner, proof) = embedded_owner(&vault)?;
        let root = smart_http::origin_serving_root(&vault)?;
        git(
            &root,
            &["init", "--bare", "--initial-branch=main", "demo.git"],
        );

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
                        serve_connection(&vault, DoorSeam::Landed, owner, stream, &reports);
                    });
                }
            }
        });
        Ok(Self {
            _dir: dir,
            vault,
            owner,
            proof,
            addr,
            reports,
            shutdown,
        })
    }

    fn url(&self) -> String {
        format!("http://{}/{REPO}.git", self.addr)
    }

    fn landed(&self) -> Vec<ServeReport> {
        self.reports
            .lock()
            .expect("reports lock")
            .iter()
            .filter(|report| report.landing.is_some())
            .cloned()
            .collect()
    }
}

impl Drop for Origin {
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
            // The registered principal the server layer passes: the owner.
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
        // No length is known ahead of a streamed body: the close ends it.
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

// ── G198: the owner imports the commit the push admitted ────────────────

/// The Published publication the push of `head` to `main` made: the
/// admission receipt the import names.
fn push_publication(vault: &Vault, head: &str) -> TestResult<EntityId> {
    let mut seen = Vec::new();
    for id in vault.origin_publication_ids(None)? {
        let record = vault
            .origin_publication(id)?
            .ok_or("a listed publication reads")?;
        if record.ref_name.as_str() == MAIN
            && record.new_oid.as_str() == head
            && record.status == OriginPublicationStatus::Published
        {
            return Ok(id);
        }
        seen.push(format!(
            "{} {} {:?}",
            record.ref_name.as_str(),
            record.new_oid.as_str(),
            record.status
        ));
    }
    Err(format!("no Published publication of {head} on {MAIN}: {seen:?}").into())
}

#[test]
fn g198_the_owner_imports_the_commit_a_served_push_admitted() -> TestResult {
    let source = tempfile::tempdir()?;
    let head = seed_source_repo(source.path());
    let origin = Origin::start()?;
    git(
        source.path(),
        &["push", &origin.url(), &format!("main:{MAIN}")],
    );
    let landed = origin.landed();
    assert_eq!(landed.len(), 1, "the push has one landing");
    assert_eq!(landed[0].door.verdict, DoorWindowVerdict::Clean);
    let publication = push_publication(&origin.vault, &head)?;

    let request = CodeRepoImportRequest {
        repo: REPO.to_owned(),
        project: origin.vault.root_project()?,
        source_ref: MAIN.to_owned(),
        source_commit: head,
        admission_receipt: publication,
        accept: None,
    };
    let memory = origin
        .vault
        .memory(origin.owner, EdgeActorClass::Human)
        .with_owner_authorship(&origin.proof);
    let view = memory.code_repo_import_as(&origin.proof, request.clone())?;
    assert_eq!(view.state, CodeRepoImportState::ManifestReady);
    assert!(
        view.manifest
            .files
            .iter()
            .any(|file| file.file.path == "README.md"),
        "the manifest lists the pushed file: {:?}",
        view.manifest.files
    );

    // A repeat answers the same manifest.
    let again = memory.code_repo_import_as(&origin.proof, request)?;
    assert_eq!(again.manifest.manifest_ref, view.manifest.manifest_ref);
    Ok(())
}
