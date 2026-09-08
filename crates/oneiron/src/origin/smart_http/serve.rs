//! One-request orchestration: coordinator lock, reconcile, threaded exchange,
//! finish.

use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::{ChildStderr, ChildStdin};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use super::advertise::AdvertisedRefGate;
use super::cgi_finish::{finish_serve, stream_response};
use super::door::{DoorAdmissionStamp, DoorHook, DoorSeam, NoopDoorHook};
use super::door_window::{DoorWindowContext, DoorWindowReport, serve_door_window};
use super::evidence::{ReceivePackOutcome, receive_pack_provenance_refused};
use super::hooks::DoorHooksDir;
use super::intent::ReceivePackRefResult;
use super::landing::ReceivePackLanding;
use super::paths::{
    DOOR_WINDOW_TIMEOUT, SERVE_MAX_STDERR_BYTES, SERVE_STREAM_CHUNK_BYTES, now_secs,
    origin_door_root, origin_repo_dir, origin_serving_root, serve_failed,
};
use super::serve_cmd::{ServeChild, ServeCommand, ServeRequest};
use crate::Vault;
use crate::codebase::RepoRef;
use crate::credential_door::CredentialDoorService;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::lock_repository;

/// Where a serve invocation writes its response.
///
/// The transport owns framing; this module owns the wire. Bodies pass through
/// chunk by chunk and are never buffered whole.
pub trait ServeSink {
    /// Announces the response status and headers the CGI backend produced.
    fn begin(&mut self, status: u16, headers: &[(String, String)]) -> io::Result<()>;

    /// Streams one response chunk.
    fn write_chunk(&mut self, bytes: &[u8]) -> io::Result<()>;
}

/// What one serve invocation did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeReport {
    /// The status the backend produced.
    pub status: u16,
    /// The admission stamped for a receive-pack, when one ran.
    pub admission: Option<DoorAdmissionStamp>,
    /// The door window, when one opened.
    pub door: DoorWindowReport,
    /// The first certified ref's exact observer-backed outcome, or the first
    /// durable observation if none certified. Byte counters cover the whole
    /// exchange; ref counters cover this outcome only. This is not an atomic
    /// multi-ref replay token: `ref_results` describes the complete operation.
    pub outcome: Option<ReceivePackOutcome>,
    /// The journaled landing, when one happened.
    pub landing: Option<ReceivePackLanding>,
    /// Truthful per-ref completion, including partially published operations.
    pub ref_results: Vec<ReceivePackRefResult>,
}

/// Serves one git smart-HTTP request against a vault-hosted repository.
///
/// Exactly one `git http-backend` child runs per request. The request body
/// streams into its stdin while the response streams out of its stdout, and a
/// receive-pack additionally opens the door window and lands its refs.
///
/// # The receive-pack mutation window (RA2)
///
/// A receive-pack takes the repository coordinator BEFORE the backend is
/// spawned and holds it until the landing is journaled, because the mutation
/// window is not the landing alone: `git receive-pack` moves refs and migrates
/// the quarantined objects inside the exchange. Taking the coordinator
/// afterwards would leave exactly that window open to a concurrent
/// [`crate::Vault::apply_repo_mutation`] or GitWire ref effect, which is the
/// interleaving single-writer forbids.
///
/// It cannot deadlock the worker:
///
/// - The coordinator is re-entrant on one thread, and the landing runs on THIS
///   thread, so [`Vault::apply_receive_pack_update`]'s own acquisition of the
///   same key is a depth bump rather than a second wait.
/// - No thread this function spawns takes it: the body pump, the stderr drain
///   and the door window do not, and the door's scan reads the vault store
///   only.
/// - The `git http-backend` child takes git's own lockfiles, never this
///   advisory lock, so the process holding the coordinator is never waiting on
///   a process that wants it.
///
/// Streaming is unchanged: the wait happens before the exchange begins, so no
/// request is admitted and then stalled mid-body.
pub fn serve(
    vault: &Arc<Vault>,
    repo_name: &str,
    request: &ServeRequest,
    seam: DoorSeam,
    body: &mut (dyn Read + Send),
    sink: &mut dyn ServeSink,
) -> Result<ServeReport> {
    serve_with_provenance(vault, repo_name, request, seam, None, body, sink)
}

/// Compatibility entry point. A new exchange always produces its own evidence;
/// external claim ids cannot stand in for this request's admission or outcome.
/// Passing `None` uses the same production path as [`serve`].
pub fn serve_with_provenance(
    vault: &Arc<Vault>,
    repo_name: &str,
    request: &ServeRequest,
    seam: DoorSeam,
    provenance_claim_id: Option<EntityId>,
    body: &mut (dyn Read + Send),
    sink: &mut dyn ServeSink,
) -> Result<ServeReport> {
    if provenance_claim_id.is_some() {
        return Err(receive_pack_provenance_refused(
            "a new exchange cannot reuse external evidence",
        ));
    }
    let repo_dir = origin_repo_dir(vault, repo_name)?;
    let project_root = origin_serving_root(vault)?;
    let hooks = DoorHooksDir::materialize(&origin_door_root(vault)?)?;
    let command = ServeCommand::http_backend(&repo_dir, &project_root, hooks.path())?;
    let admission = stamp_admission(vault, request, &repo_dir, seam)?;
    if let Some(stamp) = admission.as_ref() {
        vault.record_receive_pack_admission(&repo_dir, stamp, seam)?;
    }
    let coordinator = if request.is_receive_pack() {
        Some(lock_repository(&repo_common_dir(&repo_dir)?)?)
    } else {
        // A fetch and an advertisement mutate nothing, so neither queues behind
        // a push and neither delays one.
        None
    };
    // This also runs for advertisements and no-op retries. A crash after the
    // backend effect must not leave a ref hidden merely because no new hook runs.
    vault.reconcile_receive_pack_operations(&repo_dir)?;
    let mut child = command.spawn(request)?;
    let exchange = run_exchange(
        vault,
        request,
        DoorWindowContext {
            seam,
            admission: admission.as_ref(),
        },
        &repo_dir,
        &hooks,
        &mut child,
        body,
        sink,
    );
    let exchange = match exchange {
        Ok(exchange) => exchange,
        Err(error) => {
            child.kill();
            return Err(error);
        }
    };
    let succeeded = child.wait()?;
    if !succeeded {
        return Err(serve_failed(format!(
            "git http-backend exited with a failure: {}",
            exchange.stderr
        )));
    }
    let report = finish_serve(vault, request, &repo_dir, admission, exchange);
    // Held to here on purpose: the ref mutation, the quarantine migration and
    // the journaled advance are one window, and it closes here.
    drop(coordinator);
    report
}

/// The git common directory that backs a served repository's refs and objects —
/// the key the repository coordinator is taken on.
///
/// A served repository IS a git directory: every serve invocation runs with
/// `GIT_DIR=<repo_dir>`, so git's own rule applies unchanged — the common
/// directory is the `commondir` pointer when one exists and the git directory
/// itself otherwise. Canonicalized, that is the same path
/// [`GitWire::open_repo`] resolves for the same directory, which is what makes
/// this guard and the landing's guard the SAME guard rather than two locks.
pub(super) fn repo_common_dir(repo_dir: &Path) -> Result<PathBuf> {
    let pointer = repo_dir.join("commondir");
    let common = match fs::read_to_string(&pointer) {
        Ok(text) => {
            let named = PathBuf::from(text.trim_end_matches(['\r', '\n']));
            if named.is_absolute() {
                named
            } else {
                repo_dir.join(named)
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => repo_dir.to_path_buf(),
        Err(error) => return Err(Error::Io(error)),
    };
    Ok(common.canonicalize()?)
}

/// Stamps the admission before any subprocess exists.
///
/// The transport has already proved a registered principal and a write scope by
/// the time this runs; the door derives its record from that (and from a
/// presented slip, when Phase B starts presenting one). `peer_addr` is passed
/// through unread on purpose — the door's own contract is that "localhost"
/// describes a route and never a principal.
///
/// This is also where the landed door's catastrophe dial reaches the push: the
/// `Landed` seam admits the `door:receive-pack` effector here, with no slip
/// required, so an operator-narrowed effector set closes the push path BEFORE
/// the backend is spawned and before a single pushed byte is read. The `Noop`
/// seam refuses nothing, which is its whole contract.
pub(super) fn stamp_admission(
    vault: &Arc<Vault>,
    request: &ServeRequest,
    repo_dir: &Path,
    seam: DoorSeam,
) -> Result<Option<DoorAdmissionStamp>> {
    if !request.is_receive_pack() {
        return Ok(None);
    }
    let principal_ref = request
        .remote_user
        .as_deref()
        .ok_or_else(|| serve_failed("receive-pack requires a registered principal"))?;
    let repo = unpinned_repo_ref(repo_dir);
    let peer_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let now = now_secs();
    let stamp = match seam {
        DoorSeam::Noop => {
            NoopDoorHook.admit_receive_pack(None, principal_ref, &repo, peer_addr, now)?
        }
        DoorSeam::Landed => CredentialDoorService::new(Arc::clone(vault)).admit_receive_pack(
            None,
            principal_ref,
            &repo,
            peer_addr,
            now,
        )?,
    };
    Ok(Some(stamp))
}

/// A repo_ref that names the repository before any commit is pinned to it.
///
/// The door reads only the repository's name from it, and the door window runs
/// before the pushed objects leave quarantine, so there is nothing to pin yet.
pub(super) fn unpinned_repo_ref(repo_dir: &Path) -> RepoRef {
    RepoRef::LocalFolder {
        path: repo_dir.to_string_lossy().into_owned(),
        commit: "0".repeat(40),
    }
}

pub(super) struct ServeExchange {
    pub(super) status: u16,
    pub(super) request_bytes: u64,
    pub(super) response_bytes: u64,
    pub(super) door: DoorWindowReport,
    pub(super) stderr: String,
}

#[allow(clippy::too_many_arguments)]
fn run_exchange(
    vault: &Arc<Vault>,
    request: &ServeRequest,
    context: DoorWindowContext<'_>,
    repo_dir: &Path,
    hooks: &DoorHooksDir,
    child: &mut ServeChild,
    body: &mut (dyn Read + Send),
    sink: &mut dyn ServeSink,
) -> Result<ServeExchange> {
    let stdin = child.take_stdin()?;
    let stdout = child.take_stdout()?;
    let stderr = child.take_stderr()?;
    let finished = AtomicBool::new(false);
    let repo = unpinned_repo_ref(repo_dir);
    let deadline = Instant::now() + DOOR_WINDOW_TIMEOUT;
    let receive_pack = request.is_receive_pack();

    std::thread::scope(|scope| {
        let pump = scope.spawn(move || pump_request_body(body, stdin));
        let drain = scope.spawn(move || drain_stderr(stderr));
        let door = receive_pack.then(|| {
            scope.spawn(|| serve_door_window(vault, &repo, hooks, &finished, deadline, context))
        });
        // The ref list is the one response body this module rewrites, and it
        // is rewritten in flight: the gate holds one pkt-line, never the
        // advertisement.
        let streamed = if request.is_ref_advertisement() {
            let mut gate = AdvertisedRefGate::new(vault, repo_dir, sink);
            stream_response(stdout, &mut gate)
        } else {
            stream_response(stdout, sink)
        };
        finished.store(true, Ordering::SeqCst);
        let (status, response_bytes) = streamed?;
        let request_bytes = join_thread(pump.join())?;
        let stderr = drain.join().unwrap_or_default();
        let door = match door {
            Some(handle) => join_thread(handle.join())?,
            None => DoorWindowReport::not_invoked(),
        };
        Ok(ServeExchange {
            status,
            request_bytes,
            response_bytes,
            door,
            stderr,
        })
    })
}

fn join_thread<T>(joined: std::thread::Result<Result<T>>) -> Result<T> {
    match joined {
        Ok(result) => result,
        Err(_) => Err(serve_failed("a serve worker panicked")),
    }
}

/// Streams the request body into the backend. Nothing is buffered whole: the
/// body moves one chunk at a time and stdin closes on the last one.
fn pump_request_body(body: &mut (dyn Read + Send), mut stdin: ChildStdin) -> Result<u64> {
    let mut buffer = vec![0_u8; SERVE_STREAM_CHUNK_BYTES];
    let mut total = 0_u64;
    loop {
        let read = match body.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Error::Io(error)),
        };
        // A backend that closed its input first is not a request failure: the
        // response it already produced is the answer.
        if stdin.write_all(&buffer[..read]).is_err() {
            break;
        }
        total = total.saturating_add(read as u64);
    }
    let _ = stdin.flush();
    drop(stdin);
    Ok(total)
}

/// Drains the backend's diagnostics for the failure message, and only for
/// that. A diagnostic that cannot be read is not a request failure, so this
/// reports what it got rather than an error.
fn drain_stderr(mut stderr: ChildStderr) -> String {
    let mut captured = Vec::new();
    let mut buffer = vec![0_u8; SERVE_STREAM_CHUNK_BYTES];
    loop {
        match stderr.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                if captured.len() < SERVE_MAX_STDERR_BYTES {
                    let room = SERVE_MAX_STDERR_BYTES - captured.len();
                    captured.extend_from_slice(&buffer[..read.min(room)]);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&captured).into_owned()
}
