//! One-request orchestration: coordinator lock, reconcile, threaded exchange,
//! finish.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{ChildStderr, ChildStdin};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::advertise::AdvertisedRefGate;
use super::bounds::{ExchangeBounds, ScanBounds};
use super::cgi_finish::{finish_serve, stream_response};
use super::door::{DoorAdmissionStamp, DoorSeam};
use super::door_window::{DoorWindowContext, DoorWindowReport, serve_door_window};
use super::evidence::{ReceivePackOutcome, receive_pack_provenance_refused};
use super::exchange_idle::{Progress, ProgressRead, ProgressSink, Watched, stall_as_idle, watch};
use super::held::{HeldBytes, SpillFloor};
use super::hooks::DoorHooksDir;
use super::intent::ReceivePackRefResult;
use super::landing::ReceivePackLanding;
use super::paths::{
    DOOR_WINDOW_TIMEOUT, ORIGIN_COMMAND_SECTION_MEMORY_BYTES, SERVE_IDLE_TIMEOUT,
    SERVE_MAX_STDERR_BYTES, SERVE_STREAM_CHUNK_BYTES, origin_door_root, origin_repo_dir,
    origin_serving_root, push_refused, repository_busy, serve_failed, serve_idle,
};
use super::projected_serve::{ProjectedExchange, select_projected_exchange};
use super::push_admission::{ServeCaller, admit_push, stamp_admission};
use super::read_projection::RepoGitBackend;
use super::recipient_serve::RepoGitReadContext;
use super::serve_cmd::{IncomingQuarantines, ServeChild, ServeCommand, ServeRequest};
use crate::Vault;
use crate::codebase::RepoRef;
use crate::credential_door::CredentialDoorService;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::git_push::GitPushStamp;
use crate::git_wire::{lock_repository, lock_repository_within, try_lock_repository};
use crate::origin::residence::{OriginAuthorityLease, OriginAuthorityStamp};

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
///
/// # The idle limit
///
/// This function owns the child for its whole life. An exchange that moves no
/// byte in either direction for [`SERVE_IDLE_TIMEOUT`](super::SERVE_IDLE_TIMEOUT) has its backend killed
/// and fails with [`CodeError::GitHttpExchangeIdle`], which also releases the
/// coordinator a push holds; [`serve_bounded`] sets another limit. A child
/// is always reaped before this returns. The door's scan keeps the default
/// [`ScanBounds`](super::ScanBounds).
///
/// [`CodeError::GitHttpExchangeIdle`]: crate::error::CodeError::GitHttpExchangeIdle
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

/// [`serve`] for a transport that admits exchanges by permit.
///
/// It runs under its host's [`ExchangeBounds`]: its own idle limit in place of
/// [`SERVE_IDLE_TIMEOUT`], and the floors its door scan keeps. A transport
/// whose body and sink bound their own waits passes the same idle limit, so
/// whichever side sees the stall first ends the exchange the same way. A
/// push that finds the repository coordinator taken waits for it, for
/// `repository_wait` at most, and only then fails with
/// [`CodeError::GitHttpRepositoryBusy`]; the transport queues its own pushes
/// to one repository before this, so the wait is for a writer outside it.
/// The host's repository maintenance gives the coordinator up to it, within
/// one of the maintenance's polls, and the push waits that out whatever
/// `repository_wait` is. A read never waits for the coordinator: it recovers
/// and projects its ref list under the coordinator only when it finds it free.
///
/// [`CodeError::GitHttpRepositoryBusy`]: crate::error::CodeError::GitHttpRepositoryBusy
pub fn serve_bounded(
    vault: &Arc<Vault>,
    repo_name: &str,
    request: &ServeRequest,
    seam: DoorSeam,
    bounds: ExchangeBounds,
    body: &mut (dyn Read + Send),
    sink: &mut dyn ServeSink,
) -> Result<ServeReport> {
    serve_bounded_with_authority(vault, repo_name, request, seam, bounds, None, body, sink)
}

/// [`serve_bounded`] under the lease its host holds, when the repository has
/// an origin authority: the transport's form of [`serve_with_authority`]. The
/// host reads its lease from trusted configuration
/// ([`Vault::origin_host_authority`](crate::Vault::origin_host_authority)),
/// never from the request; `None` is an origin with no authority configured,
/// which refuses every push once one is.
#[expect(clippy::too_many_arguments)]
pub fn serve_bounded_with_authority(
    vault: &Arc<Vault>,
    repo_name: &str,
    request: &ServeRequest,
    seam: DoorSeam,
    bounds: ExchangeBounds,
    authority: Option<&OriginAuthorityLease>,
    body: &mut (dyn Read + Send),
    sink: &mut dyn ServeSink,
) -> Result<ServeReport> {
    let terms = ServeTerms {
        seam,
        authority,
        idle: bounds.idle,
        scan: bounds.scan,
        spill_floor: bounds.spill_floor,
        wait_for_repository: false,
        push_wait: Some(bounds.repository_wait),
        caller: ServeCaller::InProcess,
        read: None,
    };
    serve_request(vault, repo_name, request, terms, body, sink)
}

/// The key one served repository's pushes queue under: the git common
/// directory its coordinator is taken on, so two names for one repository
/// share one line.
pub fn push_queue_key(vault: &Vault, repo_name: &str) -> Result<PathBuf> {
    repo_common_dir(&origin_repo_dir(vault, repo_name)?)
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
    let terms = ServeTerms {
        seam,
        authority: None,
        idle: SERVE_IDLE_TIMEOUT,
        scan: ScanBounds::default(),
        spill_floor: None,
        wait_for_repository: true,
        push_wait: None,
        caller: ServeCaller::InProcess,
        read: None,
    };
    serve_request(vault, repo_name, request, terms, body, sink)
}

/// Serves using a lease supplied by trusted host configuration, not by the
/// pusher or a CGI/header field. A configured origin refuses ordinary `serve`.
/// The coordinator pins this epoch from admission through durable landing.
pub fn serve_with_authority(
    vault: &Arc<Vault>,
    repo_name: &str,
    request: &ServeRequest,
    seam: DoorSeam,
    authority: &OriginAuthorityLease,
    body: &mut (dyn Read + Send),
    sink: &mut dyn ServeSink,
) -> Result<ServeReport> {
    let terms = ServeTerms {
        seam,
        authority: Some(authority),
        idle: SERVE_IDLE_TIMEOUT,
        scan: ScanBounds::default(),
        spill_floor: None,
        wait_for_repository: true,
        push_wait: None,
        caller: ServeCaller::InProcess,
        read: None,
    };
    serve_request(vault, repo_name, request, terms, body, sink)
}

/// What one invocation runs under besides its request: the door seam, a lease
/// from trusted host configuration, the exchange's idle limit, scan floors
/// and spill floor, whether a read may wait for a repository a writer holds,
/// and how long a push waits for it (`None`: until it is free), and who it
/// pushes as (G1-PUSH).
pub(super) struct ServeTerms<'a> {
    pub(super) seam: DoorSeam,
    pub(super) authority: Option<&'a OriginAuthorityLease>,
    pub(super) idle: Duration,
    pub(super) scan: ScanBounds,
    pub(super) spill_floor: Option<Arc<dyn SpillFloor>>,
    pub(super) wait_for_repository: bool,
    pub(super) push_wait: Option<Duration>,
    pub(super) caller: ServeCaller<'a>,
    /// The read recipient the host proved (FIX 7608 2b-ii-B2); `None` on
    /// every in-process and exact path, which serves as before.
    pub(super) read: Option<&'a RepoGitReadContext>,
}

pub(super) fn serve_request(
    vault: &Arc<Vault>,
    repo_name: &str,
    request: &ServeRequest,
    terms: ServeTerms<'_>,
    body: &mut (dyn Read + Send),
    sink: &mut dyn ServeSink,
) -> Result<ServeReport> {
    let ServeTerms {
        seam,
        authority,
        idle,
        scan,
        spill_floor,
        wait_for_repository,
        push_wait,
        caller,
        read,
    } = terms;
    let repo_dir = origin_repo_dir(vault, repo_name)?;
    let project_root = origin_serving_root(vault)?;
    let mut tickets = request
        .query_string
        .split('&')
        .filter_map(|pair| pair.strip_prefix("checkout-lease="));
    if let Some(ticket) = tickets.next() {
        if tickets.next().is_some() || seam != DoorSeam::Landed {
            return Err(serve_failed("invalid checkout lease route"));
        }
        let principal = request
            .remote_user
            .as_deref()
            .ok_or_else(|| serve_failed("checkout lease requires a registered principal"))?;
        CredentialDoorService::new(Arc::clone(vault))
            .checkout_credential(ticket, principal, &unpinned_repo_ref(&repo_dir))
            .map_err(|error| super::paths::door_refused(&error))?;
    }
    // Every receive-pack advertisement and RPC meets the push decision
    // before a hook, a child or a body byte exists (G1-PUSH).
    let push = admit_push(vault, request, repo_name, &repo_dir, caller)?;
    // After that same decision, a masked recipient on a marked store is
    // served its masked copy or received into its private ingress; every
    // other exchange is today's (FIX 7608 2b-ii-B2). The canonical store
    // keeps the coordinator; the ingress is where the push physically lands.
    let projected = select_projected_exchange(vault, request, &repo_dir, &project_root, read)?;
    let served_dir = projected
        .as_ref()
        .and_then(ProjectedExchange::ingress_root)
        .map_or_else(|| repo_dir.clone(), Path::to_path_buf);
    let door_root = origin_door_root(vault)?;
    let list_paths = push.as_ref().is_some_and(GitPushStamp::is_checkout);
    let hooks = DoorHooksDir::materialize_listing(&door_root, scan, list_paths)?;
    let command = match &projected {
        Some(projected) => projected.command(&project_root, hooks.path())?,
        None => ServeCommand::http_backend(&repo_dir, &project_root, hooks.path())?,
    };
    let coordinator = if request.is_receive_pack() {
        let common_dir = repo_common_dir(&repo_dir)?;
        match push_wait {
            None => Some(lock_repository(&common_dir)?),
            Some(wait) => {
                Some(lock_repository_within(&common_dir, wait)?.ok_or_else(repository_busy)?)
            }
        }
    } else {
        // A fetch and an advertisement mutate nothing, so neither queues behind
        // a push and neither delays one.
        None
    };
    // The ingress's own coordinator, after the canonical one, never before.
    let ingress_coordinator = match (&coordinator, served_dir != repo_dir) {
        (Some(_), true) => Some(lock_repository(&repo_common_dir(&served_dir)?)?),
        _ => None,
    };
    // The same coordinator guards epoch cutover. Stamp and persist only after
    // acquiring it, so an old accepted request cannot cross an epoch change.
    let mut admission = stamp_admission(vault, request, &repo_dir, seam, push)?;
    if let Some(stamp) = admission.as_mut() {
        stamp.origin_authority = authority.map(OriginAuthorityStamp::from_lease);
        if let Some(projected) = &projected {
            projected.bind(vault, stamp)?;
        }
        vault.record_receive_pack_admission(&served_dir, stamp, seam)?;
    }
    // This also runs for advertisements and no-op retries. A crash after the
    // backend effect must not leave a ref hidden merely because no new hook runs.
    // Recovery takes the coordinator, which a push already holds here. A read
    // that may not wait for it leaves recovery to whoever holds it or to the
    // next request that finds it free: a ref still hidden is the safe side,
    // and a read never queues behind a write.
    if coordinator.is_some() || wait_for_repository {
        vault.reconcile_receive_pack_operations(&served_dir)?;
    } else if let Some(_free) = try_lock_repository(&repo_common_dir(&served_dir)?)? {
        vault.reconcile_receive_pack_operations(&served_dir)?;
    }
    // No byte of the body is read before the admission above is checked and
    // recorded. A push body the backend would inflate is inflated here
    // instead, once: the command section read below is then the one
    // receive-pack reads, and the backend gets the whole body plain.
    let plain;
    let mut inflated;
    let (request, body): (&ServeRequest, &mut (dyn Read + Send)) =
        if request.is_receive_pack() && backend_inflates(request) {
            plain = ServeRequest {
                content_length: None,
                content_encoding: None,
                ..request.clone()
            };
            inflated = flate2::read::GzDecoder::new(body);
            (&plain, &mut inflated)
        } else {
            (request, body)
        };
    // A body that stalls here ends at the idle limit, as it would mid-exchange.
    let mut commands = if request.is_receive_pack() {
        read_command_section(body, door_root, spill_floor.clone()).map_err(stall_as_idle)?
    } else {
        HeldBytes::new(0, None)
    };
    // A publication this push may land on again gets its roots back while no
    // backend can move a ref yet, on the thread holding the coordinator.
    if coordinator.is_some() {
        vault.repin_pushed_move_owners(&served_dir, &mut commands.reader().map_err(Error::Io)?)?;
    }
    let body = &mut commands.reader().map_err(Error::Io)?.chain(body);
    // Between the coordinator and the child, so on every way out the child
    // is reaped first, then what a killed backend left in quarantine is
    // swept, and only then is the coordinator let go. Noted only now: a push
    // refused before its backend runs made no quarantine, so it sweeps none.
    let mut quarantines = match coordinator {
        Some(_) => Some(IncomingQuarantines::note(
            repo_common_dir(&served_dir)?.join("objects"),
        )),
        None => None,
    };
    let mut child = command.spawn(request)?;
    let exchange = run_exchange(
        &ExchangeSetup {
            vault,
            request,
            context: DoorWindowContext {
                seam,
                admission: admission.as_ref(),
                scan,
                spill_floor: spill_floor.as_ref(),
            },
            repo_dir: &served_dir,
            hooks: &hooks,
            idle,
            wait_for_repository,
            backend: projected.as_ref().and_then(ProjectedExchange::backend),
            ingress: projected
                .as_ref()
                .is_some_and(|projected| projected.ingress_root().is_some()),
        },
        &mut child,
        body,
        sink,
    );
    let exchange = match exchange {
        Ok(exchange) => exchange,
        Err(error) => {
            child.kill();
            if let Some(quarantines) = quarantines.as_mut() {
                quarantines.settle(&child);
            }
            return Err(error);
        }
    };
    let succeeded = child.wait();
    if let Some(quarantines) = quarantines.as_mut() {
        quarantines.settle(&child);
    }
    let succeeded = succeeded?;
    if !succeeded {
        return Err(serve_failed(format!(
            "git http-backend exited with a failure: {}",
            exchange.stderr
        )));
    }
    #[cfg(test)]
    if request.is_receive_pack()
        && vault
            .test_hooks()
            .stop_push_before_landing
            .swap(false, Ordering::SeqCst)
    {
        return Err(serve_failed("stopped before the landing"));
    }
    let report = finish_serve(vault, request, &served_dir, admission, exchange);
    // Held to here on purpose: the ref mutation, the quarantine migration and
    // the journaled advance are one window, and it closes here.
    drop(quarantines);
    drop(ingress_coordinator);
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

/// The immutable setup one exchange runs against: who is serving, what was
/// asked, under which door window, out of which repository and hooks
/// directory, and how long it may sit idle. Every field is fixed before the
/// backend is spawned; the live handles the exchange consumes are the
/// separate parameters beside it.
struct ExchangeSetup<'a> {
    vault: &'a Arc<Vault>,
    request: &'a ServeRequest,
    context: DoorWindowContext<'a>,
    repo_dir: &'a Path,
    hooks: &'a DoorHooksDir,
    idle: Duration,
    wait_for_repository: bool,
    /// The masked copy's frozen read backend, whose gate the advertisement
    /// passes instead of the canonical one (FIX 7608 2b-ii-B2).
    backend: Option<&'a RepoGitBackend>,
    /// Whether the exchange runs in a masked copy's private ingress, whose
    /// own refs its advertisement names as they stand.
    ingress: bool,
}

fn run_exchange(
    setup: &ExchangeSetup<'_>,
    child: &mut ServeChild,
    body: &mut (dyn Read + Send),
    sink: &mut dyn ServeSink,
) -> Result<ServeExchange> {
    let &ExchangeSetup {
        vault,
        request,
        context,
        repo_dir,
        hooks,
        idle,
        wait_for_repository,
        backend,
        ingress,
    } = setup;
    let stdin = child.take_stdin()?;
    let stdout = child.take_stdout()?;
    let stderr = child.take_stderr()?;
    let finished = AtomicBool::new(false);
    let repo = unpinned_repo_ref(repo_dir);
    let deadline = Instant::now() + DOOR_WINDOW_TIMEOUT;
    let receive_pack = request.is_receive_pack();
    let progress = Progress::new();
    let mut body = ProgressRead {
        body,
        progress: &progress,
    };
    let mut sink = ProgressSink {
        sink,
        progress: &progress,
    };
    let (watching, watched) = std::sync::mpsc::channel::<Watched>();

    std::thread::scope(|scope| {
        // Closed when this body returns, however it returns, so the
        // watchdog never outlives the exchange it watches; closed by an
        // unwind, as when a thread below cannot start, it ends the backend.
        let watching = watching;
        let _finished = FinishedOnDrop(&finished);
        let clock = &progress;
        let watchdog = scope.spawn(move || watch(clock, idle, &watched, child));
        let pump = scope.spawn(move || pump_request_body(&mut body, stdin));
        let drain = scope.spawn(move || drain_stderr(stderr));
        let door = receive_pack.then(|| {
            scope.spawn(|| {
                serve_door_window(vault, &repo, hooks, &finished, deadline, &progress, context)
            })
        });
        // The ref list is the one response body this module rewrites, and it
        // is rewritten in flight: the gate holds one pkt-line, never the
        // advertisement.
        let streamed = if let (true, Some(backend)) = (request.is_ref_advertisement(), backend) {
            let mut gate = backend.advertisement_gate(vault, clock, &mut sink);
            stream_response(stdout, &mut gate)
        } else if request.is_ref_advertisement() && !ingress {
            let mut gate =
                AdvertisedRefGate::new(vault, repo_dir, wait_for_repository, clock, &mut sink);
            stream_response(stdout, &mut gate)
        } else {
            stream_response(stdout, &mut sink)
        };
        finished.store(true, Ordering::SeqCst);
        if streamed.is_err() {
            // Nothing more is wanted from the backend, and a push's hook may
            // be waiting on a verdict the door window will now never give:
            // end it, so the joins below see their ends.
            let _ = watching.send(Watched::End);
        }
        let pumped = join_thread(pump.join());
        let stderr = drain.join().unwrap_or_default();
        let door = match door {
            Some(handle) => join_thread(handle.join()),
            None => Ok(DoorWindowReport::not_invoked()),
        };
        // Disarmed only once every thread is joined: until then, a backend
        // one of them still waited on was watched.
        let _ = watching.send(Watched::Joined);
        // A response cut short by the watchdog's kill reads as an ending; it
        // is the idle limit's, never a success.
        if join_thread(watchdog.join().map(Ok))? {
            return Err(serve_idle());
        }
        let (status, response_bytes) = streamed.map_err(stall_as_idle)?;
        let request_bytes = pumped.map_err(stall_as_idle)?;
        let door = door?;
        Ok(ServeExchange {
            status,
            request_bytes,
            response_bytes,
            door,
            stderr,
        })
    })
}

/// Marks the response finished when the exchange body ends however it ends,
/// an unwind included, so the door window stops waiting for a request that
/// can no longer come.
struct FinishedOnDrop<'a>(&'a AtomicBool);

impl Drop for FinishedOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn join_thread<T>(joined: std::thread::Result<Result<T>>) -> Result<T> {
    match joined {
        Ok(result) => result,
        Err(_) => Err(serve_failed("a serve worker panicked")),
    }
}

/// Reads a receive-pack's command section, up to its first flush, before the
/// backend reads any of the body, and refuses one carrying a push certificate.
///
/// `git receive-pack` writes a push certificate into the repository's object
/// store as a blob before any hook runs, so its bytes would stay there with no
/// door having read them, even on a delete-only push. This origin offers no
/// signed push (the advertisement drops the capability), and a request that
/// sends a certificate anyway is refused here. A section this cannot read, a
/// malformed pkt-line, is refused too. A push may name any number of refs
/// (rule 5), so the section is held whatever its size: in memory up to
/// [`ORIGIN_COMMAND_SECTION_MEMORY_BYTES`], then in an unnamed file in
/// `door_root`, as long as each write to it keeps `floor`. `body` is what
/// receive-pack would read, already inflated where the backend would inflate
/// it. Returns the bytes read, which go to the backend ahead of the rest.
fn read_command_section(
    body: &mut (dyn Read + Send),
    door_root: PathBuf,
    floor: Option<Arc<dyn SpillFloor>>,
) -> Result<HeldBytes> {
    let mut section =
        HeldBytes::new(ORIGIN_COMMAND_SECTION_MEMORY_BYTES, Some(door_root)).with_floor(floor);
    // One pkt-line at a time: its four-digit length bounds it at 64 KiB.
    let mut line = Vec::new();
    loop {
        line.clear();
        // A body that ends before its flush goes on as it is: receive-pack's
        // reader dies at that end before any command runs or any certificate
        // is written, and no certificate line here was whole.
        let whole = read_exactly(body, &mut line, 4)?;
        if whole {
            let length = std::str::from_utf8(&line)
                .ok()
                .filter(|_| line.iter().all(u8::is_ascii_hexdigit))
                .and_then(|hex| usize::from_str_radix(hex, 16).ok())
                .ok_or_else(|| push_refused("the push's command section is malformed"))?;
            match length {
                0 => {
                    section.write_all(&line).map_err(Error::Io)?;
                    return Ok(section);
                }
                1..=3 => return Err(push_refused("the push's command section is malformed")),
                _ => {}
            }
            if read_exactly(body, &mut line, length - 4)? {
                // receive-pack's own reading: one trailing newline chomped,
                // and the line's name ends at the NUL before any
                // capabilities.
                let payload = &line[4..];
                let payload = payload.strip_suffix(b"\n").unwrap_or(payload);
                if payload.split(|byte| *byte == 0).next() == Some(b"push-cert".as_slice()) {
                    return Err(push_refused("the origin accepts no push certificate"));
                }
                section.write_all(&line).map_err(Error::Io)?;
                continue;
            }
        }
        section.write_all(&line).map_err(Error::Io)?;
        return Ok(section);
    }
}

/// Whether `git http-backend` would inflate this request's body before
/// receive-pack reads it: for exactly these two encodings, spelled exactly so
/// (http-backend.c, `run_service`). Any other body reaches receive-pack as it
/// came, and is read here as it came.
fn backend_inflates(request: &ServeRequest) -> bool {
    matches!(request.content_encoding.as_deref(), Some("gzip" | "x-gzip"))
}

/// Appends up to `count` bytes of `body` to `into`; whether all of them came.
fn read_exactly(body: &mut (dyn Read + Send), into: &mut Vec<u8>, count: usize) -> Result<bool> {
    let want = into.len() + count;
    (&mut *body)
        .take(count as u64)
        .read_to_end(into)
        .map_err(Error::Io)?;
    Ok(into.len() == want)
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
