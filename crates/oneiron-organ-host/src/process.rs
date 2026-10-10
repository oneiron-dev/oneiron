//! One live organ process: spawn, handshake, a reader thread, calls.
//!
//! Every wait is bounded by a deadline: the handshake as a whole, each send
//! (a peer that stops reading cannot hold a writer), and each reply. Ending
//! a process never needs the socket: the host kills the organ's process
//! group, shuts its socket down so the reader thread wakes, and reaps it.

use std::collections::{HashMap, HashSet};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, TryLockError};
use std::thread;
use std::time::{Duration, Instant};

use oneiron_organ_protocol::{
    Call, CancelReason, DEFAULT_FRAME_LIMIT, FrameError, FromOrgan, Hello, HelloAck, Limits,
    PROTOCOL, Reply, ToOrgan, recv_frame, recv_frame_until, send_frame_until, spin,
};

use crate::error::HostError;
use crate::sandbox;
use crate::spec::{HostConfig, OrganSpec};

type Delivery = Option<(Reply, Vec<OwnedFd>)>;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Waits for `mutex` until `deadline`, so a stuck holder cannot hold a
/// caller past its own deadline.
fn lock_until<T>(mutex: &Mutex<T>, deadline: Instant) -> Option<MutexGuard<'_, T>> {
    let mut pause = Duration::from_micros(20);
    loop {
        match mutex.try_lock() {
            Ok(guard) => return Some(guard),
            Err(TryLockError::Poisoned(poisoned)) => return Some(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => {}
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        thread::sleep(pause.min(left));
        pause = (pause * 2).min(Duration::from_millis(2));
    }
}

/// What the reader thread shares with callers.
#[derive(Debug, Default)]
struct Inbox {
    alive: AtomicBool,
    pending: Mutex<HashMap<u64, SyncSender<Delivery>>>,
}

impl Inbox {
    fn close(&self) {
        self.alive.store(false, Ordering::SeqCst);
        for (_, waiter) in lock(&self.pending).drain() {
            let _ = waiter.try_send(None);
        }
    }
}

/// The child and the way to end it, shared with the reader thread so
/// either side can end and reap it.
#[derive(Debug)]
struct Lifeline {
    pid: u32,
    child: Mutex<Option<Child>>,
    /// Set once `end` has reaped the child; read without waiting for an
    /// `end` in progress.
    reaped: AtomicBool,
    /// A handle on the host's end of the socket, kept to shut it down.
    socket: UnixStream,
}

impl Lifeline {
    /// Kills the organ and everything in its process group, shuts the
    /// socket down and reaps the child. Safe to call twice.
    fn end(&self) {
        let _ = self.socket.shutdown(Shutdown::Both);
        // Held through the reap, so whoever calls second returns only once
        // the process is gone.
        let mut slot = lock(&self.child);
        let Some(child) = slot.as_mut() else {
            return;
        };
        if let Ok(group) = i32::try_from(self.pid) {
            // SAFETY: kill(2) with a negative pid signals the process group
            // the organ leads (the sandbox's setpgid). Only this call reaps
            // the child (`exited` looks without reaping), so its pid, and
            // with it the group id, cannot have been reused.
            unsafe {
                libc::kill(-group, libc::SIGKILL);
            }
        }
        let _ = child.kill();
        let _ = child.wait();
        *slot = None;
        self.reaped.store(true, Ordering::SeqCst);
    }

    /// Whether the organ has exited. It looks without reaping: a reaped
    /// pid could be reused before `end` signals its group.
    fn exited(&self) -> bool {
        let child = lock(&self.child);
        if child.is_none() {
            return true;
        }
        // SAFETY: an all-zero siginfo_t is a valid value of this plain C
        // struct; waitid(2) only writes into it.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: as above; WNOWAIT leaves the child waitable for `end`.
        let found = unsafe {
            libc::waitid(
                libc::P_PID,
                self.pid,
                &raw mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        // With WNOHANG, a child still running leaves si_pid zero.
        // SAFETY: waitid filled `info` (or left it zeroed).
        found == 0 && unsafe { info.si_pid() } != 0
    }

    /// Whether `end` has run: the process and its group are gone.
    fn ended(&self) -> bool {
        lock(&self.child).is_none()
    }
}

/// Calls in flight on one process, at most one per worker thread, so the
/// descriptors queued in the organ stay inside its open-file limit.
#[derive(Debug)]
struct Seats {
    taken: Mutex<u32>,
    freed: Condvar,
    cap: u32,
}

/// Ends a just-spawned child unless the start completes.
struct EndOnDrop(Option<Arc<Lifeline>>);

impl Drop for EndOnDrop {
    fn drop(&mut self) {
        if let Some(lifeline) = self.0.take() {
            lifeline.end();
        }
    }
}

/// Why a call to a live process did not come back.
#[derive(Debug)]
pub(crate) enum CallFailure {
    /// The process died or broke the protocol.
    Crashed,
    /// The deadline passed. `stopped` says whether the process was killed;
    /// if it answered the cancel in time it lives on.
    Deadline {
        stopped: bool,
    },
    /// The call's grant was withdrawn before it was sent.
    Revoked,
    /// Every seat on the process stayed taken until the deadline.
    Busy,
    /// The call was refused before any byte left (too large to send); the
    /// process saw nothing and is unharmed.
    Refused(HostError),
    Frame(HostError),
}

#[derive(Debug)]
pub(crate) struct OrganProcess {
    pub(crate) pid: u32,
    pub(crate) hello: HelloAck,
    pub(crate) spawn_time: Duration,
    pub(crate) net_isolated: bool,
    max_call_frame: u32,
    lifeline: Arc<Lifeline>,
    writer: Mutex<UnixStream>,
    inbox: Arc<Inbox>,
    stopped_by_host: AtomicBool,
    next_id: AtomicU64,
    seats: Seats,
    last_used: Mutex<Instant>,
    grants: Mutex<HashSet<String>>,
}

impl OrganProcess {
    /// Starts the organ confined and completes the handshake by `deadline`
    /// (the handshake timeout, or the caller's deadline if sooner). A start
    /// cut short by the caller's deadline is the caller's
    /// [`HostError::DeadlineExceeded`], never the organ's failure.
    /// `on_end` runs on the reader thread once the process has been ended
    /// and reaped, however it ended.
    pub(crate) fn spawn(
        spec: &OrganSpec,
        config: &HostConfig,
        deadline: Option<Instant>,
        on_end: impl FnOnce() + Send + 'static,
    ) -> Result<Arc<Self>, HostError> {
        let started = Instant::now();
        if deadline.is_some_and(|deadline| deadline <= started) {
            return Err(HostError::DeadlineExceeded);
        }
        let own = started + config.handshake_timeout;
        let handshake_by = deadline.map_or(own, |deadline| deadline.min(own));
        let (ours, theirs) = UnixStream::pair()?;
        let reader = ours.try_clone()?;
        let shutdown = ours.try_clone()?;
        let mut command = Command::new(&spec.program);
        command.args(&spec.args);
        sandbox::confine(&mut command, theirs.as_raw_fd(), spec);
        let child = command.spawn()?;
        drop(theirs);
        let pid = child.id();
        let lifeline = Arc::new(Lifeline {
            pid,
            child: Mutex::new(Some(child)),
            reaped: AtomicBool::new(false),
            socket: shutdown,
        });
        let mut guard = EndOnDrop(Some(Arc::clone(&lifeline)));
        let hello = handshake(&ours, spec, config, handshake_by, handshake_by < own)?;
        let inbox = Arc::new(Inbox::default());
        inbox.alive.store(true, Ordering::SeqCst);
        let reader_inbox = Arc::clone(&inbox);
        let reader_lifeline = Arc::clone(&lifeline);
        let limit = spec.max_reply_frame;
        thread::Builder::new()
            .name(format!("organ-{}", spec.name))
            .spawn(move || {
                read_replies(&reader, &reader_inbox, &reader_lifeline, limit);
                on_end();
            })?;
        guard.0 = None;
        Ok(Arc::new(Self {
            pid,
            hello,
            spawn_time: started.elapsed(),
            net_isolated: sandbox::net_isolated(pid),
            max_call_frame: spec.max_call_frame,
            lifeline,
            writer: Mutex::new(ours),
            inbox,
            stopped_by_host: AtomicBool::new(false),
            next_id: AtomicU64::new(1),
            seats: Seats {
                taken: Mutex::new(0),
                freed: Condvar::new(),
                cap: u32::from(spec.threads.max(1)),
            },
            last_used: Mutex::new(Instant::now()),
            grants: Mutex::new(HashSet::new()),
        }))
    }

    pub(crate) fn is_alive(&self) -> bool {
        self.inbox.alive.load(Ordering::SeqCst)
    }

    /// Whether the process may still run, even with its socket closed: only
    /// `end` makes this false. Waits for an `end` in progress.
    pub(crate) fn is_running(&self) -> bool {
        !self.lifeline.ended()
    }

    /// Whether `end` has finished, without waiting: a process being ended
    /// still counts as running here.
    pub(crate) fn has_ended(&self) -> bool {
        self.lifeline.reaped.load(Ordering::SeqCst)
    }

    /// How long the process has had no call in flight; `None` while busy.
    pub(crate) fn idle_for(&self) -> Option<Duration> {
        (*lock(&self.seats.taken) == 0).then(|| lock(&self.last_used).elapsed())
    }

    /// Waits for a free seat until `deadline`.
    fn take_seat(&self, deadline: Instant) -> Result<(), CallFailure> {
        let mut taken = lock(&self.seats.taken);
        while *taken >= self.seats.cap {
            if !self.is_alive() {
                return Err(CallFailure::Crashed);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(CallFailure::Busy);
            }
            taken = self
                .seats
                .freed
                .wait_timeout(taken, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        *taken += 1;
        Ok(())
    }

    fn free_seat(&self) {
        let mut taken = lock(&self.seats.taken);
        *taken = taken.saturating_sub(1);
        self.seats.freed.notify_one();
    }

    pub(crate) fn holds_grant(&self, grant: &str) -> bool {
        lock(&self.grants).contains(grant)
    }

    /// Sends one call and waits for its reply until `deadline`; then cancels,
    /// waits `grace`, and kills the process if it still has not answered.
    ///
    /// The process is marked as holding `grant` before `revoked` is asked,
    /// and a revocation records itself before it looks for holders, so one
    /// of the two always sees the other.
    pub(crate) fn call(
        &self,
        mut call: Call,
        fds: &[BorrowedFd<'_>],
        grant: &str,
        revoked: &dyn Fn() -> bool,
        deadline: Instant,
        grace: Duration,
    ) -> Result<(Reply, Vec<OwnedFd>), CallFailure> {
        self.take_seat(deadline)?;
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        call.id = id;
        let (waiter, reply) = mpsc::sync_channel(1);
        lock(&self.inbox.pending).insert(id, waiter);
        lock(&self.grants).insert(grant.to_owned());
        let outcome = if revoked() {
            Err(CallFailure::Revoked)
        } else {
            self.exchange(call, fds, &reply, deadline, grace)
        };
        lock(&self.inbox.pending).remove(&id);
        *lock(&self.last_used) = Instant::now();
        self.free_seat();
        outcome
    }

    /// Sends one frame, the writer's lock and the frame both bounded by
    /// `deadline`. A deadline that passes while another frame holds the
    /// writer is [`FrameError::Late`]: this frame sent nothing.
    fn send(
        &self,
        msg: &ToOrgan,
        fds: &[BorrowedFd<'_>],
        limit: u32,
        deadline: Instant,
    ) -> Result<(), FrameError> {
        let writer = lock_until(&self.writer, deadline).ok_or(FrameError::Late)?;
        send_frame_until(&writer, msg, fds, limit, Some(deadline))
    }

    fn exchange(
        &self,
        call: Call,
        fds: &[BorrowedFd<'_>],
        reply: &mpsc::Receiver<Delivery>,
        deadline: Instant,
        grace: Duration,
    ) -> Result<(Reply, Vec<OwnedFd>), CallFailure> {
        if !self.is_alive() {
            return Err(CallFailure::Crashed);
        }
        let id = call.id;
        match self.send(&ToOrgan::Call(call), fds, self.max_call_frame, deadline) {
            Ok(()) => {}
            // Nothing left: the organ is in step and keeps its other calls.
            Err(FrameError::Late) => return Err(CallFailure::Deadline { stopped: false }),
            Err(err) if err.is_local() => return Err(CallFailure::Refused(err.into())),
            Err(FrameError::TimedOut) => {
                // A half-sent frame leaves the stream out of step.
                self.stop();
                return Err(CallFailure::Deadline { stopped: true });
            }
            Err(err) => {
                self.kill();
                return Err(CallFailure::Frame(err.into()));
            }
        }
        match spin::recv_spinning(reply, Some(deadline)) {
            Ok(Some(delivery)) => return Ok(delivery),
            Ok(None) | Err(RecvTimeoutError::Disconnected) => return Err(CallFailure::Crashed),
            Err(RecvTimeoutError::Timeout) => {}
        }
        self.cancel(id, CancelReason::Deadline, Instant::now() + grace);
        if matches!(reply.recv_timeout(grace), Ok(Some(_))) {
            Err(CallFailure::Deadline { stopped: false })
        } else {
            self.stop();
            Err(CallFailure::Deadline { stopped: true })
        }
    }

    /// Cancels one call. An organ that cannot take the cancel by `deadline`
    /// is not reading: it is stopped.
    pub(crate) fn cancel(&self, id: u64, reason: CancelReason, deadline: Instant) {
        let cancel = ToOrgan::Cancel { id, reason };
        if self
            .send(&cancel, &[], DEFAULT_FRAME_LIMIT, deadline)
            .is_err()
        {
            self.stop();
        }
    }

    /// Cancels every call in flight, as a revoked grant does.
    pub(crate) fn cancel_all(&self, reason: CancelReason, deadline: Instant) {
        let ids: Vec<u64> = lock(&self.inbox.pending).keys().copied().collect();
        for id in ids {
            self.cancel(id, reason, deadline);
        }
    }

    /// Asks the organ to exit, then kills it after `grace`.
    pub(crate) fn shutdown(&self, grace: Duration) {
        self.stopped_by_host.store(true, Ordering::SeqCst);
        let until = Instant::now() + grace;
        if self
            .send(&ToOrgan::Shutdown, &[], DEFAULT_FRAME_LIMIT, until)
            .is_ok()
        {
            while Instant::now() < until && !self.lifeline.exited() {
                thread::sleep(Duration::from_millis(5));
            }
        }
        self.stop();
    }

    /// Kills the process on the host's own decision (deadline, revoke,
    /// unload), so its death is not counted as a crash.
    pub(crate) fn stop(&self) {
        self.stopped_by_host.store(true, Ordering::SeqCst);
        self.kill();
    }

    pub(crate) fn stopped_by_host(&self) -> bool {
        self.stopped_by_host.load(Ordering::SeqCst)
    }

    /// Kills the process group now. The kernel drops every region they had
    /// mapped.
    pub(crate) fn kill(&self) {
        self.lifeline.end();
        self.inbox.close();
        self.seats.freed.notify_all();
    }
}

impl Drop for OrganProcess {
    fn drop(&mut self) {
        self.kill();
    }
}

fn handshake(
    stream: &UnixStream,
    spec: &OrganSpec,
    config: &HostConfig,
    deadline: Instant,
    caller_cut: bool,
) -> Result<HelloAck, HostError> {
    let hello = ToOrgan::Hello(Hello {
        protocol: PROTOCOL,
        engine: config.engine_version.clone(),
        organ: spec.name.clone(),
        limits: Limits {
            threads: spec.threads,
            memory_bytes: spec.memory_bytes,
            max_call_frame: spec.max_call_frame,
            max_reply_frame: spec.max_reply_frame,
        },
    });
    // An organ that dies or stalls before answering failed to start, which
    // counts as a crash; one that answers wrongly is incompatible. A stall
    // the caller's deadline cut short is only the caller's.
    let start_failed = |err: FrameError| match err {
        FrameError::TimedOut | FrameError::Late if caller_cut => HostError::DeadlineExceeded,
        FrameError::Closed | FrameError::TimedOut | FrameError::Late | FrameError::Io(_) => {
            HostError::StartFailed {
                organ: spec.name.clone(),
                reason: err.to_string(),
            }
        }
        other => HostError::Handshake(format!("no hello_ack: {other}")),
    };
    send_frame_until(stream, &hello, &[], DEFAULT_FRAME_LIMIT, Some(deadline))
        .map_err(start_failed)?;
    let (ack, _) = recv_frame_until::<FromOrgan>(stream, DEFAULT_FRAME_LIMIT, Some(deadline))
        .map_err(start_failed)?;
    let FromOrgan::HelloAck(ack) = ack else {
        return Err(HostError::Handshake(
            "the first reply was not hello_ack".into(),
        ));
    };
    check_handshake(spec, &ack)?;
    Ok(ack)
}

fn check_handshake(spec: &OrganSpec, ack: &HelloAck) -> Result<(), HostError> {
    if ack.protocol.major != PROTOCOL.major {
        return Err(HostError::Handshake(format!(
            "protocol {}.{}; the engine speaks {}.x",
            ack.protocol.major, ack.protocol.minor, PROTOCOL.major
        )));
    }
    if ack.organ.name != spec.name {
        return Err(HostError::Handshake(format!(
            "the binary says it is {}, installed as {}",
            ack.organ.name, spec.name
        )));
    }
    if let Some(pin) = &spec.version_pin
        && &ack.organ.version != pin
    {
        return Err(HostError::Handshake(format!(
            "organ version {} is outside the pin {pin}",
            ack.organ.version
        )));
    }
    if let Some(missing) = spec
        .verbs
        .iter()
        .find(|verb| !ack.verbs.iter().any(|offered| &offered.name == *verb))
    {
        return Err(HostError::Handshake(format!(
            "the organ does not offer {missing}"
        )));
    }
    Ok(())
}

/// Delivers replies until the organ closes, breaks a frame, or sends a
/// second `hello_ack`; then fails every waiting call and ends the process,
/// so an organ that exits while idle is reaped at once.
fn read_replies(stream: &UnixStream, inbox: &Inbox, lifeline: &Lifeline, limit: u32) {
    loop {
        spin::poll_readable(stream);
        let Ok((FromOrgan::Reply(reply), fds)) = recv_frame::<FromOrgan>(stream, limit) else {
            break;
        };
        let waiter = lock(&inbox.pending).remove(&reply.id);
        // A reply nobody waits for came after its deadline: drop it.
        if let Some(waiter) = waiter {
            let _ = waiter.try_send(Some((reply, fds)));
        }
    }
    inbox.close();
    lifeline.end();
}
