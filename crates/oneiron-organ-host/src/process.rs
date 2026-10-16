//! One live organ process: spawn, handshake, a reader thread, calls.
//!
//! Every wait is bounded by a deadline: the handshake as a whole, each send
//! (a peer that stops reading cannot hold a writer), and each reply. Ending
//! a process never needs the socket: the host kills the organ's process
//! group, shuts its socket down so the reader thread wakes, and reaps it.
//!
//! On a 1.1 session the organ may ask inside a call. The reader thread hands
//! each ask to the thread waiting on that call, which answers it there and
//! keeps waiting. One ask is in flight per call: a second one, or more asks
//! for calls not in flight than calls the host cancelled, breaks the
//! protocol and ends the process.

use std::collections::{HashMap, HashSet};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::process::Child;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::sync::{
    Arc, Condvar, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, TryLockError,
};
use std::thread;
use std::time::{Duration, Instant};

use oneiron_organ_protocol::{
    Ask, Call, CancelReason, DEFAULT_FRAME_LIMIT, FrameError, FromOrgan, Hash32, Hello, HelloAck,
    Limits, PROTOCOL, ProtocolVersion, Reply, ToOrgan, recv_frame_polled, recv_frame_until,
    send_frame_if, send_frame_until, spin,
};

use crate::asks::{AskStep, CallAsks};
use crate::error::HostError;
use crate::sandbox;
use crate::spec::{HostConfig, OrganSpec};

/// What the reader thread hands a waiting call.
#[derive(Debug)]
enum Delivery {
    Reply(Reply, Vec<OwnedFd>),
    Ask(Ask),
    /// The process ended.
    Closed,
}

/// A call in flight, as the reader thread sees it.
#[derive(Debug)]
struct Pending {
    deliver: SyncSender<Delivery>,
    /// An ask of this call waits for its answer.
    asking: bool,
    /// A revocation is cancelling the call: no answer of it starts now.
    revoked: bool,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Waits for `mutex` until `deadline`, so a stuck holder cannot hold a
/// caller past its own deadline; `None` then, or as soon as `give_up` says
/// the wait is for nothing.
fn lock_until<T>(
    mutex: &Mutex<T>,
    deadline: Instant,
    give_up: impl Fn() -> bool,
) -> Option<MutexGuard<'_, T>> {
    let mut pause = Duration::from_micros(20);
    loop {
        match mutex.try_lock() {
            Ok(guard) => return Some(guard),
            Err(TryLockError::Poisoned(poisoned)) => return Some(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => {}
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || give_up() {
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
    pending: Mutex<HashMap<u64, Pending>>,
    /// The session speaks 1.1 or later, so the organ may ask.
    asks: bool,
    /// Calls the host cancelled on this process: an ask of each may cross
    /// the cancel honestly.
    cancels: AtomicU64,
    /// Asks that came for calls not in flight.
    stale_asks: AtomicU64,
}

impl Inbox {
    fn close(&self) {
        self.alive.store(false, Ordering::SeqCst);
        for (_, pending) in lock(&self.pending).drain() {
            let _ = pending.deliver.try_send(Delivery::Closed);
        }
    }

    /// Hands an ask to the call it names. `false` when the ask breaks the
    /// protocol: a second one in flight for its call, or more stale asks
    /// than cancelled calls.
    fn route_ask(&self, ask: Ask) -> bool {
        let mut pending = lock(&self.pending);
        let Some(call) = pending.get_mut(&ask.call) else {
            drop(pending);
            let stale = self.stale_asks.fetch_add(1, Ordering::SeqCst) + 1;
            return stale <= self.cancels.load(Ordering::SeqCst);
        };
        if call.asking {
            return false;
        }
        call.asking = true;
        call.deliver.try_send(Delivery::Ask(ask)).is_ok()
    }

    /// Whether call `id` still waits for its reply: the reader takes its
    /// entry when the reply comes or the process ends.
    fn in_flight(&self, id: u64) -> bool {
        lock(&self.pending).contains_key(&id)
    }

    /// Holds the calls in flight while call `id` is one of them and no
    /// revocation has marked it: no reply or ask is routed, and no
    /// revocation marks it, until the guard drops.
    fn holding_answerable(&self, id: u64) -> Option<MutexGuard<'_, HashMap<u64, Pending>>> {
        let pending = lock(&self.pending);
        pending
            .get(&id)
            .is_some_and(|call| !call.revoked)
            .then_some(pending)
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
    /// socket down and reaps the child. Safe to call twice; once the reap is
    /// done it returns without waiting, so dropping an ended process never
    /// waits on the thread that reaped it.
    fn end(&self) {
        if self.reaped.load(Ordering::SeqCst) {
            return;
        }
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

/// Ends a call's hold on its process however its wait ends, a panic
/// included. A call a panic left in flight is cancelled, so the organ's ask
/// wakes rather than holding one of its threads. (A panic in an ask's
/// handler is the watchdog's: it cancels the call itself.)
struct Seated<'p> {
    process: &'p OrganProcess,
    id: u64,
    grace: Duration,
}

impl Drop for Seated<'_> {
    fn drop(&mut self) {
        // Cancelled before the entry goes, so an ask crossing the cancel
        // is excused rather than read as stale.
        let in_flight = lock(&self.process.inbox.pending).contains_key(&self.id);
        if in_flight && thread::panicking() {
            let until = Instant::now() + self.grace;
            self.process.cancel(self.id, CancelReason::Caller, until);
        }
        lock(&self.process.inbox.pending).remove(&self.id);
        *lock(&self.process.last_used) = Instant::now();
        self.process.free_seat();
    }
}

/// What a call's deadline did while an ask's handler ran.
enum Overrun {
    /// The handler returned before the deadline.
    InTime,
    /// The deadline passed after the reader had taken the call's entry, for
    /// its reply or as the process ended: nothing was cancelled.
    Ended,
    /// The deadline passed and the call was cancelled; within the grace
    /// the reader took the call's entry, for its reply or as the process
    /// ended.
    Cancelled,
    /// The organ did not reply within the grace, or ended: it was stopped.
    Stopped,
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
    /// The host ended the call itself, as for an organ asking past its caps.
    Ended(HostError),
}

/// The call grants a host has withdrawn. A revocation is recorded by a
/// write, and an answer's first byte goes under a read
/// ([`Grant::holding_unrevoked`]), so each revocation comes either before
/// the answer's check or after that byte.
#[derive(Debug, Default)]
pub(crate) struct Revocations(RwLock<HashSet<String>>);

impl Revocations {
    pub(crate) fn record(&self, grant: &str) {
        self.0
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(grant.to_owned());
    }

    pub(crate) fn contains(&self, grant: &str) -> bool {
        self.read().contains(grant)
    }

    fn read(&self) -> Unrevoked<'_> {
        self.0.read().unwrap_or_else(PoisonError::into_inner)
    }
}

type Unrevoked<'a> = RwLockReadGuard<'a, HashSet<String>>;

/// A call's grant, as the host's revocations see it.
#[derive(Clone, Copy)]
pub(crate) struct Grant<'a> {
    pub(crate) name: &'a str,
    pub(crate) revocations: &'a Revocations,
}

impl<'a> Grant<'a> {
    fn revoked(self) -> bool {
        self.revocations.contains(self.name)
    }

    /// A read of the revocations while this grant is not among them: none
    /// is recorded until it drops.
    fn holding_unrevoked(self) -> Option<Unrevoked<'a>> {
        let revoked = self.revocations.read();
        (!revoked.contains(self.name)).then_some(revoked)
    }
}

/// How a call waits for its reply: until `deadline`, answering asks
/// through `asks`, then `grace` for a cancel to take.
pub(crate) struct Wait<'a, 'b> {
    pub(crate) grant: Grant<'a>,
    pub(crate) asks: &'a mut CallAsks<'b>,
    pub(crate) deadline: Instant,
    pub(crate) grace: Duration,
}

/// Waits `grace` for a cancelled call's reply. Its asks are not run, only
/// receipted: their waits end with the cancel. `true` if the reply came.
fn wait_reply(reply: &mpsc::Receiver<Delivery>, grace: Duration, asks: &mut CallAsks<'_>) -> bool {
    let until = Instant::now() + grace;
    loop {
        match reply.recv_timeout(until.saturating_duration_since(Instant::now())) {
            Ok(Delivery::Reply(..)) => return true,
            Ok(Delivery::Ask(ask)) => asks.skipped(&ask),
            Ok(Delivery::Closed) | Err(_) => return false,
        }
    }
}

/// The reply of a call whose entry the reader has taken; `None` when the
/// process ended instead. Never waits long: the entry held the only
/// sender, and the reader drops it right after delivering.
fn taken(
    reply: &mpsc::Receiver<Delivery>,
    asks: &mut CallAsks<'_>,
) -> Option<(Reply, Vec<OwnedFd>)> {
    loop {
        match reply.recv() {
            Ok(Delivery::Reply(reply, fds)) => return Some((reply, fds)),
            Ok(Delivery::Ask(ask)) => asks.skipped(&ask),
            Ok(Delivery::Closed) | Err(_) => return None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct OrganProcess {
    pub(crate) pid: u32,
    pub(crate) hello: HelloAck,
    /// The version the session speaks: one major, the lower minor.
    pub(crate) session: ProtocolVersion,
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
        check_program_pin(spec)?;
        let own = started + config.handshake_timeout;
        let handshake_by = deadline.map_or(own, |deadline| deadline.min(own));
        let (ours, theirs) = UnixStream::pair()?;
        // Nonblocking for its whole life, and so for its clones: a timed
        // send needs it (macOS ignores MSG_DONTWAIT while a send waits for
        // room), and the reader waits in poll(2) instead.
        ours.set_nonblocking(true)?;
        let reader = ours.try_clone()?;
        let shutdown = ours.try_clone()?;
        let mut command =
            oneiron_spawn::command_with_fds(&spec.program, &[(theirs.as_raw_fd(), 3)]);
        command.args(&spec.args);
        sandbox::confine(&mut command, spec);
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
        let session = PROTOCOL.session(hello.protocol).unwrap_or(hello.protocol);
        let inbox = Arc::new(Inbox {
            asks: session.asks(),
            ..Inbox::default()
        });
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
            session,
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

    /// Whether the organ has exited, whether or not the reader has seen
    /// its socket close yet. It looks without reaping.
    pub(crate) fn exited(&self) -> bool {
        self.lifeline.exited()
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

    /// Sends one call and waits for its reply until `deadline`, answering
    /// the organ's asks through `asks` as they come; then cancels, waits
    /// `grace`, and kills the process if it still has not answered.
    ///
    /// The process is marked as holding the call's grant before the grant
    /// is checked, and a revocation records itself before it looks for
    /// holders, so one of the two always sees the other.
    pub(crate) fn call(
        &self,
        mut call: Call,
        fds: &[BorrowedFd<'_>],
        wait: Wait<'_, '_>,
    ) -> Result<(Reply, Vec<OwnedFd>), CallFailure> {
        self.take_seat(wait.deadline)?;
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        call.id = id;
        // Room for the one ask in flight and the reply behind it.
        let (deliver, reply) = mpsc::sync_channel(2);
        let pending = Pending {
            deliver,
            asking: false,
            revoked: false,
        };
        lock(&self.inbox.pending).insert(id, pending);
        let _seated = Seated {
            process: self,
            id,
            grace: wait.grace,
        };
        let Wait {
            grant,
            asks,
            deadline,
            grace,
        } = wait;
        lock(&self.grants).insert(grant.name.to_owned());
        let result = if grant.revoked() {
            Err(CallFailure::Revoked)
        } else {
            let wait = Wait {
                grant,
                asks: &mut *asks,
                deadline,
                grace,
            };
            self.exchange(call, fds, &reply, wait)
        };
        self.settle(id, &reply, asks);
        result
    }

    /// Ends call `id`'s deliveries, however it ended. Once its entry is gone
    /// the reader can route it no ask (it sends an ask only under the lock
    /// that holds the entry), so every ask still queued is receipted here,
    /// not run.
    fn settle(&self, id: u64, reply: &mpsc::Receiver<Delivery>, asks: &mut CallAsks<'_>) {
        lock(&self.inbox.pending).remove(&id);
        while let Ok(delivery) = reply.try_recv() {
            if let Delivery::Ask(ask) = delivery {
                asks.skipped(&ask);
            }
        }
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
        let writer = lock_until(&self.writer, deadline, || false).ok_or(FrameError::Late)?;
        send_frame_until(&writer, msg, fds, limit, Some(deadline))
    }

    /// Sends the answer to call `id`'s ask; `false` when it is dropped
    /// instead.
    ///
    /// Once it holds the writer, it drops the answer if the call's grant was
    /// revoked or the call is no longer in flight. A revocation records
    /// itself before its cancel takes the writer, so an answer that waited
    /// for the writer never follows its call's revoked cancel. Either one,
    /// while the answer still waits for the writer or at its deadline, drops
    /// it there, so a call that has replied takes its reply, not a deadline.
    /// The answer's first byte goes under the lock the reader routes replies
    /// and asks under and `cancel_all` marks calls under, with the call
    /// checked in flight and unmarked again, and under a read of the host's
    /// revocations, with its grant checked unrevoked again. So an answer
    /// never goes after the reply the reader has taken, nor once its call is
    /// marked or its grant's revocation is recorded; one that waits for room
    /// meanwhile is dropped when any of them comes. (A reply the organ sends
    /// once the answer has started crosses it, as an ask crosses a cancel.)
    ///
    /// The call may ask again from the moment that first byte leaves, not
    /// when the write returns: the organ can read the whole answer and ask
    /// again before this thread sees its write finish, so a check there
    /// would end an organ that kept the rule. An ask that comes before it,
    /// while the answer waits for the writer or for room, still breaks the
    /// protocol.
    fn send_answer(
        &self,
        id: u64,
        answer: &ToOrgan,
        fds: &[BorrowedFd<'_>],
        deadline: Instant,
        grant: Grant<'_>,
    ) -> Result<bool, FrameError> {
        let dropped = || grant.revoked() || self.inbox.holding_answerable(id).is_none();
        let Some(writer) = lock_until(&self.writer, deadline, dropped) else {
            return if dropped() {
                Ok(false)
            } else {
                Err(FrameError::Late)
            };
        };
        if dropped() {
            return Ok(false);
        }
        // The first byte also holds a read of the host's revocations, taken
        // only while the grant is not among them: recording a revocation
        // waits for that byte. (Lock order: the writer, `pending`, the
        // revocations.)
        let still = || {
            let pending = self.inbox.holding_answerable(id)?;
            Some((pending, grant.holding_unrevoked()?))
        };
        let started = |held: &mut (MutexGuard<'_, HashMap<u64, Pending>>, Unrevoked<'_>)| {
            if let Some(call) = held.0.get_mut(&id) {
                call.asking = false;
            }
        };
        let limit = self.max_call_frame;
        match send_frame_if(&writer, answer, fds, limit, deadline, still, started) {
            Ok(()) => Ok(true),
            Err(FrameError::Withdrawn) => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Runs an ask's handler on this thread while a watchdog keeps the
    /// call's deadline (see [`Self::watch`]). `handler` learns whether the
    /// watchdog runs: with none it must refuse the ask without running it,
    /// since nothing would stop the organ at the deadline.
    fn run_handler<T>(
        &self,
        id: u64,
        deadline: Instant,
        grace: Duration,
        handler: impl FnOnce(bool) -> T,
    ) -> (T, Overrun) {
        thread::scope(|scope| {
            let (done, finished) = mpsc::channel::<()>();
            let watchdog = thread::Builder::new()
                .name("organ-ask-deadline".into())
                .spawn_scoped(scope, move || self.watch(id, deadline, grace, &finished));
            let Ok(watchdog) = watchdog else {
                return (handler(false), Overrun::InTime);
            };
            let out = handler(true);
            // A panic drops `done` unsent instead, and the scope waits for
            // the watchdog before the panic goes on.
            let _ = done.send(());
            let overrun = watchdog.join().unwrap_or_else(|_| {
                self.stop();
                Overrun::Stopped
            });
            (out, overrun)
        })
    }

    /// Keeps call `id`'s deadline while one of its ask handlers runs. At
    /// the deadline, or when the handler panics, it cancels the call if it
    /// is still in flight; if the organ has not replied when the grace ends,
    /// it stops the process. It waits out the grace itself, whatever the
    /// handler does meanwhile.
    fn watch(
        &self,
        id: u64,
        deadline: Instant,
        grace: Duration,
        finished: &mpsc::Receiver<()>,
    ) -> Overrun {
        let left = deadline.saturating_duration_since(Instant::now());
        let reason = match finished.recv_timeout(left) {
            Ok(()) => return Overrun::InTime,
            Err(RecvTimeoutError::Timeout) => CancelReason::Deadline,
            // The handler panicked: the call is over for its caller.
            Err(RecvTimeoutError::Disconnected) => CancelReason::Caller,
        };
        // Settled before any cancel: a call the reader has taken has its
        // reply queued (or its process ended), and there is nothing to cancel.
        if !self.inbox.in_flight(id) {
            return Overrun::Ended;
        }
        let until = Instant::now() + grace;
        self.cancel(id, reason, until);
        loop {
            let left = until.saturating_duration_since(Instant::now());
            {
                let mut pending = lock(&self.inbox.pending);
                // The reader takes a call's entry when its reply comes.
                // Taking it here once the grace is over, under the same
                // lock, settles which came first: a reply after it is late.
                if !pending.contains_key(&id) {
                    break;
                }
                if left.is_zero() {
                    pending.remove(&id);
                    drop(pending);
                    self.stop();
                    return Overrun::Stopped;
                }
            }
            thread::sleep(left.min(Duration::from_millis(5)));
        }
        Overrun::Cancelled
    }

    fn exchange(
        &self,
        call: Call,
        fds: &[BorrowedFd<'_>],
        reply: &mpsc::Receiver<Delivery>,
        wait: Wait<'_, '_>,
    ) -> Result<(Reply, Vec<OwnedFd>), CallFailure> {
        let Wait {
            grant,
            asks,
            deadline,
            grace,
        } = wait;
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
        loop {
            match spin::recv_spinning(reply, Some(deadline)) {
                Ok(Delivery::Reply(reply, fds)) => return Ok((reply, fds)),
                Ok(Delivery::Ask(ask)) => {
                    // A revocation is ending the call, or the organ has
                    // already replied (the reader took the call's entry, and
                    // the reply waits behind this ask): run and answer
                    // nothing more. Past the deadline, the call is cancelled.
                    if grant.revoked() || !self.inbox.in_flight(id) {
                        asks.skipped(&ask);
                        continue;
                    }
                    if Instant::now() >= deadline {
                        asks.skipped(&ask);
                        break;
                    }
                    let (step, overrun) =
                        self.run_handler(id, deadline, grace, |watched| asks.take(ask, watched));
                    if !matches!(overrun, Overrun::InTime) {
                        asks.unsent();
                    }
                    match overrun {
                        Overrun::InTime => {}
                        // The settle point below takes the reply.
                        Overrun::Ended => break,
                        // A reply in the grace counts even if the organ then
                        // ended: its end is the reader's to report, as a crash.
                        Overrun::Cancelled if taken(reply, asks).is_some() => {
                            return Err(CallFailure::Deadline { stopped: false });
                        }
                        Overrun::Cancelled | Overrun::Stopped => {
                            self.stop();
                            return Err(CallFailure::Deadline { stopped: true });
                        }
                    }
                    // The organ broke the protocol while the handler ran.
                    if !self.is_alive() {
                        asks.unsent();
                        return Err(CallFailure::Crashed);
                    }
                    if grant.revoked() {
                        asks.unsent();
                        continue;
                    }
                    // An answer after the deadline is dropped.
                    if Instant::now() >= deadline {
                        asks.unsent();
                        break;
                    }
                    match step {
                        AskStep::Answer(answer, region) => {
                            let held: Vec<BorrowedFd<'_>> =
                                region.iter().map(|region| region.fd()).collect();
                            let answer = ToOrgan::Answer(answer);
                            let sent = self.send_answer(id, &answer, &held, deadline, grant);
                            if !matches!(sent, Ok(true)) {
                                asks.unsent();
                            }
                            match sent {
                                Ok(_) => {}
                                Err(FrameError::Late) => break,
                                Err(FrameError::TimedOut) => {
                                    self.stop();
                                    return Err(CallFailure::Deadline { stopped: true });
                                }
                                Err(err) => {
                                    self.kill();
                                    return Err(CallFailure::Frame(err.into()));
                                }
                            }
                        }
                        AskStep::End(err) => {
                            return Err(self.end_call(
                                id,
                                CancelReason::Caller,
                                reply,
                                grace,
                                asks,
                                err,
                            ));
                        }
                    }
                }
                Ok(Delivery::Closed) | Err(RecvTimeoutError::Disconnected) => {
                    return Err(CallFailure::Crashed);
                }
                Err(RecvTimeoutError::Timeout) => break,
            }
        }
        // Past the deadline, by any cutoff above. The call fails on it only
        // while it is still in flight: the reader queues a reply under the
        // lock it takes the call under, so a call it has taken has its reply
        // waiting, and that reply stands.
        if !self.inbox.in_flight(id) {
            return taken(reply, asks).ok_or(CallFailure::Crashed);
        }
        self.cancel(id, CancelReason::Deadline, Instant::now() + grace);
        if wait_reply(reply, grace, asks) {
            Err(CallFailure::Deadline { stopped: false })
        } else {
            self.stop();
            Err(CallFailure::Deadline { stopped: true })
        }
    }

    /// Cancels a call the host ends itself, waits `grace` for the organ to
    /// stop, and kills it if it does not.
    fn end_call(
        &self,
        id: u64,
        reason: CancelReason,
        reply: &mpsc::Receiver<Delivery>,
        grace: Duration,
        asks: &mut CallAsks<'_>,
        err: HostError,
    ) -> CallFailure {
        self.cancel(id, reason, Instant::now() + grace);
        if !wait_reply(reply, grace, asks) {
            self.stop();
        }
        CallFailure::Ended(err)
    }

    /// Cancels one call. An organ that cannot take the cancel by `deadline`
    /// is not reading: it is stopped.
    pub(crate) fn cancel(&self, id: u64, reason: CancelReason, deadline: Instant) {
        // Counted first: an ask that crosses this cancel is then excused.
        self.inbox.cancels.fetch_add(1, Ordering::SeqCst);
        let cancel = ToOrgan::Cancel { id, reason };
        if self
            .send(&cancel, &[], DEFAULT_FRAME_LIMIT, deadline)
            .is_err()
        {
            self.stop();
        }
    }

    /// Cancels every call in flight, as a revoked grant does. Each is first
    /// marked revoked under the lock an answer's first byte goes under, so
    /// an answer that has not started by then never does.
    pub(crate) fn cancel_all(&self, reason: CancelReason, deadline: Instant) {
        let ids: Vec<u64> = lock(&self.inbox.pending)
            .iter_mut()
            .map(|(id, call)| {
                call.revoked = true;
                *id
            })
            .collect();
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
        match recv_frame_polled::<FromOrgan>(stream, limit) {
            Ok((FromOrgan::Reply(reply), fds)) => {
                // Queued under the lock the call is taken under, so a call
                // taken for its reply already has the reply waiting.
                let mut pending = lock(&inbox.pending);
                // A reply nobody waits for came after its deadline: drop it.
                if let Some(waiter) = pending.remove(&reply.id) {
                    let _ = waiter.deliver.try_send(Delivery::Reply(reply, fds));
                }
            }
            Ok((FromOrgan::Ask(ask), _)) if inbox.asks => {
                if !inbox.route_ask(ask) {
                    break;
                }
            }
            // An ask on a 1.0 session, a second hello_ack, a broken frame.
            _ => break,
        }
    }
    inbox.close();
    lifeline.end();
}

/// Refuses a program file that is not the one the install pinned.
fn check_program_pin(spec: &OrganSpec) -> Result<(), HostError> {
    let Some(pinned) = spec.program_hash else {
        return Ok(());
    };
    let mut hasher = blake3::Hasher::new();
    hasher.update_reader(std::fs::File::open(&spec.program)?)?;
    let found = Hash32(*hasher.finalize().as_bytes());
    if found != pinned {
        return Err(HostError::Handshake(format!(
            "the program file is not the pinned binary {pinned:?}"
        )));
    }
    Ok(())
}
