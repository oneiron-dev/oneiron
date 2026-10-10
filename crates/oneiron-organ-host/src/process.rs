//! One live organ process: spawn, handshake, a reader thread, calls.

use std::collections::{HashMap, HashSet};
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use oneiron_organ_protocol::{
    Call, CancelReason, DEFAULT_FRAME_LIMIT, FromOrgan, Hello, HelloAck, Limits, PROTOCOL, Reply,
    ToOrgan, recv_frame, send_frame,
};

use crate::error::HostError;
use crate::sandbox;
use crate::spec::{HostConfig, OrganSpec};

type Delivery = Option<(Reply, Vec<OwnedFd>)>;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
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

/// Why a call to a live process did not come back.
#[derive(Debug)]
pub(crate) enum CallFailure {
    /// The process died or broke the protocol.
    Crashed,
    /// The deadline and the cancel grace both passed; the process was killed.
    Deadline,
    Frame(HostError),
}

#[derive(Debug)]
pub(crate) struct OrganProcess {
    pub(crate) pid: u32,
    pub(crate) hello: HelloAck,
    pub(crate) spawn_time: Duration,
    pub(crate) net_isolated: bool,
    max_call_frame: u32,
    child: Mutex<Child>,
    writer: Mutex<UnixStream>,
    inbox: Arc<Inbox>,
    stopped_by_host: AtomicBool,
    next_id: AtomicU64,
    inflight: AtomicU32,
    last_used: Mutex<Instant>,
    grants: Mutex<HashSet<String>>,
}

impl OrganProcess {
    /// Starts the organ confined and completes the handshake.
    pub(crate) fn spawn(spec: &OrganSpec, config: &HostConfig) -> Result<Arc<Self>, HostError> {
        let started = Instant::now();
        let (ours, theirs) = UnixStream::pair()?;
        let mut command = Command::new(&spec.program);
        command.args(&spec.args);
        sandbox::confine(&mut command, theirs.as_raw_fd(), spec);
        let mut child = command.spawn()?;
        drop(theirs);
        let hello = match handshake(&ours, spec, config) {
            Ok(hello) => hello,
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(err);
            }
        };
        let pid = child.id();
        let inbox = Arc::new(Inbox::default());
        inbox.alive.store(true, Ordering::SeqCst);
        let reader = ours.try_clone()?;
        let reader_inbox = Arc::clone(&inbox);
        let limit = spec.max_reply_frame;
        thread::Builder::new()
            .name(format!("organ-{}", spec.name))
            .spawn(move || read_replies(&reader, &reader_inbox, limit))?;
        Ok(Arc::new(Self {
            pid,
            hello,
            spawn_time: started.elapsed(),
            net_isolated: sandbox::net_isolated(pid),
            max_call_frame: spec.max_call_frame,
            child: Mutex::new(child),
            writer: Mutex::new(ours),
            inbox,
            stopped_by_host: AtomicBool::new(false),
            next_id: AtomicU64::new(1),
            inflight: AtomicU32::new(0),
            last_used: Mutex::new(Instant::now()),
            grants: Mutex::new(HashSet::new()),
        }))
    }

    pub(crate) fn is_alive(&self) -> bool {
        self.inbox.alive.load(Ordering::SeqCst)
    }

    /// How long the process has had no call in flight; `None` while busy.
    pub(crate) fn idle_for(&self) -> Option<Duration> {
        (self.inflight.load(Ordering::SeqCst) == 0).then(|| lock(&self.last_used).elapsed())
    }

    pub(crate) fn holds_grant(&self, grant: &str) -> bool {
        lock(&self.grants).contains(grant)
    }

    /// Sends one call and waits for its reply until `deadline`; then cancels,
    /// waits `grace`, and kills the process if it still has not answered.
    pub(crate) fn call(
        &self,
        mut call: Call,
        fds: &[BorrowedFd<'_>],
        grant: &str,
        deadline: Duration,
        grace: Duration,
    ) -> Result<(Reply, Vec<OwnedFd>), CallFailure> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        call.id = id;
        let (waiter, reply) = mpsc::sync_channel(1);
        lock(&self.inbox.pending).insert(id, waiter);
        lock(&self.grants).insert(grant.to_owned());
        self.inflight.fetch_add(1, Ordering::SeqCst);
        let outcome = self.exchange(call, fds, &reply, deadline, grace);
        lock(&self.inbox.pending).remove(&id);
        *lock(&self.last_used) = Instant::now();
        self.inflight.fetch_sub(1, Ordering::SeqCst);
        outcome
    }

    fn exchange(
        &self,
        call: Call,
        fds: &[BorrowedFd<'_>],
        reply: &mpsc::Receiver<Delivery>,
        deadline: Duration,
        grace: Duration,
    ) -> Result<(Reply, Vec<OwnedFd>), CallFailure> {
        if !self.is_alive() {
            return Err(CallFailure::Crashed);
        }
        let id = call.id;
        let sent = send_frame(
            &lock(&self.writer),
            &ToOrgan::Call(call),
            fds,
            self.max_call_frame,
        );
        if let Err(err) = sent {
            self.kill();
            return Err(CallFailure::Frame(err.into()));
        }
        match reply.recv_timeout(deadline) {
            Ok(Some(delivery)) => return Ok(delivery),
            Ok(None) | Err(RecvTimeoutError::Disconnected) => return Err(CallFailure::Crashed),
            Err(RecvTimeoutError::Timeout) => {}
        }
        self.cancel(id, CancelReason::Deadline);
        if !matches!(reply.recv_timeout(grace), Ok(Some(_))) {
            self.stop();
        }
        Err(CallFailure::Deadline)
    }

    pub(crate) fn cancel(&self, id: u64, reason: CancelReason) {
        let _ = send_frame(
            &lock(&self.writer),
            &ToOrgan::Cancel { id, reason },
            &[],
            DEFAULT_FRAME_LIMIT,
        );
    }

    /// Cancels every call in flight, as a revoked grant does.
    pub(crate) fn cancel_all(&self, reason: CancelReason) {
        let ids: Vec<u64> = lock(&self.inbox.pending).keys().copied().collect();
        for id in ids {
            self.cancel(id, reason);
        }
    }

    /// Asks the organ to exit, then kills it after `grace`.
    pub(crate) fn shutdown(&self, grace: Duration) {
        self.stopped_by_host.store(true, Ordering::SeqCst);
        let _ = send_frame(
            &lock(&self.writer),
            &ToOrgan::Shutdown,
            &[],
            DEFAULT_FRAME_LIMIT,
        );
        let until = Instant::now() + grace;
        while Instant::now() < until {
            if matches!(lock(&self.child).try_wait(), Ok(Some(_))) {
                break;
            }
            thread::sleep(Duration::from_millis(5));
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

    /// Kills the process now. The kernel drops every region it had mapped.
    pub(crate) fn kill(&self) {
        let mut child = lock(&self.child);
        let _ = child.kill();
        let _ = child.wait();
        drop(child);
        self.inbox.close();
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
) -> Result<HelloAck, HostError> {
    stream.set_read_timeout(Some(config.handshake_timeout))?;
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
    send_frame(stream, &hello, &[], DEFAULT_FRAME_LIMIT)?;
    let (ack, _) = recv_frame::<FromOrgan>(stream, DEFAULT_FRAME_LIMIT)
        .map_err(|err| HostError::Handshake(format!("no hello_ack: {err}")))?;
    stream.set_read_timeout(None)?;
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
/// second `hello_ack`; then fails every waiting call.
fn read_replies(stream: &UnixStream, inbox: &Inbox, limit: u32) {
    while let Ok((FromOrgan::Reply(reply), fds)) = recv_frame::<FromOrgan>(stream, limit) {
        let waiter = lock(&inbox.pending).remove(&reply.id);
        // A reply nobody waits for came after its deadline: drop it.
        if let Some(waiter) = waiter {
            let _ = waiter.try_send(Some((reply, fds)));
        }
    }
    inbox.close();
}
