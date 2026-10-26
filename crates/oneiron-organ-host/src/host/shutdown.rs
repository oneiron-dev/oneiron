//! The mesh's stop, as the organ work it admitted sees it (FIX 4755, 4756).
//!
//! A host's mesh listener stops its organ work in two steps, under one
//! deadline. First it takes no new work ([`MeshCancel::stop`]): a redrive
//! starts no next held call, a pack rescan no next organ, and the organ
//! service admits no new call; what is admitted runs on. At the deadline it
//! cancels what still runs ([`MeshCancel::cancel`]): each organ call in
//! flight under it is cancelled with the protocol's shutdown reason, each
//! wait for budget, room or a seat ends, and a call sent to another node is
//! dropped. A call cut short says [`HostError::Interrupted`], never a clean
//! end; one that finished first keeps its outputs and receipt. Nothing here
//! withdraws a grant: a revocation is another act.
//!
//! Blocking work runs under the cancel on its own thread
//! ([`MeshCancel::scope`]), so the waits deep inside a call read it there.

use std::cell::RefCell;
#[cfg(unix)]
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
#[cfg(unix)]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(unix)]
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::sync::Notify;

use crate::error::HostError;
#[cfg(unix)]
use crate::process::OrganProcess;

/// A mesh listener's stop and cancel for the organ work it admitted. Its
/// clones are one stop: each step taken on one is seen by all.
#[derive(Clone, Default)]
pub struct MeshCancel(Arc<Cancel>);

#[derive(Default)]
struct Cancel {
    /// No new work starts.
    stopping: AtomicBool,
    /// The work still running is cancelled.
    cancelled: AtomicBool,
    /// Wakes the waits for either step.
    moved: Notify,
    /// The organ calls in flight under this cancel, by registration.
    #[cfg(unix)]
    calls: Mutex<BTreeMap<u64, Arc<InFlight>>>,
    #[cfg(unix)]
    next: AtomicU64,
}

impl fmt::Debug for MeshCancel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MeshCancel")
            .field("stopping", &self.is_stopping())
            .field("cancelled", &self.is_cancelled())
            .finish_non_exhaustive()
    }
}

impl MeshCancel {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes no new work from now: each redrive or rescan stops before its
    /// next unit, and the organ service admits no new call. What is
    /// admitted runs on.
    pub fn stop(&self) {
        self.0.stopping.store(true, Ordering::SeqCst);
        self.0.moved.notify_waiters();
    }

    /// Cancels the work still running, and takes no new work: each organ
    /// call in flight under it is told to stop with the protocol's shutdown
    /// reason, and stopped once its grace ends unanswered; each wait for
    /// budget, room or a seat ends. The cancels run on threads of their own,
    /// so this never waits on an organ.
    pub fn cancel(&self) {
        self.0.stopping.store(true, Ordering::SeqCst);
        self.0.cancelled.store(true, Ordering::SeqCst);
        self.0.moved.notify_waiters();
        #[cfg(unix)]
        {
            let calls: Vec<Arc<InFlight>> = lock(&self.0.calls).values().cloned().collect();
            for call in calls {
                call.interrupt();
            }
        }
    }

    /// Whether new work stays unstarted.
    #[must_use]
    pub fn is_stopping(&self) -> bool {
        self.0.stopping.load(Ordering::SeqCst)
    }

    /// Whether the work still running was cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::SeqCst)
    }

    /// Returns once the stop has begun.
    pub async fn stopped(&self) {
        self.until(Self::is_stopping).await;
    }

    /// Returns once the work still running was cancelled.
    pub async fn cancelled(&self) {
        self.until(Self::is_cancelled).await;
    }

    async fn until(&self, reached: fn(&Self) -> bool) {
        loop {
            // Made before the check, so a step taken between the two still
            // wakes it.
            let moved = self.0.moved.notified();
            if reached(self) {
                return;
            }
            moved.await;
        }
    }

    /// Runs `work`, blocking work on this thread, under this cancel: the
    /// redrive's units, its calls' waits and the organ calls it sends all
    /// read it here.
    pub fn scope<T>(&self, work: impl FnOnce() -> T) -> T {
        let _scope = Scope::enter(self.clone());
        work()
    }
}

thread_local! {
    /// The cancel the blocking work on this thread runs under, if any.
    static CURRENT: RefCell<Option<MeshCancel>> = const { RefCell::new(None) };
    /// The organ call this thread is sending under that cancel, if any.
    #[cfg(unix)]
    static CALL: RefCell<Option<Arc<InFlight>>> = const { RefCell::new(None) };
}

/// This thread's cancel until dropped; the one before it comes back.
struct Scope(Option<MeshCancel>);

impl Scope {
    fn enter(cancel: MeshCancel) -> Self {
        Self(CURRENT.with(|current| current.replace(Some(cancel))))
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        let before = self.0.take();
        CURRENT.with(|current| *current.borrow_mut() = before);
    }
}

/// The cancel this thread's work runs under.
pub(crate) fn current() -> Option<MeshCancel> {
    CURRENT.with(|current| current.borrow().clone())
}

/// Whether this thread's work was cancelled.
pub(crate) fn interrupted() -> bool {
    CURRENT.with(|current| {
        current
            .borrow()
            .as_ref()
            .is_some_and(MeshCancel::is_cancelled)
    })
}

/// Whether this thread's work starts no next unit.
pub(crate) fn stopping() -> bool {
    CURRENT.with(|current| {
        current
            .borrow()
            .as_ref()
            .is_some_and(MeshCancel::is_stopping)
    })
}

/// `wait`, but no longer than `recheck` while this thread's work runs under
/// a cancel, so a wait nothing wakes for the cancel still sees it.
pub(crate) fn bounded(wait: Duration, recheck: Duration) -> Duration {
    if CURRENT.with(|current| current.borrow().is_some()) {
        wait.min(recheck)
    } else {
        wait
    }
}

/// Fails once this thread's work was cancelled: the next unit is not tried.
pub(crate) fn check() -> Result<(), HostError> {
    if interrupted() {
        Err(HostError::Interrupted)
    } else {
        Ok(())
    }
}

/// A call's result as the cancel leaves it: once this thread's work was
/// cancelled, a failure is the stop's, [`HostError::Interrupted`]. An
/// outcome that came stands, and so does a withdrawn grant.
pub(crate) fn settle<T>(result: Result<T, HostError>) -> Result<T, HostError> {
    match result {
        Err(error) if !matches!(error, HostError::Revoked) && interrupted() => {
            Err(HostError::Interrupted)
        }
        result => result,
    }
}

/// Returns once `cancel` cancels its work; never without one.
pub(crate) async fn cancelled(cancel: Option<&MeshCancel>) {
    match cancel {
        Some(cancel) => cancel.cancelled().await,
        None => std::future::pending().await,
    }
}

#[cfg(unix)]
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One organ call under a cancel: its process, its id there once it is
/// sent, and the grace a cancel gets to take.
#[cfg(unix)]
struct InFlight {
    process: Arc<OrganProcess>,
    grace: Duration,
    id: Mutex<Option<u64>>,
    /// Already cancelled: a call is cancelled once.
    interrupted: AtomicBool,
}

#[cfg(unix)]
impl InFlight {
    /// Cancels the call on a thread of its own. One not sent yet waits for
    /// a seat: that wait wakes and sees the cancel.
    fn interrupt(self: &Arc<Self>) {
        let Some(id) = *lock(&self.id) else {
            self.process.wake_seats();
            return;
        };
        if self.interrupted.swap(true, Ordering::SeqCst) {
            return;
        }
        let call = Arc::clone(self);
        let spawned = std::thread::Builder::new()
            .name("organ-mesh-cancel".into())
            .spawn(move || call.process.interrupt(id, call.grace));
        // With no thread to spare, the cancel runs here.
        if spawned.is_err() {
            self.process.interrupt(id, self.grace);
        }
    }
}

/// An organ call's place under this thread's cancel while it runs on its
/// process; none outside a cancel. Dropped as the call ends.
#[cfg(unix)]
pub(crate) struct Interruptible {
    cancel: MeshCancel,
    key: u64,
}

/// The organ call this thread is about to send on `process`, under its
/// cancel: a cancel reaches it from now, with `grace` to take.
#[cfg(unix)]
pub(crate) fn interruptible(process: &Arc<OrganProcess>, grace: Duration) -> Option<Interruptible> {
    let cancel = current()?;
    let call = Arc::new(InFlight {
        process: Arc::clone(process),
        grace,
        id: Mutex::new(None),
        interrupted: AtomicBool::new(false),
    });
    let key = cancel.0.next.fetch_add(1, Ordering::Relaxed);
    lock(&cancel.0.calls).insert(key, Arc::clone(&call));
    CALL.with(|slot| *slot.borrow_mut() = Some(call));
    Some(Interruptible { cancel, key })
}

#[cfg(unix)]
impl Drop for Interruptible {
    fn drop(&mut self) {
        lock(&self.cancel.0.calls).remove(&self.key);
        CALL.with(|slot| *slot.borrow_mut() = None);
    }
}

/// This thread's organ call went out as `id`: a cancel interrupts it from
/// now, and one that came first interrupts it at once.
#[cfg(unix)]
pub(crate) fn sent(id: u64) {
    let Some(call) = CALL.with(|slot| slot.borrow().clone()) else {
        return;
    };
    *lock(&call.id) = Some(id);
    if interrupted() {
        call.interrupt();
    }
}
