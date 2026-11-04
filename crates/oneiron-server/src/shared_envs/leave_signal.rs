//! A shared lane's nonblocking request for its verified leave check.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub(super) struct LeaveCheckSignal {
    requested: AtomicBool,
    running: AtomicBool,
    wake: Arc<tokio::sync::Notify>,
}

impl LeaveCheckSignal {
    pub(super) fn new(wake: Arc<tokio::sync::Notify>) -> Self {
        Self {
            requested: AtomicBool::new(false),
            running: AtomicBool::new(false),
            wake,
        }
    }

    pub(super) fn request(&self) {
        self.requested.store(true, Ordering::Release);
        self.wake.notify_one();
    }

    pub(super) fn take(self: &Arc<Self>, due: bool) -> Option<LeaveCheckRun> {
        if !due && !self.requested.load(Ordering::Acquire) {
            return None;
        }
        self.running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        self.requested.swap(false, Ordering::AcqRel);
        Some(LeaveCheckRun(Arc::clone(self)))
    }

    pub(super) fn wake_if_requested(&self) {
        if self.requested.load(Ordering::Acquire) {
            self.wake.notify_one();
        }
    }
}

/// One check at a time per membership; a request during it stays owed.
pub(super) struct LeaveCheckRun(Arc<LeaveCheckSignal>);

impl Drop for LeaveCheckRun {
    fn drop(&mut self) {
        self.0.running.store(false, Ordering::Release);
        self.0.wake_if_requested();
    }
}
