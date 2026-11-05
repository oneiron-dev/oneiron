//! Settlements kept for one scope on the calling thread (FIX 10075 seam):
//! a host that must name the calls a piece of work settled (a hook's
//! `ai.verdict`) runs that work in [`capture_settlements`] and binds its run
//! handle through [`RunAdmission::capturing_settlements`]. Only permits
//! admitted through that handle keep settlements for the scope. The host's
//! own sink still receives every receipt unchanged.

use std::cell::RefCell;
use std::sync::{Arc, Mutex, PoisonError};

use super::admission::RunAdmission;
use super::receipt::{RunEvent, RunReceipt};

/// The settlements a capture keeps, in the order their runs recorded them.
type Kept = Arc<Mutex<Vec<RunReceipt>>>;

thread_local! {
    /// The captures a run handle can bind on this thread.
    static CAPTURE: RefCell<Vec<Kept>> = const { RefCell::new(Vec::new()) };
}

/// Runs `work`, and returns beside what it returned each settlement receipt
/// recorded meanwhile by permits whose run handle bound this scope through
/// [`RunAdmission::capturing_settlements`], in record order. An enclosing capture
/// is put back after, panic or not, and sees none of these.
pub fn capture_settlements<T>(work: impl FnOnce() -> T) -> (T, Vec<RunReceipt>) {
    capture(work, false)
}

/// Like [`capture_settlements`], while currently visible captures also keep
/// each settlement at record time. An exclusive capture still hides its
/// parents; the host sink receives each receipt once.
pub fn capture_settlements_shared<T>(work: impl FnOnce() -> T) -> (T, Vec<RunReceipt>) {
    capture(work, true)
}

fn capture<T>(work: impl FnOnce() -> T, shared: bool) -> (T, Vec<RunReceipt>) {
    struct Restore(Vec<Kept>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let previous = std::mem::take(&mut self.0);
            CAPTURE.with(|slot| *slot.borrow_mut() = previous);
        }
    }
    let kept: Kept = Arc::default();
    let mut captures = CAPTURE.with(|slot| {
        if shared {
            slot.borrow().clone()
        } else {
            Vec::new()
        }
    });
    captures.push(Arc::clone(&kept));
    let restore = Restore(CAPTURE.with(|slot| slot.replace(captures)));
    let done = work();
    drop(restore);
    let settled = std::mem::take(&mut *kept.lock().unwrap_or_else(PoisonError::into_inner));
    (done, settled)
}

/// The capture targets bound to a handle, copied to each permit it admits.
#[derive(Clone, Default)]
pub(super) struct SettlementCapture {
    kept: Vec<Kept>,
}

impl RunAdmission {
    /// This run, keeping settlements from calls admitted through the returned
    /// handle for the captures currently visible on this thread. Other
    /// handles to the same run gain no observer. Already bound captures stay
    /// bound, once each; cloning and the other handle overlays preserve them.
    #[must_use]
    pub fn capturing_settlements(&self) -> Self {
        let mut run = self.clone();
        CAPTURE.with(|slot| {
            for kept in slot.borrow().iter() {
                if !run
                    .capture
                    .kept
                    .iter()
                    .any(|bound| Arc::ptr_eq(bound, kept))
                {
                    run.capture.kept.push(Arc::clone(kept));
                }
            }
        });
        run
    }
}

impl SettlementCapture {
    pub(super) fn record(&self, receipt: &RunReceipt) {
        if matches!(receipt.event, RunEvent::Settled { .. }) {
            for kept in &self.kept {
                kept.lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(receipt.clone());
            }
        }
    }
}
