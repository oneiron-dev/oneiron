//! Settlements kept for one scope on the calling thread (FIX 10075 seam):
//! a host that must name the calls a piece of work settled (a hook's
//! `ai.verdict`) runs that work in [`capture_settlements`], and each run
//! admission built meanwhile on its thread through [`captured_sink`] keeps a
//! copy of every settlement it records. The host's own sink still receives
//! every receipt unchanged: this adds no settlement and changes none.

use std::cell::RefCell;
use std::sync::{Arc, Mutex, PoisonError};

use super::super::{BudgetDenied, BudgetGuard};
use super::receipt::{RunEvent, RunReceipt, RunReceiptSink};

/// The settlements a capture keeps, in the order their runs recorded them.
type Kept = Arc<Mutex<Vec<RunReceipt>>>;

thread_local! {
    /// The captures this thread's newly built run admissions keep to.
    static CAPTURE: RefCell<Vec<Kept>> = const { RefCell::new(Vec::new()) };
}

/// Runs `work`, and returns beside what it returned each settlement receipt
/// recorded meanwhile by a run admission built on this thread through
/// [`captured_sink`], in the order they were recorded. An enclosing capture
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

/// `sink` for a run admission built now: inside a capture on this thread,
/// a sink that records every receipt to `sink` unchanged and keeps a copy
/// of each settlement for the capture; anywhere else, `sink` itself.
#[must_use]
pub fn captured_sink(sink: Arc<dyn RunReceiptSink>) -> Arc<dyn RunReceiptSink> {
    let kept = CAPTURE.with(|slot| slot.borrow().clone());
    if kept.is_empty() {
        sink
    } else {
        Arc::new(CapturedSink { sink, kept })
    }
}

/// A host sink with its captures beside it.
struct CapturedSink {
    sink: Arc<dyn RunReceiptSink>,
    kept: Vec<Kept>,
}

impl RunReceiptSink for CapturedSink {
    fn record(&self, receipt: RunReceipt) {
        if matches!(receipt.event, RunEvent::Settled { .. }) {
            for kept in &self.kept {
                kept.lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(receipt.clone());
            }
        }
        self.sink.record(receipt);
    }

    fn budget_hit(&self, seat: &str, guard: &BudgetGuard, denied: &BudgetDenied) {
        self.sink.budget_hit(seat, guard, denied);
    }
}
