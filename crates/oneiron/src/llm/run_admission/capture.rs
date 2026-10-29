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
    /// The capture this thread's newly built run admissions keep to.
    static CAPTURE: RefCell<Option<Kept>> = const { RefCell::new(None) };
}

/// Runs `work`, and returns beside what it returned each settlement receipt
/// recorded meanwhile by a run admission built on this thread through
/// [`captured_sink`], in the order they were recorded. An enclosing capture
/// is put back after, panic or not, and sees none of these.
pub fn capture_settlements<T>(work: impl FnOnce() -> T) -> (T, Vec<RunReceipt>) {
    struct Restore(Option<Kept>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let previous = self.0.take();
            CAPTURE.with(|slot| *slot.borrow_mut() = previous);
        }
    }
    let kept: Kept = Arc::default();
    let restore = Restore(CAPTURE.with(|slot| slot.replace(Some(Arc::clone(&kept)))));
    let done = work();
    drop(restore);
    let settled = std::mem::take(&mut *kept.lock().unwrap_or_else(PoisonError::into_inner));
    (done, settled)
}

/// `sink` for a run admission built now: inside [`capture_settlements`] on
/// this thread, a sink that records every receipt to `sink` unchanged and
/// keeps a copy of each settlement for the capture; anywhere else, `sink`
/// itself.
#[must_use]
pub fn captured_sink(sink: Arc<dyn RunReceiptSink>) -> Arc<dyn RunReceiptSink> {
    match CAPTURE.with(|slot| slot.borrow().clone()) {
        Some(kept) => Arc::new(CapturedSink { sink, kept }),
        None => sink,
    }
}

/// A host sink with a capture beside it.
struct CapturedSink {
    sink: Arc<dyn RunReceiptSink>,
    kept: Kept,
}

impl RunReceiptSink for CapturedSink {
    fn record(&self, receipt: RunReceipt) {
        if matches!(receipt.event, RunEvent::Settled { .. }) {
            self.kept
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(receipt.clone());
        }
        self.sink.record(receipt);
    }

    fn budget_hit(&self, seat: &str, guard: &BudgetGuard, denied: &BudgetDenied) {
        self.sink.budget_hit(seat, guard, denied);
    }
}
