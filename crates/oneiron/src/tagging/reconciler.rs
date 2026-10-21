//! The drain pass a host worker drives: claim ready markers, read each turn,
//! call the tagger outside any write transaction, check the answer, settle.

mod call;
mod claim;
mod coordinator;
mod history;
mod recovery;
mod settle;

pub use coordinator::{TaggingBackoff, TaggingPass, TaggingReconciler};

#[cfg(test)]
std::thread_local! {
    static AFTER_TURN_READ: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Runs `hook` once on this thread, between an attempt's read of its turn and
/// the transaction that settles it.
#[cfg(test)]
pub(super) fn set_after_turn_read_hook(hook: impl FnOnce() + 'static) {
    AFTER_TURN_READ.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_after_turn_read_hook() {
    let hook = AFTER_TURN_READ.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}
