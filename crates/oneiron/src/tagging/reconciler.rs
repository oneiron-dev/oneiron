//! The tagging reconciler (FIX 6755): the engine half of the drain. It
//! claims ready markers, a live one before any bulk one, reads each turn,
//! has the tagger called outside any write transaction, checks the answer and
//! settles the marker against the turn's current text, in one transaction
//! with its trace. A host drives it a pass at a time
//! ([`TaggingReconciler::drain_until_paused`]) or a marker at a time through
//! its staged API ([`TaggingReconciler::ready_class`],
//! [`TaggingReconciler::prepare_next`], [`TaggingReconciler::settle`]),
//! which the pass composes, so there is one settlement path. A claimed marker
//! is the reconciler's from its claim's commit to the commit that settles
//! it: an error, a panic or a preparation let go is handed back, never
//! stranded.

mod call;
mod claim;
mod coordinator;
mod history;
mod recovery;
mod settle;

pub use coordinator::{
    PreparedTagging, TaggingBackoff, TaggingPass, TaggingPreparation, TaggingReconciler,
};

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
