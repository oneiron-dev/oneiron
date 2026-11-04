//! The capture caller a model-call capture attributes (FIX 12516/12742).
//!
//! [`run_verdict`](super::run_verdict) binds its caller here while the
//! decision answers, on this thread only; `BigModel::decide` reads it back to
//! stamp the actual caller on its evidence row. Outside the scope the slot is
//! empty and the capture is skipped — never guessed, never the payer. The
//! slot carries the bound principal and its optional session: no room, no
//! policy. Only [`scoped`] binds it, on the decision's blocking thread.
use std::cell::RefCell;

use oneiron::EntityId;

/// The capture caller bound while a decision answers: the bound principal
/// and its optional session.
#[derive(Clone)]
pub(crate) struct ModelCallCaller {
    pub(crate) principal: EntityId,
    pub(crate) session: Option<String>,
}

thread_local! {
    /// The capture caller bound on this thread, while a decision answers.
    static CALLER: RefCell<Option<ModelCallCaller>> = const { RefCell::new(None) };
}

/// Runs `call` with `principal` and `session` bound as this thread's capture
/// caller, and puts back what was there before, panic or not. Scopes nest:
/// the inner caller's restore returns the outer caller.
pub(crate) fn scoped<T>(principal: EntityId, session: Option<&str>, call: impl FnOnce() -> T) -> T {
    struct Restore(Option<ModelCallCaller>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let previous = self.0.take();
            CALLER.with(|slot| *slot.borrow_mut() = previous);
        }
    }
    let caller = ModelCallCaller {
        principal,
        session: session.map(str::to_owned),
    };
    let _restore = Restore(CALLER.with(|slot| slot.replace(Some(caller))));
    call()
}

/// This thread's capture caller, inside a [`scoped`] decision on this thread;
/// `None` outside one, where the capture is skipped.
pub(crate) fn caller() -> Option<ModelCallCaller> {
    CALLER.with(|slot| slot.borrow().clone())
}
