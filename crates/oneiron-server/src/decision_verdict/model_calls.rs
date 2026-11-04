//! The verdict caller a model-call capture attributes (FIX 12742).
//!
//! [`run_verdict`](super::run_verdict) binds its principal here while the
//! verdict answers, on this thread only; `BigModel::decide` reads it back to
//! stamp the actual caller on its evidence row. Outside the scope the slot is
//! empty and the capture is skipped — never guessed, never the payer. The
//! slot carries the principal alone: no session, no room, no policy.
use std::cell::Cell;

use oneiron::EntityId;

thread_local! {
    /// The verdict principal bound on this thread, while a verdict answers.
    static ACTOR: Cell<Option<EntityId>> = const { Cell::new(None) };
}

/// Runs `call` with `principal` bound as this thread's verdict actor, and
/// puts back what was there before, panic or not. Scopes nest: the inner
/// caller's restore returns the outer principal.
pub(crate) fn scoped<T>(principal: EntityId, call: impl FnOnce() -> T) -> T {
    struct Restore(Option<EntityId>);
    impl Drop for Restore {
        fn drop(&mut self) {
            ACTOR.with(|slot| slot.set(self.0.take()));
        }
    }
    let _restore = Restore(ACTOR.with(|slot| slot.replace(Some(principal))));
    call()
}

/// This thread's verdict actor, inside a [`scoped`] verdict on this thread;
/// `None` outside one, where the capture is skipped.
pub(crate) fn actor() -> Option<EntityId> {
    ACTOR.with(|slot| slot.get())
}
