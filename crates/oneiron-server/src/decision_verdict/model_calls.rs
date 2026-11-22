//! The capture caller a model-call capture attributes (FIX 12516/12742).
//!
//! [`run_verdict`](super::run_verdict) binds its caller here while the
//! decision answers, on this thread only; `BigModel::decide` reads it back to
//! stamp the actual caller on its evidence row. Outside the scope the slot is
//! empty and the capture is skipped — never guessed, never the payer. The
//! slot carries the bound principal and its optional session: no room, no
//! policy. Only [`scoped`] binds it, on the decision's blocking thread.
use std::cell::RefCell;

use oneiron::llm::run_admission::RunAdmission;
use oneiron::{EntityId, Vault};

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

/// `run`, for a rung's call inside a [`scoped`] decision whose bound caller is
/// verified in an off-record session that keeps no model-call record
/// ([`Vault::model_call_keeps_no_record_for`], census L5-25): kept
/// [`RunAdmission::off_record`], so no receipt of the call names the rows its
/// evidence read, or their worlds. Unchanged outside a scope and for any
/// other caller, as the evidence row's own check reads it.
pub(crate) fn run_for_caller(vault: &Vault, run: RunAdmission) -> RunAdmission {
    let keeps_no_record = caller().is_some_and(|caller| {
        vault.model_call_keeps_no_record_for(caller.session.as_deref(), Some(caller.principal))
    });
    if keeps_no_record {
        run.off_record()
    } else {
        run
    }
}
