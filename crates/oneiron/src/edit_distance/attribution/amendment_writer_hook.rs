//! A test door into the amendment attribution writers: one step run on the
//! calling thread after the evidence door or the judge has read what it
//! decides from, just before its writer opens. A test puts a racing erase
//! there. The step exists only under `--cfg oneiron_test_support`; in every
//! other build the call does nothing.

#[cfg(oneiron_test_support)]
use std::cell::RefCell;

use crate::Vault;

#[cfg(oneiron_test_support)]
type Step = Box<dyn FnOnce(&Vault)>;

#[cfg(oneiron_test_support)]
thread_local! {
    static BEFORE_WRITER: RefCell<Option<Step>> = const { RefCell::new(None) };
}

/// Runs `step` once, on this thread, the next time an amendment attribution
/// writer (the evidence door's or the judge's) is about to open.
#[cfg(oneiron_test_support)]
pub(crate) fn set_before_amendment_writer_hook(step: Step) {
    BEFORE_WRITER.with(|slot| *slot.borrow_mut() = Some(step));
}

/// Takes and runs the step [`set_before_amendment_writer_hook`] left for
/// this thread, if any.
pub(super) fn run_before_amendment_writer_hook(vault: &Vault) {
    #[cfg(oneiron_test_support)]
    {
        let step = BEFORE_WRITER.with(|slot| slot.borrow_mut().take());
        if let Some(step) = step {
            step(vault);
        }
    }
    #[cfg(not(oneiron_test_support))]
    let _ = vault;
}
