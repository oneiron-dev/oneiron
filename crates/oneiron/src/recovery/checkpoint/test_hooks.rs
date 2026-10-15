//! Test hooks that fail or panic a restore at a chosen step.

use crate::{Error, Result};

/// A step of a restore after its destination is made, which a test fails
/// as a refusal there would.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RestoreStep {
    FirstOpen,
    ImageWrite,
    SecondOpen,
    ReceiptCheck,
}

thread_local! {
    static RESTORE_FAILS_AT: std::cell::Cell<Option<RestoreStep>> =
        const { std::cell::Cell::new(None) };
}

/// Fails the next restore on this thread at `step`.
pub(super) fn arm_restore_failure(step: RestoreStep) {
    RESTORE_FAILS_AT.with(|slot| slot.set(Some(step)));
}

pub(super) fn fail_at(step: RestoreStep) -> Result<()> {
    if RESTORE_FAILS_AT.with(|slot| slot.get()) != Some(step) {
        return Ok(());
    }
    RESTORE_FAILS_AT.with(|slot| slot.set(None));
    Err(Error::InvalidConfig(
        "a restore step was failed by a test".into(),
    ))
}

thread_local! {
    static RESTORE_PANICS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Panics the next restore on this thread in its final checks against the
/// current vault, as a host callback there could.
pub(super) fn arm_restore_panic() {
    RESTORE_PANICS.with(|slot| slot.set(true));
}

pub(super) fn panic_if_armed() {
    assert!(
        !RESTORE_PANICS.with(|slot| slot.replace(false)),
        "a restore's final checks panicked in a test"
    );
}
