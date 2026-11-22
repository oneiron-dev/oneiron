//! Door for `tests/snapshot_page_ended_during_read.rs` (FIX
//! SNAPSHOT-PAGE-STALE-BOUNDS-NO-EXPIRY): one step that runs between a
//! snapshot page's read and the write that counts its rows, so the test can
//! end the handle, or lower the owner's bounds, while the page is read.

use std::cell::RefCell;

use crate::Vault;

/// A step run once at the next page's accounting.
type AccountingStep = Box<dyn FnOnce(&Vault)>;

thread_local! {
    static BEFORE_PAGE_ACCOUNTING: RefCell<Option<AccountingStep>> = const { RefCell::new(None) };
}

/// Runs `step` once, on this thread, after the next `vault.snapshot.page`
/// has read its rows and before the write that counts them against the
/// handle.
pub fn before_next_page_accounting(step: impl FnOnce(&Vault) + 'static) {
    BEFORE_PAGE_ACCOUNTING.with(|slot| *slot.borrow_mut() = Some(Box::new(step)));
}

/// The seam `snapshot_page` calls between its read and its accounting write:
/// takes the step [`before_next_page_accounting`] set on this thread, if
/// any, and runs it.
pub(crate) fn run_before_page_accounting(vault: &Vault) {
    let step = BEFORE_PAGE_ACCOUNTING.with(|slot| slot.borrow_mut().take());
    if let Some(step) = step {
        step(vault);
    }
}
