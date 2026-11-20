//! Door for `tests/esign_send_binding.rs`: a write between an e-sign act's
//! command binding and its writer. The test arms a one-shot write; the next
//! e-sign dispatch on this thread runs it inline right after it binds its
//! command to the document as it stands, before the gate and the act's own
//! writer, so the act meets a document other than the one its binding names.
//! No transaction is open at that point.

use std::cell::RefCell;

use crate::Vault;

type BoundWrite = Box<dyn FnOnce(&Vault)>;

thread_local! {
    static AFTER_COMMAND_BINDING: RefCell<Option<BoundWrite>> = const { RefCell::new(None) };
}

/// Arms `write` to run once, on this thread, right after the next e-sign
/// dispatch binds its command to the document.
pub fn race_after_command_binding(write: impl FnOnce(&Vault) + 'static) {
    AFTER_COMMAND_BINDING.with(|slot| *slot.borrow_mut() = Some(Box::new(write)));
}

/// The race point: runs the armed write, if one is armed, and disarms it, so
/// a dispatch the write makes itself does not run it again.
pub(crate) fn after_command_binding(vault: &Vault) {
    let armed = AFTER_COMMAND_BINDING.with(|slot| slot.borrow_mut().take());
    if let Some(write) = armed {
        write(vault);
    }
}
