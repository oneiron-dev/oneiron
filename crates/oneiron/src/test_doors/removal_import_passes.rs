//! Door for `tests/removal_import_body_digest.rs` (FIX
//! [REMOVAL-IMPORT-KEPT-BODY-UNBOUND]): runs a test's hook on this thread
//! after each pass [`crate::Vault::import_removal_archive`] makes over the
//! archive it was handed, so the test can rewrite the caller's file between
//! passes.

use std::cell::RefCell;

/// A pass the import makes over the archive it was handed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemovalImportPass {
    /// The archive's bytes were checked against the digest its copy names.
    Digest,
    /// The archive was read through the whole-vault archive reader.
    ArchiveRead,
}

type PassHook = Box<dyn FnMut(RemovalImportPass)>;

thread_local! {
    static HOOK: RefCell<Option<PassHook>> = const { RefCell::new(None) };
}

/// Runs `hook` after each pass of every removal import on this thread, until
/// [`disarm`].
pub fn arm(hook: impl FnMut(RemovalImportPass) + 'static) {
    HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

/// Stops the hook [`arm`] set on this thread.
pub fn disarm() {
    HOOK.with(|slot| *slot.borrow_mut() = None);
}

/// The pass point; a no-op unless [`arm`] armed this thread. The hook is
/// taken out while it runs, so it may import again without running itself.
pub(crate) fn after_pass(pass: RemovalImportPass) {
    let Some(mut hook) = HOOK.with(|slot| slot.borrow_mut().take()) else {
        return;
    };
    hook(pass);
    HOOK.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = Some(hook);
        }
    });
}
