//! The removal archive kept for a member under one receipt, and the hook
//! the kept-body test arms between the import's passes: the BLAKE3 of the
//! bytes its row keeps, so the test can check the kept bytes against the
//! digest the import checked, and the `after_digest_pass` hook point, so the
//! test can rewrite the spool file deterministically once that check passes.

use std::cell::RefCell;

use crate::{EntityId, Result, Vault};

/// What [`set_after_digest_pass`] arms: against the import's spool file.
type AfterDigestPassHook = Box<dyn FnMut(&mut std::fs::File) -> std::io::Result<()>>;

thread_local! {
    /// The hook [`after_digest_pass`] runs on this thread, armed by
    /// [`set_after_digest_pass`]; `None` runs nothing. The import fires it
    /// inline on its caller's thread, so a thread-local slot is enough.
    static AFTER_DIGEST_PASS: RefCell<Option<AfterDigestPassHook>> =
        const { RefCell::new(None) };
}

/// Arms this thread's removal-import hook: the next
/// [`Vault::import_removal_archive`] on this thread runs `hook` against its
/// spool file once its format and spool-digest check passes, before the
/// indexed archive read. A test overwrites the spool there to stand in for a
/// caller rewriting the file between the import's passes. Stays armed until
/// [`clear_after_digest_pass`].
#[doc(hidden)]
pub fn set_after_digest_pass(
    hook: impl FnMut(&mut std::fs::File) -> std::io::Result<()> + 'static,
) {
    AFTER_DIGEST_PASS.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

/// Disarms this thread's removal-import hook, if any.
#[doc(hidden)]
pub fn clear_after_digest_pass() {
    AFTER_DIGEST_PASS.with(|slot| *slot.borrow_mut() = None);
}

/// The hook point in [`Vault::import_removal_archive`]: runs the armed hook,
/// if any, against the import's spool file. A hook I/O error fails the
/// import the way the import's own spool reads do.
pub(crate) fn after_digest_pass(file: &mut std::fs::File) -> std::io::Result<()> {
    let taken = AFTER_DIGEST_PASS.with(|slot| slot.borrow_mut().take());
    let Some(mut hook) = taken else {
        return Ok(());
    };
    let outcome = hook(file);
    AFTER_DIGEST_PASS.with(|slot| *slot.borrow_mut() = Some(hook));
    outcome
}

/// The BLAKE3 of the bytes of the removal archive kept for `member` under
/// `receipt`, lowercase hex; `None` when no archive is kept under it within
/// its term at `now`.
///
/// # Errors
/// The vault's and the store's.
#[doc(hidden)]
pub fn kept_removal_archive_digest(
    vault: &Vault,
    member: EntityId,
    receipt: EntityId,
    now: u64,
) -> Result<Option<String>> {
    let txn = vault.store.env.read_txn()?;
    let Some(stored) = vault.removal_export_in_txn(&txn, member, receipt, now)? else {
        return Ok(None);
    };
    let mut copies = vault.removal_export_copies_in_txn(&txn, vec![stored])?;
    Ok(copies.pop().map(|copy| copy.digest().to_owned()))
}
