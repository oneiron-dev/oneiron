//! Whether the entity doors on this thread carry a federation peer's import
//! (Docs Q04). Window admission judges a peer's rows in a read transaction
//! before the import; a door that must judge one again in its own writer
//! transaction, after a local change that committed in between, asks here.
//! It holds for the reason the birth watch does: every entity door runs on
//! the importing thread.

use std::cell::RefCell;
use std::path::PathBuf;

use crate::Vault;

thread_local! {
    static PEER_IMPORT: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

/// Puts back the scope an outer import installed, on every exit.
struct Restore(Option<PathBuf>);

impl Drop for Restore {
    fn drop(&mut self) {
        let outer = self.0.take();
        PEER_IMPORT.with(|slot| *slot.borrow_mut() = outer);
    }
}

/// Runs `import` with the entity doors writing `vault` on this thread told
/// they carry a federation peer's rows.
pub(in crate::sync) fn peer_import<T>(vault: &Vault, import: impl FnOnce() -> T) -> T {
    let path = vault.store.env.path().to_path_buf();
    let _restore = Restore(PEER_IMPORT.with(|slot| slot.borrow_mut().replace(path)));
    import()
}

/// Whether an import on this thread carries a federation peer's rows into
/// `vault`.
pub(in crate::sync) fn in_peer_import(vault: &Vault) -> bool {
    PEER_IMPORT.with(|slot| {
        slot.borrow()
            .as_deref()
            .is_some_and(|path| path == vault.store.env.path())
    })
}
