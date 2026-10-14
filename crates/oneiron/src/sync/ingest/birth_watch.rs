//! The rows a federated import watches for their births. A facet stamp a peer
//! sent onto a row this vault lacks counts only once that sender's own birth
//! of the row applied: an entity door wrote the sender's exact bytes where no
//! row was stored, in a transaction that committed (Astra-b F1, Sol R10 F2,
//! Astra R11 F3 on #1432). A row another writer stored first makes the
//! sender's copy an idempotent skip, and another writer's image created
//! during the import is not the sender's birth, so neither counts.
//!
//! Every entity door runs on the importing thread: Observer B's entity batch
//! and its edge batch's endpoint hydration fire inside the import, and
//! forward rematerialization is called from it.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use crate::{EntityId, Vault};

thread_local! {
    static WATCH: RefCell<Option<Watch>> = const { RefCell::new(None) };
}

struct Watch {
    vault: PathBuf,
    rows: BTreeMap<EntityId, Vec<u8>>,
    born: BTreeSet<EntityId>,
}

impl Watch {
    fn of(&self, vault: &Vault) -> bool {
        self.vault == vault.store.env.path()
    }
}

/// Puts back the watch an outer import installed, on every exit.
struct Restore(Option<Watch>);

impl Drop for Restore {
    fn drop(&mut self) {
        let outer = self.0.take();
        WATCH.with(|watch| *watch.borrow_mut() = outer);
    }
}

/// Runs `import` while the entity doors writing `vault` on this thread watch
/// `rows`, each with the bytes its sender brought, and returns the ones whose
/// births from those bytes it committed.
pub(in crate::sync) fn watch_births<E>(
    vault: &Vault,
    rows: &[(EntityId, Vec<u8>)],
    import: impl FnOnce() -> std::result::Result<(), E>,
) -> std::result::Result<BTreeSet<EntityId>, E> {
    if rows.is_empty() {
        import()?;
        return Ok(BTreeSet::new());
    }
    let watch = Watch {
        vault: vault.store.env.path().to_path_buf(),
        rows: rows.iter().cloned().collect(),
        born: BTreeSet::new(),
    };
    let _restore = Restore(WATCH.with(|slot| slot.borrow_mut().replace(watch)));
    import()?;
    Ok(WATCH.with(|slot| {
        slot.borrow_mut()
            .as_mut()
            .map(|watch| std::mem::take(&mut watch.born))
            .unwrap_or_default()
    }))
}

/// Whether an import on this thread watches `id` in `vault` for its birth.
pub(in crate::sync) fn watches(vault: &Vault, id: &EntityId) -> bool {
    WATCH.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|watch| watch.of(vault) && watch.rows.contains_key(id))
    })
}

/// Records the rows a door wrote into `vault` where none was stored, each
/// with the bytes it wrote, once the transaction that wrote them committed.
/// Only a watched row written with its sender's bytes is a birth.
pub(in crate::sync) fn note_born<'a>(
    vault: &Vault,
    written: impl IntoIterator<Item = (EntityId, &'a [u8])>,
) {
    WATCH.with(|slot| {
        if let Some(watch) = slot.borrow_mut().as_mut()
            && watch.of(vault)
        {
            for (id, bytes) in written {
                if watch.rows.get(&id).is_some_and(|sent| sent[..] == *bytes) {
                    watch.born.insert(id);
                }
            }
        }
    });
}
