//! The rows a federated import watches for their births. A facet stamp a peer
//! sent onto a row this vault lacks counts only once that sender's own birth
//! of the row applied: the entity door wrote the row where none was stored, in
//! the transaction that committed it (Astra-b F1, Sol R10 F2 on #1432). A row
//! another writer stored first makes the sender's copy an idempotent skip, so
//! equal bytes after the import are not proof of a birth.
//!
//! Both entity doors run on the importing thread: Observer B fires inside the
//! import, and forward rematerialization is called from it.

use std::cell::RefCell;
use std::collections::BTreeSet;

use crate::EntityId;

thread_local! {
    static WATCH: RefCell<Option<Watch>> = const { RefCell::new(None) };
}

struct Watch {
    rows: BTreeSet<EntityId>,
    born: BTreeSet<EntityId>,
}

/// Puts back the watch an outer import installed, on every exit.
struct Restore(Option<Watch>);

impl Drop for Restore {
    fn drop(&mut self) {
        let outer = self.0.take();
        WATCH.with(|watch| *watch.borrow_mut() = outer);
    }
}

/// Runs `import` while the entity doors on this thread watch `rows`, and
/// returns the ones whose births it committed.
pub(in crate::sync) fn watch_births<E>(
    rows: impl IntoIterator<Item = EntityId>,
    import: impl FnOnce() -> std::result::Result<(), E>,
) -> std::result::Result<BTreeSet<EntityId>, E> {
    let rows: BTreeSet<_> = rows.into_iter().collect();
    if rows.is_empty() {
        import()?;
        return Ok(BTreeSet::new());
    }
    let watch = Watch {
        rows,
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

/// Whether an import on this thread watches `id` for its birth.
pub(in crate::sync) fn watches(id: &EntityId) -> bool {
    WATCH.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|watch| watch.rows.contains(id))
    })
}

/// Records births of watched rows, once the transaction that wrote them
/// committed.
pub(in crate::sync) fn note_born(ids: impl IntoIterator<Item = EntityId>) {
    WATCH.with(|slot| {
        if let Some(watch) = slot.borrow_mut().as_mut() {
            let rows = &watch.rows;
            watch
                .born
                .extend(ids.into_iter().filter(|id| rows.contains(id)));
        }
    });
}
