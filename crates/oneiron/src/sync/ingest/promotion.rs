//! What a promotion owes the TURNs it lands (OF-534). Demotion dropped a
//! removed TURN's tag set and sieve reading, which never sync, and the sieve's
//! cursor has passed it, so the promotion that brings the row back owes it a
//! tag pass and a sieve read, in the transaction that lands the row. A TURN
//! the demotion kept is stored here already and is owed neither.
//!
//! Every entity door runs on the importing thread (`birth_watch`), so a
//! promotion rides a thread-local for its import's span: the promotion
//! snapshot's import and the sealed mirror it materializes.
//!
//! The cold open of a window for its first promotion rides one too: its
//! reverse pass mirrors no key pad (FIX 3789). A pad another window's
//! promotion brought here would be local history in the fresh window, which
//! the promotion refuses, and the home's snapshot carries the window's pads.

use std::cell::RefCell;
use std::path::PathBuf;

use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_TURN;

thread_local! {
    static PROMOTING: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
    /// The store a window of which this thread opens for its first promotion.
    static FIRST_OPEN: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

/// Puts back the promotion an outer import marked, on every exit.
struct Restore(Option<PathBuf>);

impl Drop for Restore {
    fn drop(&mut self) {
        let outer = self.0.take();
        PROMOTING.with(|slot| *slot.borrow_mut() = outer);
    }
}

/// Runs `import` while the entity doors writing `vault` on this thread land
/// a promotion's rows.
pub(in crate::sync) fn with_promotion<T>(vault: &Vault, import: impl FnOnce() -> T) -> T {
    let path = vault.store.env.path().to_path_buf();
    let _restore = Restore(PROMOTING.with(|slot| slot.borrow_mut().replace(path)));
    import()
}

/// Whether an import on this thread lands a promotion's rows in `vault`.
pub(in crate::sync) fn promoting(vault: &Vault) -> bool {
    PROMOTING.with(|slot| slot.borrow().as_deref() == Some(vault.store.env.path()))
}

/// Puts back the first-promotion open an outer one marked, on every exit.
struct RestoreOpen(Option<PathBuf>);

impl Drop for RestoreOpen {
    fn drop(&mut self) {
        let outer = self.0.take();
        FIRST_OPEN.with(|slot| *slot.borrow_mut() = outer);
    }
}

/// Runs `open`, the open of a window of `vault` for its first promotion
/// here, while the reverse pass on this thread mirrors no key pad.
pub(in crate::sync) fn with_first_promotion_open<T>(vault: &Vault, open: impl FnOnce() -> T) -> T {
    let path = vault.store.env.path().to_path_buf();
    let _restore = RestoreOpen(FIRST_OPEN.with(|slot| slot.borrow_mut().replace(path)));
    open()
}

/// Whether this thread opens a window of `vault` for its first promotion.
pub(in crate::sync) fn first_promotion_open(vault: &Vault) -> bool {
    FIRST_OPEN.with(|slot| slot.borrow().as_deref() == Some(vault.store.env.path()))
}

/// Owes the row `blob` an entity door wrote at `id` in `wtxn`, where no row
/// was stored, under a promotion on this thread: a TURN its tag pass and
/// sieve read ([`crate::store::local_replica::owe_promoted_turn_in_txn`]).
pub(in crate::sync) fn owe_landed_turn_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: EntityId,
    blob: &[u8],
) -> Result<()> {
    if EntityMetadataHeader::parse(blob)
        .is_some_and(|header| header.entity_type == ENTITY_TYPE_TURN)
    {
        crate::store::local_replica::owe_promoted_turn_in_txn(vault, wtxn, &id)?;
    }
    Ok(())
}
