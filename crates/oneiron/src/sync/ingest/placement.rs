//! The birth placements a guest's admitted update carries for its TASK and
//! SUMMARY rows (FIX 3656), landed beside each row in the transaction whose
//! put lands that row here first.
//!
//! Federation admission validates each carried placement against the row it
//! rides with and remaps its world into the guest's foreign WORLD copy
//! (`selector::admission`). The validated placements stay out of the admitted
//! Loro bytes: they ride the import's span on its thread, as a delivery does
//! (`delivery`), each bound to its window, its row and the digest of the exact
//! bytes admission admitted. Every entity door runs on the importing thread
//! (`birth_watch`). Nothing here outlives the import or travels in the
//! window: a forward pass, a window open and a staged confirmation replay
//! persisted bytes with no placement, so those rows stay unstamped, as a row
//! its sender carried no placement for does.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::entity_id::EntityId;
use crate::federation::record_scope::GuestPlacement;
use crate::sync::types::WindowKey;
use crate::vault::Vault;

/// Each row an admitted part brings that its sender carried a birth
/// placement for: the digest of the bytes admission admitted for the row,
/// and the placement as admission validated it.
pub(in crate::sync) type AdmittedPlacements = BTreeMap<EntityId, ([u8; 32], GuestPlacement)>;

thread_local! {
    static PLACEMENTS: RefCell<Option<PlacementSpan>> = const { RefCell::new(None) };
}

/// One import's placements: the vault and window it lands in, and its rows'.
struct PlacementSpan {
    vault: PathBuf,
    window: String,
    rows: AdmittedPlacements,
}

/// Puts back the span an outer import installed, on every exit.
struct Restore(Option<PlacementSpan>);

impl Drop for Restore {
    fn drop(&mut self) {
        let outer = self.0.take();
        PLACEMENTS.with(|slot| *slot.borrow_mut() = outer);
    }
}

/// Runs `land`, which imports a part admission admitted into the window
/// `window`, while the entity doors on this thread land `placements` beside
/// their rows. With none, no door `land` runs lands a placement, whatever
/// import encloses it.
pub(in crate::sync) fn with_placements<T>(
    vault: &Vault,
    window: &WindowKey,
    placements: &AdmittedPlacements,
    land: impl FnOnce() -> T,
) -> T {
    let span = (!placements.is_empty()).then(|| PlacementSpan {
        vault: vault.store.env.path().to_path_buf(),
        window: window.as_str().to_owned(),
        rows: placements.clone(),
    });
    let _restore =
        Restore(PLACEMENTS.with(|slot| std::mem::replace(&mut *slot.borrow_mut(), span)));
    land()
}

/// The placement the import on this thread carries for the row keyed `key`
/// of the window `window_key` in `vault`, when `blob` is the exact bytes
/// admission admitted for that row.
pub(super) fn carried_for(
    vault: &Vault,
    window_key: &str,
    key: &str,
    blob: Option<&[u8]>,
) -> Option<(EntityId, GuestPlacement)> {
    let blob = blob?;
    PLACEMENTS.with(|slot| {
        let slot = slot.borrow();
        let span = slot.as_ref()?;
        if span.vault != vault.store.env.path() || span.window != window_key {
            return None;
        }
        let id = EntityId::from_hex(key)
            .ok()
            .filter(|id| id.to_hex() == key)?;
        let (sent, placement) = span.rows.get(&id)?;
        (*sent == *blake3::hash(blob).as_bytes()).then_some((id, *placement))
    })
}
