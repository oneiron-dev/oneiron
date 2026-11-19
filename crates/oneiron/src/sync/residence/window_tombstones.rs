//! A window's tombstone id set: what a residence read serves a device that
//! follows the window's world, so the device writes the delete marker even
//! for a window it never held (FOLLOWED-WORLD-TIER1-TOMBSTONE-IDS; canon
//! ARCH-0023b :500).
//!
//! The set is the tombstones map of the selector export a granted window sync
//! sends to the same machine, and nothing else: an id leaves only where that
//! export's own rule lets its tombstone travel, row by row (a narrower
//! grant's captured delete scope, FIX 10161; the member's relationship read
//! the delete captured, SELECTOR-TOMBSTONE-LABEL; a device-only claim), so
//! the set names no row the device could not read and reveals nothing a
//! refused window hides. A world kept off the machine is withheld whole: its
//! windows give no ids (Engine ANSWER FOLLOWED-WORLD-TOMBSTONE-IDS-FIX-OR-PARK
//! = A, Thu 19 Nov 12:44).

use loro::LoroDoc;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::FederationGrantScope;
use crate::sync::loro_support::map_for_each_tombstone_value;
use crate::sync::selector::{SyncSelector, filtered_window_doc_for};
use crate::sync::types::WindowKey;
use crate::sync::window::Withhold;

/// One tombstone of a window's id set: the deleted row's id and the raw value
/// the window keeps for it, whose reason the receiving replay reads (a soft
/// delete stays soft).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowTombstoneEntry {
    pub entity_id: EntityId,
    pub value: Vec<u8>,
}

/// The tombstones of `source` that the selector's export carries to the
/// machine `withhold` describes, in ascending id order. A key in another hex
/// case names the same row (ONE-1158) and is answered under the row's
/// canonical id; where both casings carry one, the canonical key's value is
/// kept.
///
/// # Errors
///
/// The selector export's: a grant that does not authorize the selector, or a
/// storage error.
pub fn window_tombstone_projection_with(
    vault: &Vault,
    source: &LoroDoc,
    window: &WindowKey,
    scope: FederationGrantScope,
    selector: &SyncSelector,
    withhold: Withhold<'_>,
) -> Result<Vec<WindowTombstoneEntry>> {
    let selected = filtered_window_doc_for(vault, source, window, scope, selector, withhold)?;
    // Keyed by the canonical id: its hex order is the row order a cursor
    // pages by. The flag says the value came under the canonical key.
    let mut entries = std::collections::BTreeMap::<String, (EntityId, bool, Vec<u8>)>::new();
    map_for_each_tombstone_value(&selected.get_map("tombstones"), |key, value| {
        let Ok(id) = EntityId::from_hex(key) else {
            return;
        };
        let canonical = id.to_hex();
        let exact = canonical == key;
        if entries
            .get(&canonical)
            .is_some_and(|(_, held_exact, _)| *held_exact || !exact)
        {
            return;
        }
        entries.insert(canonical, (id, exact, value.to_vec()));
    });
    Ok(entries
        .into_values()
        .map(|(entity_id, _, value)| WindowTombstoneEntry { entity_id, value })
        .collect())
}
