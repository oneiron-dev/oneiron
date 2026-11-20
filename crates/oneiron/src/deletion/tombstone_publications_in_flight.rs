//! The soft deletes whose `pt:` pending-tombstone marker has committed with
//! their scrub while their own publication has not finished.
//!
//! The soft arm commits its marker in its scrub transaction, so a crash
//! between the scrub and the publication still publishes the delete at the
//! window's next load. While the process lives, the publication that follows
//! re-proves the delete's authority and withdraws the marker on refusal, and a
//! replay of the marker in that span (a window open, another door's
//! `publish_pending_tombstones`, a window replacement) would publish it with
//! no re-proof. Each replay reader therefore leaves a marker held here to its
//! publication, and the reverse pass reads its id as the tombstone that
//! publication writes. The set belongs to the vault's store, not to the
//! process, and a crash empties it.

use std::collections::BTreeSet;
use std::sync::{Mutex, MutexGuard, PoisonError};

use super::tombstone::{TOMBSTONE_VALUE_V2_LEN, TombstoneValueV2};
use crate::entity_id::EntityId;

/// A held marker: its window label, its entity and its exact wire value,
/// which names the deletion request.
type HeldMarker = (String, EntityId, [u8; TOMBSTONE_VALUE_V2_LEN]);

/// The markers whose publication is in flight on this vault.
#[derive(Default)]
pub(crate) struct TombstonePublicationsInFlight {
    markers: Mutex<BTreeSet<HeldMarker>>,
}

impl TombstonePublicationsInFlight {
    /// Holds the marker `value` at `id` in `window_label` until the returned
    /// guard drops. Taken before the transaction that commits the marker, so
    /// no replay reads the marker before it is held.
    pub(crate) fn hold(
        &self,
        window_label: &str,
        id: &EntityId,
        value: &TombstoneValueV2,
    ) -> TombstonePublicationInFlight<'_> {
        let marker = (window_label.to_owned(), *id, value.encode());
        self.markers().insert(marker.clone());
        TombstonePublicationInFlight {
            publications: self,
            marker,
        }
    }

    /// Whether the marker `raw` at `id` in `window_label` waits for its own
    /// publication.
    pub(crate) fn holds_marker(&self, window_label: &str, id: &EntityId, raw: &[u8]) -> bool {
        let Ok(value) = <[u8; TOMBSTONE_VALUE_V2_LEN]>::try_from(raw) else {
            return false;
        };
        self.markers()
            .contains(&(window_label.to_owned(), *id, value))
    }

    /// The ids whose publication into `window_label` is in flight.
    pub(crate) fn entities_in(&self, window_label: &str) -> BTreeSet<EntityId> {
        self.markers()
            .iter()
            .filter(|(window, _, _)| window == window_label)
            .map(|(_, id, _)| *id)
            .collect()
    }

    fn markers(&self) -> MutexGuard<'_, BTreeSet<HeldMarker>> {
        self.markers.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One soft delete's hold on its marker. It drops once the publication and
/// the marker's retirement have run, or at any error before then, which
/// leaves a marker still committed to the next replay as a crash would.
pub(crate) struct TombstonePublicationInFlight<'a> {
    publications: &'a TombstonePublicationsInFlight,
    marker: HeldMarker,
}

impl Drop for TombstonePublicationInFlight<'_> {
    fn drop(&mut self) {
        self.publications.markers().remove(&self.marker);
    }
}
