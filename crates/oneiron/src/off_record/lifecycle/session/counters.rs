//! A room's additive side-table counters (FIX 4415): the overlay-local
//! delta and the base value, read apart so a counter adds both instead of
//! taking the overlay's shadow. Moved out of the session module whole.

use super::super::registry::session_entry_state;
use super::OffRecordSession;
use crate::error::{Error, OffRecordError, Result};
use crate::session_overlay::{OverlayKeyspace, SnapshotLookup};
use crate::side_table::{SideCodec, SideKey, SideTable};

impl OffRecordSession<'_> {
    /// This room's overlay-local contribution to an additive counter row;
    /// `None` when the overlay holds no row for it.
    pub(super) fn overlay_counter_delta<K: SideKey, V, C: SideCodec<V>>(
        &self,
        counter: &SideTable<K, V, C>,
        key: &K,
    ) -> Result<Option<V>> {
        match self
            .entry
            .overlay
            .snapshot()?
            .lookup_single(OverlayKeyspace::VaultMeta, &counter.key_bytes(key))
        {
            SnapshotLookup::Present(value) => counter.decode_value(&value).map(Some),
            SnapshotLookup::Passthrough | SnapshotLookup::Tombstone => Ok(None),
        }
    }

    /// The base and room-overlay components of an additive side-table
    /// counter. Ordinary composed reads intentionally keep shadow semantics;
    /// only additive counters opt into this explicit merge (FIX 4415). A
    /// stretch found closing or gone once both are read is refused as
    /// closing: a drained overlay never reads as a zero delta beside base.
    pub(crate) fn side_table_counter_components<K: SideKey, V, C: SideCodec<V>>(
        &self,
        counter: &SideTable<K, V, C>,
        key: &K,
    ) -> Result<(Option<V>, Option<V>)> {
        let overlay = self.overlay_counter_delta(counter, key)?;
        let rtxn = self.vault.store.env.read_txn()?;
        self.participant_in_txn(&rtxn)?;
        let base = counter.get(&self.vault.store, &rtxn, key)?;
        drop(rtxn);
        let state = session_entry_state(&self.entry)?;
        if state.record.closing || state.gone || state.overlay_closed {
            return Err(Error::OffRecord(OffRecordError::OffRecordSessionClosing {
                session_ref: self.session_ref.clone(),
            }));
        }
        Ok((base, overlay))
    }
}
