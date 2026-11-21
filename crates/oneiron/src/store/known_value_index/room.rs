//! The matcher a compare inside an off-record room reads
//! (ROOM-LOCAL-CUSTODY): base custody's values, and beside them each value
//! the room keeps in its own custody, under its room handle. A row the room
//! holds is read against a call made again as a template, as a base row is
//! (FIX REPLAY-COMPARE-KNOWN-MATCHER): its room handle meets the value the
//! room keeps under it, and no other value. Outside the room no matcher
//! holds a room value, so a room handle meets only itself there.

use std::sync::Arc;

use heed::{RoTxn, RwTxn};
use rand_core::RngCore;
use zeroize::Zeroizing;

use super::{Keys, KnownValues, ValueOrigin};
use crate::error::{Error, Result};
use crate::ports::ShortIdStoreRead;
use crate::session_overlay::{KeptRoomSecret, SessionOverlay};
use crate::store::{KnownHistory, Store};
use crate::vault::Vault;

impl Vault {
    /// [`Self::known_values_now`] for a compare inside the off-record room
    /// whose overlay is `room` (see the module notes). Each room value is
    /// printed under base's master, or under a random one while base keys
    /// no value, in this matcher alone, which wipes its prints when it
    /// drops: the known-value index learns none of them. `None` when
    /// neither base nor the room knows a value.
    ///
    /// # Errors
    ///
    /// The custody snapshot's, or the index's read.
    pub(crate) fn known_values_with_room(
        &self,
        room: &SessionOverlay,
    ) -> Result<Option<Arc<KnownValues>>> {
        let kept = room.kept_room_secrets()?;
        if kept.is_empty() {
            return self.known_values_now();
        }
        let snapshot = self.store.custody_snapshot()?;
        let txn: &RoTxn<'_> = &snapshot;
        let history = self.store.known_history_in_snapshot(txn)?;
        let known = with_room_values(&self.store, txn, history.as_ref(), &kept)?;
        // The prints and entries drop before the snapshot and its guard.
        drop(kept);
        drop(history);
        drop(snapshot);
        Ok(known.map(Arc::new))
    }
}

impl KnownValues {
    /// [`Self::shared_in_writer`] for an erase inside the off-record room
    /// whose overlay is `room` (REVIEW-10003): base custody's values as the
    /// writer `wtxn` reads them, and beside them each value the room keeps,
    /// under its room handle, printed as [`Vault::known_values_with_room`]
    /// prints them. A request the erase rewrites keeps the identity of a
    /// room value it names as exactly as a base value's; the known-value
    /// index learns none of them.
    ///
    /// # Errors
    ///
    /// The index's read in the writer.
    pub(crate) fn with_room_in_writer(
        store: &Store,
        wtxn: &RwTxn<'_>,
        room: &SessionOverlay,
    ) -> Result<Option<Arc<Self>>> {
        let kept = room.kept_room_secrets()?;
        if kept.is_empty() {
            return Self::shared_in_writer(store, wtxn);
        }
        let history = store.known_history_in_writer(wtxn)?;
        let txn: &RoTxn<'_> = wtxn;
        Ok(with_room_values(store, txn, history.as_ref(), &kept)?.map(Arc::new))
    }
}

/// A matcher of the values `history`, base custody's as `txn` reads it,
/// holds, and beside them each value of `kept` under its room handle,
/// printed under base's master or, while base keys no value, a random one.
/// `None` when it holds no value.
fn with_room_values(
    store: &Store,
    txn: &RoTxn<'_>,
    history: Option<&KnownHistory>,
    kept: &[KeptRoomSecret],
) -> Result<Option<KnownValues>> {
    let mut base = Vec::new();
    let master = match history {
        Some(history) => {
            for (custody, entries) in &history.holders {
                let Some((handle, _)) = store.port_short_id_reference(txn, custody)? else {
                    continue;
                };
                base.push((*custody, entries, handle));
            }
            history.master.clone()
        }
        None => {
            let mut master = Zeroizing::new([0; 32]);
            rand_core::OsRng.fill_bytes(&mut *master);
            master
        }
    };
    let keys = Keys::derive(&master);
    let mut room_entries = Vec::with_capacity(kept.len());
    for secret in kept {
        if secret.value.is_empty() {
            continue;
        }
        let len = u32::try_from(secret.value.len())
            .map_err(|_| Error::ArithmeticOverflow("known value length"))?;
        room_entries.push((
            keys.entry(&secret.value, len),
            secret.record,
            secret.handle.clone(),
        ));
    }
    let values = base
        .iter()
        .flat_map(|(custody, entries, handle)| {
            entries.iter().map(move |(generation, entry)| {
                (
                    entry,
                    *generation,
                    ValueOrigin::Custody(*custody),
                    handle.clone(),
                )
            })
        })
        .chain(room_entries.iter().map(|(entry, record, handle)| {
            (entry, 0, ValueOrigin::Custody(*record), handle.clone())
        }));
    let known = KnownValues::of_entries(&master, values)?;
    drop(room_entries);
    drop(base);
    Ok(known)
}
