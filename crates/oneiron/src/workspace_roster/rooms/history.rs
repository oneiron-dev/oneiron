//! Bounded room-local history and transactional auxiliary-row cleanup.
use super::*;
use crate::store::Store;

const PAGE_LIMIT: usize = 256;

pub(super) fn index_turn(store: &Store, txn: &mut heed::RwTxn<'_>, turn: &RoomTurn) -> Result<()> {
    let room = EntityId::from_hex(&turn.room_id)?;
    let id = EntityId::from_hex(&turn.turn_id)?;
    HISTORY.put(store, txn, &(room, turn.at, id), &id)?;
    if turn.thread_of.is_none() {
        HEADS.put(store, txn, &(room, turn.at, id), &id)?;
    }
    Ok(())
}
/// Deletes every auxiliary row a room owns, paged in [`PAGE_LIMIT`]-sized
/// chunks so no single collect-then-delete pass has to hold an unbounded
/// number of keys for a room with a long history.
pub(in crate::workspace_roster) fn delete_room_metadata(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
) -> Result<()> {
    loop {
        let page: Vec<((EntityId, u64, EntityId), EntityId)> = HISTORY
            .iter_from(store, txn, room.as_bytes())?
            .take(PAGE_LIMIT)
            .collect::<Result<Vec<_>>>()?;
        if page.is_empty() {
            break;
        }
        for (row_key, turn) in page {
            TURNS.delete(store, txn, &turn)?;
            CLAIMS.delete(store, txn, &turn)?;
            RESPONSE.delete(store, txn, &turn)?;
            HISTORY.delete(store, txn, &row_key)?;
        }
    }
    loop {
        let keys: Vec<(EntityId, u64, EntityId)> = HEADS
            .iter_from(store, txn, room.as_bytes())?
            .take(PAGE_LIMIT)
            .map(|row| row.map(|(key, _)| key))
            .collect::<Result<Vec<_>>>()?;
        if keys.is_empty() {
            break;
        }
        for key in &keys {
            HEADS.delete(store, txn, key)?;
        }
    }
    loop {
        let keys: Vec<(EntityId, String)> = HANDLES
            .iter_from(store, txn, room.as_bytes())?
            .take(PAGE_LIMIT)
            .map(|row| row.map(|(key, _)| key))
            .collect::<Result<Vec<_>>>()?;
        if keys.is_empty() {
            break;
        }
        for key in &keys {
            HANDLES.delete(store, txn, key)?;
        }
    }
    Ok(())
}
impl Memory<'_> {
    /// First bounded page in chronological order. Continue with the last turn's
    /// id through `rooms_messages_page`; room membership is rechecked per page.
    pub fn rooms_messages(&self, room: EntityId) -> MemoryResult<Vec<RoomTurn>> {
        Ok(self.rooms_messages_page(room, None, PAGE_LIMIT)?.rows)
    }
    pub fn rooms_messages_page(
        &self,
        room: EntityId,
        after: Option<EntityId>,
        limit: usize,
    ) -> MemoryResult<RoomPage> {
        if limit == 0 || limit > PAGE_LIMIT {
            return Err(MemoryError::from(invalid()));
        }
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        require_member(self.vault(), &txn, room, self.actor())?;
        let start = if let Some(after) = after {
            let turn = turn_in(self.vault(), &txn, after)?;
            if turn.room_id != room.to_hex() {
                return Err(MemoryError::from(invalid()));
            }
            Some((turn.at, after))
        } else {
            None
        };
        let mut rows = HISTORY
            .iter_from(&self.vault().store, &txn, room.as_bytes())?
            .skip_while(|row| match (start, row) {
                (Some(start), Ok(((_, at, id), _))) => (*at, *id) <= start,
                _ => false,
            })
            .take(limit + 1)
            .map(|row| {
                let (_, turn_id) = row?;
                Ok(turn_in(self.vault(), &txn, turn_id)?)
            })
            .collect::<MemoryResult<Vec<_>>>()?;
        let has_more = rows.len() > limit;
        rows.truncate(limit);
        let next_after = if has_more {
            rows.last().map(|turn| turn.turn_id.clone())
        } else {
            None
        };
        Ok(RoomPage { rows, next_after })
    }
    /// Canonical HEAD is a room-local indexed read; branch turns are excluded.
    pub fn room_head(&self, room: EntityId) -> MemoryResult<Option<RoomTurn>> {
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        require_member(self.vault(), &txn, room, self.actor())?;
        HEADS
            .iter_rev_from(&self.vault().store, &txn, room.as_bytes())?
            .next()
            .map(|row| {
                let (_, turn_id) = row?;
                Ok(turn_in(self.vault(), &txn, turn_id)?)
            })
            .transpose()
    }
}
