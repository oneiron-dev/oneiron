//! Bounded room-local history and transactional auxiliary-row cleanup.
use super::*;
use crate::store::Store;
use std::ops::Bound;

const HISTORY: &[u8] = b"rooms.history.v1/";
const HEADS: &[u8] = b"rooms.heads.v1/";
const RESPONSE: &[u8] = b"rooms.response.v1/";
const PAGE_LIMIT: usize = 256;

fn ordered_key(prefix: &[u8], room: EntityId, at: u64, turn: EntityId) -> Vec<u8> {
    [
        prefix,
        room.as_bytes(),
        at.to_be_bytes().as_slice(),
        turn.as_bytes(),
    ]
    .concat()
}
pub(super) fn index_turn(store: &Store, txn: &mut heed::RwTxn<'_>, turn: &RoomTurn) -> Result<()> {
    let room = EntityId::from_hex(&turn.room_id)?;
    let id = EntityId::from_hex(&turn.turn_id)?;
    store
        .vault_meta
        .put(txn, &ordered_key(HISTORY, room, turn.at, id), id.as_bytes())?;
    if turn.thread_of.is_none() {
        store
            .vault_meta
            .put(txn, &ordered_key(HEADS, room, turn.at, id), id.as_bytes())?;
    }
    Ok(())
}
fn stored_id(raw: &[u8]) -> Result<EntityId> {
    EntityId::from_bytes(
        raw.try_into()
            .map_err(|_| Error::CorruptedIndex("room history id"))?,
    )
}
pub(in crate::workspace_roster) fn delete_room_metadata(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
) -> Result<()> {
    let prefix = key(HISTORY, room);
    loop {
        let page = store
            .vault_meta
            .prefix_iter(txn, &prefix)?
            .take(PAGE_LIMIT)
            .map(|r| r.map(|(k, v)| (k.to_vec(), v.to_vec())))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if page.is_empty() {
            break;
        }
        for (row_key, raw) in page {
            let turn = stored_id(&raw)?;
            for prefix in [TURNS, CLAIMS, RESPONSE] {
                store.vault_meta.delete(txn, &key(prefix, turn))?;
            }
            store.vault_meta.delete(txn, &row_key)?;
        }
    }
    for prefix in [HEADS, HANDLES] {
        loop {
            let keys = store
                .vault_meta
                .prefix_iter(txn, &key(prefix, room))?
                .take(PAGE_LIMIT)
                .map(|r| r.map(|(k, _)| k.to_vec()))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if keys.is_empty() {
                break;
            }
            for key in keys {
                store.vault_meta.delete(txn, &key)?;
            }
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
            ordered_key(HISTORY, room, turn.at, after)
        } else {
            key(HISTORY, room)
        };
        let end = [key(HISTORY, room).as_slice(), &[u8::MAX; 24]].concat();
        let mut rows = self
            .vault()
            .store
            .vault_meta
            .range(
                &txn,
                &(
                    Bound::Excluded(start.as_slice()),
                    Bound::Included(end.as_slice()),
                ),
            )?
            .take(limit + 1)
            .map(|row| {
                let (_, raw) = row?;
                Ok(turn_in(self.vault(), &txn, stored_id(&raw)?)?)
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
        let start = key(HEADS, room);
        let end = [start.as_slice(), &[u8::MAX; 24]].concat();
        self.vault()
            .store
            .vault_meta
            .rev_range(
                &txn,
                &(
                    Bound::Included(start.as_slice()),
                    Bound::Included(end.as_slice()),
                ),
            )?
            .next()
            .map(|row| {
                let (_, raw) = row?;
                Ok(turn_in(self.vault(), &txn, stored_id(&raw)?)?)
            })
            .transpose()
    }
}

impl Memory<'_> {
    /// Complete snapshot for a room liveness fold; never silently truncates
    /// the working-set census to the first `rooms.messages` page.
    pub(super) fn room_turn_snapshot(&self, room: EntityId) -> MemoryResult<Vec<RoomTurn>> {
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        require_member(self.vault(), &txn, room, self.actor())?;
        let mut turns = Vec::new();
        for row in self
            .vault()
            .store
            .vault_meta
            .prefix_iter(&txn, &key(HISTORY, room))?
        {
            let (_, raw) = row?;
            if turns.len() == 100_000 {
                return Err(Error::IndexOverflow("room thread history").into());
            }
            turns.push(turn_in(self.vault(), &txn, stored_id(&raw)?)?);
        }
        Ok(turns)
    }

    /// Recomputes thread liveness from the current room history and TASK
    /// registers. The projection is not a vault_meta row or a cached flag.
    pub fn rooms_threads(
        &self,
        room: EntityId,
        policy: super::RoomThreadPolicy,
    ) -> MemoryResult<super::RoomThreads> {
        if policy.rows_per_list > 64 {
            return Err(MemoryError::from(invalid()));
        }
        let turns = self.room_turn_snapshot(room)?;
        let roots = turns
            .iter()
            .filter(|turn| turn.thread_of.is_some())
            .map(|turn| EntityId::from_hex(&turn.turn_id))
            .collect::<Result<std::collections::BTreeSet<_>>>()?;
        let members = self
            .vault()
            .project_room(room)?
            .ok_or_else(invalid)?
            .member_ids
            .into_iter()
            .collect();
        let tasks = crate::task_verb::room_thread_tasks(self, &roots, &members, policy.now)?;
        Ok(super::liveness::project(&turns, &tasks, policy)?)
    }

    /// Standalone room view. The Context Board ROOM section retains its four
    /// independent roster/scope/posture/claims fields (ARCH-0067 §8).
    pub fn rooms_render_threads(
        &self,
        room: EntityId,
        policy: super::RoomThreadPolicy,
    ) -> MemoryResult<Vec<String>> {
        Ok(self.rooms_threads(room, policy)?.render_rows())
    }

    /// Scoped find handle; the full set is paged even when the render is folded.
    pub fn rooms_find_threads(
        &self,
        room: EntityId,
        after: Option<EntityId>,
        limit: usize,
    ) -> MemoryResult<Vec<EntityId>> {
        if limit == 0 || limit > 256 {
            return Err(MemoryError::from(invalid()));
        }
        let turns = self.room_turn_snapshot(room)?;
        let mut roots = turns
            .iter()
            .filter(|turn| turn.thread_of.is_some())
            .map(|turn| EntityId::from_hex(&turn.turn_id))
            .collect::<Result<Vec<_>>>()?;
        roots.sort();
        if after.is_some_and(|cursor| !roots.contains(&cursor)) {
            return Err(MemoryError::from(invalid()));
        }
        Ok(roots
            .into_iter()
            .filter(|id| after.is_none_or(|cursor| *id > cursor))
            .take(limit)
            .collect())
    }

    /// Scoped get handle; reaches a thread even when every list omits it.
    pub fn rooms_get_thread(
        &self,
        room: EntityId,
        handle: EntityId,
    ) -> MemoryResult<Option<super::RoomThread>> {
        let turns = self.room_turn_snapshot(room)?;
        let roots = turns
            .iter()
            .filter(|turn| turn.thread_of.is_some())
            .map(|turn| EntityId::from_hex(&turn.turn_id))
            .collect::<Result<std::collections::BTreeSet<_>>>()?;
        if !roots.contains(&handle) {
            return Ok(None);
        }
        let members = self
            .vault()
            .project_room(room)?
            .ok_or_else(invalid)?
            .member_ids
            .into_iter()
            .collect();
        let now = crate::unix_seconds_now();
        let selected = std::collections::BTreeSet::from([handle]);
        let tasks = crate::task_verb::room_thread_tasks(self, &selected, &members, now)?;
        Ok(super::liveness::project_target(
            &turns, &tasks, handle, now,
        )?)
    }
}
