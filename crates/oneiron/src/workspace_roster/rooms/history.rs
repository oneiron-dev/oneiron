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

impl Memory<'_> {
    /// Complete snapshot for a room liveness fold; never silently truncates
    /// the working-set census to the first `rooms.messages` page.
    pub(super) fn room_turn_snapshot(&self, room: EntityId) -> MemoryResult<Vec<RoomTurn>> {
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        require_member(self.vault(), &txn, room, self.actor())?;
        let mut turns = Vec::new();
        for row in HISTORY.iter_from(&self.vault().store, &txn, room.as_bytes())? {
            let (_, turn_id) = row?;
            if turns.len() == 100_000 {
                return Err(Error::IndexOverflow("room thread history").into());
            }
            turns.push(turn_in(self.vault(), &txn, turn_id)?);
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
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        let settings = crate::gate::resolve_policy_manifest(&self.vault().store, &txn)?
            .room_thread_settings(self.actor())?;
        drop(txn);
        let policy = policy.narrowed(settings);
        let turns = self.room_turn_snapshot(room)?;
        let roots = super::liveness::thread_root_map(&turns)?;
        let members = self
            .vault()
            .project_room(room)?
            .ok_or_else(invalid)?
            .member_ids
            .into_iter()
            .collect();
        let tasks = crate::task_verb::room_thread_tasks(self, &roots, &members, policy.now)?;
        Ok(super::liveness::project_in_room(
            &turns, &tasks, policy, room,
        )?)
    }

    /// Standalone room view. The Context Board ROOM section retains its four
    /// independent roster/scope/posture/claims fields (ARCH-0067 §8).
    pub fn rooms_render_threads(
        &self,
        room: EntityId,
        policy: super::RoomThreadPolicy,
    ) -> MemoryResult<Vec<String>> {
        Ok(self.rooms_threads(room, policy)?.render_rows(room))
    }

    /// Read one trunk turn with the completed TASK result headers that hang
    /// under it. The only write is the existing TASK terminal register: every
    /// read joins that fact to the room's thread anchors, including after
    /// replay, without duplicating a result into a synthetic message or a
    /// local liveness cache. Task and result visibility use scoped reads.
    pub fn rooms_trunk(&self, room: EntityId, trunk: EntityId) -> MemoryResult<super::RoomTrunk> {
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        let members = require_member(self.vault(), &txn, room, self.actor())?
            .member_ids
            .into_iter()
            .collect();
        let turn = turn_in(self.vault(), &txn, trunk)?;
        if turn.room_id != room.to_hex() || turn.thread_of.is_some() {
            return Err(MemoryError::from(invalid()));
        }
        drop(txn);
        let turns = self.room_turn_snapshot(room)?;
        let trunk_hex = trunk.to_hex();
        let root_ids = turns
            .iter()
            .filter(|turn| {
                super::liveness::is_thread_root(turn)
                    && turn.thread_of.as_deref() == Some(trunk_hex.as_str())
            })
            .map(|turn| EntityId::from_hex(&turn.turn_id))
            .collect::<Result<std::collections::BTreeSet<_>>>()?;
        let roots = super::liveness::thread_root_map(&turns)?
            .into_iter()
            .filter(|(_, root)| root_ids.contains(root))
            .collect();
        let tasks =
            crate::task_verb::room_thread_tasks(self, &roots, &members, crate::unix_seconds_now())?;
        let mut headers = tasks
            .into_iter()
            .filter_map(|task| {
                task.delivered
                    .map(|(result_ref, _)| super::RoomTrunkHeader {
                        thread: task.thread,
                        task: task.task,
                        result_ref,
                    })
            })
            .collect::<Vec<_>>();
        headers.sort_by_key(|header| (header.thread, header.task));
        Ok(super::RoomTrunk { turn, headers })
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
            .filter(|turn| super::liveness::is_thread_root(turn))
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

    /// Exact page end for SDK cursors, including a full final page.
    pub fn rooms_find_threads_page(
        &self,
        room: EntityId,
        after: Option<EntityId>,
        limit: usize,
    ) -> MemoryResult<super::RoomThreadPage> {
        let rows = self.rooms_find_threads(room, after, limit)?;
        let next_after = if rows.len() == limit
            && !self
                .rooms_find_threads(room, rows.last().copied(), 1)?
                .is_empty()
        {
            rows.last().copied()
        } else {
            None
        };
        Ok(super::RoomThreadPage { rows, next_after })
    }

    /// Scoped get handle; reaches a thread even when every list omits it.
    pub fn rooms_get_thread(
        &self,
        room: EntityId,
        handle: EntityId,
    ) -> MemoryResult<Option<super::RoomThread>> {
        let turns = self.room_turn_snapshot(room)?;
        let roots = super::liveness::thread_root_map(&turns)?;
        if !roots.contains_key(&handle) || roots.get(&handle) != Some(&handle) {
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
        let selected = roots
            .into_iter()
            .filter(|(_, root)| *root == handle)
            .collect();
        let tasks = crate::task_verb::room_thread_tasks(self, &selected, &members, now)?;
        Ok(super::liveness::project_target(
            &turns, &tasks, handle, now,
        )?)
    }
}
