//! Bounded room-local history and transactional auxiliary-row cleanup.
use super::*;
use crate::store::Store;
use std::ops::Bound;

const HISTORY: &[u8] = b"rooms.history.v1/";
const HEADS: &[u8] = b"rooms.heads.v1/";
pub(in crate::workspace_roster) const THREAD_CHILDREN: &[u8] = b"rooms.thread_children.v1/";
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
    if let Some(parent) = &turn.thread_of {
        let parent = EntityId::from_hex(parent)?;
        let key = [
            THREAD_CHILDREN,
            room.as_bytes(),
            parent.as_bytes(),
            id.as_bytes(),
        ]
        .concat();
        store.vault_meta.put(txn, &key, id.as_bytes())?;
    } else {
        store
            .vault_meta
            .put(txn, &ordered_key(HEADS, room, turn.at, id), id.as_bytes())?;
    }
    Ok(())
}
fn turn_in_raw(store: &Store, txn: &heed::RoTxn<'_>, turn: EntityId) -> Result<RoomTurn> {
    let raw = store
        .vault_meta
        .get(txn, &key(TURNS, turn))?
        .ok_or(Error::CorruptedIndex("room turn"))?;
    decode(&raw)
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
            let stored = turn_in_raw(store, txn, turn)?;
            if let Some(parent) = stored.thread_of {
                let parent = EntityId::from_hex(&parent)?;
                store.vault_meta.delete(
                    txn,
                    &[
                        THREAD_CHILDREN,
                        room.as_bytes(),
                        parent.as_bytes(),
                        turn.as_bytes(),
                    ]
                    .concat(),
                )?;
            }
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
    /// Bounded first trunk page: the original thread is a pointer card,
    /// followed by trunk turns. Thread replies never consume trunk slots.
    pub fn room_trunk(&self, room: EntityId) -> MemoryResult<Vec<RoomTrunkItem>> {
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        let project_room = require_member(self.vault(), &txn, room, self.actor())?;
        let origin = project_room.origin;
        let mut entries = Vec::with_capacity(PAGE_LIMIT + usize::from(origin.is_some()));
        if let Some(origin) = origin {
            entries.push(RoomTrunkItem::Origin(origin));
        }
        for row in self
            .vault()
            .store
            .vault_meta
            .prefix_iter(&txn, &key(HEADS, room))?
            .take(PAGE_LIMIT)
        {
            let (_, raw) = row?;
            entries.push(RoomTrunkItem::Turn(turn_in(
                self.vault(),
                &txn,
                stored_id(&raw)?,
            )?));
        }
        Ok(entries)
    }

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
