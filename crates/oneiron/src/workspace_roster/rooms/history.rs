//! Bounded room-local history and transactional auxiliary-row cleanup.
use super::*;
use crate::store::Store;

const PAGE_LIMIT: usize = 256;
/// History rows one page reads at most, across all its windows. A page that
/// would read more refuses, rather than return a short page that claims the
/// history ended.
const HISTORY_SCAN_CEILING: usize = 100_000;

/// One HISTORY row: its `(room, at, turn)` key and the turn id.
type HistoryRow = Result<((EntityId, u64, EntityId), EntityId)>;

pub(super) fn index_turn(store: &Store, txn: &mut heed::RwTxn<'_>, turn: &RoomTurn) -> Result<()> {
    let room = EntityId::from_hex(&turn.room_id)?;
    let id = EntityId::from_hex(&turn.turn_id)?;
    HISTORY.put(store, txn, &(room, turn.at, id), &id)?;
    if let Some(parent) = &turn.thread_of {
        let parent = EntityId::from_hex(parent)?;
        THREAD_CHILDREN.put(store, txn, &(room, parent, id), &id)?;
    } else {
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
            let stored = TURNS
                .get(store, txn, &turn)?
                .ok_or(Error::CorruptedIndex("room turn"))?;
            if let Some(parent) = stored.thread_of {
                let parent = EntityId::from_hex(&parent)?;
                THREAD_CHILDREN.delete(store, txn, &(room, parent, turn))?;
            }
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
    /// The turns among `turns` this reader may read. Membership admits none
    /// of them: each passes the reader's own read lane, which inside a room
    /// turn is the room's lane, so every other member's read binds it too. A
    /// turn is kept only when its TURN record and the turns it answers are
    /// admitted, and it names only the messages, tasks and project the lane
    /// admits as well.
    pub(super) fn admitted_turns(&self, turns: Vec<RoomTurn>) -> MemoryResult<Vec<RoomTurn>> {
        if turns.is_empty() {
            return Ok(turns);
        }
        let ids: BTreeSet<EntityId> = turns
            .iter()
            .flat_map(|turn| {
                [&turn.turn_id]
                    .into_iter()
                    .chain(&turn.reply_to)
                    .chain(&turn.thread_of)
                    .chain(&turn.message_ids)
                    .chain(&turn.task_ids)
                    .chain(&turn.converted_project)
            })
            .filter_map(|id| EntityId::from_hex(id).ok())
            .collect();
        let ids: Vec<_> = ids.into_iter().collect();
        let lane = self.read_lane(crate::claim::ClaimReadStatus::Recorded)?;
        let mut admitted = BTreeSet::<EntityId>::new();
        for chunk in ids.chunks(128) {
            let reads: Vec<_> = chunk
                .iter()
                .copied()
                .map(crate::claim::PointRead::id)
                .collect();
            let rows = lane.read(&reads, None)?.value;
            admitted.extend(
                chunk
                    .iter()
                    .zip(rows)
                    .filter_map(|(id, row)| row.map(|_| *id)),
            );
        }
        let readable = |id: &String| EntityId::from_hex(id).is_ok_and(|id| admitted.contains(&id));
        Ok(turns
            .into_iter()
            .filter(|turn| {
                readable(&turn.turn_id)
                    && turn.reply_to.iter().all(readable)
                    && turn.thread_of.iter().all(readable)
            })
            .map(|mut turn| {
                turn.message_ids.retain(readable);
                turn.task_ids.retain(readable);
                turn.converted_project = turn.converted_project.filter(readable);
                turn
            })
            .collect())
    }

    /// Bounded first trunk page: the original thread is a pointer card,
    /// followed by trunk turns. Thread replies never consume trunk slots.
    pub fn room_trunk(&self, room: EntityId) -> MemoryResult<Vec<RoomTrunkItem>> {
        let scope = self.room_read_scope(room)?;
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        let project_room = require_member(self.vault(), &txn, room, self.actor())?;
        if !turns_readable(&scope) {
            return Ok(Vec::new());
        }
        let heads = HEADS
            .iter_from(&self.vault().store, &txn, room.as_bytes())?
            .take(PAGE_LIMIT)
            .map(|row| Ok(turn_in(self.vault(), &txn, row?.1)?))
            .collect::<MemoryResult<Vec<_>>>()?;
        drop(txn);
        // The origin card is the room record's own field.
        let origin = match project_room.origin {
            Some(origin) if self.room_record_readable(room)? => Some(origin),
            _ => None,
        };
        let mut entries = Vec::with_capacity(PAGE_LIMIT + usize::from(origin.is_some()));
        if let Some(origin) = origin {
            entries.push(RoomTrunkItem::Origin(origin));
        }
        entries.extend(
            self.admitted_turns(heads)?
                .into_iter()
                .map(RoomTrunkItem::Turn),
        );
        Ok(entries)
    }

    /// First bounded page in chronological order. Continue with the last turn's
    /// id through `rooms_messages_page`; room membership is rechecked per page.
    pub fn rooms_messages(&self, room: EntityId) -> MemoryResult<Vec<RoomTurn>> {
        Ok(self.rooms_messages_page(room, None, PAGE_LIMIT)?.rows)
    }
    /// One page of the turns this reader may read. A withheld turn never
    /// fills a slot or becomes the cursor, and a cursor must be a turn the
    /// reader may read.
    pub fn rooms_messages_page(
        &self,
        room: EntityId,
        after: Option<EntityId>,
        limit: usize,
    ) -> MemoryResult<RoomPage> {
        if limit == 0 || limit > PAGE_LIMIT {
            return Err(MemoryError::from(invalid()));
        }
        let scope = self.room_read_scope(room)?;
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        require_member(self.vault(), &txn, room, self.actor())?;
        if !turns_readable(&scope) {
            return Ok(RoomPage {
                rows: Vec::new(),
                next_after: None,
                scope,
            });
        }
        let cursor = after
            .map(|after| turn_in(self.vault(), &txn, after))
            .transpose()?;
        drop(txn);
        let mut start = match cursor {
            Some(turn) if turn.room_id == room.to_hex() => {
                let at = turn.at;
                if self.admitted_turns(vec![turn])?.is_empty() {
                    return Err(MemoryError::from(invalid()));
                }
                after.map(|after| (at, after))
            }
            Some(_) => return Err(MemoryError::from(invalid())),
            None => None,
        };
        let mut rows = Vec::new();
        let mut window = limit + 1;
        let mut read = 0;
        loop {
            let scanned = self.history_after(room, start, window)?;
            let exhausted = scanned.len() < window;
            read += scanned.len();
            start = scanned.last().map(|(key, _)| *key).or(start);
            rows.extend(self.admitted_turns(scanned.into_iter().map(|(_, turn)| turn).collect())?);
            if rows.len() > limit || exhausted {
                break;
            }
            if read >= HISTORY_SCAN_CEILING {
                return Err(Error::IndexOverflow("room history page").into());
            }
            window = window.saturating_mul(2).min(PAGE_LIMIT * 16);
        }
        let has_more = rows.len() > limit;
        rows.truncate(limit);
        let next_after = if has_more {
            rows.last().map(|turn| turn.turn_id.clone())
        } else {
            None
        };
        Ok(RoomPage {
            rows,
            next_after,
            scope,
        })
    }

    /// Up to `window` history rows after `start`, each with its index key,
    /// from a snapshot in which the reader still belongs to the room. The
    /// snapshot closes before the caller admits any of them.
    pub(super) fn history_after(
        &self,
        room: EntityId,
        start: Option<(u64, EntityId)>,
        window: usize,
    ) -> MemoryResult<Vec<((u64, EntityId), RoomTurn)>> {
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        require_member(self.vault(), &txn, room, self.actor())?;
        let store = &self.vault().store;
        // Seek straight past `start`; never walk the room from its first row.
        let after = start.map(|(at, id)| (room, at, id));
        let history: Box<dyn Iterator<Item = HistoryRow> + '_> = match &after {
            Some(after) => Box::new(
                HISTORY
                    .iter_range(
                        store,
                        &txn,
                        std::ops::Bound::Excluded(after),
                        std::ops::Bound::Unbounded,
                    )?
                    .take_while(
                        move |row| !matches!(row, Ok(((other, _, _), _)) if *other != room),
                    ),
            ),
            None => Box::new(HISTORY.iter_from(store, &txn, room.as_bytes())?),
        };
        let rows = history
            .take(window)
            .map(|row| {
                let ((_, at, id), turn_id) = row?;
                Ok(((at, id), turn_in(self.vault(), &txn, turn_id)?))
            })
            .collect::<MemoryResult<Vec<_>>>()?;
        Ok(rows)
    }

    /// Canonical HEAD is a room-local indexed read; branch turns are excluded.
    /// A head this reader may not read is no head for it.
    pub fn room_head(&self, room: EntityId) -> MemoryResult<Option<RoomTurn>> {
        let scope = self.room_read_scope(room)?;
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        require_member(self.vault(), &txn, room, self.actor())?;
        if !turns_readable(&scope) {
            return Ok(None);
        }
        let head = HEADS
            .iter_rev_from(&self.vault().store, &txn, room.as_bytes())?
            .next()
            .map(|row| -> MemoryResult<RoomTurn> {
                let (_, turn_id) = row?;
                Ok(turn_in(self.vault(), &txn, turn_id)?)
            })
            .transpose()?;
        drop(txn);
        Ok(self.admitted_turns(head.into_iter().collect())?.pop())
    }
}

impl Memory<'_> {
    /// Complete snapshot for a room liveness fold; never silently truncates
    /// the working-set census to the first `rooms.messages` page. Empty when
    /// the room Scope reads no turns.
    pub(super) fn room_turn_snapshot(&self, room: EntityId) -> MemoryResult<Vec<RoomTurn>> {
        let scope = self.room_read_scope(room)?;
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        require_member(self.vault(), &txn, room, self.actor())?;
        if !turns_readable(&scope) {
            return Ok(Vec::new());
        }
        let mut turns = Vec::new();
        for row in HISTORY.iter_from(&self.vault().store, &txn, room.as_bytes())? {
            let (_, turn_id) = row?;
            if turns.len() == 100_000 {
                return Err(Error::IndexOverflow("room thread history").into());
            }
            turns.push(turn_in(self.vault(), &txn, turn_id)?);
        }
        drop(txn);
        Ok(answer_closed(self.admitted_turns(turns)?))
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
        // Task and result reads run inside the room too, on every transport.
        let tasks = crate::task_verb::room_thread_tasks(
            self.for_room_turn(room)?.memory(),
            &roots,
            &members,
            policy.now,
        )?;
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
        let scope = self.room_read_scope(room)?;
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        let members = require_member(self.vault(), &txn, room, self.actor())?
            .member_ids
            .into_iter()
            .collect();
        if !turns_readable(&scope) {
            return Err(outside_scope());
        }
        let turn = turn_in(self.vault(), &txn, trunk)?;
        drop(txn);
        if turn.room_id != room.to_hex() || turn.thread_of.is_some() {
            return Err(MemoryError::from(invalid()));
        }
        let turn = self.admitted_turns(vec![turn])?.pop().ok_or_else(invalid)?;
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
        let tasks = crate::task_verb::room_thread_tasks(
            self.for_room_turn(room)?.memory(),
            &roots,
            &members,
            crate::unix_seconds_now(),
        )?;
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
        let tasks = crate::task_verb::room_thread_tasks(
            self.for_room_turn(room)?.memory(),
            &selected,
            &members,
            now,
        )?;
        Ok(super::liveness::project_target(
            &turns, &tasks, handle, now,
        )?)
    }
}

/// The turns among `turns` whose answered turns are among them too, each
/// chain followed to its end. Admission keeps a reply whose own parent is
/// readable even when that parent's ancestor is withheld; the thread fold
/// then meets the gap. Dropping the whole cut chain lets it fold the rest.
fn answer_closed(turns: Vec<RoomTurn>) -> Vec<RoomTurn> {
    let held: BTreeSet<&str> = turns.iter().map(|turn| turn.turn_id.as_str()).collect();
    let mut answers = std::collections::BTreeMap::<&str, Vec<&str>>::new();
    let mut cut = Vec::new();
    for turn in &turns {
        for parent in turn.reply_to.iter().chain(&turn.thread_of) {
            answers
                .entry(parent.as_str())
                .or_default()
                .push(turn.turn_id.as_str());
            if !held.contains(parent.as_str()) {
                cut.push(turn.turn_id.as_str());
            }
        }
    }
    let mut dropped = BTreeSet::new();
    while let Some(id) = cut.pop() {
        if dropped.insert(id) {
            cut.extend(answers.get(id).into_iter().flatten().copied());
        }
    }
    let dropped: BTreeSet<String> = dropped.into_iter().map(str::to_owned).collect();
    turns
        .into_iter()
        .filter(|turn| !dropped.contains(&turn.turn_id))
        .collect()
}
