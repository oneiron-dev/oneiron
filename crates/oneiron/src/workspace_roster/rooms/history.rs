//! Bounded room-local history and transactional auxiliary-row cleanup.
use super::*;
use crate::store::Store;

pub(in crate::workspace_roster) const PAGE_LIMIT: usize = 256;

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
/// The complete selected thread in the conversion's own transaction. The
/// caller names its root, while a card may sit on any reply inside it.
pub(in crate::workspace_roster) fn thread_turns_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    thread: EntityId,
) -> Result<Vec<RoomTurn>> {
    room_in(vault, txn, room)?;
    let turns = HISTORY
        .iter_from(&vault.store, txn, room.as_bytes())?
        .map(|row| turn_in(vault, txn, row?.1))
        .collect::<Result<Vec<_>>>()?;
    let roots = super::liveness::thread_root_map(&turns)?;
    if roots.get(&thread) != Some(&thread) {
        return Err(invalid());
    }
    Ok(turns
        .into_iter()
        .filter(|turn| {
            EntityId::from_hex(&turn.turn_id).is_ok_and(|id| roots.get(&id) == Some(&thread))
        })
        .collect())
}

/// Deletes every auxiliary row a room owns, paged in [`PAGE_LIMIT`]-sized
/// chunks so no single collect-then-delete pass has to hold an unbounded
/// number of keys for a room with a long history: its history, host pin and
/// participation facts, every join receipt and offer card filed for it, and
/// their room-keyed indexes.
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
    super::hosting::delete_room_host_pin(store, txn, room)?;
    super::participation::delete_room_facts(store, txn, room)?;
    crate::workspace_roster::join_receipt::delete_room_joins(store, txn, room)?;
    super::offers::delete_room_offers(store, txn, room)?;
    Ok(())
}

/// [`delete_room_metadata`] for a CONVERSATION whose record leaves, run by
/// the shared erase doors (`deletion/derived_rows.rs`) before its body goes;
/// a no-op for any other entity. A project's home room reaches it from
/// `deindex_project_room` as well; the sweep is idempotent.
pub(crate) fn erase_room_side_rows(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)? else {
        return Ok(());
    };
    let is_room = crate::batch::EntityMetadataHeader::parse(&raw)
        .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_CONVERSATION);
    if is_room {
        delete_room_metadata(store, txn, *id)?;
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
        self.admitted_turns_at(turns, None)
    }

    /// [`Self::admitted_turns`] for the room's reader, or, with `thread`,
    /// for a reader of that one thread (OF-529): its own gate and a lane
    /// bound to that thread, never the room's.
    fn admitted_turns_at(
        &self,
        mut turns: Vec<RoomTurn>,
        thread: Option<EntityId>,
    ) -> MemoryResult<Vec<RoomTurn>> {
        if turns.is_empty() {
            return Ok(turns);
        }
        let room = EntityId::from_hex(&turns[0].room_id)?;
        if turns.iter().any(|turn| turn.room_id != room.to_hex()) {
            return Err(invalid().into());
        }
        {
            let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
            match thread {
                None => require_reader(self.vault(), &txn, room, self.actor())?,
                Some(thread) => {
                    require_thread_reader(self.vault(), &txn, room, thread, self.actor())?
                }
            };
            for turn in &mut turns {
                if super::liveness::is_thread_root(turn) {
                    turn.converted_project = self
                        .vault()
                        .thread_project_in_txn(&txn, room, EntityId::from_hex(&turn.turn_id)?)?
                        .map(|id| id.to_hex());
                }
            }
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
        let projection = match thread {
            None => self.for_room_projection(room)?,
            Some(thread) => self.for_thread_projection(room, thread)?,
        };
        let lane = projection
            .memory()
            .read_lane(crate::claim::ClaimReadStatus::Recorded)?;
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

    /// First trunk page: an admitted origin pointer, then trunk turns and
    /// their TASK result headers. Thread replies never consume trunk slots.
    pub fn room_trunk(&self, room: EntityId) -> MemoryResult<Vec<RoomTrunkItem>> {
        let worlds = self.room_read_worlds(room)?;
        let project_room = {
            let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
            require_reader(self.vault(), &txn, room, self.actor())?
        };
        if !turns_readable(&worlds) {
            return Ok(Vec::new());
        }
        let origin = match project_room.origin {
            Some(origin) if self.admitted_room_origin(room, &origin)? => Some(origin),
            _ => None,
        };
        let turns = self.room_turn_snapshot(room)?;
        let headers = self.room_result_headers(room, &turns, origin.as_ref())?;
        let mut entries = Vec::new();
        if let Some(origin) = origin {
            let thread = EntityId::from_hex(&origin.thread)?;
            entries.push(RoomTrunkItem::Origin(origin));
            entries.extend(
                headers
                    .iter()
                    .filter(|header| header.thread == thread)
                    .cloned()
                    .map(RoomTrunkItem::Result),
            );
        }
        for turn in turns
            .iter()
            .filter(|turn| turn.thread_of.is_none())
            .take(PAGE_LIMIT)
        {
            let roots = turns
                .iter()
                .filter(|thread| {
                    super::liveness::is_thread_root(thread)
                        && thread.thread_of.as_ref() == Some(&turn.turn_id)
                })
                .map(|thread| EntityId::from_hex(&thread.turn_id))
                .collect::<Result<BTreeSet<_>>>()?;
            entries.push(RoomTrunkItem::Turn(turn.clone()));
            entries.extend(
                headers
                    .iter()
                    .filter(|header| roots.contains(&header.thread))
                    .cloned()
                    .map(RoomTrunkItem::Result),
            );
        }
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
        let worlds = self.room_read_worlds(room)?;
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        require_reader(self.vault(), &txn, room, self.actor())?;
        if !turns_readable(&worlds) {
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
        // A page reads on until it fills or the history ends, however many
        // rows it passes over (rule 5): a withheld turn never ends a page
        // early, so a short page always means the history ended (DEC-0005).
        // Past the threshold row the owner's check is raised for the room.
        let mut count = {
            let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
            crate::scan_check::ScanCount::start(
                &self.vault().store,
                &txn,
                crate::scan_check::EngineScan::RoomPageRows,
                room.as_bytes(),
            )?
        };
        let mut rows = Vec::new();
        let mut window = limit;
        let exhausted = loop {
            let scanned = self.history_after(room, start, window)?;
            let exhausted = scanned.len() < window;
            scanned.iter().for_each(|_| count.row());
            start = scanned.last().map(|(key, _)| *key).or(start);
            rows.extend(self.admitted_turns(scanned.into_iter().map(|(_, turn)| turn).collect())?);
            if rows.len() >= limit || exhausted {
                break exhausted;
            }
            window = window.saturating_mul(2).min(PAGE_LIMIT * 16);
        };
        // A full page continues when an admitted turn lies past it. Rows this
        // page already decoded say so themselves; past them `room_continues`
        // reads each turn's key and own record before its body.
        let has_more = rows.len() > limit
            || (rows.len() == limit
                && !exhausted
                && self.room_continues(room, start, &mut count)?);
        count.finish(self.vault());
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
        self.history_rows(room, start, window, |txn, key, turn_id| {
            Ok((key, turn_in(self.vault(), txn, turn_id)?))
        })
    }

    /// Up to `window` history rows after `start`, each mapped by `row` from
    /// its index key and turn id inside one snapshot in which the reader still
    /// belongs to the room.
    fn history_rows<T>(
        &self,
        room: EntityId,
        start: Option<(u64, EntityId)>,
        window: usize,
        row: impl Fn(&heed::RoTxn<'_>, (u64, EntityId), EntityId) -> MemoryResult<T>,
    ) -> MemoryResult<Vec<T>> {
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        require_reader(self.vault(), &txn, room, self.actor())?;
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
        history
            .take(window)
            .map(|entry| {
                let ((_, at, id), turn_id) = entry?;
                row(&txn, (at, id), turn_id)
            })
            .collect()
    }

    /// Whether an admitted turn lies past `start`. Each turn's history key
    /// and own record are read first; a body is decoded only once its own
    /// record is admitted, to admit the turns it answers. A body that does not
    /// decode continues this page, and the page that would return it reports
    /// it. Its rows count toward the page's scan check.
    fn room_continues(
        &self,
        room: EntityId,
        mut start: Option<(u64, EntityId)>,
        count: &mut crate::scan_check::ScanCount,
    ) -> MemoryResult<bool> {
        let lane = self.read_lane(crate::claim::ClaimReadStatus::Recorded)?;
        loop {
            let keys = self.history_rows(room, start, 128, |_, key, turn_id| Ok((key, turn_id)))?;
            count.rows(keys.len());
            if keys.is_empty() {
                return Ok(false);
            }
            let reads: Vec<_> = keys
                .iter()
                .map(|(_, turn_id)| crate::claim::PointRead::id(*turn_id))
                .collect();
            let records = lane.read(&reads, None)?.value;
            for ((_, turn_id), record) in keys.iter().zip(records) {
                if record.is_none() {
                    continue;
                }
                let body = {
                    let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
                    require_reader(self.vault(), &txn, room, self.actor())?;
                    TURNS.get(&self.vault().store, &txn, turn_id)
                };
                match body {
                    Err(_) => return Ok(true),
                    Ok(None) => {}
                    Ok(Some(turn)) => {
                        if !self.admitted_turns(vec![turn])?.is_empty() {
                            return Ok(true);
                        }
                    }
                }
            }
            if keys.len() < 128 {
                return Ok(false);
            }
            start = keys.last().map(|(key, _)| *key);
        }
    }

    /// Canonical HEAD is a room-local indexed read; branch turns are excluded.
    /// A head this reader may not read is no head for it.
    pub fn room_head(&self, room: EntityId) -> MemoryResult<Option<RoomTurn>> {
        let worlds = self.room_read_worlds(room)?;
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        require_reader(self.vault(), &txn, room, self.actor())?;
        if !turns_readable(&worlds) {
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
    /// the working-set census to the first `vault.rooms.messages` page. Empty when
    /// the room Scope reads no turns.
    pub(super) fn room_turn_snapshot(&self, room: EntityId) -> MemoryResult<Vec<RoomTurn>> {
        let worlds = self.room_read_worlds(room)?;
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        require_reader(self.vault(), &txn, room, self.actor())?;
        if !turns_readable(&worlds) {
            return Ok(Vec::new());
        }
        // Every turn is read, however many (rule 5); past the threshold row
        // the owner's check is raised for the room.
        let mut count = crate::scan_check::ScanCount::start(
            &self.vault().store,
            &txn,
            crate::scan_check::EngineScan::RoomHistoryRows,
            room.as_bytes(),
        )?;
        let mut turns = Vec::new();
        for row in HISTORY.iter_from(&self.vault().store, &txn, room.as_bytes())? {
            count.row();
            let (_, turn_id) = row?;
            turns.push(turn_in(self.vault(), &txn, turn_id)?);
        }
        drop(txn);
        count.finish(self.vault());
        Ok(answer_closed(self.admitted_turns(turns)?))
    }

    /// [`Self::room_turn_snapshot`] for a reader of one thread (OF-529): the
    /// root `handle` and every reply in it, with the trunk turn it hangs from
    /// and the turns that turn answers, which the fold needs to place the
    /// thread and never returns. No sibling thread or other trunk turn is
    /// read. Empty when the thread's Scope reads no turns or `handle` is no
    /// thread root of this room.
    pub(super) fn thread_turn_snapshot(
        &self,
        room: EntityId,
        handle: EntityId,
    ) -> MemoryResult<Vec<RoomTurn>> {
        let worlds = self.thread_read_worlds(room, handle)?;
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        require_thread_reader(self.vault(), &txn, room, handle, self.actor())?;
        if !turns_readable(&worlds) {
            return Ok(Vec::new());
        }
        // The thread is found by walking the room's history, every row of it
        // (rule 5); past the threshold row the owner's check is raised for
        // the room.
        let mut count = crate::scan_check::ScanCount::start(
            &self.vault().store,
            &txn,
            crate::scan_check::EngineScan::RoomHistoryRows,
            room.as_bytes(),
        )?;
        let mut turns = Vec::new();
        for row in HISTORY.iter_from(&self.vault().store, &txn, room.as_bytes())? {
            count.row();
            let (_, turn_id) = row?;
            turns.push(turn_in(self.vault(), &txn, turn_id)?);
        }
        drop(txn);
        count.finish(self.vault());
        let roots = super::liveness::thread_root_map(&turns)?;
        if roots.get(&handle) != Some(&handle) {
            return Ok(Vec::new());
        }
        // The thread, then each turn it answers, followed to its end: the
        // trunk anchor and that anchor's own answer chain.
        let kept = {
            let by_id: std::collections::BTreeMap<&str, &RoomTurn> = turns
                .iter()
                .map(|turn| (turn.turn_id.as_str(), turn))
                .collect();
            let mut pending: Vec<&str> = turns
                .iter()
                .filter(|turn| {
                    EntityId::from_hex(&turn.turn_id)
                        .is_ok_and(|id| roots.get(&id) == Some(&handle))
                })
                .map(|turn| turn.turn_id.as_str())
                .collect();
            let mut kept = BTreeSet::new();
            while let Some(id) = pending.pop() {
                if kept.insert(id.to_owned())
                    && let Some(turn) = by_id.get(id)
                {
                    pending.extend(
                        turn.reply_to
                            .iter()
                            .chain(&turn.thread_of)
                            .map(String::as_str),
                    );
                }
            }
            kept
        };
        let selected = turns
            .into_iter()
            .filter(|turn| kept.contains(&turn.turn_id))
            .collect();
        Ok(answer_closed(
            self.admitted_turns_at(selected, Some(handle))?,
        ))
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
        let bindings = super::liveness::thread_task_bindings(&turns, &roots)?;
        let tasks = crate::task_verb::room_thread_tasks(
            self.for_room_projection(room)?.memory(),
            &roots,
            &bindings,
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
        let worlds = self.room_read_worlds(room)?;
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        require_reader(self.vault(), &txn, room, self.actor())?;
        if !turns_readable(&worlds) {
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
            .collect::<Result<BTreeSet<_>>>()?;
        let headers = self
            .room_result_headers(room, &turns, None)?
            .into_iter()
            .filter(|header| root_ids.contains(&header.thread))
            .collect();
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
    /// An agent with no standing in the room itself reads the thread on that
    /// thread's own Ready receipt (OF-529), through a snapshot and a lane
    /// bound to that thread alone; every other reader reads the room.
    pub fn rooms_get_thread(
        &self,
        room: EntityId,
        handle: EntityId,
    ) -> MemoryResult<Option<super::RoomThread>> {
        let thread = {
            let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
            agent_off_room_in_txn(self.vault(), &txn, room, self.actor())?.then_some(handle)
        };
        let turns = match thread {
            None => self.room_turn_snapshot(room)?,
            Some(thread) => self.thread_turn_snapshot(room, thread)?,
        };
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
        let bindings = super::liveness::thread_task_bindings(&turns, &selected)?;
        let projection = match thread {
            None => self.for_room_projection(room)?,
            Some(thread) => self.for_thread_projection(room, thread)?,
        };
        let tasks = crate::task_verb::room_thread_tasks(
            projection.memory(),
            &selected,
            &bindings,
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
pub(super) fn answer_closed(turns: Vec<RoomTurn>) -> Vec<RoomTurn> {
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
