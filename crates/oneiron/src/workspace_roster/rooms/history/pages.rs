//! Room history pages, thread lists and thread find/get: a positive ask of
//! any size is served a page at a time, the rest through the page's
//! continuation, and the ask counted against its row (rule 5).
use super::*;
use crate::scan_check::{EngineScan, ScanCount};

/// The rows one room thread list renders at most; a larger ask renders this
/// many, with its find/get continuation.
const THREAD_LIST_ROWS: usize = 64;

/// The page size an ask of `requested` rows is served at: at most `max`,
/// the rest reachable through the page's continuation. The ask is counted
/// against `scan`'s row for `scope` (rule 5); none refuses for its size.
pub(in crate::workspace_roster) fn served_page_size(
    vault: &Vault,
    scan: EngineScan,
    scope: EntityId,
    requested: usize,
    max: usize,
) -> Result<usize> {
    let txn = vault.store.env.read_txn()?;
    let mut count = ScanCount::start(&vault.store, &txn, scan, scope.as_bytes())?;
    drop(txn);
    count.rows(requested);
    count.defer(&vault.store);
    Ok(requested.min(max))
}

impl Memory<'_> {
    /// One page of the turns this reader may read. A withheld turn never
    /// fills a slot or becomes the cursor, and a cursor must be a turn the
    /// reader may read.
    pub fn rooms_messages_page(
        &self,
        room: EntityId,
        after: Option<EntityId>,
        limit: usize,
    ) -> MemoryResult<RoomPage> {
        if limit == 0 {
            return Err(MemoryError::from(invalid()));
        }
        // A larger ask is served a page at a time through `next_after`.
        let limit = served_page_size(
            self.vault(),
            EngineScan::RoomRequestedPageRows,
            room,
            limit,
            PAGE_LIMIT,
        )?;
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

    /// Recomputes thread liveness from the current room history and TASK
    /// registers. The projection is not a vault_meta row or a cached flag.
    pub fn rooms_threads(
        &self,
        room: EntityId,
        policy: super::super::RoomThreadPolicy,
    ) -> MemoryResult<super::super::RoomThreads> {
        // A list asked for more than its 64 rows renders 64 with its find/get
        // continuation; the ask is counted (rule 5).
        let rows_per_list = served_page_size(
            self.vault(),
            EngineScan::RoomThreadListRows,
            room,
            policy.rows_per_list,
            THREAD_LIST_ROWS,
        )?;
        let policy = super::super::RoomThreadPolicy {
            rows_per_list,
            ..policy
        };
        let fold = {
            let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
            super::super::liveness::thread_fold_in(self.vault(), &txn, self.actor(), policy)?
        };
        let reach = self.room_turn_snapshot(room)?;
        let turns = reach.placed();
        let roots = super::super::liveness::thread_root_map(turns)?;
        let members = self
            .vault()
            .project_room(room)?
            .ok_or_else(invalid)?
            .member_ids
            .into_iter()
            .collect();
        // Task and result reads run inside the room too, on every transport.
        let bindings = super::super::liveness::thread_task_bindings(turns, &roots)?;
        let tasks = crate::task_verb::room_thread_tasks(
            self.for_room_projection(room)?.memory(),
            &roots,
            &bindings,
            &members,
            fold.now,
        )?;
        let edits = self.audience_edits_among(turns)?;
        Ok(super::super::liveness::project_in_room(
            turns, &edits, &tasks, fold, room,
        )?)
    }

    /// Scoped find handle; the full set is paged even when the render is folded.
    pub fn rooms_find_threads(
        &self,
        room: EntityId,
        after: Option<EntityId>,
        limit: usize,
    ) -> MemoryResult<Vec<EntityId>> {
        let limit = self.find_page_size(room, limit)?;
        self.find_threads_served(room, after, limit)
    }

    /// The page size a find asking for `limit` roots is served at: positive,
    /// at most [`PAGE_LIMIT`], the rest through its cursor.
    fn find_page_size(&self, room: EntityId, limit: usize) -> MemoryResult<usize> {
        if limit == 0 {
            return Err(MemoryError::from(invalid()));
        }
        Ok(served_page_size(
            self.vault(),
            EngineScan::RoomRequestedPageRows,
            room,
            limit,
            PAGE_LIMIT,
        )?)
    }

    /// [`Self::rooms_find_threads`] at its served page size `limit`.
    fn find_threads_served(
        &self,
        room: EntityId,
        after: Option<EntityId>,
        limit: usize,
    ) -> MemoryResult<Vec<EntityId>> {
        // FIX 5545: the vault's Owner or an Admin also finds the room's
        // private threads, by root id alone, with a seat in it or not.
        let owner = self.owner_private_roots(room)?;
        let turns = match &owner {
            Some(owner) if !owner.reads_room => RoomReach::default(),
            _ => self.room_turn_snapshot(room)?,
        };
        let mut roots = turns
            .placed()
            .iter()
            .filter(|turn| super::super::liveness::is_thread_root(turn))
            .map(|turn| EntityId::from_hex(&turn.turn_id))
            .collect::<Result<Vec<_>>>()?;
        roots.extend(owner.into_iter().flat_map(|owner| owner.roots));
        roots.sort();
        roots.dedup();
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
    ) -> MemoryResult<super::super::RoomThreadPage> {
        let limit = self.find_page_size(room, limit)?;
        let rows = self.find_threads_served(room, after, limit)?;
        let next_after = if rows.len() == limit
            && !self
                .find_threads_served(room, rows.last().copied(), 1)?
                .is_empty()
        {
            rows.last().copied()
        } else {
            None
        };
        Ok(super::super::RoomThreadPage { rows, next_after })
    }

    /// Scoped get handle; reaches a thread even when every list omits it.
    /// An agent with no standing in the room itself reads the thread on that
    /// thread's own Ready receipt (OF-529), through a snapshot and a lane
    /// bound to that thread alone, and so does a reader in a private
    /// thread's audience (FIX 2951); every other reader reads the room. The
    /// room's snapshot withholds a private thread from anyone off its
    /// audience, so it answers them as it answers a missing one. A reader
    /// in a private thread's audience also gets that audience and its
    /// walk-ins and opened histories (FIX 6381).
    pub fn rooms_get_thread(
        &self,
        room: EntityId,
        handle: EntityId,
    ) -> MemoryResult<Option<super::super::RoomThread>> {
        let thread = {
            let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
            let private = matches!(
                super::super::audience::thread_audience_in(self.vault(), &txn, room, handle),
                Ok(Some(_))
            );
            ((private && self.reads_thread_audience_in(&txn, room, handle)?)
                || agent_off_room_in_txn(self.vault(), &txn, room, self.actor())?)
            .then_some(handle)
        };
        let reach = match thread {
            None => self.room_turn_snapshot(room)?,
            Some(thread) => self.thread_turn_snapshot(room, thread)?,
        };
        let turns = reach.placed();
        let roots = super::super::liveness::thread_root_map(turns)?;
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
        // The caller's own thread settings, resolved before any reader is
        // rebound to the room or the thread.
        let fold = {
            let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
            super::super::liveness::direct_thread_fold_in(self.vault(), &txn, self.actor(), now)?
        };
        let selected = roots
            .into_iter()
            .filter(|(_, root)| *root == handle)
            .collect();
        let bindings = super::super::liveness::thread_task_bindings(turns, &selected)?;
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
        // A private thread's audience and walk-ins, for a reader in it
        // (FIX 6381).
        let edits = self.audience_edits_among(turns)?;
        let thread = super::super::liveness::project_target(turns, &edits, &tasks, handle, fold)?;
        self.with_thread_audience(room, handle, thread)
    }
}
