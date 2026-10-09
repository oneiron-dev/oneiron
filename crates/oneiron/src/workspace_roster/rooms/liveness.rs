//! Read-time room thread liveness; the room history and TASK rows remain truth.
use super::{RoomTurn, invalid};
use crate::{EntityId, error::Result};
use std::collections::{BTreeMap, BTreeSet};

/// A TASK fact already bound to a room turn. Never persisted as a liveness row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RoomThreadTask {
    pub(crate) task: EntityId,
    pub(crate) thread: EntityId,
    pub(crate) open: bool,
    pub(crate) wait: Option<RoomThreadWait>,
    pub(crate) delivered: Option<(EntityId, u64)>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RoomWaitKind {
    Ask,
    Hold,
    HumanTask,
}
impl RoomWaitKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ask => "ask",
            Self::Hold => "hold",
            Self::HumanTask => "human-task",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RoomThreadWait {
    pub task: EntityId,
    pub kind: RoomWaitKind,
    pub who: EntityId,
    pub since: u64,
    pub next_nudge: Option<u64>,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RoomThread {
    pub handle: EntityId,
    pub trunk: EntityId,
    pub last_message_at: u64,
    pub open_tasks: usize,
    pub waits: Vec<RoomThreadWait>,
    #[serde(skip)]
    pub wait_render_limit: usize,
    /// Result pointer projected beside its trunk anchor; never a copied result body.
    pub result_header: Option<EntityId>,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RoomThreadList {
    pub rows: Vec<RoomThread>,
    pub more: usize,
}
impl RoomThreads {
    /// Three separate capped room lists, not extra Context Board ROOM fields.
    /// `+N` counts describe every omitted row; find/get retain the full set.
    pub fn render_rows(&self, room: EntityId) -> Vec<String> {
        let mut rows = Vec::new();
        for (name, list) in [
            ("active", &self.active),
            ("waiting", &self.waiting),
            ("quiet", &self.quiet),
        ] {
            rows.push(format!("threads {name}: {}", list.rows.len() + list.more));
            rows.extend(list.rows.iter().map(|row| row.line(name)));
            if list.more > 0 || name == "quiet" {
                rows.push(format!(
                    "threads {name}: +{} more; find=rooms.find(room_ref={}) get=rooms.get(room_ref={},turn_ref=<handle>)",
                    list.more, room.to_hex(), room.to_hex()
                ));
            }
        }
        rows
    }
}
impl RoomThread {
    /// Bounded structural row; no message or task prose enters the board.
    pub fn line(&self, lane: &str) -> String {
        let mut row = format!(
            "{lane} {} trunk={} last={} tasks={}",
            self.handle.to_hex(),
            self.trunk.to_hex(),
            self.last_message_at,
            self.open_tasks
        );
        // Keep one structural row bounded even when the thread has many
        // waits. The typed get returns the complete wait set.
        for wait in self.waits.iter().take(self.wait_render_limit) {
            row.push_str(&format!(
                " wait={} kind={} who={} since={} next={}",
                wait.task.to_hex(),
                wait.kind.as_str(),
                wait.who.to_hex(),
                wait.since,
                wait.next_nudge
                    .map_or_else(|| "none".to_owned(), |at| at.to_string())
            ));
        }
        if self.waits.len() > self.wait_render_limit {
            row.push_str(&format!(
                " waits:+{} get=rooms.get",
                self.waits.len() - self.wait_render_limit
            ));
        }
        if let Some(header) = self.result_header {
            row.push_str(&format!(" result_header={}", header.to_hex()));
        }
        row
    }
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RoomThreads {
    pub active: RoomThreadList,
    pub waiting: RoomThreadList,
    pub quiet: RoomThreadList,
}
/// Policy input. The engine applies one shared row ceiling to each list and
/// never permits a caller to widen the cap silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoomThreadPolicy {
    pub now: u64,
    pub fresh_for: u64,
    pub rows_per_list: usize,
    /// Per-list maximum tokens including the list's count and find/get footer.
    pub tokens_per_list: usize,
    pub fill: crate::workspace_roster::RoomThreadFill,
    pub waits_per_thread: usize,
}
impl Default for RoomThreadPolicy {
    fn default() -> Self {
        Self {
            now: crate::unix_seconds_now(),
            fresh_for: 7 * 86_400,
            rows_per_list: 8,
            tokens_per_list: 512,
            fill: crate::workspace_roster::RoomThreadFill::Stage,
            waits_per_thread: 8,
        }
    }
}

/// A root names a trunk anchor; continuations inherit that same anchor but
/// point at a turn inside the thread rather than at the trunk itself.
pub(super) fn is_thread_root(turn: &RoomTurn) -> bool {
    turn.thread_of.as_ref().is_some_and(|anchor| {
        turn.reply_to
            .as_deref()
            .is_none_or(|parent| parent == anchor)
    })
}

/// Validated, memoized room-turn → thread-root map. Trunk turns have no
/// entry; every reply within a thread resolves to the same root as its parent.
pub(super) fn thread_root_map(turns: &[RoomTurn]) -> Result<BTreeMap<EntityId, EntityId>> {
    let mut by_id = BTreeMap::new();
    let mut roots = BTreeSet::new();
    for turn in turns {
        let id = EntityId::from_hex(&turn.turn_id)?;
        if by_id.insert(id, turn).is_some() {
            return Err(invalid());
        }
        if is_thread_root(turn) {
            let trunk = EntityId::from_hex(turn.thread_of.as_deref().ok_or_else(invalid)?)?;
            if trunk == id {
                return Err(invalid());
            }
            roots.insert(id);
        }
    }
    let mut cache: BTreeMap<EntityId, Option<EntityId>> = BTreeMap::new();
    let mut result = BTreeMap::new();
    for turn in turns {
        let id = EntityId::from_hex(&turn.turn_id)?;
        if roots.contains(&id) {
            result.insert(id, id);
            continue;
        }
        let mut cursor = id;
        let mut path = Vec::new();
        let mut seen = BTreeSet::new();
        let found = loop {
            if !seen.insert(cursor) {
                return Err(invalid());
            }
            if roots.contains(&cursor) {
                break Some(cursor);
            }
            if let Some(cached) = cache.get(&cursor) {
                break *cached;
            }
            path.push(cursor);
            let ancestor = by_id.get(&cursor).ok_or_else(invalid)?;
            match ancestor
                .reply_to
                .as_deref()
                .map(EntityId::from_hex)
                .transpose()?
            {
                Some(parent) => cursor = parent,
                None => break None,
            }
        };
        for member in path {
            cache.insert(member, found);
        }
        if let Some(root) = found {
            result.insert(id, root);
        }
    }
    Ok(result)
}

impl RoomThreadPolicy {
    pub(super) fn narrowed(mut self, settings: crate::gate::RoomThreadSettings) -> Self {
        self.fresh_for = self.fresh_for.min(settings.fresh_for);
        self.rows_per_list = self.rows_per_list.min(settings.rows_per_list);
        self.tokens_per_list = self.tokens_per_list.min(settings.tokens_per_list);
        // Ranking is selected by trusted policy, not an ordinal minimum.
        self.fill = settings.fill;
        self.waits_per_thread = self.waits_per_thread.min(settings.waits_per_thread);
        self
    }
}

/// The public room read supplies its exact room id even for an empty history.
pub(super) fn project_in_room(
    turns: &[RoomTurn],
    tasks: &[RoomThreadTask],
    policy: RoomThreadPolicy,
    room: EntityId,
) -> Result<RoomThreads> {
    project_inner(turns, tasks, policy, None, &room.to_hex())
}

/// Direct-by-handle fold: no render cap and no unrelated thread rows built.
pub(super) fn project_target(
    turns: &[RoomTurn],
    tasks: &[RoomThreadTask],
    handle: EntityId,
    now: u64,
) -> Result<Option<RoomThread>> {
    let projection = project_inner(
        turns,
        tasks,
        RoomThreadPolicy {
            now,
            rows_per_list: usize::MAX,
            ..Default::default()
        },
        Some(handle),
        &turns
            .first()
            .map_or_else(|| "0".repeat(32), |turn| turn.room_id.clone()),
    )?;
    Ok(projection
        .active
        .rows
        .into_iter()
        .chain(projection.waiting.rows)
        .chain(projection.quiet.rows)
        .next())
}

fn project_inner(
    turns: &[RoomTurn],
    tasks: &[RoomThreadTask],
    policy: RoomThreadPolicy,
    target: Option<EntityId>,
    room_hex: &str,
) -> Result<RoomThreads> {
    const MAX_ROWS: usize = 100_000;
    if turns.len() > MAX_ROWS
        || tasks.len() > MAX_ROWS
        || policy.rows_per_list > MAX_ROWS && policy.rows_per_list != usize::MAX
        || policy.tokens_per_list == 0
        || policy.tokens_per_list > 1_000_000
        || policy.waits_per_thread == 0
        || policy.waits_per_thread > MAX_ROWS
    {
        return Err(invalid());
    }
    let mut by_id = BTreeMap::new();
    for turn in turns {
        if turn.room_id != room_hex {
            return Err(invalid());
        }
        let id = EntityId::from_hex(&turn.turn_id)?;
        if by_id.insert(id, turn).is_some() {
            return Err(invalid());
        }
    }
    let mut roots = BTreeMap::new();
    for turn in turns {
        if let Some(trunk) = &turn.thread_of {
            // Replies inherit the anchor but are not new thread roots.
            if !is_thread_root(turn) {
                continue;
            }
            let id = EntityId::from_hex(&turn.turn_id)?;
            if target.is_some_and(|handle| handle != id) {
                continue;
            }
            let trunk = EntityId::from_hex(trunk)?;
            if !by_id.contains_key(&trunk) || trunk == id {
                return Err(invalid());
            }
            roots.insert(
                id,
                RoomThread {
                    handle: id,
                    trunk,
                    last_message_at: turn.at,
                    open_tasks: 0,
                    waits: Vec::new(),
                    wait_render_limit: policy.waits_per_thread,
                    result_header: None,
                },
            );
        }
    }
    let root_by_turn = thread_root_map(turns)?;
    let mut last_reply = BTreeMap::new();
    for turn in turns {
        let id = EntityId::from_hex(&turn.turn_id)?;
        let Some(&root_id) = root_by_turn.get(&id) else {
            continue;
        };
        if id == root_id {
            continue;
        }
        if let Some(root) = roots.get_mut(&root_id) {
            root.last_message_at = root.last_message_at.max(turn.at);
            last_reply
                .entry(root_id)
                .and_modify(|at: &mut u64| *at = (*at).max(turn.at))
                .or_insert(turn.at);
        }
    }
    let mut delivered = BTreeMap::new();
    let mut seen_tasks = BTreeSet::new();
    for fact in tasks {
        if !seen_tasks.insert(fact.task) {
            return Err(invalid());
        }
        let root = roots.get_mut(&fact.thread).ok_or_else(invalid)?;
        if fact.open {
            root.open_tasks += 1;
            if let Some(wait) = &fact.wait {
                root.waits.push(wait.clone());
            }
        } else if fact.wait.is_some() {
            return Err(invalid());
        }
        if let Some((result, at)) = fact.delivered {
            if fact.open {
                return Err(invalid());
            }
            let slot = delivered
                .entry(fact.thread)
                .or_insert((result, at, fact.task));
            if (at, fact.task) > (slot.1, slot.2) {
                *slot = (result, at, fact.task);
            }
        }
    }
    let mut active = Vec::new();
    let mut waiting = Vec::new();
    let mut quiet = Vec::new();
    for (id, mut row) in roots {
        row.waits
            .sort_by_key(|wait| (wait.next_nudge.unwrap_or(u64::MAX), wait.since, wait.task));
        if let Some((result, at, _)) = delivered.get(&id).copied() {
            row.result_header = Some(result);
            // A later reply relists a delivered, formerly folded thread.
            if last_reply.get(&id).is_none_or(|reply| *reply <= at)
                && row.open_tasks == 0
                && row.waits.is_empty()
            {
                quiet.push(row);
                continue;
            }
        }
        if row.open_tasks > row.waits.len()
            || (row.last_message_at.saturating_add(policy.fresh_for) >= policy.now
                && (row.waits.is_empty()
                    || last_reply.get(&id).is_some_and(|reply| {
                        let since = row.waits.iter().map(|wait| wait.since).max().unwrap_or(0);
                        *reply > since.max(delivered.get(&id).map_or(0, |v| v.1))
                    })))
        {
            active.push(row);
        } else if !row.waits.is_empty() {
            waiting.push(row);
        } else {
            quiet.push(row);
        }
    }
    if policy.fill == crate::workspace_roster::RoomThreadFill::Stage {
        active.sort_by_key(|row| {
            (
                std::cmp::Reverse(row.open_tasks),
                std::cmp::Reverse(row.last_message_at),
                row.handle,
            )
        });
    } else {
        active.sort_by_key(|row| (std::cmp::Reverse(row.last_message_at), row.handle));
    }
    if policy.fill == crate::workspace_roster::RoomThreadFill::Recency {
        waiting.sort_by_key(|row| (std::cmp::Reverse(row.last_message_at), row.handle));
    } else {
        waiting.sort_by_key(|row| {
            (
                row.waits[0].next_nudge.unwrap_or(u64::MAX),
                std::cmp::Reverse(row.last_message_at),
                row.handle,
            )
        });
    }
    quiet.sort_by_key(|row| (std::cmp::Reverse(row.last_message_at), row.handle));
    let list = |mut rows: Vec<RoomThread>, lane: &str| -> Result<RoomThreadList> {
        let total = rows.len();
        if policy.rows_per_list == usize::MAX {
            return Ok(RoomThreadList { rows, more: 0 });
        }
        let heading = format!("threads {lane}: {total}");
        let heading_tok = crate::tokenizer::count_context_pack_tokens(&heading);
        let mut row_tok = 0;
        let mut selected = None;
        for count in 0..=total.min(policy.rows_per_list) {
            if count > 0 {
                row_tok += crate::tokenizer::count_context_pack_tokens(&rows[count - 1].line(lane));
            }
            let more = total - count;
            let footer_tok = if more > 0 || lane == "quiet" {
                let footer = format!(
                    "threads {lane}: +{more} more; find=rooms.find(room_ref={room_hex}) get=rooms.get(room_ref={room_hex},turn_ref=<handle>)"
                );
                crate::tokenizer::count_context_pack_tokens(&footer)
            } else {
                0
            };
            if heading_tok
                .saturating_add(row_tok)
                .saturating_add(footer_tok)
                <= policy.tokens_per_list
            {
                selected = Some(count);
            }
        }
        let selected = selected.ok_or(crate::Error::IndexOverflow("room thread render floor"))?;
        rows.truncate(selected);
        Ok(RoomThreadList {
            rows,
            more: total - selected,
        })
    };
    Ok(RoomThreads {
        active: list(active, "active")?,
        waiting: list(waiting, "waiting")?,
        quiet: list(quiet, "quiet")?,
    })
}
