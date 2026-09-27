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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomThreadWait {
    pub task: EntityId,
    pub kind: RoomWaitKind,
    pub who: EntityId,
    pub since: u64,
    pub next_nudge: Option<u64>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomThread {
    pub handle: EntityId,
    pub trunk: EntityId,
    pub last_message_at: u64,
    pub open_tasks: usize,
    pub waits: Vec<RoomThreadWait>,
    /// Result pointer projected beside its trunk anchor; never a copied result body.
    pub result_header: Option<EntityId>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomThreadList {
    pub rows: Vec<RoomThread>,
    pub more: usize,
}
impl RoomThreads {
    /// Three separate capped room lists, not extra Context Board ROOM fields.
    /// `+N` counts describe every omitted row; find/get retain the full set.
    pub fn render_rows(&self) -> Vec<String> {
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
                    "threads {name}: +{} more; find=rooms_find_threads get=rooms_get_thread",
                    list.more
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
        for wait in self.waits.iter().take(8) {
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
        if self.waits.len() > 8 {
            row.push_str(&format!(
                " waits:+{} get=rooms_get_thread",
                self.waits.len() - 8
            ));
        }
        if let Some(header) = self.result_header {
            row.push_str(&format!(" result_header={}", header.to_hex()));
        }
        row
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
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
}
impl Default for RoomThreadPolicy {
    fn default() -> Self {
        Self {
            now: crate::unix_seconds_now(),
            fresh_for: 7 * 86_400,
            rows_per_list: 8,
            tokens_per_list: 512,
        }
    }
}

/// Fold indexed turns and already-validated TASK facts into a room working set.
/// Resolve reply chains rather than trusting the caller to label a thread's root.
pub(super) fn project(
    turns: &[RoomTurn],
    tasks: &[RoomThreadTask],
    policy: RoomThreadPolicy,
) -> Result<RoomThreads> {
    project_inner(turns, tasks, policy, None)
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
) -> Result<RoomThreads> {
    const MAX_ROWS: usize = 100_000;
    if turns.len() > MAX_ROWS
        || tasks.len() > MAX_ROWS
        || policy.rows_per_list > 64 && policy.rows_per_list != usize::MAX
        || !(64..=2_048).contains(&policy.tokens_per_list)
    {
        return Err(invalid());
    }
    let mut by_id = BTreeMap::new();
    for turn in turns {
        let id = EntityId::from_hex(&turn.turn_id)?;
        if by_id.insert(id, turn).is_some() {
            return Err(invalid());
        }
    }
    let mut roots = BTreeMap::new();
    for turn in turns {
        if let Some(trunk) = &turn.thread_of {
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
                    result_header: None,
                },
            );
        }
    }
    // Memoize ancestry. A normal trunk reply has no thread root and is
    // ignored; only malformed missing parents and cycles refuse the read.
    let mut resolved: BTreeMap<EntityId, Option<EntityId>> = BTreeMap::new();
    let mut last_reply = BTreeMap::new();
    for turn in turns {
        let id = EntityId::from_hex(&turn.turn_id)?;
        if turn.thread_of.is_some() || turn.reply_to.is_none() {
            continue;
        }
        let mut target = id;
        let mut path = Vec::new();
        let mut seen = BTreeSet::new();
        let found = loop {
            if !seen.insert(target) {
                return Err(invalid());
            }
            if roots.contains_key(&target) {
                break Some(target);
            }
            if let Some(prior) = resolved.get(&target) {
                break *prior;
            }
            path.push(target);
            let parent = by_id.get(&target).ok_or_else(invalid)?;
            match parent
                .reply_to
                .as_deref()
                .map(EntityId::from_hex)
                .transpose()?
            {
                Some(next) => target = next,
                None => break None,
            }
        };
        for node in path {
            resolved.insert(node, found);
        }
        if let Some(root_id) = found {
            let root = roots.get_mut(&root_id).ok_or_else(invalid)?;
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
    active.sort_by_key(|row| (std::cmp::Reverse(row.last_message_at), row.handle));
    waiting.sort_by_key(|row| {
        (
            row.waits[0].next_nudge.unwrap_or(u64::MAX),
            std::cmp::Reverse(row.last_message_at),
            row.handle,
        )
    });
    quiet.sort_by_key(|row| (std::cmp::Reverse(row.last_message_at), row.handle));
    let list = |mut rows: Vec<RoomThread>, lane: &str| {
        let total = rows.len();
        let heading = format!("threads {lane}: {total}");
        let footer =
            format!("threads {lane}: +{total} more; find=rooms_find_threads get=rooms_get_thread");
        let mut used = crate::tokenizer::count_context_pack_tokens(&heading)
            + crate::tokenizer::count_context_pack_tokens(&footer);
        let mut selected = 0;
        for row in &rows {
            if policy.rows_per_list == usize::MAX {
                selected += 1;
                continue;
            }
            if selected == policy.rows_per_list {
                break;
            }
            let cost = crate::tokenizer::count_context_pack_tokens(&row.line(lane));
            if used + cost > policy.tokens_per_list {
                break;
            }
            used += cost;
            selected += 1;
        }
        rows.truncate(selected);
        RoomThreadList {
            rows,
            more: total - selected,
        }
    };
    Ok(RoomThreads {
        active: list(active, "active"),
        waiting: list(waiting, "waiting"),
        quiet: list(quiet, "quiet"),
    })
}

#[cfg(test)]
#[path = "liveness/tests.rs"]
mod tests;
