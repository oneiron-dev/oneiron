//! Moved from `crates/oneiron/src/workspace_roster/rooms/liveness.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;

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
    /// Absolute TASK cutoff; follow-up never extends it.
    pub until: Option<u64>,
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
    /// The origin card replaces this thread after conversion.
    pub converted_project: Option<EntityId>,
    /// A private thread's audience now (FIX 6381), each 32-hex, for a
    /// reader in it whom the thread's own view (`vault.rooms.get`) admits:
    /// who is in the thread, a walk-in included, where `participants`
    /// names who took part. Empty on every list row and on a public thread.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audience: Vec<String>,
    /// Each walk-in that entered and each opened full history of a private
    /// thread, in order (FIX 6381, 6383), for the same reader alone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audience_events: Vec<RoomThreadAudienceEvent>,
}

/// What a private thread's audience event did (FIX 6381, 6383).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoomThreadAudienceOp {
    /// Its person walked in, reading the thread from that event on.
    WalkIn,
    /// The Owner opened the thread's whole history to its person.
    OpenFullHistory,
}

/// One walk-in or opened full history of a private thread: structure
/// alone, never a name or a turn's words.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RoomThreadAudienceEvent {
    /// The event's own TURN, 32-hex.
    pub event_ref: String,
    pub op: RoomThreadAudienceOp,
    /// Whom it walked in or opened the history to, 32-hex; absent once
    /// this vault erased them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person_ref: Option<String>,
    /// When the event was recorded: its TURN's time.
    pub at: u64,
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
                    "threads {name}: +{} more; find=vault.rooms.find(room_ref={}) get=vault.rooms.get(room_ref={},turn_ref=<handle>)",
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
                " wait={} kind={} who={} since={} next={} until={}",
                wait.task.to_hex(),
                wait.kind.as_str(),
                wait.who.to_hex(),
                wait.since,
                wait.next_nudge
                    .map_or_else(|| "none".to_owned(), |at| at.to_string()),
                wait.until
                    .map_or_else(|| "none".to_owned(), |at| at.to_string())
            ));
        }
        if self.waits.len() > self.wait_render_limit {
            row.push_str(&format!(
                " waits:+{} get=vault.rooms.get",
                self.waits.len() - self.wait_render_limit
            ));
        }
        if let Some(header) = self.result_header {
            row.push_str(&format!(" result_header={}", header.to_hex()));
        }
        if let Some(project) = self.converted_project {
            row.push_str(&format!(" project={}", project.to_hex()));
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
