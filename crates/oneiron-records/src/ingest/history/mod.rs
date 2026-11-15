//! Moved from `crates/oneiron/src/ingest/history/mod.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::ingest::history::land::HistoryImportReport;
use oneiron_contracts::entity_id::EntityId;
use serde::Serialize;

/// [`HistoryMessage::said_by`] for user-side words the source does not say
/// were the owner's or an agent's, such as copied history whose thread a copy
/// left out. Never read as the owner's; a later import that knows the
/// speaker lands the words again.
pub const UNKNOWN_SPEAKER: &str = "unknown";

/// Which file a session-log reader is reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryFile {
    /// The file name without its extension: a Claude Code session id or
    /// `agent-<id>`, a Codex `rollout-<time>-<id>`, a Copilot or Cursor
    /// session id (for a Copilot CLI `events.jsonl`, its session folder's).
    pub stem: String,
    /// A Claude Code subagent log (under `<session>/subagents/`); `parent` is
    /// then the session it ran in.
    pub parent: Option<String>,
}

/// Which side of a source conversation a message is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryRole {
    User,
    Assistant,
}

/// One kept message, as its source recorded it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryMessage {
    /// The source's own id for the message, unique within the source (a reader
    /// qualifies an id the source only keeps unique per session).
    pub native_id: String,
    pub parent_id: Option<String>,
    pub role: HistoryRole,
    pub text: String,
    /// Unix milliseconds, when the source recorded one for this message.
    pub at_ms: Option<u64>,
    /// Who spoke on the user side when it was not the owner: in a subagent's
    /// log that is the agent that delegated the task ([`DELEGATING_AGENT`]);
    /// [`UNKNOWN_SPEAKER`] when the source does not say.
    pub said_by: Option<&'static str>,
    /// Names of the tools this assistant message went on to call. The calls
    /// and their results are counted in [`HistorySkips`], not kept.
    pub tools: Vec<String>,
    /// The id an earlier read of a growing log gave this message: a Codex
    /// reply logged first as its event alone, with its item (and the item's
    /// own id) after it; a Claude Code prompt handed over from the queue
    /// before its own copy was logged. The import knows the message by
    /// either id.
    pub alias: Option<String>,
}

/// How a conversation relates to the source's main thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryThreadKind {
    /// The conversation as it was first written.
    Main,
    /// An edit or regeneration the source kept, with what followed it.
    Branch,
    /// A Claude Code sidechain recorded inside its session's log.
    Sidechain,
    /// A subagent's own log (Claude Code subagent, Codex spawned or forked thread).
    Subagent,
}

impl HistoryThreadKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Main => "main",
            Self::Branch => "branch",
            Self::Sidechain => "sidechain",
            Self::Subagent => "subagent",
        }
    }
}

/// One source conversation, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryConversation {
    /// The source's id, qualified for a branch, sidechain or subagent thread.
    pub native_id: String,
    pub kind: HistoryThreadKind,
    /// The conversation a branch, sidechain or subagent thread belongs to.
    pub parent: Option<String>,
    pub title: Option<String>,
    /// Unix milliseconds, when the source recorded when it started.
    pub started_at_ms: Option<u64>,
    /// When this thread itself began, when its source records that apart from
    /// its messages (a Codex rollout's own meta). The import makes the
    /// conversation occur then; otherwise it occurs with its first message
    /// that landed, since a resumed or forked log's first lines are copies
    /// of another conversation's.
    pub own_started_at_ms: Option<u64>,
    /// The folder the session ran in, when the source records one (a coding
    /// agent's working directory).
    pub cwd: Option<String>,
    pub messages: Vec<HistoryMessage>,
    pub skipped: HistorySkips,
    /// The source's own sharing of the conversation, when the source keeps
    /// one (ARCH-0027 #import-audience). `None` lands it private to the
    /// importer, as every source without sharing data does.
    pub sharing: Option<HistorySharing>,
}

/// A source's own sharing of one conversation: the unit the source shares
/// by and the people it shares that unit with. Every conversation of one
/// container reads under one source policy, so a later import that names
/// fewer members takes the read away from those it no longer names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistorySharing {
    /// The source's own sharing unit, stable from one export to the next
    /// (for a chat workspace's channel, `<workspace>:<channel>`).
    pub container: String,
    /// The people the source shares the container with.
    pub members: Vec<HistoryMember>,
}

/// One person a source shares a container with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryMember {
    /// The source's own id for the person.
    pub provider_id: String,
    /// The vault PERSON the owner says the member is. A member with none
    /// reads nothing.
    pub person: Option<EntityId>,
}

impl HistoryConversation {
    fn new(native_id: String, kind: HistoryThreadKind, parent: Option<String>) -> Self {
        Self {
            native_id,
            kind,
            parent,
            title: None,
            started_at_ms: None,
            own_started_at_ms: None,
            cwd: None,
            messages: Vec::new(),
            skipped: HistorySkips::default(),
            sharing: None,
        }
    }
}

/// What a reader saw and did not keep, by kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct HistorySkips {
    pub tool_calls: u32,
    pub tool_results: u32,
    pub thinking: u32,
    /// System and developer prompts, instructions, engine notices.
    pub system: u32,
    /// Context a host put on the user side: reminders, notifications, command
    /// output, compaction summaries, messages between agents.
    pub injected: u32,
    /// Images and files.
    pub attachments: u32,
    pub empty: u32,
    /// A second representation of a kept message (Codex events and response
    /// items), or a message id seen twice.
    pub duplicates: u32,
    /// Bookkeeping lines: titles, modes, costs, snapshots, token counts.
    pub other: u32,
    /// Lines that are not JSON objects; for a hook transcript, also lines
    /// that are not a record its reader knows.
    pub unreadable: u32,
}

impl HistorySkips {
    /// Adds another conversation's counts to these.
    pub fn add(&mut self, other: &Self) {
        let Self {
            tool_calls,
            tool_results,
            thinking,
            system,
            injected,
            attachments,
            empty,
            duplicates,
            other: bookkeeping,
            unreadable,
        } = other;
        self.tool_calls += tool_calls;
        self.tool_results += tool_results;
        self.thinking += thinking;
        self.system += system;
        self.injected += injected;
        self.attachments += attachments;
        self.empty += empty;
        self.duplicates += duplicates;
        self.other += bookkeeping;
        self.unreadable += unreadable;
    }
}
pub mod land;
pub mod ledger;
