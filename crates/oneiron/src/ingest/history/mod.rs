//! The owner's own history, imported (ARCH-0027): ChatGPT and Claude.ai
//! exports and the on-device Claude Code and Codex session logs.
//!
//! Each reader decodes the text of ONE source file into source conversations:
//! the messages a person or an assistant said, in order, with the source's own
//! ids, parents and times. What a reader does not keep (tool calls and results,
//! reasoning, system prompts, injected context, attachments) it counts, so
//! nothing is dropped silently. Readers are pure: the host chooses the files
//! and reads them, and nothing here touches a filesystem.
//!
//! [`crate::Vault::import_history`] lands a decoded conversation as an imported
//! transcript, with a ledger that makes a re-import add nothing.

mod chatgpt;
mod claude;
mod claude_code;
mod codex;
mod land;
mod ledger;
mod plan;
mod text;
mod tree;

#[cfg(test)]
mod tests;

pub use land::HistoryImportReport;
pub use plan::{HistoryDryRun, HistoryLedgerSnapshot};

use serde::Serialize;

use super::IngestResult;

/// The four history sources `oneiron import` reads. Their ids are the ingest
/// registry's, which carries their Imported trust ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HistorySource {
    Chatgpt,
    Claude,
    ClaudeCode,
    Codex,
}

impl HistorySource {
    pub const ALL: [Self; 4] = [Self::Chatgpt, Self::Claude, Self::ClaudeCode, Self::Codex];

    /// The ingest registry id.
    #[must_use]
    pub const fn source_id(self) -> &'static str {
        match self {
            Self::Chatgpt => "chatgpt",
            Self::Claude => "claude",
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
        }
    }

    #[must_use]
    pub fn parse(source_id: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|source| source.source_id() == source_id)
    }

    /// Decodes one source file. `file` names it for sources that read one
    /// session per file; an export reads its `conversations.json` whole.
    ///
    /// # Errors
    ///
    /// [`super::IngestError`] when an export is not the source's layout. A
    /// session log's unreadable line is counted, not fatal: the last line of a
    /// live session is often half-written.
    pub fn decode(self, text: &str, file: &HistoryFile) -> IngestResult<Vec<HistoryConversation>> {
        match self {
            Self::Chatgpt => chatgpt::decode(text),
            Self::Claude => claude::decode(text),
            Self::ClaudeCode => Ok(claude_code::decode(text, file)),
            Self::Codex => Ok(codex::decode(text, file)),
        }
    }
}

/// Which file a session-log reader is reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryFile {
    /// The file name without its extension: a Claude Code session id or
    /// `agent-<id>`, a Codex `rollout-<time>-<id>`.
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
    /// log that is the agent that delegated the task.
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
    pub messages: Vec<HistoryMessage>,
    pub skipped: HistorySkips,
}

impl HistoryConversation {
    fn new(native_id: String, kind: HistoryThreadKind, parent: Option<String>) -> Self {
        Self {
            native_id,
            kind,
            parent,
            title: None,
            started_at_ms: None,
            messages: Vec::new(),
            skipped: HistorySkips::default(),
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
    /// Lines that are not JSON objects.
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
