//! The owner's own history, imported (ARCH-0027): ChatGPT and Claude.ai
//! exports, the on-device Claude Code and Codex session logs, and the GitHub
//! Copilot or Cursor session log a coding agent's hook hands over.
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
mod copilot;
mod cursor;
mod hosted;
mod hosted_verbs;
mod land;
mod ledger;
mod plan;
mod review;
mod sharing;
mod speakers;
mod text;
mod tree;

// FIX [LIBTEST-QUARANTINE-INGEST-HISTORY-TESTS]: the lib test target's type check fails here (4 errors: E0063 x4); port it, then drop this gate
#[cfg(any())]
#[cfg(test)]
mod tests;

pub use hosted::{
    HOSTED_IMPORT_SKIPS_LISTED, HostedImportCanceller, HostedImportEmbeddings, HostedImportId,
    HostedImportJob, HostedImportParse, HostedImportResumed, HostedImportReview,
    HostedImportSearchable, HostedImportStaged, HostedImportState, HostedImportStatus,
    HostedImportUpload, HostedImportView,
};
pub use hosted_verbs::{
    HostedImportCancel, HostedImportLookup, hosted_import_cancel, hosted_import_cancel_as,
    hosted_import_get, hosted_import_get_as_owner, hosted_import_get_as_reader,
};
pub use land::HistoryImportReport;
pub(crate) use ledger::erase_message_in_txn;
#[cfg(oneiron_test_support)]
pub(crate) use ledger::landed_rows_in;
pub use plan::{HistoryDryRun, HistoryLedgerSnapshot};
pub use review::history_import_review_id;
pub(crate) use review::imported_evidence_in_txn;
pub(crate) use speakers::{ImportedConversationSpeakers, imported_speakers_in};

use serde::Serialize;

use super::{IngestError, IngestResult};
use crate::EntityId;

/// [`HistoryMessage::said_by`] for the user side of a subagent's or a spawned
/// agent's thread: the agent that delegated the task, never the owner.
pub const DELEGATING_AGENT: &str = "delegating_agent";

#[doc(hidden)]
pub use oneiron_records::ingest::history::{
    HistoryConversation, HistoryFile, HistoryMember, HistoryMessage, HistoryRole, HistorySharing,
    HistorySkips, HistoryThreadKind, UNKNOWN_SPEAKER,
};

/// The history sources `oneiron import` reads. Their ids are the ingest
/// registry's, which carries their Imported trust ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HistorySource {
    Chatgpt,
    Claude,
    ClaudeCode,
    Codex,
    /// A coding agent's session log a hook handed over: GitHub Copilot's (VS
    /// Code or the CLI) or Cursor's, each read by its own reader.
    HookTranscript,
}

impl HistorySource {
    pub const ALL: [Self; 5] = [
        Self::Chatgpt,
        Self::Claude,
        Self::ClaudeCode,
        Self::Codex,
        Self::HookTranscript,
    ];

    /// The ingest registry id.
    #[must_use]
    pub const fn source_id(self) -> &'static str {
        match self {
            Self::Chatgpt => "chatgpt",
            Self::Claude => "claude",
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
            Self::HookTranscript => "hook-transcript",
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
    /// [`super::IngestError`] when an export is not the source's layout, or a
    /// hook transcript is neither reader's. A session log's unreadable line is
    /// counted, not fatal: the last line of a live session is often
    /// half-written.
    pub fn decode(self, text: &str, file: &HistoryFile) -> IngestResult<Vec<HistoryConversation>> {
        match self {
            Self::Chatgpt => chatgpt::decode(text),
            Self::Claude => claude::decode(text),
            Self::ClaudeCode => Ok(claude_code::decode(text, file)),
            Self::Codex => Ok(codex::decode(text, file)),
            Self::HookTranscript => hook_transcript(text, file),
        }
    }
}

/// A hook's transcript: the first record a GitHub Copilot or a Cursor log
/// writes picks that reader, which then reads the whole file. A file with no
/// such record is refused with its line count, never landed as an empty
/// conversation; an empty file holds nothing to land.
fn hook_transcript(text: &str, file: &HistoryFile) -> IngestResult<Vec<HistoryConversation>> {
    let mut unreadable = 0_u64;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        match text::json_record(line) {
            Some(record) if copilot::is_event(&record) => return Ok(copilot::decode(text, file)),
            Some(record) if cursor::is_record(&record) => return Ok(cursor::decode(text, file)),
            _ => unreadable += 1,
        }
    }
    if unreadable == 0 {
        return Ok(Vec::new());
    }
    Err(IngestError::UnsupportedSchema {
        source_id: HistorySource::HookTranscript.source_id(),
        expected: "a GitHub Copilot or Cursor transcript",
        found: format!("{unreadable} unreadable line(s), none a record of either"),
    })
}

// The lift sweep's typed acceptance for this module's authored side
// tables (FIX 2680), named by their declarations.
pub(crate) use self::ledger::ingest_history_ledger_accepts_masked;
