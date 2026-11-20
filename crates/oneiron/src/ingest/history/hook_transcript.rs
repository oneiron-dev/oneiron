//! `vault.imports.hook_transcript` (census L10-17; Engine ruling Tue 17 Nov
//! 06:50, L10-17-PR3-MEMORY = B): one Claude Code session, sent by the CLI
//! on another machine, lands in this vault through the same import the local
//! `oneiron import claude-code <log>` runs, with the same dedupe, Imported
//! provenance and refusals, and an answer that names the session's
//! CONVERSATION, which `vault.runners.continue` then takes.
//!
//! The owner calls it, or an agent whose live Grant names the verb
//! (substrate behind grants). The Grant is checked at the door's admission,
//! before any verb hook runs, again before anything is read, and again in
//! each of the import's writers, where the owner's proof is revalidated, so
//! a Grant revoked during an import refuses the turns that had not landed
//! yet; what had landed still reaches the owner's inbox and the Dreamer.
//!
//! Each log travels gzip-compressed in standard base64: the `oneiron mcp`
//! bridge reads at most 2 MiB per message, and a long session's log is
//! larger. All the logs of one call inflate to at most
//! [`HOOK_TRANSCRIPT_MAX_BYTES`], read through a bounded reader; past that
//! the call is refused before anything lands.

use std::collections::BTreeSet;
use std::io::Read;

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::land::conversation_id;
use super::{
    HistoryConversation, HistoryFile, HistoryImportReport, HistorySource, earliest_first,
    history_import_review_id,
};
use crate::Vault;
use crate::authority::OwnerActKind;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::memory::{MEMORY_CODE_BAD_REQUEST, MemoryError, MemoryResult};

/// The most bytes the logs of one call inflate to, together: the server's
/// own request floor.
pub const HOOK_TRANSCRIPT_MAX_BYTES: usize = 64 * 1024 * 1024;

/// The most subagent logs one call carries.
pub const HOOK_TRANSCRIPT_MAX_SUBAGENTS: usize = 256;

/// The longest subagent log stem, in bytes.
const SUBAGENT_STEM_MAX_BYTES: usize = 128;

/// The source a hook transcript is: a Claude Code session log.
const SOURCE: HistorySource = HistorySource::ClaudeCode;

/// A session id that is not a Claude Code session log's stem.
const ERR_SESSION: &str =
    "the hook transcript's session is not a Claude Code session id (36 hex digits and dashes)";

/// A subagent log stem that is not `agent-<id>`.
const ERR_SUBAGENT_STEM: &str =
    "a subagent log's stem is not agent-<id> (up to 128 letters, digits, dashes and underscores)";

/// Two subagent logs with one stem.
const ERR_SUBAGENT_TWICE: &str = "two subagent logs have the same stem";

/// More subagent logs than one call carries.
const ERR_SUBAGENTS_MANY: &str = "the hook transcript carries more than 256 subagent logs";

/// Logs past the inflated cap.
const ERR_PAST_CAP: &str = "the hook transcript's logs inflate past 64 MiB (HOOK_TRANSCRIPT_MAX_BYTES): nothing was imported";

/// What the caller does about logs past the cap.
const HINT_PAST_CAP: &str =
    "Import the session on the machine it ran on: oneiron import claude-code <log>.";

/// A session log that left its CONVERSATION absent: no message of it was
/// kept, now or before.
const ERR_NO_CONVERSATION: &str = "the hook transcript's session log holds no message the import keeps, so the session has no CONVERSATION to continue";

/// What the caller does about a session log with no message kept.
const HINT_NO_CONVERSATION: &str = "Send the log once the session has a user or assistant message.";

/// `vault.imports.hook_transcript`'s input: one Claude Code session's log,
/// as the hook names it, and the logs of its subagents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HookTranscriptImportRequest {
    /// The session's id: the session log's file stem, 36 hex digits and
    /// dashes.
    pub session: String,
    /// The session log's bytes, gzip-compressed, in standard base64.
    pub transcript_gzip_base64: String,
    /// The session's subagent logs (`<session>/subagents/agent-<id>.jsonl`).
    #[serde(default)]
    pub subagents: Vec<HookSubagentTranscript>,
}

/// One subagent log of a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HookSubagentTranscript {
    /// The log's file stem, `agent-<id>`.
    pub stem: String,
    /// The log's bytes, gzip-compressed, in standard base64.
    pub transcript_gzip_base64: String,
}

/// `vault.imports.hook_transcript`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HookTranscriptImportView {
    /// The session's CONVERSATION entity id, hex: what
    /// `vault.runners.continue` takes as its `conversation`.
    pub conversation: String,
    /// Each conversation the logs held, earliest first, as it landed.
    pub conversations: Vec<HookTranscriptConversation>,
    /// The review the Dreamer's claims from this import wait in for the
    /// owner; absent when nothing landed new or changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review: Option<String>,
}

/// One conversation of the session, in counts, as the import reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HookTranscriptConversation {
    /// The conversation's id in Claude Code: the session id, or
    /// `<session>/<stem>` for a subagent's log and
    /// `<session>/sidechain/<agent>` for a sidechain the session's log kept.
    pub native_id: String,
    /// Its CONVERSATION entity id, hex.
    pub conversation: String,
    /// `main`, `sidechain` or `subagent`.
    pub kind: String,
    /// Messages the reader kept.
    pub messages: u32,
    /// Messages not imported before, now landed.
    pub new: u32,
    /// Messages imported before and unchanged: nothing written.
    pub skipped: u32,
    /// Messages imported before with other text, landed as a revision.
    pub changed: u32,
    /// Messages refused at the write door; nothing written.
    pub refused: u32,
    /// Messages other imports kept landing first; the next import lands them.
    pub pending: u32,
    /// Why turns were refused, as reason codes.
    pub refusal_reasons: Vec<String>,
}

impl HookTranscriptConversation {
    fn of(report: &HistoryImportReport) -> Result<Self> {
        Ok(Self {
            native_id: report.conversation.clone(),
            conversation: conversation_id(SOURCE, &report.conversation)?.to_hex(),
            kind: report.kind.as_str().to_owned(),
            messages: report.messages,
            new: report.new,
            skipped: report.skipped,
            changed: report.changed,
            refused: report.refused,
            pending: report.pending,
            refusal_reasons: report.refusal_reasons.iter().cloned().collect(),
        })
    }
}

/// Who an import lands for: the owner under the owner's proof, or an agent
/// whose live Grant names `vault.imports.hook_transcript`. Either way the
/// import is the owner's act and lands as the owner's: the Grant carries the
/// owner's will.
#[derive(Debug, Clone, Copy)]
pub enum HistoryImportCaller<'a> {
    Owner(&'a AuthenticatedOwner),
    GrantedAgent(EntityId),
}

impl HistoryImportCaller<'_> {
    /// The owner whose act the import is, as `txn` reads the caller: the
    /// owner's proof revalidated, or the agent's Grant still naming the act
    /// now.
    pub(super) fn owner_in_txn(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<EntityId> {
        match self {
            Self::Owner(owner) => owner.revalidate_in_txn(vault, txn),
            Self::GrantedAgent(agent) => {
                vault.agent_act_owner_in_txn(txn, *agent, OwnerActKind::HookTranscriptImport)
            }
        }
    }

    /// [`Self::owner_in_txn`] in a read snapshot of its own.
    pub(super) fn owner(&self, vault: &Vault) -> Result<EntityId> {
        let txn = vault.store.env.read_txn()?;
        self.owner_in_txn(vault, &txn)
    }
}

impl Vault {
    /// The door's admission of `caller` to `vault.imports.hook_transcript`,
    /// before any verb hook sees the call: the owner's proof revalidated, or
    /// the agent's live Grant naming the act, in a read snapshot of its own.
    /// [`Self::import_hook_transcript`] judges the caller again.
    ///
    /// # Errors
    ///
    /// A caller the door refuses.
    pub fn admit_hook_transcript_caller(
        &self,
        caller: HistoryImportCaller<'_>,
    ) -> MemoryResult<()> {
        caller.owner(self)?;
        Ok(())
    }

    /// Lands one Claude Code session a CLI on another machine sent, as
    /// `oneiron import claude-code <log>` lands it: the session's log and
    /// its subagents' logs decode as Claude Code logs, land earliest first
    /// through [`Self::import_history`]'s import at a second of their own,
    /// and what landed goes in front of the Dreamer, its claims waiting in
    /// the import's review.
    ///
    /// `caller` is judged before any log is read, so a refused caller is
    /// told nothing of them, and again in each of the import's writers. A
    /// conversation refused part-way (a Grant revoked during the call) ends
    /// the call with its refusal, after the conversations that had landed
    /// get the call's inbox row and Dreamer planning at the call's import
    /// second, as a whole call's would.
    ///
    /// # Errors
    ///
    /// A caller the door refuses; a request that fails its checks, a log
    /// that is not gzip in standard base64, and logs that inflate past
    /// [`HOOK_TRANSCRIPT_MAX_BYTES`], with nothing landed; a session log
    /// whose CONVERSATION is absent after the import (no message kept);
    /// every error [`Self::import_history`] has.
    pub fn import_hook_transcript(
        &self,
        caller: HistoryImportCaller<'_>,
        input: &HookTranscriptImportRequest,
    ) -> MemoryResult<HookTranscriptImportView> {
        caller.owner(self)?;
        let mut conversations: Vec<HistoryConversation> = Vec::new();
        for (file, text) in inflated_logs(input)? {
            let read = SOURCE
                .decode(&text, &file)
                .map_err(|error| MemoryError::bad_request(error.to_string()))?;
            conversations.extend(read);
        }
        earliest_first(&mut conversations);
        let imported_at = self.own_import_second()?;
        let mut landed = false;
        let mut views = Vec::with_capacity(conversations.len());
        let mut refusal = None;
        for conversation in &conversations {
            match self.import_history_as(caller, SOURCE, conversation, imported_at, None) {
                Ok(report) => {
                    landed |= report.new > 0 || report.changed > 0;
                    views.push(report);
                }
                Err(error) => {
                    refusal = Some(error);
                    break;
                }
            }
        }
        // One inbox row for the call, never one per conversation; written
        // for what landed before a refusal too.
        let review = if landed {
            self.record_history_import_finished(SOURCE, imported_at)?;
            Some(history_import_review_id(SOURCE, imported_at))
        } else {
            None
        };
        crate::dreamer_consolidation::plan_dirty_turn_rounds(self, imported_at)?;
        if let Some(refusal) = refusal {
            return Err(refusal);
        }
        let conversation = conversation_id(SOURCE, &input.session)?;
        let txn = self.store.env.read_txn()?;
        if !crate::ports::EntityStoreRead::port_entity_present(&self.store, &txn, &conversation)? {
            return Err(MemoryError::new(
                MEMORY_CODE_BAD_REQUEST,
                ERR_NO_CONVERSATION,
                &[HINT_NO_CONVERSATION],
            ));
        }
        drop(txn);
        Ok(HookTranscriptImportView {
            conversation: conversation.to_hex(),
            conversations: views
                .iter()
                .map(HookTranscriptConversation::of)
                .collect::<Result<_>>()?,
            review,
        })
    }
}

/// Each log of `input` with the file it decodes as, inflated: the session's
/// first, then each subagent's under the session. Checks every name and the
/// count before any log is inflated.
fn inflated_logs(input: &HookTranscriptImportRequest) -> MemoryResult<Vec<(HistoryFile, String)>> {
    if !session_id(&input.session) {
        return Err(MemoryError::bad_request(ERR_SESSION));
    }
    if input.subagents.len() > HOOK_TRANSCRIPT_MAX_SUBAGENTS {
        return Err(MemoryError::bad_request(ERR_SUBAGENTS_MANY));
    }
    let mut stems = BTreeSet::new();
    for subagent in &input.subagents {
        if !subagent_stem(&subagent.stem) {
            return Err(MemoryError::bad_request(ERR_SUBAGENT_STEM));
        }
        if !stems.insert(subagent.stem.as_str()) {
            return Err(MemoryError::bad_request(ERR_SUBAGENT_TWICE));
        }
    }
    let mut room = HOOK_TRANSCRIPT_MAX_BYTES;
    let mut logs = Vec::with_capacity(input.subagents.len() + 1);
    let session = HistoryFile {
        stem: input.session.clone(),
        parent: None,
    };
    logs.push((session, inflated(&input.transcript_gzip_base64, &mut room)?));
    for subagent in &input.subagents {
        let file = HistoryFile {
            stem: subagent.stem.clone(),
            parent: Some(input.session.clone()),
        };
        logs.push((file, inflated(&subagent.transcript_gzip_base64, &mut room)?));
    }
    Ok(logs)
}

/// One log's text: `encoded` decoded and inflated, at most `room` bytes,
/// which it then takes from `room`. Bytes that are not UTF-8 read as the
/// local import reads them, replaced.
fn inflated(encoded: &str, room: &mut usize) -> MemoryResult<String> {
    let compressed = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| MemoryError::bad_request("a hook transcript log is not standard base64"))?;
    let limit = u64::try_from(*room).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::new();
    flate2::read::MultiGzDecoder::new(compressed.as_slice())
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| MemoryError::bad_request("a hook transcript log is not gzip"))?;
    if bytes.len() > *room {
        return Err(MemoryError::new(
            MEMORY_CODE_BAD_REQUEST,
            ERR_PAST_CAP,
            &[HINT_PAST_CAP],
        ));
    }
    *room -= bytes.len();
    Ok(String::from_utf8(bytes)
        .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned()))
}

/// Whether `session` is a Claude Code session log's stem, as the local
/// import's queue takes one: 36 hex digits and dashes.
fn session_id(session: &str) -> bool {
    session.len() == 36 && session.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// Whether `stem` names a subagent log: `agent-<id>`, of letters, digits,
/// dashes and underscores only, so it never names a path.
fn subagent_stem(stem: &str) -> bool {
    stem.len() <= SUBAGENT_STEM_MAX_BYTES
        && stem.len() > "agent-".len()
        && stem.starts_with("agent-")
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}
