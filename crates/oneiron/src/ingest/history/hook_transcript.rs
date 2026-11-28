//! `vault.imports.hook_transcript` (census L10-17; Engine ruling Tue 17 Nov
//! 06:50, L10-17-PR3-MEMORY = B): one coding agent's session, sent by the CLI
//! on another machine, lands in this vault through the same import the local
//! `oneiron import <source> <log>` runs, with the same dedupe, Imported
//! provenance and refusals, and an answer that names the session's
//! CONVERSATION, which `vault.runners.continue` then takes. The session is a
//! Claude Code log and its subagents' logs, unless the request names another
//! source a hook hands over (FIX HOOK-HOSTED-HAND-OVER-OTHER-HOSTS): a Codex
//! rollout, or a GitHub Copilot or Cursor hook transcript, each one file.
//!
//! The owner calls it, or an agent whose live Grant names the verb
//! (substrate behind grants). The Grant is checked at the door's admission,
//! before any verb hook runs, again before anything is read, and again in
//! each of the import's writers, where the owner's proof is revalidated, so
//! a Grant revoked during an import refuses the turns that had not landed
//! yet; what had landed still reaches the owner's inbox and the Dreamer.
//!
//! Each log travels gzip-compressed in standard base64, so a long session's
//! log fits the call's carrier: one line `oneiron mcp` reads (at most 64
//! MiB) for a slip or OAuth sign-in, one frame of the vault's socket (about
//! 8 MiB) for the owner, whose calls ride the socket alone. A request too
//! long for the owner's frame goes in parts
//! (`vault.imports.hook_transcript_part`, [`HookTranscriptPartRequest`];
//! FIX HOOK-TRANSCRIPT-IMPORT-PAST-CARRIER): the served vault holds them in
//! memory, at most [`HOOK_TRANSCRIPT_STAGED_MAX_BYTES`] of the request's
//! JSON text, and no verb hook sees a part; its last part runs the request
//! as one call of `vault.imports.hook_transcript`, whose hooks judge it as
//! they judge any call of it. All the logs of one request inflate to at most
//! [`HOOK_TRANSCRIPT_MAX_BYTES`], read through a bounded reader; past that
//! the request is refused before anything lands.

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
use crate::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};

/// The most bytes the logs of one call inflate to, together: the server's
/// own request floor.
pub const HOOK_TRANSCRIPT_MAX_BYTES: usize = 64 * 1024 * 1024;

/// The most bytes of one request's JSON text a staged upload
/// (`vault.imports.hook_transcript_part`) holds: the longest line `oneiron
/// mcp` reads, so the owner's socket carries in parts a request as long as
/// a slip's one call carries.
pub const HOOK_TRANSCRIPT_STAGED_MAX_BYTES: usize = 64 * 1024 * 1024;

/// The most subagent logs one call carries.
pub const HOOK_TRANSCRIPT_MAX_SUBAGENTS: usize = 256;

/// The longest subagent log stem, in bytes.
const SUBAGENT_STEM_MAX_BYTES: usize = 128;

/// The longest session log stem of a source other than Claude Code, in
/// bytes.
const SESSION_STEM_MAX_BYTES: usize = 128;

/// A session id that is not a Claude Code session log's stem.
const ERR_SESSION: &str =
    "the hook transcript's session is not a Claude Code session id (36 hex digits and dashes)";

/// A session that is not a plain log stem.
const ERR_SESSION_STEM: &str = "the hook transcript's session is not its log's file stem (up to 128 letters, digits, dashes and underscores)";

/// Subagent logs sent with a log that keeps its subagents in itself.
const ERR_SUBAGENTS_OF_SOURCE: &str = "only a Claude Code session has subagent logs of its own; this source's log holds its subagents";

/// A subagent log stem that is not `agent-<id>`.
const ERR_SUBAGENT_STEM: &str =
    "a subagent log's stem is not agent-<id> (up to 128 letters, digits, dashes and underscores)";

/// Two subagent logs with one stem.
const ERR_SUBAGENT_TWICE: &str = "two subagent logs have the same stem";

/// More subagent logs than one call carries.
const ERR_SUBAGENTS_MANY: &str = "the hook transcript carries more than 256 subagent logs";

const HOOK_TRANSCRIPT_MAX_FOLDER_DIGESTS: usize = 2;
const ERR_FOLDER_DIGESTS_MANY: &str =
    "a hook transcript names its session's folder in at most two digests";
const ERR_FOLDER_DIGEST: &str =
    "a hook transcript's folder digest is blake3: and 64 lowercase hex digits";

/// Logs past the inflated cap.
const ERR_PAST_CAP: &str = "the hook transcript's logs inflate past 64 MiB (HOOK_TRANSCRIPT_MAX_BYTES): nothing was imported";

/// What the caller does about logs past the cap, by the source.
const fn hint_past_cap(source: HookTranscriptSource) -> &'static str {
    match source {
        HookTranscriptSource::ClaudeCode => {
            "Import the session on the machine it ran on: oneiron import claude-code <log>."
        }
        HookTranscriptSource::Codex => {
            "Import the session on the machine it ran on: oneiron import codex <log>."
        }
        HookTranscriptSource::HookTranscript => {
            "Import the session on the machine it ran on: oneiron import hook-transcript <log>."
        }
    }
}

/// A session log that left its CONVERSATION absent: no message of it was
/// kept, now or before.
const ERR_NO_CONVERSATION: &str = "the hook transcript's session log holds no message the import keeps, so the session has no CONVERSATION to continue";

/// What the caller does about a session log with no message kept.
const HINT_NO_CONVERSATION: &str = "Send the log once the session has a user or assistant message.";

/// `vault.imports.hook_transcript`'s input: one session's log, as the hook
/// names it, and, for Claude Code, the logs of its subagents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HookTranscriptImportRequest {
    /// The session log's file stem, as the local import names the file: a
    /// Claude Code session id (36 hex digits and dashes); a Codex
    /// `rollout-<time>-<id>`; a Copilot or Cursor session id (for a Copilot
    /// CLI `events.jsonl`, its session folder's name). Up to 128 letters,
    /// digits, dashes and underscores.
    pub session: String,
    /// The session log's bytes, gzip-compressed, in standard base64.
    pub transcript_gzip_base64: String,
    /// The session's subagent logs (`<session>/subagents/agent-<id>.jsonl`);
    /// Claude Code's only.
    #[serde(default)]
    pub subagents: Vec<HookSubagentTranscript>,
    /// Which import reads the logs; absent for Claude Code, so a request
    /// written before other sources were taken reads as it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<HookTranscriptSource>,
    /// The session's folder, as the machine the session ran on names an attached session's
    /// folder (`blake3:` and 64 lowercase hex digits each, its own checkout's first; at most
    /// two). The session's TURNs and MESSAGEs land in the project that folder is bound to in
    /// this vault, as the local import lands a log read in that folder; absent or empty, at the
    /// default project, as a request written before folders were sent lands.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub folder_digests: Vec<String>,
}

/// The import a hook transcript's logs are read by: the `oneiron import`
/// source of the host's session logs.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum HookTranscriptSource {
    /// A Claude Code session log and its subagents' logs.
    #[default]
    ClaudeCode,
    /// A Codex session rollout.
    Codex,
    /// A GitHub Copilot or Cursor hook transcript.
    HookTranscript,
}

impl HookTranscriptSource {
    /// The import source that reads it.
    #[must_use]
    pub const fn history_source(self) -> HistorySource {
        match self {
            Self::ClaudeCode => HistorySource::ClaudeCode,
            Self::Codex => HistorySource::Codex,
            Self::HookTranscript => HistorySource::HookTranscript,
        }
    }

    /// The conversation import names for the session id a hook reports.
    pub(crate) fn session_conversation(harness: &str, session: &str) -> Result<Option<EntityId>> {
        let (source, native_id) = match harness {
            "claude-code" => (Self::ClaudeCode, std::borrow::Cow::Borrowed(session)),
            "codex" => (Self::Codex, std::borrow::Cow::Borrowed(session)),
            "cursor" => (Self::HookTranscript, format!("cursor:{session}").into()),
            "copilot" => (Self::HookTranscript, format!("copilot:{session}").into()),
            _ => return Ok(None),
        };
        conversation_id(source.history_source(), &native_id).map(Some)
    }
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

/// `vault.imports.hook_transcript_part`'s input: one part of the JSON text
/// of a [`HookTranscriptImportRequest`] too long for one call over the
/// owner's socket. The parts of one upload go in order, each starting where
/// the ones before it end; the last runs the request as one call of
/// `vault.imports.hook_transcript`, and, when that call's hooks hold it on
/// an ask, runs the same call again when it is sent again as it was.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HookTranscriptPartRequest {
    /// The upload's id: 32 lowercase hex digits the caller draws at random
    /// for one request and names in each of its parts.
    pub upload: String,
    /// Where this part starts in the request's JSON text, in bytes: 0 opens
    /// the upload; a later part starts where the parts before it end.
    pub offset: u64,
    /// The part: the request's JSON text from `offset` on, not empty.
    pub text: String,
    /// Whether this part ends the request's JSON text: the vault then runs
    /// the request.
    #[serde(default)]
    pub last: bool,
}

/// `vault.imports.hook_transcript_part`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HookTranscriptPartView {
    /// The upload's id.
    pub upload: String,
    /// The bytes of the request's JSON text the upload holds, this part's
    /// included: where its next part starts.
    pub staged: u64,
    /// Once the last part ran the request: the answer of its call of
    /// `vault.imports.hook_transcript`, as that call's post hooks left it
    /// (a [`HookTranscriptImportView`] when no hook redacts it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imported: Option<serde_json::Value>,
}

/// One conversation of the session, in counts, as the import reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HookTranscriptConversation {
    /// The conversation's id in its source: for Claude Code the session id,
    /// or `<session>/<stem>` for a subagent's log and
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
    fn of(source: HistorySource, report: &HistoryImportReport) -> Result<Self> {
        Ok(Self {
            native_id: report.conversation.clone(),
            conversation: conversation_id(source, &report.conversation)?.to_hex(),
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

    /// Lands one session a CLI on another machine sent, as `oneiron import
    /// <source> <log>` lands it: the session's log and its subagents' logs
    /// decode as the request's source's logs, land earliest first through
    /// [`Self::import_history`]'s import at a second of their own, and what
    /// landed goes in front of the Dreamer, its claims waiting in the
    /// import's review. The answer names the session's own conversation:
    /// for Claude Code the session id's, else the first the session's log
    /// decodes to (a Codex rollout's thread, a Cursor log's conversation, a
    /// Copilot log's main conversation before its subagents').
    ///
    /// `caller` is judged before any log is read, so a refused caller is
    /// told nothing of them, and again in each of the import's writers. A
    /// conversation refused part-way (a Grant revoked during the call) ends
    /// the call with its refusal, after the conversations that had landed
    /// get the call's inbox row and Dreamer planning at the call's import
    /// second, as a whole call's would.
    ///
    /// The session lands in its folder's bound project, read once for the whole
    /// call (FIX SESSION-PROJECT-HOOK-TRANSCRIPT-PLACEMENT). A granted agent's
    /// `presented` transport credential must cover that project; otherwise the
    /// hand-over is refused before any log is read (E-AGENT = (a)).
    ///
    /// # Errors
    ///
    /// A caller the door refuses; a granted agent without a credential that
    /// covers the bound project; malformed or too many folder digests; a request
    /// that fails its other checks, a log that is not gzip in standard base64, and
    /// logs that inflate past [`HOOK_TRANSCRIPT_MAX_BYTES`], with nothing landed;
    /// a session log whose CONVERSATION is absent after the import (no message
    /// kept); every error [`Self::import_history`] has.
    pub fn import_hook_transcript(
        &self,
        caller: HistoryImportCaller<'_>,
        presented: Option<&crate::authority::VerifiedSlip>,
        input: &HookTranscriptImportRequest,
    ) -> MemoryResult<HookTranscriptImportView> {
        caller.owner(self)?;
        let placement = self.hook_transcript_placement(caller, presented, &input.folder_digests)?;
        let kind = input.source.unwrap_or_default();
        let source = kind.history_source();
        let mut conversations: Vec<HistoryConversation> = Vec::new();
        // The session's own conversation's id in its source.
        let mut own = (kind == HookTranscriptSource::ClaudeCode).then(|| input.session.clone());
        for (index, (file, text)) in inflated_logs(kind, input)?.into_iter().enumerate() {
            let read = source
                .decode(&text, &file)
                .map_err(|error| MemoryError::bad_request(error.to_string()))?;
            if index == 0 && own.is_none() {
                own = read.first().map(|first| first.native_id.clone());
            }
            conversations.extend(read);
        }
        earliest_first(&mut conversations);
        let imported_at = self.own_import_second()?;
        let mut landed = false;
        let mut views = Vec::with_capacity(conversations.len());
        let mut refusal = None;
        for conversation in &conversations {
            match self.import_history_placed_as(
                caller,
                source,
                conversation,
                imported_at,
                None,
                placement,
            ) {
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
            self.record_history_import_finished(source, imported_at)?;
            Some(history_import_review_id(source, imported_at))
        } else {
            None
        };
        crate::dreamer_consolidation::plan_dirty_turn_rounds(self, imported_at)?;
        if let Some(refusal) = refusal {
            return Err(refusal);
        }
        let no_conversation = || {
            MemoryError::new(
                MEMORY_CODE_BAD_REQUEST,
                ERR_NO_CONVERSATION,
                &[HINT_NO_CONVERSATION],
            )
        };
        let conversation = conversation_id(source, &own.ok_or_else(no_conversation)?)?;
        if !self.transcript_conversation_present(&conversation)? {
            return Err(no_conversation());
        }
        Ok(HookTranscriptImportView {
            conversation: conversation.to_hex(),
            conversations: views
                .iter()
                .map(|report| HookTranscriptConversation::of(source, report))
                .collect::<Result<_>>()?,
            review,
        })
    }

    /// The project a hand-over's TURNs and MESSAGEs land in: the one `folder_digests`, the
    /// sender's session folder, is bound to here, read once, so every conversation of the call
    /// lands in the project its admission judged. `None` (the default project): no digests, an
    /// unbound folder, a project gone, or the default project itself. An agent's presented
    /// credential must cover a bound project by the rule its own session-folder writes meet
    /// ([`Vault::credential_admits_project_placement_in_txn`]; Engine ANSWER
    /// HOOK-TRANSCRIPT-PLACEMENT-BEFORE-B, E-AGENT = (a)); else the whole hand-over is refused
    /// before any log is read, and nothing lands at the root instead.
    fn hook_transcript_placement(
        &self,
        caller: HistoryImportCaller<'_>,
        presented: Option<&crate::authority::VerifiedSlip>,
        folder_digests: &[String],
    ) -> MemoryResult<Option<EntityId>> {
        if folder_digests.len() > HOOK_TRANSCRIPT_MAX_FOLDER_DIGESTS {
            return Err(MemoryError::bad_request(ERR_FOLDER_DIGESTS_MANY));
        }
        if folder_digests
            .iter()
            .any(|d| !crate::session_project::is_digest_text(d))
        {
            return Err(MemoryError::bad_request(ERR_FOLDER_DIGEST));
        }
        if folder_digests.is_empty() {
            return Ok(None);
        }
        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
        let Some(project) =
            crate::session_project::workspace_project_in_txn(self, &txn, folder_digests)?
                .filter(|project| *project != crate::claim::default_project_id())
        else {
            return Ok(None);
        };
        if let HistoryImportCaller::GrantedAgent(agent) = caller
            && !self
                .credential_admits_project_placement_in_txn(&txn, agent, presented, true, project)?
        {
            return Err(hand_over_placement_refused(project, presented));
        }
        Ok(Some(project))
    }

    /// Whether the CONVERSATION `id` is present, as `vault.runners.continue`
    /// asks of the one it takes, in a read snapshot of its own.
    fn transcript_conversation_present(&self, id: &EntityId) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        crate::ports::EntityStoreRead::port_entity_present(&self.store, &txn, id)
    }
}

/// A refused hand-over names the project and credential, never a token.
fn hand_over_placement_refused(
    project: EntityId,
    presented: Option<&crate::authority::VerifiedSlip>,
) -> MemoryError {
    let hint = "Hand the log over under a credential whose audience covers that project (a Grant that covers it), or have the owner hand the log over.";
    let project = project.to_hex();
    match presented {
        Some(proof) => {
            let credential = if proof.claims().slip_id != [0; 32] {
                crate::entity_id::bytes_to_hex_lower(&proof.claims().slip_id)
            } else {
                proof.claims().holder_ref.clone()
            };
            MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                format!(
                    "the hand-over's session folder is bound to project {project}, which the agent's credential {credential} does not cover"
                ),
                &[hint],
            )
        }
        None => MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!(
                "the hand-over's session folder is bound to project {project}, and the agent presented no credential whose audience covers it"
            ),
            &[hint],
        ),
    }
}

/// Each log of `input`, read by `source`'s import, with the file it decodes
/// as, inflated: the session's first, then each subagent's under the
/// session. Checks every name and the count before any log is inflated.
fn inflated_logs(
    source: HookTranscriptSource,
    input: &HookTranscriptImportRequest,
) -> MemoryResult<Vec<(HistoryFile, String)>> {
    match source {
        HookTranscriptSource::ClaudeCode if !session_id(&input.session) => {
            return Err(MemoryError::bad_request(ERR_SESSION));
        }
        HookTranscriptSource::ClaudeCode => {}
        HookTranscriptSource::Codex | HookTranscriptSource::HookTranscript => {
            if !session_stem(&input.session) {
                return Err(MemoryError::bad_request(ERR_SESSION_STEM));
            }
            if !input.subagents.is_empty() {
                return Err(MemoryError::bad_request(ERR_SUBAGENTS_OF_SOURCE));
            }
        }
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
    let hint = hint_past_cap(source);
    logs.push((
        session,
        inflated(&input.transcript_gzip_base64, &mut room, hint)?,
    ));
    for subagent in &input.subagents {
        let file = HistoryFile {
            stem: subagent.stem.clone(),
            parent: Some(input.session.clone()),
        };
        logs.push((
            file,
            inflated(&subagent.transcript_gzip_base64, &mut room, hint)?,
        ));
    }
    Ok(logs)
}

/// One log's text: `encoded` decoded and inflated, at most `room` bytes,
/// which it then takes from `room`; past them, refused with `hint`. Bytes
/// that are not UTF-8 read as the local import reads them, replaced.
fn inflated(encoded: &str, room: &mut usize, hint: &str) -> MemoryResult<String> {
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
            &[hint],
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

/// Whether `session` is a session log's stem of a source other than Claude
/// Code: up to [`SESSION_STEM_MAX_BYTES`] letters, digits, dashes and
/// underscores, so it never names a path.
fn session_stem(session: &str) -> bool {
    !session.is_empty() && session.len() <= SESSION_STEM_MAX_BYTES && plain(session)
}

/// Whether `name` is only ASCII letters, digits, dashes and underscores.
fn plain(name: &str) -> bool {
    name.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// Whether `stem` names a subagent log: `agent-<id>`, of letters, digits,
/// dashes and underscores only, so it never names a path.
fn subagent_stem(stem: &str) -> bool {
    stem.len() <= SUBAGENT_STEM_MAX_BYTES
        && stem.len() > "agent-".len()
        && stem.starts_with("agent-")
        && plain(stem)
}
