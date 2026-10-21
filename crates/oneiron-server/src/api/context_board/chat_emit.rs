//! What a live chat answer's context leaves on record (FIX 6921): the emit
//! receipt `ai.reply` keeps, and the answering agent's board history for the
//! answer's TURN. Both are taken from the board the turn's call was admitted
//! with, captured from the same render that produced its frame, and frozen
//! once the call is admitted. Neither gates the answer: the saved outcome is
//! handed on first, as it ended, and the two records are written after it,
//! off the runtime, each on its own. A record that cannot be kept is logged
//! and the answer stands as saved. A turn that keeps no durable record keeps
//! neither.
use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::claim::{PointRead, ScopedRead};
use oneiron::context_board::{BoardHistoryError, BoardRender, MemoryRow, MemoryTier, SectionView};
use oneiron::memory::ReadMode;
use oneiron::pipeline::ResolvedWorldAuthority;
use oneiron::prompt::{PROMPT_RECOMPILE_STAMP_SCHEMA_VERSION, PromptRecompileStamp};
use oneiron::receipt::ContextReceiptFields;
use oneiron::session_lifecycle::SessionKey;
use oneiron::task_verb::verb_hook_boundary;
use oneiron::{
    EdgeActorClass, EntityId, LlmMessageRole, LlmRequest, MemoriesSection, Vault, WriteActor,
};

use crate::api::ai::chat::Answering;
use crate::auth::{CoreAuth, CoreScope};
use crate::server::SyncServer;

/// The receipt's persona stamp names the role-admitted system messages it
/// hashes, never a provider's wire prompt (Engine CALL B).
const ADMITTED_SYSTEM_LABEL: &str = "chat-admitted-system:";
/// The receipt's input ref names the role-admitted request it hashes, never
/// the bytes a fallback rung was sent (Engine CALL B).
const ADMITTED_REQUEST_LABEL: &str = "chat-admitted-request:";
/// The board section a MEMORIES row of one world renders in.
const MEMORIES_SECTION_PREFIX: &str = "MEMORIES world=";
/// The TURN body key its door stamps the author byline under.
const TURN_AUTHOR_KEY: &str = "actor";

/// What a chat turn's board showed, kept beside its frame: the MEMORIES rows
/// the settled render shows, in its order and at the tier it shows them, the
/// world authority it resolved, its render's fingerprint, and the credential
/// it was read under.
#[derive(Debug)]
pub(crate) struct ChatContextCapture {
    /// `None` when the board carries no MEMORIES section.
    memories: Option<MemoriesSection>,
    worlds: ResolvedWorldAuthority,
    rendered_fingerprint: String,
    read_auth: CoreAuth,
}

/// A capture frozen against the call admitted with it. Its emit fields are
/// apart from the selection, so a stamp that cannot be frozen costs only the
/// receipt.
pub(crate) struct FrozenChatContext {
    capture: ChatContextCapture,
    /// The receipt's context fields and the admitted request's digest.
    emit: Option<(ContextReceiptFields, String)>,
}

/// The saved answer the records are kept for.
#[derive(Clone, Copy)]
struct Answered {
    /// The assistant TURN the answer opened.
    turn: EntityId,
    /// The answering agent definition, which wrote it.
    agent: EntityId,
    /// The requester the turn was written for.
    caller: WriteActor,
    session_key: SessionKey,
}

/// The capture of one rendered board, read as `auth` read it. Pure: it
/// projects what it was handed and reads nothing. A MEMORIES section the
/// settled render does not account for row by row is no capture, logged; the
/// board and its frame are as they were.
pub(super) fn capture_chat_context(
    auth: &CoreAuth,
    memories: Option<&MemoriesSection>,
    worlds: &ResolvedWorldAuthority,
    render: &BoardRender,
) -> Option<ChatContextCapture> {
    let memories = match memories {
        Some(memories) => {
            let Some(settled) = settled_memories(memories, render) else {
                tracing::warn!(
                    "a board's MEMORIES rows do not match its settled render; no chat context is captured"
                );
                return None;
            };
            Some(settled)
        }
        None => None,
    };
    Some(ChatContextCapture {
        memories,
        worlds: worlds.clone(),
        rendered_fingerprint: blake3::hash(render.text.as_bytes()).to_hex().to_string(),
        read_auth: auth.clone(),
    })
}

/// `memories` as the settled render shows it: each world's section in frame
/// order, first-party ones before foreign evidence, as the renderer places
/// them; in each, its pinned floor, then its detail rows only while the
/// section shows them. A foreign row shows no snippet, and one not pinned
/// shows as an index-only handle. `None` when a row is in no section, or in
/// more than one.
fn settled_memories(memories: &MemoriesSection, render: &BoardRender) -> Option<MemoriesSection> {
    let mut settled = memories.clone();
    settled.rows.clear();
    let mut matched = 0;
    for foreign_pass in [false, true] {
        for section in &render.shed.sections {
            let rows: Vec<&MemoryRow> = memories
                .rows
                .iter()
                .filter(|row| {
                    section.name.strip_prefix(MEMORIES_SECTION_PREFIX)
                        == Some(row.world.as_deref().unwrap_or("unscoped"))
                })
                .collect();
            let Some(first) = rows.first() else {
                continue;
            };
            let foreign = first
                .world
                .as_deref()
                .and_then(|id| EntityId::from_hex(id).ok())
                .is_some_and(oneiron::entity_id::is_foreign_world_id_range);
            if foreign != foreign_pass {
                continue;
            }
            matched += rows.len();
            for pinned in [true, false] {
                if !pinned && section.view == SectionView::Counts {
                    continue;
                }
                for row in rows
                    .iter()
                    .filter(|row| (row.tier == MemoryTier::Pinned) == pinned)
                {
                    let mut shown = MemoryRow::clone(row);
                    if foreign {
                        shown.snippet = None;
                        if shown.tier != MemoryTier::Pinned {
                            shown.tier = MemoryTier::IndexOnly;
                        }
                    }
                    shown.row_index = settled.rows.len();
                    settled.rows.push(shown);
                }
            }
        }
    }
    (matched == memories.rows.len()).then_some(settled)
}

/// Freezes `capture` against `request`, the call its board was admitted
/// with. Pure: a field that cannot be frozen leaves the receipt out, logged,
/// and keeps the selection for the board history.
pub(crate) fn freeze_chat_context(
    capture: ChatContextCapture,
    request: &LlmRequest,
) -> FrozenChatContext {
    let emit = match emit_fields(&capture, request) {
        Ok(emit) => Some(emit),
        Err(reason) => {
            tracing::warn!(
                reason,
                "a chat turn's context receipt fields were not frozen"
            );
            None
        }
    };
    FrozenChatContext { capture, emit }
}

/// The receipt's context fields, as `ai.reply` stamps its own, and the
/// admitted request's digest. The model, substrate and effort stay absent:
/// the rung that answers is not known here.
fn emit_fields(
    capture: &ChatContextCapture,
    request: &LlmRequest,
) -> Result<(ContextReceiptFields, String), &'static str> {
    let request_digest = request
        .canonical_hash_hex()
        .map_err(|_| "the admitted request was not digested")?;
    let systems: Vec<_> = request
        .messages
        .iter()
        .filter(|message| message.role == LlmMessageRole::System)
        .collect();
    let systems = serde_json::to_value(systems)
        .map_err(|_| "the admitted system messages were not encoded")?;
    let stamp = PromptRecompileStamp {
        schema_version: PROMPT_RECOMPILE_STAMP_SCHEMA_VERSION.to_owned(),
        prompt_path: String::new(),
        compiled_at_secs: super::super::params::unix_seconds_now(),
        source_fingerprint: capture.rendered_fingerprint.clone(),
        resolved_fingerprint: capture.rendered_fingerprint.clone(),
        assembled_fingerprint: Some(format!(
            "{ADMITTED_SYSTEM_LABEL}{}",
            oneiron::receipt::call_json_digest(&systems)
        )),
        source_paths: Vec::new(),
    };
    // A board with no MEMORIES section showed none: its known absence.
    let absent = MemoriesSection::pins_only(None);
    let memories = capture.memories.as_ref().unwrap_or(&absent);
    let mut fields = ContextReceiptFields::from_assembly(&stamp, memories)
        .map_err(|_| "the shown MEMORIES were not fingerprinted")?
        .prompt_input_ref(format!("{ADMITTED_REQUEST_LABEL}{request_digest}"));
    if let Some(disclosure) = &memories.disclosure {
        fields = fields.disclosure_stamp(&disclosure.emit_stamp);
    }
    Ok((fields, request_digest))
}

/// The answer `answering` produces, handed on as it ends; then, when it saved
/// text as `agent`'s message, its context records are kept for `turn`. No
/// context, as for a turn that keeps no record, leaves `answering` as it was.
pub(crate) fn record_chat_answer(
    server: Arc<SyncServer>,
    context: Option<FrozenChatContext>,
    turn: EntityId,
    agent: EntityId,
    caller: WriteActor,
    session_key: SessionKey,
    answering: Answering,
) -> Answering {
    let Some(context) = context else {
        return answering;
    };
    let Answering {
        handle,
        subscription,
        outcome,
    } = answering;
    let answered = Answered {
        turn,
        agent,
        caller,
        session_key,
    };
    let (finished, forwarded) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let Ok(ended) = outcome.await else {
            return;
        };
        let saved = ended
            .saved
            .as_ref()
            .is_some_and(|saved| saved.actor == agent && saved.message_id == handle.message_id());
        let text = (saved && !ended.text.is_empty()).then(|| ended.text.clone());
        // The outcome goes on as it ended, before any record is read or
        // written; a caller that went away stops neither.
        let _ = finished.send(ended);
        let Some(text) = text else {
            return;
        };
        let kept = tokio::task::spawn_blocking(move || {
            keep_chat_answer(&server, &context, answered, &text);
        })
        .await;
        if let Err(error) = kept {
            tracing::warn!(?error, "a chat answer's context records did not finish");
        }
    });
    Answering {
        handle,
        subscription,
        outcome: forwarded,
    }
}

/// Keeps both records, each on its own: one that is not kept never stops
/// the other. Runs off the runtime, holding no transaction.
fn keep_chat_answer(
    server: &SyncServer,
    context: &FrozenChatContext,
    answered: Answered,
    text: &str,
) {
    if let Err(reason) = keep_chat_emit(server, context, answered, text) {
        tracing::warn!(reason, "a chat answer's context emit receipt was not kept");
    }
    if let Err(reason) = keep_chat_history(server, &context.capture, answered) {
        tracing::warn!(reason, "a chat answer's board history was not kept");
    }
}

/// The requester's read, while it still stands as the turn was asked: its
/// credential live with Read and Write, its turn keeping a durable record,
/// and every captured row still readable to it, live and at the revision the
/// board served it at.
fn requester_read<'a>(
    vault: &'a Vault,
    capture: &ChatContextCapture,
    caller: WriteActor,
) -> Result<ScopedRead<'a>, &'static str> {
    let auth = &capture.read_auth;
    if !auth.credential_is_live(vault)
        || auth.require(CoreScope::Read).is_err()
        || auth.require(CoreScope::Write).is_err()
    {
        return Err("the requesting credential no longer stands");
    }
    // Judged on the caller's own surface now, never a header.
    let surface = match auth.principal_ref() {
        Some(_) => crate::api::credential_memory(
            vault,
            Some(auth),
            caller.entity_ref(),
            caller.actor_class(),
        )
        .at(auth.locality()),
        None => vault.memory(caller.entity_ref(), caller.actor_class()),
    };
    if verb_hook_boundary::keeps_no_record(&surface) {
        return Err("the requesting turn keeps no durable record");
    }
    let read = crate::api::scoped_read_for_core_auth(vault, auth)
        .map_err(|_| "the requesting read was not resolved")?;
    let mut points = Vec::new();
    for row in capture.memories.iter().flat_map(|memories| &memories.rows) {
        let Ok(id) = EntityId::from_hex(&row.id) else {
            continue;
        };
        points.push(PointRead::id(id));
        if let Some(revision) = row.source_revision {
            points.push(PointRead::id(id).at(ReadMode::Pinned(revision)));
        }
    }
    if !points.is_empty() {
        let read_now = read
            .read(&points, None)
            .map_err(|_| "the requesting read was not checked again")?;
        if read_now
            .value
            .iter()
            .any(|row| row.as_ref().is_none_or(|row| row.body.is_none()))
        {
            return Err("a captured row is no longer readable by the requester");
        }
    }
    Ok(read)
}

/// The emit receipt, as the answering agent's, on its conversation.
fn keep_chat_emit(
    server: &SyncServer,
    context: &FrozenChatContext,
    answered: Answered,
    text: &str,
) -> Result<(), &'static str> {
    let Some((fields, request_digest)) = &context.emit else {
        return Ok(());
    };
    let vault = server.vault();
    requester_read(vault, &context.capture, answered.caller)?;
    let conversation = vault
        .record_container(answered.turn)
        .map_err(|_| "the answer's conversation was not read")?
        .ok_or("the answer lies in no conversation")?;
    vault
        .memory(answered.agent, EdgeActorClass::Agent)
        .with_session(answered.session_key)
        .record_context_reply(
            conversation,
            fields,
            request_digest.clone(),
            oneiron::receipt::call_bytes_digest(text.as_bytes()),
        )
        .map_err(|_| "the context emit receipt was not written")?;
    Ok(())
}

/// The answering agent's board history for the answer's TURN, under the
/// agent's own read. A TURN whose body names no agent author has no history
/// its author can claim yet: that costs one read here, and no more.
fn keep_chat_history(
    server: &SyncServer,
    capture: &ChatContextCapture,
    answered: Answered,
) -> Result<(), &'static str> {
    let vault = server.vault();
    // Its own short read, closed before anything else is read.
    let body = vault
        .get(&answered.turn)
        .map_err(|_| "the answer's TURN was not read")?;
    if body.as_deref().and_then(turn_author) != Some(answered.agent) {
        tracing::debug!(
            "the answer's TURN does not carry its agent's byline; it keeps no board history"
        );
        return Ok(());
    }
    let requester = requester_read(vault, capture, answered.caller)?;
    // Each persisted row at the exact revision the board served it at; a
    // revision this capture does not know is never read LIVE in its place.
    let mut points = Vec::new();
    for row in capture.memories.iter().flat_map(|memories| &memories.rows) {
        if row.tier == MemoryTier::IndexOnly {
            continue;
        }
        let Ok(id) = EntityId::from_hex(&row.id) else {
            continue;
        };
        let revision = row
            .source_revision
            .ok_or("a captured row's served revision is unknown")?;
        points.push(PointRead::id(id).at(ReadMode::Pinned(revision)));
    }
    // The world authority is recorded whole or not at all.
    let worlds: BTreeSet<EntityId> = [
        &capture.worlds.allowed_set,
        &capture.worlds.default_subset,
        &capture.worlds.active_set,
    ]
    .into_iter()
    .flat_map(|set| set.worlds().iter().copied())
    .collect();
    for world in &worlds {
        if !requester
            .is_entity_readable(world)
            .map_err(|_| "a captured world was not checked again")?
        {
            return Err("a captured world is no longer readable by the requester");
        }
        points.push(PointRead::id(*world));
    }
    let key = vault
        .memory(answered.agent, EdgeActorClass::Agent)
        .with_session(answered.session_key)
        .read_key()
        .map_err(|_| "the answering agent's read was not resolved")?;
    let author = vault.scoped_read(key);
    if !points.is_empty() {
        let shown = author
            .read(&points, None)
            .map_err(|_| "the answering agent's read was not checked")?;
        if shown
            .value
            .iter()
            .any(|row| row.as_ref().is_none_or(|row| row.body.is_none()))
        {
            return Err("a captured row or world is not readable by the answering agent");
        }
    }
    match vault.record_board_turn_now(
        answered.turn,
        answered.agent,
        capture.memories.as_ref(),
        Some(&capture.worlds),
        &author,
        |_| true,
    ) {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err("the board history was not committed"),
        Err(BoardHistoryError::NotTurnAuthor(_)) => {
            Err("the answer's TURN does not name the answering agent as its author")
        }
        Err(error) => {
            tracing::warn!(%error, "a chat answer's board history was refused");
            Err("the board history write was refused or failed")
        }
    }
}

/// The one author byline a TURN body names, if it names one. The history
/// writer judges it again in its own transaction.
fn turn_author(body: &[u8]) -> Option<EntityId> {
    let mut bytes = body;
    let rmpv::Value::Map(fields) = rmpv::decode::read_value(&mut bytes).ok()? else {
        return None;
    };
    let mut authors = fields
        .iter()
        .filter(|(key, _)| key.as_str() == Some(TURN_AUTHOR_KEY));
    let (_, author) = authors.next()?;
    if authors.next().is_some() {
        return None;
    }
    EntityId::from_hex(author.as_str()?).ok()
}
