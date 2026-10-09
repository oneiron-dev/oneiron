//! Codex session rollouts: one JSONL file per session under
//! `sessions/YYYY/MM/DD/`.
//!
//! A current rollout wraps each line as `{timestamp, type, payload}`:
//! `session_meta` first, then response items (what went to and from the model)
//! and events (what the app showed). One message is often recorded twice: as a
//! response item, and as an event (a `user_message` / `agent_message`, one per
//! content block, or a completed `UserMessage` / `AgentMessage` item). The app
//! also wraps what the person typed in context it attached, and sends whole
//! context blocks (instructions, environment, plugin listings) as user items.
//! Both representations are cleared of that context first, then each message
//! is kept once: the response item's id and time, the person's words. An
//! event is paired only within its item's emission group, the lines between
//! the item before and the item after, so the same words said again later
//! stay their own message. A legacy rollout begins with `{id, timestamp,
//! instructions}` and holds bare response items with no time of their own.
//!
//! A forked or spawned thread's rollout begins with a copy of its parent's
//! history: the parent's meta line again, then its items. Items keep their ids
//! there, so the import ledger lands them once. A message with no id gets one
//! chained from the id of the message before it, which the copy reproduces,
//! so it too lands once. The words are not part of it: a corrected message
//! keeps its id, and lands as a revision. A reply is logged as its event just
//! before its item, so a log read in between holds the event alone, which
//! takes a chained id; once the item is logged, the message keeps that id as
//! its alias beside the item's own.

use std::collections::HashMap;
use std::ops::Range;

use serde_json::Value;

use super::text::{join_texts, json_record, str_field, time_field};
use super::{
    HistoryConversation, HistoryFile, HistoryMessage, HistoryRole, HistorySkips, HistoryThreadKind,
};

/// The user side of a spawned agent's thread is the agent that spawned it.
const DELEGATING_AGENT: &str = "delegating_agent";

/// How far apart (in lines) an event and the response item wrapping it may be.
const WRAPPED_PAIR_WINDOW: usize = 200;

/// Wrappers the Codex clients put around what the person typed: the IDE
/// extension's context (active file, selection, open tabs) and the files the
/// person mentioned. The request follows [`REQUEST_HEADER`].
const WRAPPER_HEADERS: [&str; 2] = [
    "# Context from my IDE setup:",
    "# Files mentioned by the user:",
];
const REQUEST_HEADER: &str = "## My request for Codex:";

/// Blocks the Codex clients add on the user side: environment, instructions,
/// plugin and skill listings, browser and app context, delegation and agent
/// notices. A user item made only of these is context, not typed words.
const CONTEXT_TAGS: [&str; 16] = [
    "environment_context",
    "user_instructions",
    "recommended_plugins",
    "in-app-browser-context",
    "codex_delegation",
    "codex_internal_context",
    "image",
    "skill",
    "subagent_notification",
    "user_action",
    "external_codex_apps_open_page",
    "turn_aborted",
    "heartbeat",
    "user_shell_command",
    "permissions",
    "app-context",
];

/// The instructions a client sends as a user item for an `AGENTS.md`.
const AGENTS_INSTRUCTIONS_HEADER: &str = "# AGENTS.md instructions for ";

/// A message as one representation recorded it.
struct Candidate {
    line: usize,
    role: HistoryRole,
    text: String,
    /// The response item's text blocks, which classic events echo one each.
    blocks: Vec<String>,
    id: Option<String>,
    at_ms: Option<u64>,
}

#[derive(Default)]
struct Rollout {
    session: Option<String>,
    /// Every meta line's session id by line: the file's own first, then the
    /// parent's a copied history carries.
    metas: Vec<(usize, String)>,
    /// The line a forked or spawned thread's own history starts at; the lines
    /// before it are its parent's, copied.
    own_history_from: Option<usize>,
    spawned_by: Option<String>,
    forked_from: Option<String>,
    started_at_ms: Option<u64>,
    responses: Vec<Candidate>,
    events: Vec<Candidate>,
    /// Tool calls by line, to label the assistant message they belong to.
    tool_calls: Vec<(usize, String)>,
    skipped: HistorySkips,
}

pub(super) fn decode(text: &str, file: &HistoryFile) -> Vec<HistoryConversation> {
    let mut rollout = Rollout::default();
    let mut first = true;
    for (line, raw) in text.lines().enumerate() {
        if raw.trim().is_empty() {
            continue;
        }
        let Some(value) = json_record(raw) else {
            rollout.skipped.unreadable += 1;
            continue;
        };
        let legacy_meta = first && value.get("type").is_none() && value.get("id").is_some();
        first = false;
        match (str_field(&value, "type"), value.get("payload")) {
            (Some(kind), Some(payload)) if payload.is_object() => {
                let at = time_field(&value, "timestamp");
                rollout.line(kind, payload, line, at);
            }
            _ if legacy_meta => rollout.meta(&value, line, None),
            _ if value.get("record_type").is_some() => rollout.skipped.other += 1,
            _ => rollout.response_item(&value, line, None),
        }
    }
    rollout.into_conversation(file)
}

/// The text blocks of a content value; images are counted.
fn content_blocks(content: Option<&Value>, skipped: &mut HistorySkips) -> Vec<String> {
    match content {
        Some(Value::String(text)) => vec![text.trim().to_owned()],
        Some(Value::Array(blocks)) => {
            let mut texts = Vec::new();
            for block in blocks {
                match str_field(block, "type") {
                    Some("input_text" | "output_text" | "text" | "Text") => {
                        texts.extend(str_field(block, "text").map(|text| text.trim().to_owned()));
                    }
                    Some("input_image" | "image" | "local_image") => skipped.attachments += 1,
                    _ => skipped.other += 1,
                }
            }
            texts
        }
        _ => Vec::new(),
    }
}

/// The opening `<tag>` of `text` when it is one of [`CONTEXT_TAGS`], with
/// the rest of `text` after that block's closing tag.
fn strip_context_block(text: &str) -> Option<&str> {
    let rest = text.strip_prefix('<')?;
    let tag = CONTEXT_TAGS.iter().find(|tag| {
        rest.strip_prefix(**tag)
            .is_some_and(|after| after.starts_with(['>', ' ', '\n']))
    })?;
    let close = format!("</{tag}>");
    let end = text.find(&close)?;
    Some(&text[end + close.len()..])
}

/// What the person typed in a user item, cleared of the context the client
/// attached; empty when the item is all context.
fn typed_words(text: &str) -> &str {
    let mut text = text.trim();
    for header in WRAPPER_HEADERS {
        if let Some(wrapped) = text.strip_prefix(header) {
            return wrapped
                .split_once(REQUEST_HEADER)
                .map_or("", |(_, request)| request.trim());
        }
    }
    if text.starts_with(AGENTS_INSTRUCTIONS_HEADER) {
        return "";
    }
    while let Some(rest) = strip_context_block(text) {
        text = rest.trim_start();
    }
    text.trim_end()
}

/// A user item's typed words, or `None` with the context counted.
fn user_text(text: &str, skipped: &mut HistorySkips) -> Option<String> {
    let typed = typed_words(text);
    if typed.len() != text.trim().len() {
        skipped.injected += 1;
    }
    (!typed.is_empty()).then(|| typed.to_owned())
}

impl Rollout {
    fn meta(&mut self, payload: &Value, line: usize, at: Option<u64>) {
        self.skipped.other += 1;
        let id = str_field(payload, "id")
            .or_else(|| str_field(payload, "session_id"))
            .map(str::to_owned);
        if let Some(id) = &id {
            self.metas.push((line, id.clone()));
        }
        // A forked or spawned thread's rollout carries its parent's meta again
        // inside the history it copied; the file's own meta comes first.
        if self.session.is_some() {
            return;
        }
        self.session = id;
        // A spawned agent names its parent thread at the top level in current
        // rollouts, and under its subagent source in earlier ones.
        self.spawned_by = str_field(payload, "parent_thread_id")
            .or_else(|| {
                payload
                    .pointer("/source/subagent/thread_spawn/parent_thread_id")
                    .and_then(Value::as_str)
            })
            .map(str::to_owned);
        self.forked_from = str_field(payload, "forked_from_id").map(str::to_owned);
        self.own_history_from = payload
            .get("subagent_history_start_ordinal")
            .and_then(Value::as_u64)
            .and_then(|line| usize::try_from(line).ok());
        self.started_at_ms = time_field(payload, "timestamp").or(at);
    }

    fn line(&mut self, kind: &str, payload: &Value, line: usize, at: Option<u64>) {
        match kind {
            "session_meta" => self.meta(payload, line, at),
            "response_item" => self.response_item(payload, line, at),
            "event_msg" => self.event(payload, line, at),
            // Turn context, compaction (its replacement history is a copy),
            // world state, token usage.
            _ => self.skipped.other += 1,
        }
    }

    fn response_item(&mut self, payload: &Value, line: usize, at: Option<u64>) {
        let kind = str_field(payload, "type").unwrap_or_default();
        match kind {
            "message" => {
                let role = match str_field(payload, "role") {
                    Some("user") => HistoryRole::User,
                    Some("assistant") => HistoryRole::Assistant,
                    _ => {
                        self.skipped.system += 1;
                        return;
                    }
                };
                let blocks = content_blocks(payload.get("content"), &mut self.skipped);
                let joined = join_texts(&blocks.iter().map(String::as_str).collect::<Vec<_>>());
                let text = match role {
                    HistoryRole::User => user_text(&joined, &mut self.skipped),
                    HistoryRole::Assistant => Some(joined),
                };
                let Some(text) = text.filter(|text| !text.is_empty()) else {
                    if blocks.iter().all(String::is_empty) {
                        self.skipped.empty += 1;
                    }
                    return;
                };
                self.responses.push(Candidate {
                    line,
                    role,
                    text,
                    blocks,
                    id: str_field(payload, "id").map(str::to_owned),
                    at_ms: at,
                });
            }
            "reasoning" => self.skipped.thinking += 1,
            // Messages between agents, not to or from the person.
            "agent_message" => self.skipped.injected += 1,
            kind if kind.ends_with("_output") => self.skipped.tool_results += 1,
            kind if kind.ends_with("_call") => {
                self.skipped.tool_calls += 1;
                let name = str_field(payload, "name").unwrap_or(kind);
                self.tool_calls.push((line, name.to_owned()));
            }
            _ => self.skipped.other += 1,
        }
    }

    fn event(&mut self, payload: &Value, line: usize, at: Option<u64>) {
        let mut uncounted = HistorySkips::default();
        // An event's item id is a counter within its session (`item-1`,
        // `item-2`, …), reused by every other session, so it never names a
        // message: an event-only message takes a chained id instead.
        let (role, text) = match str_field(payload, "type") {
            Some("user_message") => {
                // Classic events mark instructions and environment as a kind.
                if str_field(payload, "kind").is_some_and(|kind| kind != "plain") {
                    self.skipped.injected += 1;
                    return;
                }
                let text = str_field(payload, "message").unwrap_or_default();
                (HistoryRole::User, text.to_owned())
            }
            Some("agent_message") => {
                let text = str_field(payload, "message").unwrap_or_default().trim();
                (HistoryRole::Assistant, text.to_owned())
            }
            Some("item_completed") => {
                let item = payload.get("item").unwrap_or(&Value::Null);
                let role = match str_field(item, "type") {
                    Some("UserMessage") => HistoryRole::User,
                    Some("AgentMessage") => HistoryRole::Assistant,
                    // Command runs, file changes, tool calls: the event view
                    // of what the response items already count.
                    _ => {
                        self.skipped.other += 1;
                        return;
                    }
                };
                let blocks = content_blocks(item.get("content"), &mut uncounted);
                let text = join_texts(&blocks.iter().map(String::as_str).collect::<Vec<_>>());
                (role, text)
            }
            _ => {
                self.skipped.other += 1;
                return;
            }
        };
        // The event view is cleared of the same context as the item, so the
        // two compare as the same words.
        let text = match role {
            HistoryRole::User => user_text(&text, &mut uncounted),
            HistoryRole::Assistant => Some(text),
        };
        let Some(text) = text.filter(|text| !text.is_empty()) else {
            self.skipped.empty += 1;
            return;
        };
        self.events.push(Candidate {
            line,
            role,
            text,
            blocks: Vec::new(),
            id: None,
            at_ms: at,
        });
    }

    /// Pairs each response item with the events that echo it, then keeps every
    /// message once, in log order.
    fn messages(&mut self) -> Vec<Candidate> {
        let events = std::mem::take(&mut self.events);
        let mut responses = std::mem::take(&mut self.responses);
        let mut by_text: HashMap<(HistoryRole, &str), Vec<usize>> = HashMap::new();
        for (index, event) in events.iter().enumerate() {
            by_text
                .entry((event.role, event.text.as_str()))
                .or_default()
                .push(index);
        }
        // Each item's emission group: the lines after the item before it and
        // before the item after it. Its events are logged there, before the
        // item (a current reply) or after it (a request, a classic reply).
        let groups: Vec<Range<usize>> = (0..responses.len())
            .map(|index| {
                let start = index
                    .checked_sub(1)
                    .map_or(0, |before| responses[before].line + 1);
                let end = responses
                    .get(index + 1)
                    .map_or(usize::MAX, |after| after.line);
                start..end
            })
            .collect();
        // The first event in `group` with these words that no item has claimed.
        let find = |role: HistoryRole, text: &str, group: &Range<usize>, claimed: &[bool]| {
            by_text
                .get(&(role, text))?
                .iter()
                .copied()
                .find(|&index| !claimed[index] && group.contains(&events[index].line))
        };
        let mut claimed = vec![false; events.len()];
        let mut paired = vec![false; responses.len()];
        // Exact twins first, for every item, so no looser match below can take
        // an event that is another item's exact echo.
        for ((response, paired), group) in responses.iter().zip(&mut paired).zip(&groups) {
            if let Some(index) = find(response.role, &response.text, group, &claimed) {
                claimed[index] = true;
                *paired = true;
                self.skipped.duplicates += 1;
            }
        }
        // Classic events echo a reply one content block at a time, after the
        // item; a log read while it is written may hold only the first
        // blocks' events yet. Each block's echo in the item's group is the
        // item's, whether or not every block has one by now.
        for ((response, paired), group) in responses.iter().zip(&mut paired).zip(&groups) {
            if *paired || response.role != HistoryRole::Assistant {
                continue;
            }
            let blocks: Vec<&str> = response
                .blocks
                .iter()
                .map(String::as_str)
                .filter(|block| !block.is_empty())
                .collect();
            if blocks.len() < 2 {
                continue;
            }
            for block in blocks {
                if let Some(index) = find(response.role, block, group, &claimed) {
                    claimed[index] = true;
                    *paired = true;
                    self.skipped.duplicates += 1;
                }
            }
        }
        // A user item that still wraps its event's words in context no rule
        // knows: the event logged right after it, in its group.
        for ((response, paired), group) in responses.iter_mut().zip(&mut paired).zip(&groups) {
            if *paired || response.role != HistoryRole::User {
                continue;
            }
            let wrapped = events.iter().enumerate().find(|(index, event)| {
                !claimed[*index]
                    && event.role == HistoryRole::User
                    && event.line > response.line
                    && group.contains(&event.line)
                    && event.line - response.line <= WRAPPED_PAIR_WINDOW
                    && response.text.contains(event.text.as_str())
            });
            if let Some((index, event)) = wrapped {
                claimed[index] = true;
                *paired = true;
                self.skipped.duplicates += 1;
                response.text.clone_from(&event.text);
            }
        }
        let mut kept = responses;
        kept.extend(
            events
                .into_iter()
                .zip(claimed)
                .filter_map(|(event, claimed)| (!claimed).then_some(event)),
        );
        kept.sort_by_key(|candidate| candidate.line);
        kept
    }

    fn into_conversation(mut self, file: &HistoryFile) -> Vec<HistoryConversation> {
        let session = self.session.clone().unwrap_or_else(|| file.stem.clone());
        let parent = self.spawned_by.clone().or_else(|| self.forked_from.clone());
        let kind = if parent.is_some() {
            HistoryThreadKind::Subagent
        } else {
            HistoryThreadKind::Main
        };
        let said_by = self.spawned_by.is_some().then_some(DELEGATING_AGENT);
        let messages = self.messages();
        let mut conversation = HistoryConversation::new(session.clone(), kind, parent);
        conversation.started_at_ms = self.started_at_ms;
        let mut tool_calls = self.tool_calls.into_iter().peekable();
        let mut pending: Vec<String> = Vec::new();
        // An id-less message chains from the session its history began in:
        // the last meta before the first message, which a copied history
        // carries.
        let first_line = messages.first().map_or(0, |candidate| candidate.line);
        let mut previous = self
            .metas
            .iter()
            .rev()
            .find(|(line, _)| *line < first_line)
            .map_or_else(|| session.clone(), |(_, id)| id.clone());
        let mut own_chain = false;
        for candidate in messages {
            // A thread's own messages chain from its own session, so the same
            // words typed after the same copied history in two forks stay two
            // messages; only the copied history chains from the parent's.
            if !own_chain
                && self
                    .own_history_from
                    .is_some_and(|start| candidate.line >= start)
            {
                own_chain = true;
                previous.clone_from(&session);
            }
            // Calls logged before this message label the assistant message
            // they followed, or else this one.
            while let Some((_, name)) = tool_calls.next_if(|(call, _)| *call < candidate.line) {
                match conversation.messages.last_mut() {
                    Some(last) if last.role == HistoryRole::Assistant => last.tools.push(name),
                    _ => pending.push(name),
                }
            }
            let chained = chained_id(candidate.role, &previous);
            let (native_id, alias) = match candidate.id {
                Some(id) => (id, Some(chained)),
                None => (chained, None),
            };
            previous.clone_from(&native_id);
            let mut message = HistoryMessage {
                native_id,
                parent_id: None,
                role: candidate.role,
                text: candidate.text,
                at_ms: candidate.at_ms,
                said_by: None,
                tools: Vec::new(),
                alias,
            };
            match message.role {
                HistoryRole::Assistant => message.tools = std::mem::take(&mut pending),
                HistoryRole::User => {
                    pending.clear();
                    message.said_by = said_by;
                }
            }
            conversation.messages.push(message);
        }
        if let Some(last) = conversation
            .messages
            .last_mut()
            .filter(|last| last.role == HistoryRole::Assistant)
        {
            last.tools.extend(tool_calls.map(|(_, name)| name));
        }
        conversation.skipped = self.skipped;
        vec![conversation]
    }
}

/// An id for a message the rollout recorded without one: its side and the id
/// of the message before it (for the first, of the session its history began
/// in). A copied history reproduces both; another session does not.
fn chained_id(role: HistoryRole, previous: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(match role {
        HistoryRole::User => b"user\0",
        HistoryRole::Assistant => b"asst\0",
    });
    hasher.update(previous.as_bytes());
    format!("chained:{}", &hasher.finalize().to_hex()[..32])
}
