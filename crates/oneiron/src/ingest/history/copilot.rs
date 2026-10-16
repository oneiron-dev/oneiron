//! GitHub Copilot session logs, as a hook hands them over (`transcript_path`):
//! VS Code's own transcript (`<workspace storage>/transcripts/<session>.jsonl`)
//! and the Copilot CLI's `session-state/<session>/events.jsonl`.
//!
//! Both write one event per line, `{type, data, id, timestamp, parentId}`,
//! with `agentId` on a subagent's events. The words are in `user.message` and
//! `assistant.message`, whose `data.content` is what the timeline shows; the
//! rest is the session's bookkeeping, tool traffic and reasoning, counted. A
//! user message the harness wrote (a skill's hidden prompt, an autopilot
//! continuation) is counted as injected; one another agent sent is that
//! agent's, never the owner's. Formats: the VS Code writer at
//! `microsoft/vscode@f9350396c4` (`sessionTranscriptService.ts`) and the
//! CLI's events at `github/copilot-sdk@404304416a` (`session-events.ts`).

use serde_json::Value;

use super::text::{json_record, str_field, time_field};
use super::{
    DELEGATING_AGENT, HistoryConversation, HistoryFile, HistoryMessage, HistoryRole, HistorySkips,
    HistoryThreadKind, UNKNOWN_SPEAKER,
};

/// Whether a record is a Copilot event: a dotted `type` and a `data` object.
pub(super) fn is_event(value: &Value) -> bool {
    str_field(value, "type").is_some_and(|kind| kind.contains('.'))
        && value.get("data").is_some_and(Value::is_object)
}

/// One conversation being assembled, with the tool names waiting for the next
/// assistant message.
struct Thread {
    conversation: HistoryConversation,
    pending_tools: Vec<String>,
}

impl Thread {
    fn new(conversation: HistoryConversation) -> Self {
        Self {
            conversation,
            pending_tools: Vec::new(),
        }
    }

    fn skipped(&mut self) -> &mut HistorySkips {
        &mut self.conversation.skipped
    }

    /// Each message follows the one kept before it: an event's own `parentId`
    /// often names a tool or turn event, which is not kept.
    fn push(&mut self, mut message: HistoryMessage) {
        message.parent_id = self
            .conversation
            .messages
            .last()
            .map(|last| last.native_id.clone());
        match message.role {
            HistoryRole::Assistant => {
                let mut tools = std::mem::take(&mut self.pending_tools);
                tools.append(&mut message.tools);
                message.tools = tools;
            }
            HistoryRole::User => self.pending_tools.clear(),
        }
        if let Some(at) = message.at_ms {
            let started = self.conversation.started_at_ms.get_or_insert(at);
            *started = (*started).min(at);
        }
        self.conversation.messages.push(message);
    }

    /// Tool calls label the assistant message they follow, or else the next.
    fn tools(&mut self, names: Vec<String>) {
        match self.conversation.messages.last_mut() {
            Some(last) if last.role == HistoryRole::Assistant => last.tools.extend(names),
            _ => self.pending_tools.extend(names),
        }
    }
}

pub(super) fn decode(text: &str, file: &HistoryFile) -> Vec<HistoryConversation> {
    // The session's own id, from its first event; else the file's (the host
    // names a CLI `events.jsonl` by its session folder).
    let session = session_id(text).unwrap_or_else(|| file.stem.clone());
    let id = format!("copilot:{session}");
    let mut main = Thread::new(HistoryConversation::new(
        id.clone(),
        HistoryThreadKind::Main,
        None,
    ));
    // Each subagent's events form its own conversation, in the order it first
    // appears.
    let mut subagents: Vec<(String, Thread)> = Vec::new();

    for raw in text.lines() {
        if raw.trim().is_empty() {
            continue;
        }
        let Some(event) = json_record(raw).filter(is_event) else {
            main.skipped().unreadable += 1;
            continue;
        };
        let (thread, delegated) = match str_field(&event, "agentId") {
            Some(agent) => {
                let position = match subagents.iter().position(|(key, _)| key == agent) {
                    Some(position) => position,
                    None => {
                        let conversation = HistoryConversation::new(
                            format!("{id}/agent/{agent}"),
                            HistoryThreadKind::Subagent,
                            Some(id.clone()),
                        );
                        subagents.push((agent.to_owned(), Thread::new(conversation)));
                        subagents.len() - 1
                    }
                };
                (&mut subagents[position].1, true)
            }
            None => (&mut main, false),
        };
        // An event marked ephemeral is a stream delta, never meant to be kept.
        if event.get("ephemeral").and_then(Value::as_bool) == Some(true) {
            thread.skipped().other += 1;
            continue;
        }
        let data = &event["data"];
        match str_field(&event, "type").unwrap_or_default() {
            "user.message" => user_event(thread, &event, data, delegated),
            "assistant.message" => assistant_event(thread, &event, data),
            "assistant.reasoning" => thread.skipped().thinking += 1,
            "tool.execution_complete" => thread.skipped().tool_results += 1,
            "system.message" | "system.notification" => thread.skipped().system += 1,
            "session.start" => {
                let conversation = &mut thread.conversation;
                if conversation.cwd.is_none() {
                    conversation.cwd = data
                        .get("context")
                        .and_then(|context| str_field(context, "cwd"))
                        .map(str::to_owned);
                }
                if let Some(at) = time_field(data, "startTime") {
                    let started = conversation.started_at_ms.get_or_insert(at);
                    *started = (*started).min(at);
                }
                thread.skipped().other += 1;
            }
            _ => thread.skipped().other += 1,
        }
    }
    let mut out = vec![main.conversation];
    out.extend(subagents.into_iter().map(|(_, thread)| thread.conversation));
    out
}

/// The id the log's `session.start` event gives its session.
fn session_id(text: &str) -> Option<String> {
    text.lines()
        .filter(|line| line.contains("\"session.start\""))
        .filter_map(json_record)
        .find(|event| str_field(event, "type") == Some("session.start"))
        .and_then(|event| str_field(&event["data"], "sessionId").map(str::to_owned))
}

/// A user message: kept when a person or another agent said it, counted when
/// the harness wrote it. A subagent's prompts are the delegating agent's.
fn user_event(thread: &mut Thread, event: &Value, data: &Value, delegated: bool) {
    let (Some(id), Some(content)) = (
        str_field(event, "id"),
        data.get("content").and_then(Value::as_str),
    ) else {
        thread.skipped().unreadable += 1;
        return;
    };
    let attachments = data
        .get("attachments")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    thread.skipped().attachments += u32::try_from(attachments).unwrap_or(u32::MAX);
    let source = str_field(data, "source");
    let autopilot = data.get("isAutopilotContinuation").and_then(Value::as_bool) == Some(true);
    if autopilot || source.is_some_and(|source| source.starts_with("skill-")) {
        thread.skipped().injected += 1;
        return;
    }
    let said_by = if delegated {
        Some(DELEGATING_AGENT)
    } else {
        match source {
            None => None,
            Some(source) if source.starts_with("agent-") => Some(DELEGATING_AGENT),
            Some(_) => Some(UNKNOWN_SPEAKER),
        }
    };
    let text = content.trim();
    if text.is_empty() {
        thread.skipped().empty += 1;
        return;
    }
    thread.push(HistoryMessage {
        native_id: format!("copilot:{id}"),
        parent_id: None,
        role: HistoryRole::User,
        text: text.to_owned(),
        at_ms: time_field(event, "timestamp"),
        said_by,
        tools: Vec::new(),
        alias: None,
    });
}

/// An assistant message: its words kept, its tool requests named on it and
/// counted, its reasoning counted.
fn assistant_event(thread: &mut Thread, event: &Value, data: &Value) {
    let (Some(id), Some(content)) = (
        str_field(event, "id"),
        data.get("content").and_then(Value::as_str),
    ) else {
        thread.skipped().unreadable += 1;
        return;
    };
    let requests = data
        .get("toolRequests")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    thread.skipped().tool_calls += u32::try_from(requests.len()).unwrap_or(u32::MAX);
    let tools: Vec<String> = requests
        .iter()
        .filter_map(|request| str_field(request, "name"))
        .map(str::to_owned)
        .collect();
    let reasoned = ["reasoningText", "reasoningOpaque", "encryptedContent"]
        .iter()
        .any(|key| str_field(data, key).is_some());
    if reasoned {
        thread.skipped().thinking += 1;
    }
    let text = content.trim();
    if text.is_empty() {
        if requests.is_empty() && !reasoned {
            thread.skipped().empty += 1;
        }
        thread.tools(tools);
        return;
    }
    thread.push(HistoryMessage {
        native_id: format!("copilot:{id}"),
        parent_id: None,
        role: HistoryRole::Assistant,
        text: text.to_owned(),
        at_ms: time_field(event, "timestamp"),
        said_by: None,
        tools,
        alias: None,
    });
}
