//! Claude Code session logs: one JSONL file per session in a project
//! directory, and one per subagent under `<session>/subagents/`.
//!
//! A log interleaves the conversation with bookkeeping. An assistant reply
//! arrives as one line per content block (text, tool call, thinking), each with
//! its own `uuid`. Tool results come back as user lines. The host also writes
//! user-side lines nobody typed: reminders, task notifications, slash-command
//! wrappers, compaction summaries. Only what a person or the assistant said is
//! kept; the rest is counted.

use std::collections::{HashSet, VecDeque};

use serde_json::Value;

use super::text::{join_texts, str_field, time_field};
use super::{
    HistoryConversation, HistoryFile, HistoryMessage, HistoryRole, HistorySkips, HistoryThreadKind,
};

/// The user side of a subagent's log is the agent that delegated the task.
const DELEGATING_AGENT: &str = "delegating_agent";

/// User-side text the host wrote rather than the person: command wrappers and
/// their output, shell escapes, notifications, interruption markers.
const INJECTED_PREFIXES: [&str; 8] = [
    "<command-",
    "<local-command-",
    "<bash-",
    "<task-notification",
    "<system-reminder",
    "<user-prompt-submit-hook",
    "[Request interrupted by user",
    "Caveat: The messages below",
];

/// One conversation being assembled, with the tool names waiting for the next
/// assistant message and the best title seen so far.
struct Thread {
    conversation: HistoryConversation,
    pending_tools: Vec<String>,
    title_rank: u8,
}

impl Thread {
    fn new(conversation: HistoryConversation) -> Self {
        Self {
            conversation,
            pending_tools: Vec::new(),
            title_rank: 0,
        }
    }

    fn skipped(&mut self) -> &mut HistorySkips {
        &mut self.conversation.skipped
    }

    fn push(&mut self, mut message: HistoryMessage) {
        if message.role == HistoryRole::Assistant {
            let mut tools = std::mem::take(&mut self.pending_tools);
            tools.append(&mut message.tools);
            message.tools = tools;
        } else {
            self.pending_tools.clear();
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

    fn title(&mut self, title: Option<&str>, rank: u8) {
        if let Some(title) = title
            && rank >= self.title_rank
        {
            self.conversation.title = Some(title.to_owned());
            self.title_rank = rank;
        }
    }
}

pub(super) fn decode(text: &str, file: &HistoryFile) -> Vec<HistoryConversation> {
    // Subagent logs sit under `<session>/subagents/`, or (older releases) as
    // `agent-<id>.jsonl` beside the sessions, naming their session in each line.
    let session = file.parent.clone().or_else(|| {
        file.stem
            .starts_with("agent-")
            .then(|| first_session_id(text))
            .flatten()
    });
    let (id, kind, parent) = match session {
        Some(session) => (
            format!("{session}/{}", file.stem),
            HistoryThreadKind::Subagent,
            Some(session),
        ),
        None => (file.stem.clone(), HistoryThreadKind::Main, None),
    };
    let said_by = (kind == HistoryThreadKind::Subagent).then_some(DELEGATING_AGENT);
    let mut main = Thread::new(HistoryConversation::new(id.clone(), kind, parent));
    // Older logs keep a session's sidechains inline; each agent gets its own
    // conversation, in the order it first appears.
    let mut sidechains: Vec<(String, Thread)> = Vec::new();
    let typed_elsewhere = typed_texts(text);
    let mut queued: VecDeque<Queued> = VecDeque::new();

    for (line, raw) in text.lines().enumerate() {
        if raw.trim().is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(raw) else {
            main.skipped().unreadable += 1;
            continue;
        };
        if !value.is_object() {
            main.skipped().unreadable += 1;
            continue;
        }
        // A subagent's own log is all sidechain; only a session's log keeps
        // sidechains inline.
        let inline_sidechain = kind == HistoryThreadKind::Main
            && value.get("isSidechain").and_then(Value::as_bool) == Some(true);
        let (thread, said_by) = if inline_sidechain {
            let agent = str_field(&value, "agentId")
                .unwrap_or("sidechain")
                .to_owned();
            let position = match sidechains.iter().position(|(key, _)| *key == agent) {
                Some(position) => position,
                None => {
                    let conversation = HistoryConversation::new(
                        format!("{id}/sidechain/{agent}"),
                        HistoryThreadKind::Sidechain,
                        Some(id.clone()),
                    );
                    sidechains.push((agent, Thread::new(conversation)));
                    sidechains.len() - 1
                }
            };
            (&mut sidechains[position].1, Some(DELEGATING_AGENT))
        } else {
            (&mut main, said_by)
        };
        let fallback_id = format!("{id}#L{line}");
        match str_field(&value, "type") {
            Some("user") => user_line(thread, &value, &fallback_id, said_by),
            Some("assistant") => assistant_line(thread, &value, &fallback_id),
            Some("attachment") => attachment_line(thread, &value, &fallback_id, said_by),
            Some("queue-operation") => {
                let queue = Queue {
                    queued: &mut queued,
                    typed_elsewhere: &typed_elsewhere,
                };
                queue.line(thread, &value, &fallback_id, said_by);
            }
            Some("system") => thread.skipped().system += 1,
            Some("custom-title") => {
                thread.title(str_field(&value, "customTitle"), 3);
                thread.skipped().other += 1;
            }
            Some("ai-title") => {
                thread.title(str_field(&value, "aiTitle"), 2);
                thread.skipped().other += 1;
            }
            Some("summary") => {
                thread.title(str_field(&value, "summary"), 1);
                thread.skipped().other += 1;
            }
            _ => thread.skipped().other += 1,
        }
    }
    let mut out = vec![main.conversation];
    out.extend(
        sidechains
            .into_iter()
            .map(|(_, thread)| thread.conversation),
    );
    out
}

/// A prompt typed while the assistant was busy, waiting in Claude Code's queue.
struct Queued {
    text: String,
    at_ms: Option<u64>,
    native_id: String,
}

/// Every user-side text the log also holds as a typed line or a queued
/// command attachment, to land a queued prompt once.
fn typed_texts(text: &str) -> HashSet<String> {
    let mut texts = HashSet::new();
    for value in text
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
    {
        let content = match str_field(&value, "type") {
            Some("user") if value.get("isMeta").and_then(Value::as_bool) != Some(true) => {
                value.pointer("/message/content")
            }
            Some("attachment") => value
                .get("attachment")
                .filter(|attachment| str_field(attachment, "type") == Some("queued_command"))
                .and_then(|attachment| attachment.get("prompt")),
            _ => None,
        };
        let text = user_text(content, &mut HistorySkips::default());
        if !text.is_empty() {
            texts.insert(text);
        }
    }
    texts
}

/// Claude Code's prompt queue: `enqueue` holds the words; `dequeue` hands the
/// oldest to the next turn and `remove` hands one over mid-turn. Either may
/// leave no other trace of the words (a meta wrapper, an attachment the log
/// did not keep), so a handed-over prompt lands from here unless the log also
/// holds it as a typed line or a queued-command attachment. `popAll` takes the
/// queue back into the input box: those prompts were withdrawn.
struct Queue<'a> {
    queued: &'a mut VecDeque<Queued>,
    typed_elsewhere: &'a HashSet<String>,
}

impl Queue<'_> {
    fn line(
        self,
        thread: &mut Thread,
        value: &Value,
        fallback_id: &str,
        said_by: Option<&'static str>,
    ) {
        let content = str_field(value, "content").map(str::trim);
        let handed = match str_field(value, "operation") {
            Some("enqueue") => {
                match content {
                    Some(text) if !text.starts_with('<') && !injected(text) => {
                        thread.skipped().other += 1;
                        self.queued.push_back(Queued {
                            text: text.to_owned(),
                            at_ms: time_field(value, "timestamp"),
                            native_id: fallback_id.to_owned(),
                        });
                    }
                    _ => thread.skipped().injected += 1,
                }
                None
            }
            Some("dequeue") => {
                thread.skipped().other += 1;
                self.queued.pop_front()
            }
            Some("remove") => {
                thread.skipped().other += 1;
                content.and_then(|text| {
                    let position = self.queued.iter().position(|queued| queued.text == text)?;
                    self.queued.remove(position)
                })
            }
            Some("popAll") => {
                thread.skipped().other += 1;
                self.queued.clear();
                None
            }
            _ => {
                thread.skipped().other += 1;
                None
            }
        };
        let Some(queued) = handed else {
            return;
        };
        if self.typed_elsewhere.contains(&queued.text) {
            thread.skipped().duplicates += 1;
            return;
        }
        thread.push(HistoryMessage {
            native_id: queued.native_id,
            parent_id: None,
            role: HistoryRole::User,
            text: queued.text,
            at_ms: queued.at_ms,
            said_by,
            tools: Vec::new(),
        });
    }
}

/// The session id the first line that names one carries.
fn first_session_id(text: &str) -> Option<String> {
    text.lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find_map(|value| str_field(&value, "sessionId").map(str::to_owned))
}

/// A slash command the person typed with arguments, as they typed it. Without
/// arguments (`/cost`, `/clear`) it is a command, not words.
fn typed_command(text: &str) -> Option<String> {
    let field = |tag: &str| {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        let start = text.find(&open)? + open.len();
        let end = start + text[start..].find(&close)?;
        Some(text[start..end].trim())
    };
    let name = field("command-name")?;
    let arguments = field("command-args").filter(|arguments| !arguments.is_empty())?;
    Some(format!("{name} {arguments}"))
}

fn message(value: &Value, fallback_id: &str, role: HistoryRole, text: String) -> HistoryMessage {
    HistoryMessage {
        native_id: str_field(value, "uuid").unwrap_or(fallback_id).to_owned(),
        parent_id: str_field(value, "parentUuid").map(str::to_owned),
        role,
        text,
        at_ms: time_field(value, "timestamp"),
        said_by: None,
        tools: Vec::new(),
    }
}

fn injected(text: &str) -> bool {
    let text = text.trim_start();
    INJECTED_PREFIXES
        .iter()
        .any(|prefix| text.starts_with(prefix))
}

/// A user-side origin other than a person typing: a task notification, a
/// peer agent, a coordinator.
fn foreign_origin(origin: Option<&Value>) -> bool {
    origin.is_some_and(|origin| str_field(origin, "kind") != Some("human"))
}

/// Text blocks of a content value; tool results and attachments are counted.
fn user_text(content: Option<&Value>, skipped: &mut HistorySkips) -> String {
    match content {
        Some(Value::String(text)) => text.trim().to_owned(),
        Some(Value::Array(blocks)) => {
            let mut texts = Vec::new();
            for block in blocks {
                match str_field(block, "type") {
                    Some("text") => texts.extend(str_field(block, "text")),
                    Some("tool_result") => skipped.tool_results += 1,
                    Some("image" | "document") => skipped.attachments += 1,
                    _ => skipped.other += 1,
                }
            }
            join_texts(&texts)
        }
        _ => String::new(),
    }
}

fn user_line(thread: &mut Thread, value: &Value, fallback_id: &str, said_by: Option<&'static str>) {
    let flagged = ["isMeta", "isCompactSummary", "isVisibleInTranscriptOnly"]
        .iter()
        .any(|flag| value.get(*flag).and_then(Value::as_bool) == Some(true));
    if flagged || foreign_origin(value.get("origin")) {
        thread.skipped().injected += 1;
        return;
    }
    let content = value.pointer("/message/content");
    let carried_result = content.and_then(Value::as_array).is_some_and(|blocks| {
        blocks
            .iter()
            .any(|block| str_field(block, "type") == Some("tool_result"))
    });
    let text = user_text(content, thread.skipped());
    if text.is_empty() {
        if !carried_result {
            thread.skipped().empty += 1;
        }
        return;
    }
    let text = if injected(&text) {
        match typed_command(&text) {
            Some(command) => command,
            None => {
                thread.skipped().injected += 1;
                return;
            }
        }
    } else {
        text
    };
    let mut kept = message(value, fallback_id, HistoryRole::User, text);
    kept.said_by = said_by;
    thread.push(kept);
}

fn assistant_line(thread: &mut Thread, value: &Value, fallback_id: &str) {
    // An API error notice and a `<synthetic>` reply are the host's words.
    if value.get("isApiErrorMessage").and_then(Value::as_bool) == Some(true)
        || value.pointer("/message/model").and_then(Value::as_str) == Some("<synthetic>")
    {
        thread.skipped().system += 1;
        return;
    }
    let mut tools = Vec::new();
    let text = match value.pointer("/message/content") {
        Some(Value::String(text)) => text.trim().to_owned(),
        Some(Value::Array(blocks)) => {
            let mut texts = Vec::new();
            for block in blocks {
                match str_field(block, "type") {
                    Some("text") => texts.extend(str_field(block, "text")),
                    Some("tool_use" | "server_tool_use") => {
                        thread.skipped().tool_calls += 1;
                        tools.extend(str_field(block, "name").map(str::to_owned));
                    }
                    Some("thinking" | "redacted_thinking") => thread.skipped().thinking += 1,
                    _ => thread.skipped().other += 1,
                }
            }
            join_texts(&texts)
        }
        _ => String::new(),
    };
    if text.is_empty() {
        if tools.is_empty() && value.pointer("/message/content").is_none() {
            thread.skipped().empty += 1;
        }
        thread.tools(tools);
        return;
    }
    let mut kept = message(value, fallback_id, HistoryRole::Assistant, text);
    kept.tools = tools;
    thread.push(kept);
}

/// A prompt the person typed while the assistant was busy arrives as a queued
/// command attachment (`commandMode: prompt` in current releases, no mode in
/// older ones); every other attachment is context the host added. The queued
/// prompt's own id is its `source_uuid`, so a copy of it lands once.
fn attachment_line(
    thread: &mut Thread,
    value: &Value,
    fallback_id: &str,
    said_by: Option<&'static str>,
) {
    let attachment = value.get("attachment").unwrap_or(&Value::Null);
    let typed = str_field(attachment, "type") == Some("queued_command")
        && str_field(attachment, "commandMode").is_none_or(|mode| mode == "prompt")
        && !foreign_origin(attachment.get("origin"));
    if !typed {
        thread.skipped().injected += 1;
        return;
    }
    let text = user_text(attachment.get("prompt"), thread.skipped());
    if text.is_empty() || injected(&text) {
        thread.skipped().injected += 1;
        return;
    }
    let mut kept = message(value, fallback_id, HistoryRole::User, text);
    if let Some(source) = str_field(attachment, "source_uuid") {
        source.clone_into(&mut kept.native_id);
    }
    kept.said_by = said_by;
    thread.push(kept);
}
