//! The reply readers both halves of the call host share: one reply body,
//! JSON raw bytes spooled or an event stream read event by event, and the tool's
//! reply a `tools/call` answer carries.

use std::sync::atomic::{AtomicBool, Ordering};

use oneiron::outbound_consent::{ZeroizingBufReader, zeroize_json};
use zeroize::Zeroizing;

use super::live_exchange::AnswerReceipts;
use super::*;

mod data_line;
mod event_body;
mod first_answer;

/// One reply body: a parsed JSON message with the body its caller retains,
/// or an event stream still open. Control readers retain only `()`.
pub(super) enum Reply<B = RawOutboundBody> {
    /// The message that answers the request, if the body holds one, and the
    /// caller's retained body.
    Json(Option<(Value, B)>),
    Stream(EventStream),
}

/// One event of a reply stream.
pub(super) enum StreamEvent {
    /// The response that answers the request, and its own bytes.
    Answer(Value, RawOutboundBody),
    /// A server request.
    Request(Value),
    /// The stream ended without answering.
    End,
}

/// A reply stream read event by event, each message whole whatever its size
/// (FIX 8227). The first tools/call read spools normalized data fields when
/// possible, without a whole data-line String; control and later reads
/// keep their in-memory data. Past
/// `deadline`, the rest of a round is unreadable. In-memory foreign bytes
/// are wiped once read past or dropped (FIX 8309, L10 09:30): the reader's
/// buffer, the line, event data and ids, and dropped messages. Event files
/// have the raw body's anonymous, delete-on-close spool lifetime.
pub(super) struct EventStream {
    reader: ZeroizingBufReader<reqwest::blocking::Response>,
    data: event_body::Data,
    deadline: Option<Instant>,
    /// The line being read, kept across a read that timed out (FIX 9286).
    line: Zeroizing<String>,
    /// The last event id buffer: the latest `id:` field read (FIX 9157).
    id_buffer: Zeroizing<String>,
    /// The last event id, set from the buffer as each event is dispatched:
    /// what a reattachment after a restart sends as `Last-Event-ID`.
    last_event_id: Zeroizing<String>,
}

impl EventStream {
    /// The next answer to `id` or server request; notifications are
    /// dropped.
    pub(super) fn next(&mut self, id: u64) -> Result<StreamEvent, ()> {
        self.read_event(id, None, None)
    }

    /// The first tools/call read spools normalized data fragments before parsing.
    pub(super) fn next_spooled(&mut self, id: u64, vault: &Vault) -> Result<StreamEvent, ()> {
        self.read_event(id, None, Some(vault))
    }

    /// [`Self::next`] for a stream read while its round waits for an answer
    /// (FIX 9286): a quiet stream is not an ended one, so a read that timed
    /// out reads on, its partial line kept, as long as `waiting` holds.
    pub(super) fn next_while(&mut self, id: u64, waiting: &AtomicBool) -> Result<StreamEvent, ()> {
        self.read_event(id, Some(waiting), None)
    }

    /// Reads on with no deadline of its own: whoever waits on the stream
    /// keeps the round's (FIX 9286).
    pub(super) fn read_on(&mut self) {
        self.deadline = None;
    }

    fn read_event(
        &mut self,
        id: u64,
        waiting: Option<&AtomicBool>,
        vault: Option<&Vault>,
    ) -> Result<StreamEvent, ()> {
        loop {
            let n = if let Some(vault) = vault {
                data_line::read(&mut self.reader, &mut self.data, &mut self.line, vault)?
            } else {
                Some(match self.reader.read_line(&mut self.line) {
                    Ok(n) => n,
                    Err(error)
                        if timed_out(&error)
                            && waiting.is_some_and(|waiting| waiting.load(Ordering::Acquire)) =>
                    {
                        continue;
                    }
                    Err(_) => return Err(()),
                })
            };
            let line = std::mem::take(&mut self.line);
            if self
                .deadline
                .is_some_and(|deadline| Instant::now() > deadline)
            {
                return Err(());
            }
            let Some(n) = n else {
                continue;
            };
            let end = n == 0;
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if end || trimmed.is_empty() {
                self.last_event_id.clone_from(&self.id_buffer);
                if !self.data.is_empty() {
                    let event = std::mem::take(&mut self.data);
                    if let Some((message, body)) = event.read()? {
                        if answers(&message, id) {
                            return Ok(StreamEvent::Answer(message, body));
                        }
                        if message.get("method").is_some() && message.get("id").is_some() {
                            return Ok(StreamEvent::Request(message));
                        }
                        zeroize_json(message);
                    }
                }
                if end {
                    return Ok(StreamEvent::End);
                }
                continue;
            }
            if let Some(field) = trimmed.strip_prefix("data:") {
                self.data
                    .append(field.strip_prefix(' ').unwrap_or(field), vault)?;
            } else if let Some(field) = id_field(trimmed) {
                field.clone_into(&mut self.id_buffer);
            }
        }
    }

    /// The stream's last event id, once an event that set one was
    /// dispatched (FIX 9157).
    pub(super) fn last_event_id(&self) -> Option<&str> {
        (!self.last_event_id.is_empty()).then_some(self.last_event_id.as_str())
    }
}

/// The value of an event-stream `id` field line, its one leading space
/// dropped; a bare `id` line has the empty value, which clears the id. A
/// value holding a NUL is ignored, as the format says.
fn id_field(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("id")?;
    let value = if rest.is_empty() {
        rest
    } else {
        let value = rest.strip_prefix(':')?;
        value.strip_prefix(' ').unwrap_or(value)
    };
    (!value.contains('\0')).then_some(value)
}

/// Whether a read failed only because nothing came within the client's
/// per-read bound: the body itself is still readable.
fn timed_out(error: &std::io::Error) -> bool {
    if error.kind() == std::io::ErrorKind::TimedOut {
        return true;
    }
    match error.get_ref() {
        Some(inner) => inner
            .downcast_ref::<reqwest::Error>()
            .is_some_and(reqwest::Error::is_timeout),
        None => false,
    }
}

/// Opens one control reply body, JSON or an event stream. Each JSON message
/// still parses whole, whatever its size (FIX 8227). The tools/call path below
/// spools its raw bytes. A body that answers nothing, and every other message of a
/// batch, is wiped as it drops (FIX 11861), as a stream's are.
pub(super) fn open_reply(
    response: reqwest::blocking::Response,
    id: u64,
    deadline: Option<Instant>,
) -> Result<Reply<()>, ()> {
    open_reply_body(response, deadline, |body| {
        let found = first_answer::read(body, id)?;
        Ok(found.map(|message| (message, ())))
    })
}

/// A tools/call JSON response keeps its original raw bytes in a vault spool.
/// Its typed message is still parsed whole, as the direct adapter requires.
pub(super) fn open_spooled_reply(
    response: reqwest::blocking::Response,
    id: u64,
    deadline: Option<Instant>,
    vault: &Vault,
) -> Result<Reply, ()> {
    open_reply_body(response, deadline, |body| {
        let bytes = RawOutboundBody::read_spooled(vault, body).map_err(|_| ())?;
        let found = first_answer::read(bytes.reader(), id)?;
        Ok(found.map(|message| (message, bytes)))
    })
}

fn open_reply_body<B>(
    response: reqwest::blocking::Response,
    deadline: Option<Instant>,
    read_json: impl FnOnce(reqwest::blocking::Response) -> Result<Option<(Value, B)>, ()>,
) -> Result<Reply<B>, ()> {
    let stream = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim_start().starts_with("text/event-stream"));
    let body = response;
    if stream {
        return Ok(Reply::Stream(EventStream {
            reader: ZeroizingBufReader::new(body),
            data: event_body::Data::default(),
            deadline,
            line: Zeroizing::default(),
            id_buffer: Zeroizing::default(),
            last_event_id: Zeroizing::default(),
        }));
    }
    read_json(body).map(Reply::Json)
}

/// Reads one reply body until the response that answers `id`; server
/// requests and notifications on a stream are dropped. Control replies keep
/// only the message, not an unused raw-body copy.
pub(super) fn read_reply(
    response: reqwest::blocking::Response,
    id: u64,
) -> Result<Option<Value>, ()> {
    let mut stream = match open_reply(response, id, None)? {
        Reply::Json(found) => return Ok(found.map(|(message, ())| message)),
        Reply::Stream(stream) => stream,
    };
    loop {
        match stream.next(id)? {
            StreamEvent::Answer(message, _) => return Ok(Some(message)),
            StreamEvent::Request(_) => {}
            StreamEvent::End => return Ok(None),
        }
    }
}

/// A response (not a request) carrying exactly this id.
pub(super) fn answers(message: &Value, id: u64) -> bool {
    message.get("method").is_none()
        && message.get("id").and_then(Value::as_u64) == Some(id)
        && (message.get("result").is_some() || message.get("error").is_some())
}

/// A `tools/call` answer as the tool's reply: its result, or the JSON-RPC
/// error it answered with; `None` when it carries neither.
pub(super) fn tool_result(message: &mut Value) -> Option<UntrustedToolResult> {
    if let Some(error) = message.get_mut("error") {
        return Some(UntrustedToolResult {
            content: Value::Array(Vec::new()),
            structured_content: None,
            is_error: true,
            rpc_error: Some(error.take()),
        });
    }
    let result = message.get_mut("result")?;
    Some(UntrustedToolResult {
        content: result
            .get_mut("content")
            .map(Value::take)
            .unwrap_or_else(|| Value::Array(Vec::new())),
        structured_content: result.get_mut("structuredContent").map(Value::take),
        is_error: result.get("isError").and_then(Value::as_bool) == Some(true),
        rpc_error: None,
    })
}

/// The tool's terminal reply in `message`, or the failure an unreadable one
/// is.
pub(super) fn terminal(mut message: Value) -> WorkerEvent {
    let reply = tool_result(&mut message);
    zeroize_json(message);
    match reply {
        Some(result) => WorkerEvent::Result(result),
        None => WorkerEvent::Failed {
            sent: true,
            reason: "connector_reply_unreadable",
        },
    }
}

/// Reads the reply to a retried `tools/call` (`id`), refusing any server
/// request on its stream once the call's issuer binding is read again (FIX
/// 9303).
#[allow(
    clippy::result_large_err,
    reason = "the error is the worker's terminal event, handed on as is"
)]
pub(super) fn read_retry_reply(
    session: &LiveSession,
    receipts: &AnswerReceipts,
    response: reqwest::blocking::Response,
    id: u64,
) -> Result<Value, WorkerEvent> {
    let unreadable = WorkerEvent::Failed {
        sent: true,
        reason: "connector_reply_unreadable",
    };
    let status = response.status();
    if status.is_server_error() {
        return Err(WorkerEvent::Failed {
            sent: true,
            reason: "connector_server_error",
        });
    }
    if !status.is_success() {
        return Err(WorkerEvent::Failed {
            sent: false,
            reason: "connector_answer_not_taken",
        });
    }
    let mut stream = match open_reply(response, id, None) {
        Ok(Reply::Json(Some((message, _)))) => return Ok(message),
        Ok(Reply::Json(None)) | Err(()) => return Err(unreadable),
        Ok(Reply::Stream(stream)) => stream,
    };
    loop {
        match stream.next(id) {
            Ok(StreamEvent::Answer(message, _)) => return Ok(message),
            Ok(StreamEvent::Request(request)) => session.refuse_unheld(request, receipts),
            Ok(StreamEvent::End) | Err(()) => return Err(unreadable),
        }
    }
}
