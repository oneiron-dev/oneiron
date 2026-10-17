//! MCP over a guest's stdio, as `cua-driver mcp` serves it: JSON-RPC 2.0,
//! one message per line, on one reader and one writer. Replies are matched
//! to calls by id. A request the server sends is answered "method not
//! found", and its notifications are dropped: the driver only calls tools.

use crate::BrowserError;
use base64::Engine as _;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// The longest line the client reads. A window screenshot rides a reply
/// inline as base64; a line past this closes the pipe.
const MAX_MESSAGE: u64 = 48 << 20;
/// The MCP revision the client asks for.
const PROTOCOL: &str = "2025-06-18";

type Reply = Result<Value, String>;
type Pending = Arc<Mutex<Option<HashMap<u64, Sender<Reply>>>>>;
type Writer = Arc<Mutex<Box<dyn Write + Send>>>;

pub(crate) struct Mcp {
    writer: Writer,
    pending: Pending,
    next: AtomicU64,
}

/// One tool call's answer: its structured output and the images it carried.
pub(crate) struct ToolReply {
    pub(crate) output: Value,
    pub(crate) images: Vec<Vec<u8>>,
}

/// A tool call that did not answer: the driver refused it, with its code,
/// or the call itself failed.
pub(crate) enum ToolError {
    Refused {
        tool: String,
        code: String,
        words: String,
    },
    Failed(BrowserError),
}

impl From<ToolError> for BrowserError {
    fn from(error: ToolError) -> Self {
        match error {
            ToolError::Refused { tool, code, words } => {
                Self::Protocol(format!("{tool} refused ({code}): {words}"))
            }
            ToolError::Failed(error) => error,
        }
    }
}

impl Mcp {
    /// Starts the reader and runs the MCP handshake by `deadline`.
    pub(crate) fn attach(
        reader: impl Read + Send + 'static,
        writer: impl Write + Send + 'static,
        deadline: Instant,
    ) -> Result<Self, BrowserError> {
        let pending: Pending = Arc::new(Mutex::new(Some(HashMap::new())));
        let writer: Writer = Arc::new(Mutex::new(Box::new(writer)));
        let (routes, answers) = (Arc::clone(&pending), Arc::clone(&writer));
        std::thread::spawn(move || {
            read_replies(BufReader::new(reader), &routes, &answers);
            if let Ok(mut routes) = routes.lock() {
                routes.take();
            }
        });
        let mcp = Self {
            writer,
            pending,
            next: AtomicU64::new(1),
        };
        mcp.request(
            "initialize",
            json!({
                "protocolVersion": PROTOCOL,
                "capabilities": {},
                "clientInfo": {"name": "oneiron", "version": env!("CARGO_PKG_VERSION")},
            }),
            deadline,
        )?;
        send(
            &mcp.writer,
            &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        )?;
        Ok(mcp)
    }

    fn request(
        &self,
        method: &str,
        params: Value,
        deadline: Instant,
    ) -> Result<Value, BrowserError> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel();
        {
            let mut routes = self.pending.lock().map_err(|_| BrowserError::GuestLost)?;
            routes
                .as_mut()
                .ok_or(BrowserError::GuestLost)?
                .insert(id, tx);
        }
        send(
            &self.writer,
            &json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}),
        )?;
        let wait = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(wait) {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(message)) => Err(BrowserError::Protocol(format!("{method}: {message}"))),
            Err(RecvTimeoutError::Disconnected) => Err(BrowserError::GuestLost),
            Err(RecvTimeoutError::Timeout) => {
                if let Ok(mut routes) = self.pending.lock()
                    && let Some(routes) = routes.as_mut()
                {
                    routes.remove(&id);
                }
                Err(BrowserError::Timeout(method.to_owned()))
            }
        }
    }

    /// Calls one tool and waits for its answer until `deadline`. A tool
    /// that answers with an error comes back refused, with the driver's code
    /// (`tool_invocation_failed` when it names none) and words.
    pub(crate) fn tool(
        &self,
        name: &str,
        arguments: Value,
        deadline: Instant,
    ) -> Result<ToolReply, ToolError> {
        let result = self
            .request(
                "tools/call",
                json!({"name": name, "arguments": arguments}),
                deadline,
            )
            .map_err(ToolError::Failed)?;
        let content = result
            .get("content")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice);
        let texts = content
            .iter()
            .filter(|block| block.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|block| block.get("text").and_then(Value::as_str));
        if result.get("isError").and_then(Value::as_bool) == Some(true) {
            let structured = result.get("structuredContent");
            let code = ["/code", "/refusal/code", "/error/code"]
                .iter()
                .find_map(|at| structured?.pointer(at)?.as_str())
                .unwrap_or("tool_invocation_failed");
            return Err(ToolError::Refused {
                tool: name.to_owned(),
                code: code.to_owned(),
                words: texts.collect::<Vec<_>>().join(" "),
            });
        }
        // The output is the structured content; a server that sends only
        // text sends it as one JSON text block.
        let output = match result.get("structuredContent") {
            Some(output) => output.clone(),
            None => texts
                .filter_map(|text| serde_json::from_str::<Value>(text).ok())
                .find(Value::is_object)
                .unwrap_or(Value::Null),
        };
        let images: Vec<Vec<u8>> = content
            .iter()
            .filter(|block| block.get("type").and_then(Value::as_str) == Some("image"))
            .filter_map(|block| block.get("data").and_then(Value::as_str))
            .map(|data| {
                base64::engine::general_purpose::STANDARD
                    .decode(data)
                    .map_err(|e| ToolError::Failed(BrowserError::Protocol(e.to_string())))
            })
            .collect::<Result<_, _>>()?;
        Ok(ToolReply { output, images })
    }
}

fn send(writer: &Writer, message: &Value) -> Result<(), BrowserError> {
    let mut line =
        serde_json::to_vec(message).map_err(|e| BrowserError::Protocol(e.to_string()))?;
    line.push(b'\n');
    let mut writer = writer.lock().map_err(|_| BrowserError::GuestLost)?;
    writer
        .write_all(&line)
        .and_then(|()| writer.flush())
        .map_err(|_| BrowserError::GuestLost)
}

fn read_replies(mut reader: impl BufRead, routes: &Pending, writer: &Writer) {
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match (&mut reader).take(MAX_MESSAGE).read_until(b'\n', &mut buf) {
            Ok(0) | Err(_) => return,
            Ok(_) if buf.last() != Some(&b'\n') => return,
            Ok(_) => {}
        }
        let Ok(message) = serde_json::from_slice::<Value>(&buf) else {
            continue;
        };
        let id = message.get("id").cloned();
        if message.get("method").is_some() {
            // The server's own request: this client serves none of them.
            if let Some(id) = id {
                let _ = send(
                    writer,
                    &json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "method not found"}}),
                );
            }
            continue;
        }
        let Some(id) = id.as_ref().and_then(Value::as_u64) else {
            continue;
        };
        let reply = match message.get("error") {
            Some(error) => Err(error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("error")
                .to_owned()),
            None => Ok(message.get("result").cloned().unwrap_or(Value::Null)),
        };
        let Ok(mut routes) = routes.lock() else {
            return;
        };
        if let Some(tx) = routes.as_mut().and_then(|routes| routes.remove(&id)) {
            let _ = tx.send(reply);
        }
    }
}
