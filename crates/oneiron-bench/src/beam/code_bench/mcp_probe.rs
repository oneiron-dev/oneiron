//! Probes each MCP server a run plan declares before any cell that needs it
//! is ready. Canon (ARCH-0042 #code-bench): "A missing piece marks that arm
//! not ready; nothing is faked." A declared server that does not answer,
//! refuses the token, or lists none of the arm's tools is a missing piece.
//!
//! MCP Streamable HTTP: `initialize`, `notifications/initialized`, then
//! `tools/list` page by page, one JSON-RPC message per POST. A server that
//! mints an `Mcp-Session-Id` gets it back on every later message; Oneiron's
//! endpoint holds no session and answers each POST alone.

use std::time::Duration;

use reqwest::blocking::{Client, Response};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde_json::{Value, json};

/// The revision the probe asks for; the server's `initialize` answer names
/// the one every later message carries.
const PROTOCOL_VERSION: &str = "2025-06-18";
const TIMEOUT: Duration = Duration::from_secs(20);
const MAX_PAGES: usize = 64;
const SESSION_HEADER: &str = "mcp-session-id";

/// The tool names the server at `url` lists to the token held in the
/// environment variable `token_env`, or why the piece is not ready. The
/// reason never holds the token.
pub(super) fn list_tools(piece: &str, url: &str, token_env: &str) -> Result<Vec<String>, String> {
    let token = std::env::var(token_env)
        .ok()
        .filter(|token| !token.is_empty())
        .ok_or_else(|| {
            format!("{piece} token_env {token_env} is not set in the environment of the pack")
        })?;
    let client = Client::builder()
        .timeout(TIMEOUT)
        .no_proxy()
        .build()
        .map_err(|error| format!("{piece}: no HTTP client: {error}"))?;
    let mut session = Session {
        piece,
        url,
        token: &token,
        client,
        id: None,
        version: PROTOCOL_VERSION.to_owned(),
        next_id: 1,
    };
    let initialized = session.request(
        "initialize",
        json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {
                "name": "oneiron-bench code-bench-pack",
                "version": env!("CARGO_PKG_VERSION"),
            },
        }),
    )?;
    if let Some(version) = initialized["protocolVersion"].as_str() {
        session.version = version.to_owned();
    }
    session.notify("notifications/initialized")?;
    let mut tools = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let params = cursor
            .as_ref()
            .map_or_else(|| json!({}), |cursor| json!({ "cursor": cursor }));
        let page = session.request("tools/list", params)?;
        let listed = page["tools"]
            .as_array()
            .ok_or_else(|| format!("{piece} at {url} answered tools/list with no tools array"))?;
        tools.extend(
            listed
                .iter()
                .filter_map(|tool| tool["name"].as_str())
                .map(str::to_owned),
        );
        match page["nextCursor"].as_str() {
            Some(next) if !next.is_empty() => cursor = Some(next.to_owned()),
            _ => return Ok(tools),
        }
    }
    Err(format!(
        "{piece} at {url} lists more than {MAX_PAGES} pages of tools"
    ))
}

struct Session<'a> {
    piece: &'a str,
    url: &'a str,
    token: &'a str,
    client: Client,
    /// The `Mcp-Session-Id` the server minted, if any.
    id: Option<String>,
    version: String,
    next_id: u64,
}

impl Session<'_> {
    /// One request; its `result`, or why the piece is not ready.
    fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        let response = self.post(
            method,
            &json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }),
        )?;
        if let Some(session) = response
            .headers()
            .get(SESSION_HEADER)
            .and_then(|value| value.to_str().ok())
        {
            self.id = Some(session.to_owned());
        }
        let event_stream = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|kind| kind.starts_with("text/event-stream"));
        let body = response
            .text()
            .map_err(|error| self.gap(&format!("sent no readable answer to {method}: {error}")))?;
        let message = if event_stream {
            event_message(&body, id)
        } else {
            serde_json::from_str::<Value>(&body).ok()
        }
        .ok_or_else(|| self.gap(&format!("answered {method} with no JSON-RPC message")))?;
        if let Some(error) = message.get("error") {
            return Err(self.gap(&format!(
                "refused {method}: {}",
                error["message"].as_str().unwrap_or("no message")
            )));
        }
        message
            .get("result")
            .cloned()
            .ok_or_else(|| self.gap(&format!("answered {method} with no result")))
    }

    fn notify(&self, method: &str) -> Result<(), String> {
        self.post(method, &json!({ "jsonrpc": "2.0", "method": method }))
            .map(drop)
    }

    /// One POST; a status outside 2xx is a gap.
    fn post(&self, method: &str, body: &Value) -> Result<Response, String> {
        let mut request = self
            .client
            .post(self.url)
            .bearer_auth(self.token)
            .header(ACCEPT, "application/json, text/event-stream")
            .header("MCP-Protocol-Version", &self.version)
            .json(body);
        if let Some(id) = &self.id {
            request = request.header(SESSION_HEADER, id);
        }
        let response = request
            .send()
            .map_err(|error| self.gap(&format!("did not answer {method}: {error}")))?;
        if !response.status().is_success() {
            return Err(self.gap(&format!("answered HTTP {} to {method}", response.status())));
        }
        Ok(response)
    }

    fn gap(&self, what: &str) -> String {
        format!("{} at {} {what}", self.piece, self.url)
    }
}

/// The message with `id` in a `text/event-stream` answer: each event's
/// `data:` lines joined, as the SSE format joins them.
fn event_message(body: &str, id: u64) -> Option<Value> {
    body.replace("\r\n", "\n")
        .split("\n\n")
        .filter_map(|event| {
            let data: Vec<&str> = event
                .lines()
                .filter_map(|line| line.strip_prefix("data:"))
                .map(|data| data.strip_prefix(' ').unwrap_or(data))
                .collect();
            serde_json::from_str::<Value>(&data.join("\n")).ok()
        })
        .find(|message| message["id"] == id)
}
