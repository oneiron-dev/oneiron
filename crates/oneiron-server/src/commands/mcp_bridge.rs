//! `oneiron mcp`: MCP over stdio for an agent that spawns a command (Claude
//! Code's `claude mcp add`, Codex's `mcp_servers`), in front of a running
//! server's HTTP MCP endpoint.
//!
//! Such a client sends no per-request header, and a slip authenticates
//! nothing without a fresh holder proof. This process is the holder. It reads
//! one JSON-RPC message per stdin line, POSTs it to the endpoint the operator
//! named with the slip and a holder proof signed for that one request, and
//! writes the server's answer as one stdout line. Transport and signer are
//! `oneiron api`'s: the host's curl, both headers on curl's config stdin and
//! never in argv. The credential comes from an owner-only file or the
//! environment, and nothing here prints it or lets curl inherit it. Every
//! request ends within its deadline and every message and answer has a size
//! limit, so a stalled or oversized exchange costs the agent one typed error
//! for that request, not the session.
//!
//! The bridge states one thing the agent cannot know: who is calling. The
//! server resolves that from the credential, and still asks every tool call to
//! restate it in an `actor` block that it then checks. The bridge takes that
//! block from the server's own `initialize` answer for this credential, drops
//! it from each advertised input schema, and appends it to each call's
//! arguments. The server's check is unchanged, so the block can only ever
//! name the identity the credential already has.

use std::io::{self, BufRead, Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::{Value, json};

use super::api;
use crate::cli::McpArgs;

/// The one-string form a paired client stores: `v2.cred.{slip}.{seed}`, as
/// `token agent` and `token read` print it and the SDK's `pair` returns it.
const CREDENTIAL_PREFIX: &str = "v2.cred.";

/// How many requests may be in flight at once. A client that sends more
/// waits for the oldest to finish rather than spawning without bound; each
/// finishes within its deadline.
const MAX_IN_FLIGHT: usize = 8;

/// The longest message the bridge reads from the client: the server's own
/// request-body limit on its MCP routes (axum's default), which nothing
/// longer could pass anyway.
const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;

/// The largest answer the bridge takes from the server for one request.
const MAX_REPLY_BYTES: usize = 16 * 1024 * 1024;

/// Credential variables curl never inherits from this process, beside the
/// two the operator named: the defaults, and the host's issuer key.
const WITHHELD_ENV: [&str; 3] = [
    "ONEIRON_SECRET",
    "ONEIRON_BINDING_KEY",
    "ONEIRON_AUTH_SECRET",
];

/// The `initialize` the bridge sends for itself when a tool call arrives
/// before it has seen the client's own.
const BRIDGE_INITIALIZE: &str =
    r#"{"jsonrpc":"2.0","id":"oneiron-mcp-bridge","method":"initialize","params":{}}"#;
const BRIDGE_INITIALIZE_ID: &str = "oneiron-mcp-bridge";

pub fn mcp(args: McpArgs) -> anyhow::Result<()> {
    let bridge = Arc::new(Bridge::new(&args)?);
    let stdout = Arc::new(Mutex::new(io::stdout()));
    let mut stdin = io::stdin().lock();
    let mut in_flight: Vec<JoinHandle<()>> = Vec::new();
    while let Some(frame) =
        read_frame(&mut stdin).map_err(|error| anyhow::anyhow!("read stdin: {error}"))?
    {
        let line = match frame {
            Frame::Line(line) if line.trim_ascii().is_empty() => continue,
            Frame::Line(line) => match String::from_utf8(line) {
                Ok(line) => line,
                Err(_) => {
                    let refusal = rpc_error(
                        &Value::Null,
                        -32700,
                        "parse_error",
                        "the message is not UTF-8",
                        None,
                    );
                    emit(&stdout, &refusal);
                    continue;
                }
            },
            // Refused whole, before a byte of it is sent.
            Frame::TooLong(head) => {
                let refusal = rpc_error(
                    &leading_id(&head),
                    -32600,
                    "frame_too_large",
                    &format!(
                        "a message may be at most {MAX_FRAME_BYTES} bytes; this one was not sent"
                    ),
                    None,
                );
                emit(&stdout, &refusal);
                continue;
            }
        };
        in_flight.retain(|call| !call.is_finished());
        while in_flight.len() >= MAX_IN_FLIGHT {
            let _ = in_flight.remove(0).join();
        }
        let bridge = Arc::clone(&bridge);
        let stdout = Arc::clone(&stdout);
        in_flight.push(std::thread::spawn(move || {
            if let Some(answer) = bridge.answer(&line) {
                emit(&stdout, &answer);
            }
        }));
    }
    for call in in_flight {
        let _ = call.join();
    }
    Ok(())
}

/// Writes one line to the client.
fn emit(stdout: &Mutex<io::Stdout>, line: &str) {
    let mut stdout = stdout.lock().unwrap_or_else(PoisonError::into_inner);
    // A client that closed its end has gone; there is no one left to tell.
    let _ = writeln!(stdout, "{line}").and_then(|()| stdout.flush());
}

/// One stdin line, read without holding more than [`MAX_FRAME_BYTES`] of it.
enum Frame {
    /// A whole line, without its newline.
    Line(Vec<u8>),
    /// A line past the limit: its head. The rest was read and dropped.
    TooLong(Vec<u8>),
}

/// The next line, or `None` at the end of input.
fn read_frame(input: &mut impl BufRead) -> io::Result<Option<Frame>> {
    let mut line = Vec::new();
    let limit = u64::try_from(MAX_FRAME_BYTES).unwrap_or(u64::MAX);
    if input
        .by_ref()
        .take(limit + 1)
        .read_until(b'\n', &mut line)?
        == 0
    {
        return Ok(None);
    }
    if line.last() == Some(&b'\n') {
        line.pop();
        return Ok(Some(Frame::Line(line)));
    }
    if line.len() <= MAX_FRAME_BYTES {
        return Ok(Some(Frame::Line(line)));
    }
    loop {
        let available = input.fill_buf()?;
        if available.is_empty() {
            break;
        }
        match available.iter().position(|byte| *byte == b'\n') {
            Some(at) => {
                input.consume(at + 1);
                break;
            }
            None => {
                let all = available.len();
                input.consume(all);
            }
        }
    }
    Ok(Some(Frame::TooLong(line)))
}

/// The `id` of a message cut off at `head`, when it comes whole before the
/// cut, so the client hears which request was refused; `null` otherwise. A
/// number that runs to the cut may be the start of a longer one (`"id":1` of
/// `"id":12`), so it is not read: only an id something follows is.
fn leading_id(head: &[u8]) -> Value {
    struct Seek<'a>(&'a mut Option<Value>);
    impl<'de> serde::de::Visitor<'de> for Seek<'_> {
        type Value = ();
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a JSON-RPC message object")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
            while let Some(key) = map.next_key::<String>()? {
                if key == "id" {
                    *self.0 = Some(map.next_value()?);
                    return Ok(());
                }
                map.next_value::<serde::de::IgnoredAny>()?;
            }
            Ok(())
        }
    }
    let whole = head
        .iter()
        .rposition(|byte| !matches!(byte, b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E'))
        .map_or(0, |at| at + 1);
    let mut id = None;
    // The head ends mid-message, so this parse fails; an id it passed on the
    // way is already kept.
    let _ = serde::Deserializer::deserialize_map(
        &mut serde_json::Deserializer::from_slice(&head[..whole]),
        Seek(&mut id),
    );
    id.filter(|id| id.is_string() || id.is_number())
        .unwrap_or(Value::Null)
}

struct Bridge {
    endpoint: String,
    token: String,
    seed: String,
    /// How long one request may take, and how long its answer may stall.
    deadline: Duration,
    idle: Duration,
    /// Variables curl does not inherit: every name a credential may be in.
    withheld_env: Vec<String>,
    /// The `actor` block the server returned at `initialize`, as JSON text.
    actor: Mutex<Option<String>>,
}

impl Bridge {
    fn new(args: &McpArgs) -> anyhow::Result<Self> {
        let base = api::normalized_base(&args.url)?;
        let (token, seed) = match &args.credential_file {
            Some(path) => read_credential_file(path)?,
            None => (
                credential_env(&args.secret_env)?,
                credential_env(&args.binding_key_env)?,
            ),
        };
        anyhow::ensure!(
            token.starts_with("v2.slip."),
            "the credential is not a paired slip; mint one with `oneiron token agent`"
        );
        // Sign once now, so a slip and seed that do not belong together fail
        // at spawn, on the stderr the operator reads, and not on every call.
        api::signed_binding_for_seed(&token, &seed)?;
        Ok(Self {
            endpoint: format!("{base}{}", args.surface.path()),
            token,
            seed,
            deadline: Duration::from_secs(args.request_timeout_secs),
            idle: Duration::from_secs(args.idle_timeout_secs),
            // The slip and seed stay in this process: curl gets the slip and
            // a signed proof on its config stdin, and no variable either may
            // be in.
            withheld_env: [&args.secret_env, &args.binding_key_env]
                .into_iter()
                .cloned()
                .chain(WITHHELD_ENV.map(str::to_owned))
                .collect(),
            actor: Mutex::new(None),
        })
    }

    /// One stdin line in, at most one stdout line out. A notification (no
    /// `id`) is forwarded and never answered, as JSON-RPC 2.0 requires.
    fn answer(&self, line: &str) -> Option<String> {
        let message: Value = match serde_json::from_str(line) {
            Ok(message) => message,
            Err(error) => {
                return Some(rpc_error(
                    &Value::Null,
                    -32700,
                    "parse_error",
                    &format!("the message is not JSON: {error}"),
                    None,
                ));
            }
        };
        // A batch, or anything but one object, is not a message this MCP
        // revision sends; answered here, it spends no holder proof.
        if !message.is_object() {
            return Some(rpc_error(
                &Value::Null,
                -32600,
                "invalid_request",
                "send one JSON-RPC message object per line",
                None,
            ));
        }
        let id = message.get("id").cloned();
        let method = message.get("method").and_then(Value::as_str);
        let body = match method {
            Some("tools/call") => match self.with_actor(line, &message) {
                Ok(body) => body,
                Err(refusal) => return id.map(|id| refusal.rpc_error(&id)),
            },
            _ => line.to_owned(),
        };
        let reply = self.post(body.into_bytes());
        let id = id?;
        Some(match reply.and_then(|reply| reply.answer_to(&id)) {
            Ok(mut answer) => {
                match method {
                    Some("initialize") => self.remember_actor(&answer),
                    Some("tools/list") => drop_actor_from_schemas(&mut answer),
                    _ => {}
                }
                answer.to_string()
            }
            Err(refusal) => refusal.rpc_error(&id),
        })
    }

    /// The call's own text with the credential's `actor` appended as the last
    /// member of its arguments. Splicing the text, not re-serializing it,
    /// keeps every other number spelled as the agent wrote it, and the last
    /// member is the live one when a key repeats (`serde_json` and the
    /// gateway's raw scan agree), so an agent-typed `actor` cannot outvote
    /// the credential's. Arguments that are not an object go as sent, for the
    /// server to answer.
    fn with_actor(&self, line: &str, message: &Value) -> Result<String, Refusal> {
        let Some(Value::Object(fields)) = message.pointer("/params/arguments") else {
            return Ok(line.to_owned());
        };
        let Some(span) = crate::mcp::mcp_raw_call_arguments_span(line) else {
            return Ok(line.to_owned());
        };
        let close = span.end.saturating_sub(1);
        if line.as_bytes().get(close) != Some(&b'}') {
            return Ok(line.to_owned());
        }
        let actor = self.actor()?;
        let separator = if fields.is_empty() { "" } else { "," };
        Ok(format!(
            "{}{separator}\"actor\":{actor}{}",
            &line[..close],
            &line[close..]
        ))
    }

    /// The credential's `actor` block, asking the server once if the client's
    /// own `initialize` has not been seen.
    fn actor(&self) -> Result<String, Refusal> {
        let mut actor = self.actor.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(actor) = actor.as_ref() {
            return Ok(actor.clone());
        }
        let answer = self
            .post(BRIDGE_INITIALIZE.as_bytes().to_vec())?
            .answer_to(&json!(BRIDGE_INITIALIZE_ID))?;
        let found = actor_block(&answer).ok_or_else(|| Refusal::Refused(answer.clone()))?;
        *actor = Some(found.clone());
        Ok(found)
    }

    fn remember_actor(&self, answer: &Value) {
        if let Some(found) = actor_block(answer) {
            *self.actor.lock().unwrap_or_else(PoisonError::into_inner) = Some(found);
        }
    }

    /// One POST to the endpoint, signed for this request alone, that ends
    /// within its deadline whatever the server does.
    fn post(&self, body: Vec<u8>) -> Result<Reply, Refusal> {
        let binding = api::signed_binding_for_seed(&self.token, &self.seed)
            .map_err(|error| Refusal::Unreachable(error.to_string()))?;
        let bounds = api::CaptureBounds {
            deadline: self.deadline,
            idle: self.idle,
            max_reply_bytes: MAX_REPLY_BYTES,
            withheld_env: &self.withheld_env,
        };
        let (output, status) =
            api::post_json_captured(&self.endpoint, &self.token, &binding, body, &bounds)
                .map_err(|cut| self.refusal_for(cut))?;
        match output.status.code() {
            // `--fail-with-body`: an HTTP error status, with the server's body.
            Some(0 | api::CURL_HTTP_ERROR_EXIT) => Ok(Reply {
                status,
                body: output.stdout,
            }),
            _ => Err(Refusal::Unreachable(format!(
                "could not reach {}: {}",
                self.endpoint,
                String::from_utf8_lossy(&output.stderr).trim()
            ))),
        }
    }

    /// The request's error when its exchange was cut short.
    fn refusal_for(&self, cut: api::CaptureCut) -> Refusal {
        match cut {
            api::CaptureCut::Curl(error) => Refusal::Unreachable(error.to_string()),
            api::CaptureCut::Deadline => Refusal::Unreachable(format!(
                "{} gave no whole answer within {}s (--request-timeout-secs)",
                self.endpoint,
                self.deadline.as_secs()
            )),
            api::CaptureCut::Idle => Refusal::Unreachable(format!(
                "{}'s answer stalled for {}s (--idle-timeout-secs)",
                self.endpoint,
                self.idle.as_secs()
            )),
            api::CaptureCut::TooLarge => Refusal::TooLarge,
        }
    }
}

/// What the server sent back for one POST.
struct Reply {
    /// The HTTP status, when curl saw one.
    status: Option<u16>,
    body: Vec<u8>,
}

impl Reply {
    /// The server's JSON-RPC answer to request `id`, whatever the HTTP status
    /// it came with; anything else is the bridge's error for that request, so
    /// the client is never handed a line that answers nothing it sent.
    fn answer_to(self, id: &Value) -> Result<Value, Refusal> {
        let body = serde_json::from_slice::<Value>(&self.body)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&self.body).into_owned()));
        let answers = body.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
            && body.get("id") == Some(id)
            && match (body.get("result"), body.get("error")) {
                (Some(_), None) => true,
                (None, Some(error)) => {
                    error.get("code").is_some_and(Value::is_i64)
                        && error.get("message").is_some_and(Value::is_string)
                }
                _ => false,
            };
        match self.status {
            _ if answers => Ok(body),
            Some(200..=299) => Err(Refusal::Server(
                "the server's answer is not a JSON-RPC response to this request".to_owned(),
                body,
            )),
            // Only these say the credential itself was refused.
            Some(401 | 403) => Err(Refusal::Auth(body)),
            Some(status) => Err(Refusal::Server(
                format!("the server answered HTTP {status}"),
                body,
            )),
            None => Err(Refusal::Server(
                "the server's answer carried no HTTP status".to_owned(),
                body,
            )),
        }
    }
}

/// Why a request got no MCP answer from the server.
enum Refusal {
    /// The HTTP door refused the credential before MCP saw the request (401 or
    /// 403): revoked, expired or unproven, say. The server's error body rides
    /// along.
    Auth(Value),
    /// The server's `initialize` carried no actor for this credential.
    Refused(Value),
    /// The server answered, but not with a JSON-RPC answer to this request:
    /// any other HTTP error, or a body that answers something else.
    Server(String, Value),
    /// No answer at all, or none whole within the request's deadline.
    Unreachable(String),
    /// An answer past [`MAX_REPLY_BYTES`], dropped unread.
    TooLarge,
}

impl Refusal {
    fn rpc_error(&self, id: &Value) -> String {
        match self {
            Self::Auth(body) => rpc_error(
                id,
                -32001,
                "mcp_auth_required",
                "the server refused this credential before MCP; it may be revoked or expired, so ask the vault owner for a new one",
                Some(body.clone()),
            ),
            Self::Refused(answer) => match answer.get("error") {
                Some(error) => json!({ "jsonrpc": "2.0", "id": id, "error": error }).to_string(),
                None => rpc_error(
                    id,
                    -32001,
                    "mcp_auth_required",
                    "the server named no actor for this credential",
                    None,
                ),
            },
            Self::Server(message, body) => {
                rpc_error(id, -32000, "server_error", message, Some(body.clone()))
            }
            Self::Unreachable(message) => {
                rpc_error(id, -32000, "server_unreachable", message, None)
            }
            Self::TooLarge => rpc_error(
                id,
                -32000,
                "reply_too_large",
                &format!("the server's answer is over {MAX_REPLY_BYTES} bytes; it was dropped"),
                None,
            ),
        }
    }
}

/// A JSON-RPC error in the gateway's own shape, so an agent reads the same
/// `data.kind` whichever side refused.
fn rpc_error(
    id: &Value,
    code: i64,
    kind: &str,
    message: &str,
    server_error: Option<Value>,
) -> String {
    let mut data = json!({ "kind": kind, "error_code": kind, "human_message": message });
    if let (Some(server_error), Some(data)) = (server_error, data.as_object_mut()) {
        data.insert("server_error".to_owned(), server_error);
    }
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message, "data": data },
    })
    .to_string()
}

/// The `actor` block of an `initialize` answer, with absent scope members
/// left out rather than sent as `null`.
fn actor_block(answer: &Value) -> Option<String> {
    let mut actor = answer.pointer("/result/actor")?.as_object()?.clone();
    if let Some(Value::Object(scope)) = actor.get_mut("scope") {
        scope.retain(|_, value| !value.is_null());
    }
    Some(Value::Object(actor).to_string())
}

/// The agent never types an identity, so it is never asked for one.
fn drop_actor_from_schemas(answer: &mut Value) {
    let Some(tools) = answer
        .pointer_mut("/result/tools")
        .and_then(Value::as_array_mut)
    else {
        return;
    };
    for schema in tools
        .iter_mut()
        .filter_map(|tool| tool.get_mut("inputSchema"))
    {
        if let Some(properties) = schema.get_mut("properties").and_then(Value::as_object_mut) {
            properties.remove("actor");
        }
        if let Some(required) = schema.get_mut("required").and_then(Value::as_array_mut) {
            required.retain(|field| field != "actor");
        }
    }
}

fn credential_env(name: &str) -> anyhow::Result<String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value.trim().to_owned()),
        Ok(_) | Err(std::env::VarError::NotPresent) => anyhow::bail!(
            "{name} is not set; pass --credential-file or set {name} (`oneiron token agent` mints both)"
        ),
        // The error's own Display would quote the value.
        Err(std::env::VarError::NotUnicode(_)) => anyhow::bail!("{name} is not valid UTF-8"),
    }
}

/// The credential file holds the one-string form and nothing else, and only
/// its owner may read it: a file the agent's other users can read is a
/// credential they hold too.
fn read_credential_file(path: &Path) -> anyhow::Result<(String, String)> {
    let mut file = std::fs::File::open(path)
        .map_err(|error| anyhow::anyhow!("open {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = file.metadata()?.permissions().mode();
        anyhow::ensure!(
            mode & 0o077 == 0,
            "{} can be read by other users (mode {:o}); run `chmod 600` on it",
            path.display(),
            mode & 0o777
        );
    }
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))?;
    text.trim()
        .strip_prefix(CREDENTIAL_PREFIX)
        .and_then(|rest| rest.rsplit_once('.'))
        .map(|(slip, seed)| (format!("v2.slip.{slip}"), seed.to_owned()))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{} does not hold a paired credential ({CREDENTIAL_PREFIX}…)",
                path.display()
            )
        })
}
