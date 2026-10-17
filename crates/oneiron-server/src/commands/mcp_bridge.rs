//! `oneiron mcp`: MCP over stdio for an agent that spawns a command (Claude
//! Code's `claude mcp add`, Codex's `mcp_servers`), in front of a running
//! server's HTTP MCP endpoint.
//!
//! Such a client sends no per-request header, and a slip authenticates
//! nothing without a fresh holder proof. This process is the holder. It reads
//! one JSON-RPC message per stdin line, sends it to the endpoint the operator
//! named with the slip and a holder proof signed for that one request, and
//! writes the server's answer as one stdout line. It holds one connection to
//! the server for its life ([`link`]): the server's app-tier socket, or one
//! pooled HTTP client when the server offers no MCP carrier there or
//! `--transport http` asks for it; never a process per request. The signer is
//! `oneiron api`'s. The credential comes from an owner-only file or the
//! environment, and nothing here prints it. Every request ends within its
//! deadline and every message and answer has a size limit, so a stalled or
//! oversized exchange costs the agent one typed error for that request, not
//! the session.
//!
//! Every line goes to the server as the client wrote it, but for one
//! addition: a `tools/call` whose `_meta` names no `oneiron/invocation` gains
//! a fresh one there (ARCH-0080 §3), every other `_meta` key as the client
//! sent it; a call that names one goes on byte for byte. The bridge keeps a
//! memory of tool calls the server answered pending on an ask: a later call
//! naming no invocation that is the same call (same tool, same arguments)
//! goes under the pending call's invocation, so it reaches that ask instead
//! of opening a second one (OF-580). Who is calling is the credential's to
//! say, not the agent's: a tool call that names no actor runs as the
//! credential's own, and one that names another is refused (ARCH-0028
//! #surface).
//!
//! Unless the operator names `--surface`, the bridge asks the server once,
//! before the first request, which endpoint to use: `/mcp` (`setup_oneiron`
//! and `execute_code`) when `/mcp`'s `initialize` says this credential may
//! run code there, which needs a bound code host and a credential
//! `execute_code` admits, and `/mcp/tool-first` otherwise. The listing alone
//! cannot say it: `/mcp` lists `execute_code` to every credential alike.

use std::collections::HashMap;
use std::io::{self, BufRead, Read, Write};
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::api;
use crate::cli::{McpArgs, McpSurface};

mod link;

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

/// The `initialize` the bridge sends to `/mcp` for itself, to pick the
/// endpoint when the operator named none.
const SURFACE_PROBE: &str =
    r#"{"jsonrpc":"2.0","id":"oneiron-mcp-bridge","method":"initialize","params":{}}"#;
const SURFACE_PROBE_ID: &str = "oneiron-mcp-bridge";

/// The `_meta` key a `tools/call` names its invocation under, as the server's
/// MCP gateway reads it: 32 lowercase hex digits naming one logical verb call.
/// Its verb hooks fire once for it, and a retry of a call a hook stopped on an
/// ask names the same one to find that ask.
pub(crate) const INVOCATION_META: &str = "oneiron/invocation";

/// A fresh invocation id for one tool call, from the OS CSPRNG.
pub(crate) fn mint_invocation() -> String {
    let mut id = [0; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut id);
    oneiron::runtime_hooks::InvocationId(id).to_hex()
}

/// The body for a `tools/call` whose `_meta` names no invocation: the same
/// message with `invocation()` added there (a pending call's id, or a fresh
/// one). `None` sends the client's line as it wrote it: any other message, a
/// call that names its own, and a malformed one, which is the server's to
/// refuse.
fn with_invocation(message: &mut Value, invocation: impl FnOnce() -> String) -> Option<Vec<u8>> {
    if message.get("method").and_then(Value::as_str) != Some("tools/call") {
        return None;
    }
    let meta = message
        .get_mut("params")?
        .as_object_mut()?
        .entry("_meta")
        .or_insert_with(|| Value::Object(serde_json::Map::new()))
        .as_object_mut()?;
    if meta.contains_key(INVOCATION_META) {
        return None;
    }
    meta.insert(INVOCATION_META.to_owned(), Value::String(invocation()));
    serde_json::to_vec(message).ok()
}

/// What the bridge's pending-call memory keys one tool call by.
type CallKey = [u8; 32];

/// The bridge's pending-call matching rule (OF-580, canon silent; this fn is
/// the one place a ruling changes it): a `tools/call` is the same call as an
/// earlier one when it names the same tool with the same `params.arguments`,
/// every object's keys sorted at every depth. The JSON-RPC id and every
/// `params._meta` key are not part of it. `None` for any other message.
fn pending_call_key(message: &Value) -> Option<CallKey> {
    if message.get("method").and_then(Value::as_str) != Some("tools/call") {
        return None;
    }
    let params = message.get("params")?;
    let tool = params.get("name").filter(|name| name.is_string())?;
    let mut hasher = blake3::Hasher::new();
    hash_sorted(tool, &mut hasher);
    hash_sorted(params.get("arguments").unwrap_or(&Value::Null), &mut hasher);
    Some(*hasher.finalize().as_bytes())
}

/// Feeds `value` to `hasher` as JSON with every object's keys sorted, at
/// every depth (the workspace's `serde_json` keeps insertion order).
fn hash_sorted(value: &Value, hasher: &mut blake3::Hasher) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            hasher.update(b"{");
            for key in keys {
                hasher.update(&serde_json::to_vec(key).unwrap_or_default());
                hasher.update(b":");
                hash_sorted(&map[key], hasher);
                hasher.update(b",");
            }
            hasher.update(b"}");
        }
        Value::Array(items) => {
            hasher.update(b"[");
            for item in items {
                hash_sorted(item, hasher);
                hasher.update(b",");
            }
            hasher.update(b"]");
        }
        scalar => {
            hasher.update(&serde_json::to_vec(scalar).unwrap_or_default());
        }
    }
}

/// The invocation a server answer names as pending on an ask: a tool-first
/// hook stop's `result.structuredContent.hook`, or a gateway refusal's
/// `error.data.hook`, with `status` `pending`. `None` for any other answer.
fn pending_answer_invocation(answer: &Value) -> Option<&str> {
    ["/result/structuredContent/hook", "/error/data/hook"]
        .into_iter()
        .filter_map(|path| answer.pointer(path))
        .find(|hook| hook.get("status").and_then(Value::as_str) == Some("pending"))
        .and_then(|hook| hook.get("invocation"))
        .and_then(Value::as_str)
        .filter(|id| oneiron::runtime_hooks::InvocationId::parse_hex(id).is_some())
}

/// Poll cadence and request bound for this small handoff, independent of
/// the potentially much longer deadline of an agent's tool call.
const WAKE_POLL_INTERVAL: Duration = Duration::from_secs(1);
const WAKE_POLL_TIMEOUT: Duration = Duration::from_secs(8);

struct WakePump(tokio::task::JoinHandle<()>);

impl WakePump {
    fn start(bridge: Arc<Bridge>, path: &Path) -> anyhow::Result<Self> {
        let instance = crate::wake_adapters::Instance::load(path)?;
        let runtime = tokio::runtime::Handle::try_current()?;
        Ok(Self(runtime.spawn(async move {
            let mut failed = false;
            loop {
                let polling = Arc::clone(&bridge);
                let key = instance.key.clone();
                let polled = tokio::task::spawn_blocking(move || polling.wakes(&key)).await;
                match polled {
                    Ok(Ok(delivery)) => {
                        failed = false;
                        instance.deliver(delivery, &bridge.named_env).await;
                    }
                    Ok(Err(refusal)) => {
                        if !failed {
                            eprintln!("oneiron wake: {}", refusal.rpc_error(&Value::Null));
                        }
                        failed = true;
                    }
                    Err(error) => {
                        if !failed {
                            eprintln!("oneiron wake poll did not finish: {error}");
                        }
                        failed = true;
                    }
                }
                tokio::time::sleep(WAKE_POLL_INTERVAL).await;
            }
        })))
    }
}

impl Drop for WakePump {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub fn mcp(args: McpArgs) -> anyhow::Result<()> {
    let bridge = Arc::new(Bridge::new(&args)?);
    let _wakes = args
        .wake_config
        .as_deref()
        .map(|path| WakePump::start(Arc::clone(&bridge), path))
        .transpose()?;
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
    /// The one connection to the server.
    link: link::Link,
    /// The endpoint every request goes to: the operator's `--surface`, or the
    /// one a probe picked. Unset until then.
    pick: Mutex<Pick>,
    /// Signalled when a probe ends.
    probed: Condvar,
    token: String,
    seed: String,
    /// How long one request may take, and how long its answer may stall.
    deadline: Duration,
    idle: Duration,
    /// The two variables the operator named for the credential, which no
    /// wake adapter the bridge runs inherits.
    named_env: Vec<String>,
    /// Tool calls the server answered pending on an ask, by
    /// [`pending_call_key`], to the invocation the ask is on. Locked only
    /// around a lookup or an update, never across a request.
    pending_calls: Mutex<HashMap<CallKey, String>>,
}

impl Bridge {
    fn new(args: &McpArgs) -> anyhow::Result<Self> {
        let base = api::normalized_base(&args.url)?;
        let (token, seed) = match &args.credential_file {
            Some(path) => {
                let held = super::credential_file::PairedCredentialFile::read(path)?;
                (held.token, held.seed)
            }
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
            link: link::Link::new(&base, args.transport)?,
            pick: Mutex::new(Pick {
                chosen: args.surface,
                probing: false,
                failures: 0,
                last_failure: None,
            }),
            probed: Condvar::new(),
            token,
            seed,
            deadline: Duration::from_secs(args.request_timeout_secs),
            idle: Duration::from_secs(args.idle_timeout_secs),
            // The slip and seed stay in this process: the server gets the
            // slip and a proof signed for each request, and no variable
            // either may be in reaches a process the bridge starts.
            named_env: vec![args.secret_env.clone(), args.binding_key_env.clone()],
            pending_calls: Mutex::new(HashMap::new()),
        })
    }

    /// One stdin line in, at most one stdout line out. A notification (no
    /// `id`) is forwarded and never answered, as JSON-RPC 2.0 requires.
    fn answer(&self, line: &str) -> Option<String> {
        let mut message: Value = match serde_json::from_str(line) {
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
        // One deadline for the whole request, the endpoint probe included.
        let until = Instant::now() + self.deadline;
        let key = pending_call_key(&message);
        // A call naming its own invocation keeps it; one naming none goes
        // under a pending same call's, else a fresh one.
        let body = with_invocation(&mut message, || {
            key.as_ref()
                .and_then(|key| self.pending_call(key))
                .unwrap_or_else(mint_invocation)
        })
        .unwrap_or_else(|| line.as_bytes().to_vec());
        let sent = message
            .pointer("/params/_meta")
            .and_then(|meta| meta.get(INVOCATION_META))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let reply = self.post(body, until);
        let id = message.get("id").cloned()?;
        Some(match reply.and_then(|reply| reply.answer_to(&id)) {
            Ok(answer) => {
                if let Some(key) = key {
                    self.note_answer(key, sent.as_deref(), &answer);
                }
                answer.to_string()
            }
            // No answer from the server is no proof the call finished, so
            // the memory keeps what it holds.
            Err(refusal) => refusal.rpc_error(&id),
        })
    }

    /// The invocation a pending same call ran under, if one is held.
    fn pending_call(&self, key: &CallKey) -> Option<String> {
        self.pending_calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .cloned()
    }

    /// Updates the pending-call memory from the server's answer to a tool
    /// call sent under `sent`: a pending answer holds its invocation for the
    /// call; any other answer drops the entry if it still holds `sent`, as
    /// a later answer may have replaced it meanwhile.
    fn note_answer(&self, key: CallKey, sent: Option<&str>, answer: &Value) {
        let pending = pending_answer_invocation(answer);
        let mut calls = self
            .pending_calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match pending {
            Some(invocation) => {
                calls.insert(key, invocation.to_owned());
            }
            None => {
                if let Some(sent) = sent
                    && calls.get(&key).is_some_and(|held| held == sent)
                {
                    calls.remove(&key);
                }
            }
        }
    }

    /// The endpoint this bridge forwards to. With no `--surface`, a request
    /// asks `/mcp` to `initialize`, within the request's own deadline, and
    /// the answer picks the endpoint for the bridge's life. Calls that arrive
    /// meanwhile wait for that one probe, each no longer than its own
    /// deadline. A probe that gets no result picks nothing: the calls that
    /// waited on it share its answer, and the next request asks again.
    fn endpoint(&self, until: Instant) -> Result<McpSurface, Refusal> {
        let mut pick = self.pick.lock().unwrap_or_else(PoisonError::into_inner);
        let joined = pick.failures;
        loop {
            if let Some(chosen) = pick.chosen {
                return Ok(chosen);
            }
            if pick.failures != joined
                && let Some(failure) = pick.last_failure.clone()
            {
                return Err(failure);
            }
            if !pick.probing {
                break;
            }
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(self.refusal_for(McpSurface::Primary, link::Cut::Deadline));
            }
            pick = self
                .probed
                .wait_timeout(pick, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        // No lock is held while the probe runs.
        pick.probing = true;
        drop(pick);
        let probed = self.probe(until);
        let mut pick = self.pick.lock().unwrap_or_else(PoisonError::into_inner);
        pick.probing = false;
        let outcome = match probed {
            Ok(surface) => {
                pick.chosen = Some(surface);
                Ok(surface)
            }
            Err(failure) => {
                pick.failures += 1;
                pick.last_failure = Some(failure.clone());
                Err(failure)
            }
        };
        self.probed.notify_all();
        outcome
    }

    /// `/mcp` when its `initialize` says this credential may run code there;
    /// `/mcp/tool-first` otherwise, as for a server too old to say.
    fn probe(&self, until: Instant) -> Result<McpSurface, Refusal> {
        let answer = self
            .post_to(
                McpSurface::Primary,
                SURFACE_PROBE.as_bytes().to_vec(),
                until,
            )?
            .answer_to(&json!(SURFACE_PROBE_ID))?;
        let Some(result) = answer.get("result").and_then(Value::as_object) else {
            return Err(Refusal::Refused(answer));
        };
        Ok(
            if result.get("executeCodeAdmitted") == Some(&Value::Bool(true)) {
                McpSurface::Primary
            } else {
                McpSurface::ToolFirst
            },
        )
    }

    /// One host instance's wake handoff, never forwarded to MCP stdout.
    fn wakes(
        &self,
        instance_key: &str,
    ) -> Result<crate::wake_adapters::board_stream::BoardDelivery, Refusal> {
        let id = json!("oneiron-wake-adapter");
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "oneiron/wakes",
            "params": { "instance_key": instance_key },
        });
        let until = Instant::now() + self.deadline.min(WAKE_POLL_TIMEOUT);
        let answer = self
            .post(body.to_string().into_bytes(), until)?
            .answer_to(&id)?;
        let Some(delivery) = answer.get("result").cloned() else {
            return Err(Refusal::Refused(answer));
        };
        serde_json::from_value(delivery)
            .map_err(|error| Refusal::Server(format!("invalid wake handoff: {error}"), answer))
    }

    fn post(&self, body: Vec<u8>, until: Instant) -> Result<Reply, Refusal> {
        let surface = self.endpoint(until)?;
        self.post_to(surface, body, until)
    }

    /// One request to `surface` over the bridge's connection, signed for this
    /// request alone, that ends by `until` whatever the server does.
    fn post_to(
        &self,
        surface: McpSurface,
        body: Vec<u8>,
        until: Instant,
    ) -> Result<Reply, Refusal> {
        if until.saturating_duration_since(Instant::now()).is_zero() {
            return Err(self.refusal_for(surface, link::Cut::Deadline));
        }
        let sign = || {
            api::signed_binding_for_seed(&self.token, &self.seed).map_err(|error| error.to_string())
        };
        let credential = link::Credential {
            bearer: &self.token,
            sign: &sign,
        };
        let bounds = link::Bounds {
            until,
            idle: self.idle,
            max_reply_bytes: MAX_REPLY_BYTES,
        };
        let exchange = self
            .link
            .exchange(surface, &credential, body, &bounds)
            .map_err(|cut| self.refusal_for(surface, cut))?;
        Ok(Reply {
            status: exchange.status,
            body: exchange.body,
        })
    }

    /// The request's error when its exchange was cut short.
    fn refusal_for(&self, surface: McpSurface, cut: link::Cut) -> Refusal {
        let endpoint = self.link.endpoint(surface);
        match cut {
            link::Cut::Failed(error) => Refusal::Unreachable(error),
            link::Cut::Deadline => Refusal::Unreachable(format!(
                "{endpoint} gave no whole answer within {}s (--request-timeout-secs)",
                self.deadline.as_secs()
            )),
            link::Cut::Idle => Refusal::Unreachable(format!(
                "{endpoint}'s answer stalled for {}s (--idle-timeout-secs)",
                self.idle.as_secs()
            )),
            link::Cut::TooLarge => Refusal::TooLarge,
        }
    }
}

/// What the server sent back for one request.
struct Reply {
    /// The HTTP status, when there was one.
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

/// The endpoint the bridge picked, and how its probes stand.
struct Pick {
    chosen: Option<McpSurface>,
    /// A probe is running.
    probing: bool,
    /// How many probes ended with no pick, and the last one's failure.
    failures: u64,
    last_failure: Option<Refusal>,
}

/// Why a request got no MCP answer from the server.
#[derive(Clone)]
enum Refusal {
    /// The HTTP door refused the credential before MCP saw the request (401 or
    /// 403): revoked, expired or unproven, say. The server's error body rides
    /// along.
    Auth(Value),
    /// The server answered the bridge's own `initialize`, which picks the
    /// endpoint, with no result.
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
                "the server refused this credential before MCP; check --url names the vault that minted it. If revoked or expired, stop that vault, re-mint with `oneiron token agent --name <name> --tier <tier> --out <new-file> --config <vault-config>`, restart `oneiron serve --config <vault-config>`, and update --credential-file",
                Some(body.clone()),
            ),
            Self::Refused(answer) => match answer.get("error") {
                Some(error) => json!({ "jsonrpc": "2.0", "id": id, "error": error }).to_string(),
                None => rpc_error(
                    id,
                    -32000,
                    "server_error",
                    "the server's /mcp initialize held no result, so no endpoint was picked; pass --surface to name one",
                    Some(answer.clone()),
                ),
            },
            Self::Server(message, body) => {
                rpc_error(id, -32000, "server_error", message, Some(body.clone()))
            }
            Self::Unreachable(message) => rpc_error(
                id,
                -32000,
                "server_unreachable",
                &format!(
                    "{message}; start the vault with `oneiron serve --config <vault-config>` \
                         and check --url matches its host and port; MCP does not start a vault"
                ),
                None,
            ),
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
