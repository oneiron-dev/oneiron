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
//! environment, and nothing here prints it.
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

use serde_json::{Value, json};

use super::api;
use crate::cli::McpArgs;

/// The one-string form a paired client stores: `v2.cred.{slip}.{seed}`, as
/// `token agent` and `token read` print it and the SDK's `pair` returns it.
const CREDENTIAL_PREFIX: &str = "v2.cred.";

/// How many requests may be in flight at once. A client that sends more
/// waits for the oldest to finish rather than spawning without bound.
const MAX_IN_FLIGHT: usize = 8;

/// The `initialize` the bridge sends for itself when a tool call arrives
/// before it has seen the client's own.
const BRIDGE_INITIALIZE: &str =
    r#"{"jsonrpc":"2.0","id":"oneiron-mcp-bridge","method":"initialize","params":{}}"#;

pub fn mcp(args: McpArgs) -> anyhow::Result<()> {
    let bridge = Arc::new(Bridge::new(&args)?);
    let stdout = Arc::new(Mutex::new(io::stdout()));
    let mut in_flight: Vec<JoinHandle<()>> = Vec::new();
    for line in io::stdin().lock().lines() {
        let line = line.map_err(|error| anyhow::anyhow!("read stdin: {error}"))?;
        if line.trim().is_empty() {
            continue;
        }
        in_flight.retain(|call| !call.is_finished());
        while in_flight.len() >= MAX_IN_FLIGHT {
            let _ = in_flight.remove(0).join();
        }
        let bridge = Arc::clone(&bridge);
        let stdout = Arc::clone(&stdout);
        in_flight.push(std::thread::spawn(move || {
            if let Some(answer) = bridge.answer(&line) {
                let mut stdout = stdout.lock().unwrap_or_else(PoisonError::into_inner);
                // A client that closed its end has gone; there is no one left
                // to tell.
                let _ = writeln!(stdout, "{answer}").and_then(|()| stdout.flush());
            }
        }));
    }
    for call in in_flight {
        let _ = call.join();
    }
    Ok(())
}

struct Bridge {
    endpoint: String,
    token: String,
    seed: String,
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
        Some(match reply {
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
        let answer = self.post(BRIDGE_INITIALIZE.as_bytes().to_vec())?;
        let found = actor_block(&answer).ok_or_else(|| Refusal::Refused(answer.clone()))?;
        *actor = Some(found.clone());
        Ok(found)
    }

    fn remember_actor(&self, answer: &Value) {
        if let Some(found) = actor_block(answer) {
            *self.actor.lock().unwrap_or_else(PoisonError::into_inner) = Some(found);
        }
    }

    /// One POST to the endpoint, signed for this request alone.
    fn post(&self, body: Vec<u8>) -> Result<Value, Refusal> {
        let binding = api::signed_binding_for_seed(&self.token, &self.seed)
            .map_err(|error| Refusal::Unreachable(error.to_string()))?;
        let output = api::post_json_captured(&self.endpoint, &self.token, &binding, body)
            .map_err(|error| Refusal::Unreachable(error.to_string()))?;
        let parsed = serde_json::from_slice::<Value>(&output.stdout);
        match output.status.code() {
            Some(0) => parsed.map_err(|_| {
                Refusal::Unreachable(format!(
                    "{} answered with something other than JSON",
                    self.endpoint
                ))
            }),
            // `--fail-with-body`: an HTTP error status, with the server's body.
            Some(api::CURL_HTTP_ERROR_EXIT) => Err(Refusal::Http(parsed.unwrap_or_else(|_| {
                Value::String(String::from_utf8_lossy(&output.stdout).into_owned())
            }))),
            _ => Err(Refusal::Unreachable(format!(
                "could not reach {}: {}",
                self.endpoint,
                String::from_utf8_lossy(&output.stderr).trim()
            ))),
        }
    }
}

/// Why a request got no MCP answer from the server.
enum Refusal {
    /// The HTTP door refused it before MCP saw it: a revoked, expired or
    /// unproven credential, say. The server's error body rides along.
    Http(Value),
    /// The server's `initialize` carried no actor for this credential.
    Refused(Value),
    /// No answer at all.
    Unreachable(String),
}

impl Refusal {
    fn rpc_error(&self, id: &Value) -> String {
        match self {
            Self::Http(body) => rpc_error(
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
            Self::Unreachable(message) => {
                rpc_error(id, -32000, "server_unreachable", message, None)
            }
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
