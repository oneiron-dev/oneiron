//! Recall through `oneiron mcp`, spoken to one JSON-RPC request at a time,
//! and the short block a hook prints from its hits.

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Child, ChildStdin, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::cli::HookEffort;
use crate::commands::mcp_bridge::{INVOCATION_META, mint_invocation};

/// One hit's longest text, in characters.
const ITEM_CHARS: usize = 400;
/// The block's text in all, in characters, bullets and newlines aside.
const BLOCK_CHARS: usize = 6000;

pub(super) struct Recall<'a> {
    pub(super) oneiron: &'a Path,
    pub(super) url: &'a str,
    pub(super) credential: &'a Path,
    pub(super) query: &'a str,
    pub(super) limit: usize,
    pub(super) effort: HookEffort,
    pub(super) deadline: Instant,
}

impl Recall<'_> {
    /// `header` and a line per hit, or nothing when recall fails or finds
    /// nothing.
    pub(super) fn block(&self, header: &str) -> Vec<String> {
        if Instant::now() >= self.deadline {
            return Vec::new();
        }
        let Ok(result) = self.call() else {
            return Vec::new();
        };
        if result.get("isError") == Some(&Value::Bool(true)) {
            return Vec::new();
        }
        let mut found = Vec::new();
        texts(result.get("structuredContent"), &mut found);
        if found.is_empty() {
            for block in result
                .get("content")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(text) = block.get("text").and_then(Value::as_str)
                    && let Ok(value) = serde_json::from_str::<Value>(text)
                {
                    texts(Some(&value), &mut found);
                }
            }
        }
        let lines = self.shortened(found);
        if lines.is_empty() {
            return Vec::new();
        }
        std::iter::once(header.to_owned()).chain(lines).collect()
    }

    /// Whitespace folded, repeats dropped, each hit cut to [`ITEM_CHARS`],
    /// at most `limit` of them and [`BLOCK_CHARS`] in all.
    fn shortened(&self, found: Vec<String>) -> Vec<String> {
        let (mut lines, mut seen, mut size) = (Vec::new(), std::collections::HashSet::new(), 0);
        for text in found {
            let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
            if text.is_empty() || !seen.insert(text.clone()) {
                continue;
            }
            let text = if text.chars().count() > ITEM_CHARS {
                let mut cut: String = text.chars().take(ITEM_CHARS - 1).collect();
                cut.push('…');
                cut
            } else {
                text
            };
            let chars = text.chars().count();
            if size + chars > BLOCK_CHARS || lines.len() >= self.limit {
                break;
            }
            lines.push(format!("- {text}"));
            size += chars;
        }
        lines
    }

    fn call(&self) -> anyhow::Result<Value> {
        let mut bridge = Bridge::start(self)?;
        let result = self.exchange(&mut bridge);
        bridge.close();
        result
    }

    fn exchange(&self, bridge: &mut Bridge) -> anyhow::Result<Value> {
        bridge.call(
            1,
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "oneiron-claude-code-hooks", "version": "1"},
            }),
        )?;
        bridge.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))?;
        let listed = bridge.call(2, "tools/list", json!({}))?;
        let (name, arguments) = self.tool_call(&listed)?;
        // One logical call under one invocation id (ARCH-0080 §3): this
        // process makes it once and never retries it.
        let mut meta = serde_json::Map::new();
        meta.insert(INVOCATION_META.to_owned(), Value::String(mint_invocation()));
        bridge.call(
            3,
            "tools/call",
            json!({"name": name, "arguments": arguments, "_meta": meta}),
        )
    }

    /// `vault.recall` at the effort asked when the server lists it, else
    /// `memory.query`. Light runs no model and embeds nothing; medium embeds
    /// the query on the server's embedder, so it finds a paraphrase; high and
    /// above also rerank, under the server's budget. `memory.query` reads
    /// lexically, and on the one-space preset (the text kind slot bound to a
    /// declared space) it also embeds the query through that space's text
    /// tower.
    fn tool_call(&self, listed: &Value) -> anyhow::Result<(&'static str, Value)> {
        let tools = listed.get("tools").and_then(Value::as_array);
        let tool = |name: &str| {
            tools
                .into_iter()
                .flatten()
                .find(|tool| tool.get("name").and_then(Value::as_str) == Some(name))
        };
        let (name, tool) = match tool("vault.recall") {
            Some(tool) => ("vault.recall", tool),
            None => (
                "memory.query",
                tool("memory.query").ok_or_else(|| anyhow::anyhow!("no recall tool"))?,
            ),
        };
        let version = tool
            .pointer("/inputSchema/properties/schema_version/const")
            .cloned()
            .unwrap_or_else(|| json!("mcp_tool_args.v1"));
        let arguments = if name == "vault.recall" {
            json!({"spec": {"query": self.query, "effort": self.effort.as_str(), "limit": self.limit}})
        } else {
            json!({"request": {"query": self.query, "limit": self.limit, "view": "summary", "countMode": "none"}})
        };
        Ok((
            name,
            json!({
                "schema_version": version,
                "consent": {
                    "policy_ref": "policy:claude-code-hooks",
                    "purpose": "recall context for a new Claude Code session",
                },
                "arguments": arguments,
            }),
        ))
    }
}

/// One `oneiron mcp` process in a process group of its own, so giving up
/// also ends the `curl` it started.
struct Bridge {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<Vec<u8>>,
    deadline: Instant,
}

impl Bridge {
    fn start(recall: &Recall<'_>) -> anyhow::Result<Self> {
        let mut child = oneiron_spawn::command(recall.oneiron)
            .args(["mcp", "--url", recall.url, "--surface", "tool-first"])
            .arg("--credential-file")
            .arg(recall.credential)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("no bridge stdout"))?;
        let (send, lines) = mpsc::channel();
        std::thread::spawn(move || {
            let mut stdout = BufReader::new(stdout);
            loop {
                let mut line = Vec::new();
                match stdout.read_until(b'\n', &mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) if send.send(line).is_err() => break,
                    Ok(_) => {}
                }
            }
        });
        Ok(Self {
            stdin: child.stdin.take(),
            child,
            lines,
            deadline: recall.deadline,
        })
    }

    fn send(&mut self, message: &Value) -> anyhow::Result<()> {
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("bridge stdin closed"))?;
        let mut line = serde_json::to_vec(message)?;
        line.push(b'\n');
        stdin.write_all(&line)?;
        stdin.flush()?;
        Ok(())
    }

    fn call(&mut self, id: u64, method: &str, params: Value) -> anyhow::Result<Value> {
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))?;
        loop {
            let left = self.deadline.saturating_duration_since(Instant::now());
            let line = self.lines.recv_timeout(left)?;
            let Ok(answer) = serde_json::from_slice::<Value>(&line) else {
                continue;
            };
            if answer.get("id") == Some(&json!(id)) {
                anyhow::ensure!(answer.get("error").is_none(), "{method} failed");
                return Ok(answer
                    .get("result")
                    .filter(|result| !result.is_null())
                    .cloned()
                    .unwrap_or_else(|| json!({})));
            }
        }
    }

    fn close(mut self) {
        drop(self.stdin.take());
        let wait = self
            .deadline
            .max(Instant::now() + Duration::from_millis(100));
        let _ = super::wait_until(&mut self.child, wait);
        if let Some(group) = i32::try_from(self.child.id())
            .ok()
            .and_then(rustix::process::Pid::from_raw)
        {
            let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
        }
        let _ = self.child.wait();
    }
}

/// Every hit's text, in order, from the result's `items` lists.
fn texts(value: Option<&Value>, found: &mut Vec<String>) {
    match value {
        Some(Value::Object(object)) => {
            if let Some(Value::Array(items)) = object.get("items") {
                found.extend(items.iter().filter_map(hit_text));
                return;
            }
            for child in object.values() {
                texts(Some(child), found);
            }
        }
        Some(Value::Array(values)) => {
            for child in values {
                texts(Some(child), found);
            }
        }
        _ => {}
    }
}

/// One hit's words: a recall pack item's `value_text`, after a claim's
/// predicate; in a query result, a message's `body.content` or a claim's
/// `body.pred` and `body.val`. A pack item for a record with no words
/// carries its body as JSON (an actor's name, say); that gives none. A
/// message's own words are kept even when they read as JSON.
fn hit_text(item: &Value) -> Option<String> {
    if let Some(text) = item.get("value_text").and_then(Value::as_str) {
        if let Some(predicate) = item.get("predicate").and_then(Value::as_str) {
            return Some(format!("{predicate}: {text}"));
        }
        if item.get("kind").and_then(Value::as_str) != Some("MESSAGE") && structural(text) {
            return None;
        }
        return Some(text.to_owned());
    }
    let body = item.get("body")?.as_object()?;
    if let Some(content) = body.get("content").and_then(Value::as_str) {
        return Some(content.to_owned());
    }
    let value = match body.get("val")? {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        _ => return None,
    };
    Some(match body.get("pred").and_then(Value::as_str) {
        Some(predicate) => format!("{predicate}: {value}"),
        None => value,
    })
}

/// A record's body as JSON, not words to show.
fn structural(text: &str) -> bool {
    text.trim_start().starts_with('{')
        && serde_json::from_str::<Value>(text).is_ok_and(|v| v.is_object())
}
