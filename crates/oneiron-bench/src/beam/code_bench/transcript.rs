//! Reads one writer's transcript in Claude Code's `--output-format
//! stream-json`: one JSON object per line, `assistant` messages carrying
//! `tool_use` blocks and `usage`, `user` messages carrying `tool_result`
//! blocks, and a closing `result`. Claude Code takes an MCP config and a
//! tool allow-list per run, which the arms need, and one harness holds for
//! every arm. A second harness adds a second reader beside this one.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use serde::Serialize;
use serde_json::Value;

use super::super::BeamResult;
use super::manifest::rfc3339_millis;
use super::profile::Arm;

/// Tools no arm restricts.
const NEUTRAL_TOOLS: [&str; 1] = ["TodoWrite"];
/// graph_fs reads that open one file, by their `path` input.
const GRAPH_FILE_READS: [&str; 3] = ["graph_fs.read_file", "graph_fs.cat", "graph_fs.head"];
/// Verb roots that are source control, for the Scion side.
const SOURCE_CONTROL_VERB_ROOTS: [&str; 2] = ["self.code.", "vault.code."];

/// What a transcript shows of one attempt. Times are `None` when the
/// transcript carries no timing for them.
#[derive(Debug, Clone, Default, Serialize)]
pub(super) struct TranscriptMetrics {
    pub(super) turns: u64,
    /// Every prompt token: fresh, cache writes and cache reads.
    pub(super) input_tokens: u64,
    pub(super) output_tokens: u64,
    /// Distinct files read through the Read tool or a graph_fs file read.
    pub(super) files_opened: u64,
    pub(super) elapsed_secs: Option<f64>,
    /// Git commands and `self.code.*` / `vault.code.*` calls, call to result.
    pub(super) source_control_secs: Option<f64>,
    /// Start to the first successful `cargo check` or `cargo test`.
    pub(super) usable_tree_secs: Option<f64>,
    /// Tool calls outside the cell's profile, in order. Kept and shown; an
    /// attempt with one never grades as a pass.
    pub(super) breaches: Vec<String>,
    /// Lines that were not JSON (a killed run can cut its last line).
    pub(super) unreadable_lines: u64,
}

struct ToolCall {
    name: String,
    input: Value,
    called_ms: Option<i64>,
}

struct ToolResult {
    at_ms: Option<i64>,
    is_error: bool,
}

/// Reads the transcript at `path` against `arm`'s profile.
pub(super) fn read(path: &Path, arm: Arm) -> BeamResult<TranscriptMetrics> {
    let text = std::fs::read_to_string(path)?;
    let mut metrics = TranscriptMetrics::default();
    let mut usage: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut calls: Vec<(String, ToolCall)> = Vec::new();
    let mut results: BTreeMap<String, ToolResult> = BTreeMap::new();
    let (mut first_ms, mut last_ms) = (None::<i64>, None::<i64>);
    let mut duration_ms = None;
    for (number, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(event) = serde_json::from_str::<Value>(line) else {
            metrics.unreadable_lines += 1;
            continue;
        };
        let at_ms = event["timestamp"].as_str().and_then(rfc3339_millis);
        if let Some(at) = at_ms {
            first_ms = Some(first_ms.map_or(at, |first: i64| first.min(at)));
            last_ms = Some(last_ms.map_or(at, |last: i64| last.max(at)));
        }
        let message = &event["message"];
        match event["type"].as_str() {
            Some("assistant") => {
                // One message can arrive as several lines with one id; its
                // usage repeats on each, so the last one counts once.
                let id = message["id"]
                    .as_str()
                    .map_or_else(|| format!("line-{number}"), str::to_owned);
                usage.insert(id, message_usage(&message["usage"]));
                for block in content(message) {
                    if block["type"] == "tool_use" {
                        let call = ToolCall {
                            name: block["name"].as_str().unwrap_or_default().to_owned(),
                            input: block["input"].clone(),
                            called_ms: at_ms,
                        };
                        let id = block["id"].as_str().unwrap_or_default().to_owned();
                        calls.push((id, call));
                    }
                }
            }
            Some("user") => {
                for block in content(message) {
                    if block["type"] == "tool_result" {
                        let id = block["tool_use_id"].as_str().unwrap_or_default().to_owned();
                        let is_error = block["is_error"].as_bool().unwrap_or(false);
                        results.insert(id, ToolResult { at_ms, is_error });
                    }
                }
            }
            Some("result") => duration_ms = event["duration_ms"].as_f64(),
            _ => {}
        }
    }
    metrics.turns = usage.len() as u64;
    for (input, output) in usage.values() {
        metrics.input_tokens += input;
        metrics.output_tokens += output;
    }
    let timed = first_ms.is_some();
    metrics.elapsed_secs = duration_ms.map(|millis| millis / 1_000.0).or_else(|| {
        first_ms
            .zip(last_ms)
            .map(|(first, last)| seconds_between(first, last))
    });
    let mut files = BTreeSet::new();
    let mut source_control_secs = 0.0;
    let mut usable_tree_secs = None;
    for (id, call) in &calls {
        if let Some(file) = opened_file(call) {
            files.insert(file);
        }
        if breaches(arm, &call.name, &call.input) {
            metrics.breaches.push(call.name.clone());
        }
        let result = results.get(id);
        let span = call
            .called_ms
            .zip(result.and_then(|result| result.at_ms))
            .map(|(called, answered)| seconds_between(called, answered));
        if is_source_control(call) {
            source_control_secs += span.unwrap_or_default();
        }
        let built = result.is_some_and(|result| !result.is_error) && is_cargo_build(call);
        if usable_tree_secs.is_none() && built {
            usable_tree_secs = first_ms
                .zip(result.and_then(|result| result.at_ms))
                .map(|(first, answered)| seconds_between(first, answered));
        }
    }
    metrics.files_opened = files.len() as u64;
    metrics.source_control_secs = timed.then_some(source_control_secs);
    metrics.usable_tree_secs = usable_tree_secs;
    Ok(metrics)
}

fn content(message: &Value) -> &[Value] {
    message["content"].as_array().map_or(&[], Vec::as_slice)
}

/// (prompt tokens, output tokens) of one message's `usage`.
fn message_usage(usage: &Value) -> (u64, u64) {
    let count = |field: &str| usage[field].as_u64().unwrap_or(0);
    (
        count("input_tokens")
            + count("cache_creation_input_tokens")
            + count("cache_read_input_tokens"),
        count("output_tokens"),
    )
}

/// A transcript spans minutes, so its milliseconds fit an f64 exactly.
fn seconds_between(from_ms: i64, to_ms: i64) -> f64 {
    (to_ms - from_ms) as f64 / 1_000.0
}

/// The MCP tool name past `mcp__<server>__`, if the call is an MCP call.
fn mcp_tool(name: &str) -> Option<(&str, &str)> {
    name.strip_prefix("mcp__")?.split_once("__")
}

/// A verb or prefix as a tool name: the verb itself, or with its dots
/// replaced, as a client may sanitize them.
fn names_verb(tool: &str, verb: &str) -> bool {
    tool == verb || tool == verb.replace('.', "_")
}

fn starts_with_verb(tool: &str, prefix: &str) -> bool {
    tool.starts_with(prefix) || tool.starts_with(&prefix.replace('.', "_"))
}

fn opened_file(call: &ToolCall) -> Option<String> {
    if call.name == "Read" {
        return call.input["file_path"].as_str().map(str::to_owned);
    }
    let (_, tool) = mcp_tool(&call.name)?;
    if GRAPH_FILE_READS.iter().any(|verb| names_verb(tool, verb)) {
        call.input["path"].as_str().map(str::to_owned)
    } else {
        None
    }
}

fn shell_command(call: &ToolCall) -> Option<&str> {
    if call.name == "Bash" {
        call.input["command"].as_str()
    } else {
        None
    }
}

/// The commands of a shell line, split at `;`, `&`, `|` and newlines.
fn shell_segments(command: &str) -> impl Iterator<Item = &str> {
    command
        .split([';', '&', '|', '\n'])
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
}

fn is_source_control(call: &ToolCall) -> bool {
    if let Some(command) = shell_command(call) {
        return shell_segments(command)
            .any(|segment| segment == "git" || segment.starts_with("git "));
    }
    mcp_tool(&call.name).is_some_and(|(_, tool)| {
        SOURCE_CONTROL_VERB_ROOTS
            .iter()
            .any(|root| starts_with_verb(tool, root))
    })
}

fn is_cargo_build(call: &ToolCall) -> bool {
    shell_command(call).is_some_and(|command| {
        shell_segments(command)
            .any(|segment| segment.starts_with("cargo check") || segment.starts_with("cargo test"))
    })
}

/// A call outside the arm's profile: a tool it does not allow, a shell
/// command it denies, or an MCP tool of another server or outside its verbs.
fn breaches(arm: Arm, name: &str, input: &Value) -> bool {
    if let Some((server, tool)) = mcp_tool(name) {
        let allowed = arm.verbs().iter().any(|verb| names_verb(tool, verb))
            || arm
                .tool_prefixes()
                .iter()
                .any(|prefix| starts_with_verb(tool, prefix));
        return arm.server() != Some(server) || !allowed;
    }
    if NEUTRAL_TOOLS.contains(&name) {
        return false;
    }
    let denied = arm.denied_tools();
    if denied.iter().any(|rule| rule == name) {
        return true;
    }
    if name == "Bash" {
        let command = input["command"].as_str().unwrap_or_default();
        let prefixes: Vec<&str> = denied
            .iter()
            .filter_map(|rule| rule.strip_prefix("Bash(")?.strip_suffix(":*)"))
            .collect();
        return shell_segments(command).any(|segment| {
            prefixes.iter().any(|prefix| {
                segment == *prefix
                    || segment
                        .strip_prefix(prefix)
                        .is_some_and(|rest| rest.starts_with(' '))
            })
        });
    }
    !arm.allowed_tools().iter().any(|tool| tool == name)
}
