//! Claude Code's PostToolUse push, paced by one deadline and one session file.

use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::time::{Duration, Instant};

use oneiron::ingest::history::carried_headers::{CARRIED_CONTEXT_HEADER, TOOL_RESULT_CONTEXT_LEAD};
use oneiron::memory::RecallSource;
use oneiron_contracts::fingerprint::ContentHash;
use serde_json::{Map, Value, json};

use super::hosted_command::slip_vault_id;
use super::hosted_selection::HostedDiscovery;
use super::recall::Recall;
use super::session_binding::{self, BOARD_KEYFRAME, CARRIER_LINES};
use super::{bind, hosted_selection, oneiron, project_dir, read_event, recall_auth, session_id};
use crate::cli::{HookHost, HookRecallArgs};
use crate::commands::credential_file;

const TOOL_RESULT_BUDGET: Duration = Duration::from_millis(1500);
const TOOL_RESULT_LINES_PER_RESULT: usize = 1;
const TOOL_RESULT_LINES_PER_SESSION: usize = 12;
const INPUT_CHARS: usize = 300;
const RESPONSE_CHARS: usize = 400;
const MAX_SHOWN_BYTES: u64 = 64 * 1024;
/// The MCP server names Claude Code gives the Oneiron server: `oneiron`, as
/// the plugin's `.mcp.json` names it, and the plugin's `plugin:oneiron:oneiron`.
const ONEIRON_MCP_SERVERS: [&str; 2] = ["oneiron", "plugin_oneiron_oneiron"];
/// The Oneiron tools whose result holds a board keyframe; Claude Code may
/// write a tool name's dots as underscores.
const BOARD_TOOLS: [&str; 3] = ["setup_oneiron", "self.focus.refresh", "self_focus_refresh"];
/// Claude Code's own tools whose input names one file, each with that field:
/// the only input a vault not on this machine is given a word of, the file's
/// base name (REVIEW-10587 round 2 P1 2). A `path` of any other tool, an MCP
/// tool's included, may be anything.
const FILE_TOOL_FIELDS: [(&str, &str); 5] = [
    ("Read", "file_path"),
    ("Write", "file_path"),
    ("Edit", "file_path"),
    ("MultiEdit", "file_path"),
    ("NotebookEdit", "notebook_path"),
];

pub(super) fn tool_result(host: HookHost, args: &HookRecallArgs) -> Option<String> {
    if host != HookHost::ClaudeCode {
        return None;
    }
    let event = read_event()?;
    let timeout = Duration::try_from_secs_f64(args.common.timeout).unwrap_or(Duration::ZERO);
    let deadline = Instant::now() + TOOL_RESULT_BUDGET.min(timeout);
    let session = session_id(host, &event)?;
    let folder = session_binding::session_folder(host, session)?;
    let name = event.get("tool_name")?.as_str()?.trim();
    if name.is_empty() || Instant::now() >= deadline {
        return None;
    }
    let lower = name.to_lowercase();
    if lower.contains("oneiron") {
        if oneiron_board_tool(name)
            && event.get("tool_response").is_some_and(carries_keyframe)
            && Instant::now() < deadline
        {
            let _ = session_binding::add(&folder, BOARD_KEYFRAME, b"");
        }
        return None;
    }
    if args.credential_file.is_none()
        && !matches!(hosted_selection::discover(), HostedDiscovery::Selected(_))
    {
        return None;
    }

    // Keep the read and append together: simultaneous calls cannot show the
    // same key or spend the same slot. A busy hook never waits on the file.
    session_binding::ensure_session_folder(&folder).ok()?;
    let shown_path = folder.join(CARRIER_LINES);
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&shown_path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || credential_file::has_extended_acl(&file)
    {
        return None;
    }
    if metadata.mode() & 0o077 != 0 {
        eprintln!(
            "oneiron hook: {} may be read by others; run chmod 600 {}",
            shown_path.display(),
            shown_path.display()
        );
        return None;
    }
    file.try_lock().ok()?;
    let mut shown = String::new();
    (&mut file)
        .take(MAX_SHOWN_BYTES + 1)
        .read_to_string(&mut shown)
        .ok()?;
    let slots = TOOL_RESULT_LINES_PER_RESULT
        .min(TOOL_RESULT_LINES_PER_SESSION.saturating_sub(shown.lines().count()));
    if slots == 0 || shown.len() as u64 > MAX_SHOWN_BYTES || Instant::now() >= deadline {
        return None;
    }

    let bound = bind::quietly(args.url.as_deref(), deadline);
    let url = bound.url?;
    // What leaves the device is the person's words and what they handed
    // over: a vault not on this machine gets the tool name and the file's
    // base name alone (ANSWER TOOL-RESULT-HOSTED-QUERY = A, REVIEW-10587 P1 2).
    // A vault on this machine gets the full query only after it answers the
    // credential's own vault id; when the slip names none, it gets the short
    // form too.
    let mut local = bound.hosted.is_none() && bind::loopback_origin(&url);
    let slip_vault = if local {
        args.credential_file
            .as_deref()
            .and_then(|file| slip_vault_id(file).ok())
    } else {
        None
    };
    if slip_vault.is_none() {
        local = false;
    }
    let query = tool_query(name, &event, local);
    if Instant::now() >= deadline {
        return None;
    }
    let auth = recall_auth(bound.hosted.as_ref(), args.credential_file.as_deref())?;
    let oneiron = oneiron(args.common.oneiron.as_deref());
    let workspace = project_dir(&event);
    let recall = Recall {
        host,
        oneiron: &oneiron,
        url: &url,
        auth,
        workspace: workspace.as_deref(),
        query: &query,
        limit: args.limit,
        effort: args.effort,
        deadline,
        bar: RecallSource::Carrier,
        session: Some(session),
        expect_vault: slip_vault.as_deref(),
    };
    let (key, line) = recall.carrier_line(|key| {
        let digest = shown_key(key);
        shown.lines().any(|prior| prior == digest)
    })?;
    let output = json!({
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": format!("{CARRIED_CONTEXT_HEADER}\n{TOOL_RESULT_CONTEXT_LEAD} {line}"),
        }
    })
    .to_string();
    if Instant::now() >= deadline {
        return None;
    }
    let separator = if shown.is_empty() || shown.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    file.write_all(format!("{separator}{}\n", shown_key(&key)).as_bytes())
        .ok()?;
    (Instant::now() < deadline).then_some(output)
}

/// What the shown-keys file holds for `key`: its digest, never recalled
/// text. A text key from before this change simply stops matching.
fn shown_key(key: &str) -> String {
    ContentHash::of(key.as_bytes()).to_hex()
}

/// Whether `name` (`mcp__<server>__<tool>`) is a board tool of the Oneiron
/// MCP server itself, not a tool of another server that shares its tool name
/// (REVIEW-10587 P1 3).
fn oneiron_board_tool(name: &str) -> bool {
    name.strip_prefix("mcp__")
        .and_then(|rest| rest.split_once("__"))
        .is_some_and(|(server, tool)| {
            ONEIRON_MCP_SERVERS.contains(&server) && BOARD_TOOLS.contains(&tool)
        })
}

/// Whether a board tool's result holds a keyframe. Claude Code can pass the
/// MCP content blocks or the structured result, either one as a JSON string.
/// An error, or text with no keyframe in it, is not evidence that a board
/// arrived (REVIEW-10587 P1 3).
fn carries_keyframe(response: &Value) -> bool {
    let parsed;
    let response = if let Some(text) = response.as_str() {
        let Ok(value) = serde_json::from_str::<Value>(text) else {
            return false;
        };
        parsed = value;
        &parsed
    } else {
        response
    };
    if response.get("isError") == Some(&Value::Bool(true))
        || response.get("is_error") == Some(&Value::Bool(true))
        || response.get("error").is_some_and(|error| !error.is_null())
    {
        return false;
    }
    // Each Oneiron tool result states its structured payload as a text block
    // too (mcp_gateway board_setup `mcp_negotiated_content`).
    let in_blocks = response
        .get("content")
        .unwrap_or(response)
        .as_array()
        .is_some_and(|blocks| {
            blocks.iter().any(|block| {
                block
                    .get("text")
                    .and_then(Value::as_str)
                    .and_then(|text| serde_json::from_str::<Value>(text).ok())
                    .is_some_and(|output| holds_keyframe(&output))
            })
        });
    in_blocks || holds_keyframe(response.get("structuredContent").unwrap_or(response))
}

fn holds_keyframe(output: &Value) -> bool {
    output
        .pointer("/board/keyframe")
        .is_some_and(Value::is_string)
        || output
            .pointer("/output/frame/kind/kind")
            .and_then(Value::as_str)
            == Some("keyframe")
}

/// The recall query for one tool call: the tool name; when `full` (a vault
/// on this machine), the input's text fields, a path by its base name, and
/// the start of the tool's output; else only the base name of the file a
/// [`FILE_TOOL_FIELDS`] tool names.
fn tool_query(name: &str, event: &Map<String, Value>, full: bool) -> String {
    let mut parts = vec![name.to_owned()];
    if let Some(input) = event.get("tool_input") {
        if full {
            for field in [
                "file_path",
                "path",
                "command",
                "pattern",
                "description",
                "query",
                "url",
                "prompt",
            ] {
                if let Some(value) = input.get(field).and_then(Value::as_str) {
                    let value = if matches!(field, "file_path" | "path") {
                        base_name(value)
                    } else {
                        value
                    };
                    parts.push(value.chars().take(INPUT_CHARS).collect());
                }
            }
        } else if let Some((_, field)) = FILE_TOOL_FIELDS.iter().find(|(tool, _)| *tool == name)
            && let Some(value) = input.get(*field).and_then(Value::as_str)
        {
            parts.push(base_name(value).chars().take(INPUT_CHARS).collect());
        }
    }
    if full {
        parts.push(response_text(event));
    }
    parts.retain(|part| !part.is_empty());
    parts.join(" ")
}

fn base_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or_default()
}

/// The start of the tool's output, its markdown and JSON punctuation read as
/// spaces.
fn response_text(event: &Map<String, Value>) -> String {
    let mut strings = Vec::new();
    if let Some(response) = event.get("tool_response") {
        response_strings(response, &mut strings);
    }
    let mut was_space = false;
    strings
        .join(" ")
        .chars()
        .filter_map(|ch| {
            let space = ch.is_whitespace()
                || matches!(
                    ch,
                    '#' | '*' | '`' | '|' | '>' | '_' | '[' | ']' | '{' | '}' | '\\' | '"'
                );
            let keep = !space || !was_space;
            was_space = space;
            keep.then_some(if space { ' ' } else { ch })
        })
        .take(RESPONSE_CHARS)
        .collect()
}

fn response_strings<'a>(value: &'a Value, strings: &mut Vec<&'a str>) {
    match value {
        Value::String(text) => strings.push(text),
        Value::Array(values) => {
            for value in values {
                response_strings(value, strings);
            }
        }
        Value::Object(fields) => {
            for (field, value) in fields {
                if !matches!(
                    field.as_str(),
                    "type"
                        | "filePath"
                        | "file_path"
                        | "numLines"
                        | "startLine"
                        | "totalLines"
                        | "interrupted"
                        | "isImage"
                ) {
                    response_strings(value, strings);
                }
            }
        }
        _ => {}
    }
}
