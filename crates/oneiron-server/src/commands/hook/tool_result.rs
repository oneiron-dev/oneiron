//! Claude Code's PostToolUse push, paced by one deadline and one session file.

use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::time::{Duration, Instant};

use oneiron::ingest::history::carried_headers::{CARRIED_CONTEXT_HEADER, TOOL_RESULT_CONTEXT_LEAD};
use oneiron::memory::RecallSource;
use serde_json::{Map, Value, json};

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
        if ["setup_oneiron", "focus.refresh", "focus_refresh"]
            .iter()
            .any(|&suffix| lower.ends_with(suffix))
            && event
                .get("tool_response")
                .is_some_and(successful_mcp_response)
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
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(folder.join(CARRIER_LINES))
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
        || credential_file::has_extended_acl(&file)
    {
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

    let query = tool_query(name, &event);
    if Instant::now() >= deadline {
        return None;
    }
    let bound = bind::quietly(args.url.as_deref(), deadline);
    let url = bound.url?;
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
    };
    let (key, line) = recall.carrier_line(|key| shown.lines().any(|prior| prior == key))?;
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
    file.write_all(format!("{separator}{key}\n").as_bytes())
        .ok()?;
    (Instant::now() < deadline).then_some(output)
}

fn successful_mcp_response(response: &Value) -> bool {
    // Claude Code can pass MCP content blocks or the structured result as a
    // JSON string. Error text alone is not evidence that a board arrived.
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
    if response
        .get("content")
        .unwrap_or(response)
        .as_array()
        .is_some_and(|blocks| !blocks.is_empty())
    {
        return true;
    }
    let output = response.get("structuredContent").unwrap_or(response);
    output
        .pointer("/board/keyframe")
        .is_some_and(Value::is_string)
        || output
            .pointer("/output/frame/kind/kind")
            .and_then(Value::as_str)
            == Some("keyframe")
}

fn tool_query(name: &str, event: &Map<String, Value>) -> String {
    let mut parts = vec![name.to_owned()];
    if let Some(input) = event.get("tool_input") {
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
                    value.rsplit('/').next().unwrap_or_default()
                } else {
                    value
                };
                parts.push(value.chars().take(INPUT_CHARS).collect());
            }
        }
    }
    let mut strings = Vec::new();
    if let Some(response) = event.get("tool_response") {
        response_strings(response, &mut strings);
    }
    let mut was_space = false;
    let response = strings.join(" ");
    parts.push(
        response
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
            .collect(),
    );
    parts.retain(|part| !part.is_empty());
    parts.join(" ")
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
