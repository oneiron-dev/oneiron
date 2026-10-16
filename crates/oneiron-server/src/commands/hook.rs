//! `oneiron hook --host <host> <event>`: an agent harness's hooks, run by the
//! binary. It replaces the Python example the Claude Code hooks were
//! (`oneiron_hook.py`) and keeps its flags and limits. Each hook reads the
//! host's event JSON on stdin.
//!
//! - `session-start` binds a vault ([`bind`]), prints one line naming it,
//!   and recalls a short block for the project ([`recall`]).
//! - `prompt` recalls a short block for the prompt from the bound vault.
//! - `hand-over` queues the session's log for the running `serve` to import.
//! - `bind` binds a vault as `session-start` does and prints it as JSON, for
//!   a plugin that runs inside its host (Hermes's memory provider).
//!
//! A hook never blocks the host: whatever fails, it exits 0. It never reads
//! a credential itself; `oneiron mcp` reads the agent's credential file.

mod bind;
mod recall;

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Map, Value};

use crate::cli::{HookArgs, HookBindArgs, HookEvent, HookHandOverArgs, HookRecallArgs};

/// The most of the host's event read from stdin.
const MAX_EVENT_BYTES: u64 = 1 << 20;
/// How long the project's git root may take to find.
const GIT_TIMEOUT: Duration = Duration::from_secs(2);

pub fn hook(args: HookArgs) {
    // Every host's events read the same fields; the host names whose they are.
    let said = match args.event {
        HookEvent::SessionStart(args) => session_start(&args),
        HookEvent::Prompt(args) => prompt(&args),
        HookEvent::HandOver(args) => {
            hand_over(&args);
            Vec::new()
        }
        HookEvent::Bind(args) => vec![bind_json(&args)],
    };
    if !said.is_empty() {
        let _ = writeln!(std::io::stdout().lock(), "{}", said.join("\n"));
    }
}

fn session_start(args: &HookRecallArgs) -> Vec<String> {
    let Some(event) = read_event() else {
        return Vec::new();
    };
    let deadline = deadline(args.common.timeout);
    let oneiron = oneiron(args.common.oneiron.as_deref());
    let bound = bind::session(args.url.as_deref(), &oneiron, deadline);
    let mut said = bound.lines;
    let (Some(url), Some(credential)) = (bound.url, &args.credential_file) else {
        return said;
    };
    let query = args.query.clone().unwrap_or_else(|| {
        let cwd = event
            .get("cwd")
            .and_then(Value::as_str)
            .filter(|cwd| !cwd.is_empty())
            .map(PathBuf::from)
            .or_else(|| std::env::current_dir().ok());
        cwd.map_or_else(String::new, |cwd| project_name(&cwd, deadline))
            .replace(['-', '_'], " ")
    });
    if !query.trim().is_empty() {
        let recall = recall::Recall {
            oneiron: &oneiron,
            url: &url,
            credential,
            query: &query,
            limit: args.limit,
            effort: args.effort,
            deadline,
        };
        said.extend(recall.block(&format!(
            "From your Oneiron vault, for \"{query}\" (recalled at session start; may be dated):"
        )));
    }
    said
}

/// The vault a session binds, as `{"url", "lines"}`: `url` is null when none
/// answers, and `lines` are what the session is told, the first naming it.
fn bind_json(args: &HookBindArgs) -> String {
    let deadline = deadline(args.common.timeout);
    let oneiron = oneiron(args.common.oneiron.as_deref());
    let bound = bind::session(args.url.as_deref(), &oneiron, deadline);
    serde_json::json!({ "url": bound.url, "lines": bound.lines }).to_string()
}

fn prompt(args: &HookRecallArgs) -> Vec<String> {
    let Some(event) = read_event() else {
        return Vec::new();
    };
    let Some(credential) = &args.credential_file else {
        return Vec::new();
    };
    let query = args
        .query
        .as_deref()
        .or_else(|| event.get("prompt").and_then(Value::as_str))
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if query.is_empty() {
        return Vec::new();
    }
    let deadline = deadline(args.common.timeout);
    let Some(url) = bind::quietly(args.url.as_deref(), deadline) else {
        return Vec::new();
    };
    let oneiron = oneiron(args.common.oneiron.as_deref());
    let recall = recall::Recall {
        oneiron: &oneiron,
        url: &url,
        credential,
        query: &query,
        limit: args.limit,
        effort: args.effort,
        deadline,
    };
    recall.block("From your Oneiron vault, for this prompt (may be dated):")
}

/// `oneiron import claude-code <log> --queue`: one small file in the queue
/// of the config named, else of the running local vault, else of the
/// default config. Its output is not the host's.
fn hand_over(args: &HookHandOverArgs) {
    let Some(event) = read_event() else {
        return;
    };
    let Some(transcript) = event
        .get("transcript_path")
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
    else {
        return;
    };
    let mut command = oneiron_spawn::command(oneiron(args.common.oneiron.as_deref()));
    command
        .args(["import", "claude-code", transcript, "--queue"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(config) = args.config.clone().or_else(bind::running_config) {
        command.arg("--config").arg(config);
    }
    let deadline = deadline(args.common.timeout);
    if let Ok(mut child) = command.spawn()
        && wait_until(&mut child, deadline).is_none()
    {
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// The host's event: a JSON object (an empty one for empty stdin or a
/// non-object), or `None` when stdin is not JSON.
fn read_event() -> Option<Map<String, Value>> {
    let mut raw = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_EVENT_BYTES)
        .read_to_end(&mut raw)
        .ok()?;
    if raw.trim_ascii().is_empty() {
        return Some(Map::new());
    }
    match serde_json::from_slice(&raw).ok()? {
        Value::Object(event) => Some(event),
        _ => Some(Map::new()),
    }
}

/// The git repository's folder name, else the working directory's.
fn project_name(cwd: &Path, deadline: Instant) -> String {
    let top = git_top(cwd, deadline).unwrap_or_else(|| cwd.to_path_buf());
    top.file_name()
        .map_or_else(String::new, |name| name.to_string_lossy().into_owned())
}

fn git_top(cwd: &Path, deadline: Instant) -> Option<PathBuf> {
    let deadline = deadline.min(Instant::now() + GIT_TIMEOUT);
    if Instant::now() >= deadline {
        return None;
    }
    let mut child = oneiron_spawn::command("git")
        .arg("-C")
        .arg(cwd)
        .args(["rev-parse", "--show-toplevel"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let Some(status) = wait_until(&mut child, deadline) else {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    };
    let mut top = String::new();
    child.stdout.take()?.read_to_string(&mut top).ok()?;
    let top = top.trim();
    (status.success() && !top.is_empty()).then(|| PathBuf::from(top))
}

fn deadline(timeout: f64) -> Instant {
    Instant::now() + Duration::try_from_secs_f64(timeout).unwrap_or(Duration::ZERO)
}

/// The binary the bridge, the import and a started server run as.
fn oneiron(named: Option<&Path>) -> PathBuf {
    named
        .map(Path::to_path_buf)
        .or_else(|| std::env::current_exe().ok())
        .unwrap_or_else(|| PathBuf::from("oneiron"))
}

/// Waits for `child` to exit until `deadline`; `None` if it has not.
fn wait_until(child: &mut Child, deadline: Instant) -> Option<ExitStatus> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => return None,
        }
    }
}
