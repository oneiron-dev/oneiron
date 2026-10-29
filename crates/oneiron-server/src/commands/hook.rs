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
//! a credential itself; `oneiron mcp` reads the credential file: the
//! agent's `--credential-file` for a pinned or local vault, and the one the
//! hosted selection names, in its own auth mode, for the hosted vault it
//! selected (`oneiron hosted`, [`hosted_command`]).

mod bind;
mod hosted_command;
mod hosted_selection;
mod recall;

pub use self::hosted_command::hosted;

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Map, Value};

use self::hosted_selection::{HostedDiscovery, HostedVault};
use self::recall::RecallAuth;
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
    let bound = bind::session(
        args.url.as_deref(),
        &oneiron,
        args.common.settings_file.as_deref(),
        deadline,
    );
    let mut said = bound.lines;
    let Some(url) = bound.url else {
        return said;
    };
    let Some(auth) = recall_auth(bound.hosted.as_ref(), args.credential_file.as_deref()) else {
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
            auth,
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
    let bound = bind::session(
        args.url.as_deref(),
        &oneiron,
        args.common.settings_file.as_deref(),
        deadline,
    );
    serde_json::json!({ "url": bound.url, "lines": bound.lines }).to_string()
}

fn prompt(args: &HookRecallArgs) -> Vec<String> {
    let Some(event) = read_event() else {
        return Vec::new();
    };
    // Nothing to recall with: no credential named, and no hosted vault
    // selected whose own credential a recall from it would run as.
    if args.credential_file.is_none()
        && !matches!(hosted_selection::discover(), HostedDiscovery::Selected(_))
    {
        return Vec::new();
    }
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
    let bound = bind::quietly(args.url.as_deref(), deadline);
    let Some(url) = bound.url else {
        return Vec::new();
    };
    let Some(auth) = recall_auth(bound.hosted.as_ref(), args.credential_file.as_deref()) else {
        return Vec::new();
    };
    let oneiron = oneiron(args.common.oneiron.as_deref());
    let recall = recall::Recall {
        oneiron: &oneiron,
        url: &url,
        auth,
        query: &query,
        limit: args.limit,
        effort: args.effort,
        deadline,
    };
    recall.block("From your Oneiron vault, for this prompt (may be dated):")
}

/// Whom a recall from the vault bound runs as: the hosted vault step 3
/// bound, by the credential its selection names, in its own mode, which
/// goes to that vault alone; a pinned or local vault, by `--credential-file`
/// as a slip. `None` when there is nothing to recall with.
fn recall_auth<'a>(
    hosted: Option<&'a HostedVault>,
    credential_file: Option<&'a Path>,
) -> Option<RecallAuth<'a>> {
    match hosted {
        Some(vault) => Some(vault.recall_auth()),
        None => credential_file.map(RecallAuth::Slip),
    }
}

/// `oneiron import claude-code <log> --queue`: one small file in the queue
/// of the config named, else of the running local vault, else of the
/// default config, under the settings file named, else the running vault's
/// own when the import takes that vault's config. Its output is not the
/// host's.
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
    // A named file stands over a found one. The running vault's settings
    // file goes over its own config alone, never over another config named
    // here (FIX 5602).
    let running = bind::running_config().unwrap_or_default();
    let its_own = args
        .config
        .as_deref()
        .is_none_or(|config| std::path::absolute(config).ok() == running.config);
    let settings_file = args
        .common
        .settings_file
        .clone()
        .or(running.settings_file.filter(|_| its_own));
    if let Some(config) = args.config.clone().or(running.config) {
        command.arg("--config").arg(config);
    }
    if let Some(settings_file) = settings_file {
        command.arg("--settings-file").arg(settings_file);
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
