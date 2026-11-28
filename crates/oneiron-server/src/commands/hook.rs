//! `oneiron hook --host <host> <event>`: an agent harness's hooks, run by the
//! binary. It replaces the Python example the Claude Code hooks were
//! (`oneiron_hook.py`) and keeps its flags and limits. Each hook reads the
//! host's event JSON on stdin.
//!
//! - `session-start` binds a vault ([`bind`]), prints one line naming it,
//!   which also gives the bind command when no project is bound to the
//!   session's folder ([`recall::folder_unbound`]). Given the task's words
//!   (`--query`), it pushes the lines that clear the owner's start bar, at most
//!   3 ([`recall`]); keyed on nothing but the folder, it recalls nothing.
//! - `prompt` pushes the lines for the prompt that clear the owner's carrier
//!   bar, from the bound vault.
//! - `hand-over` queues the session's log for the running `serve` to import,
//!   or sends it to the selected hosted vault every start of the session
//!   bound and recorded ([`hand_over`], [`session_binding`]).
//! - `bind` binds a vault as `session-start` does and prints it as JSON, for
//!   a plugin that runs inside its host (Hermes's memory provider).
//!
//! Every host's event is read for the same fields. The host decides how the
//! session and prompt hooks print what they say ([`context_reply`]) and
//! which import reads the log a hand-over queues ([`import_source`]).
//!
//! A hook never blocks the host: whatever fails, it exits 0. It never sends
//! a credential itself; `oneiron mcp` reads the credential file and sends
//! it: the agent's `--credential-file` for a pinned or local vault, and the
//! one the hosted selection names, in its own auth mode, for the hosted
//! vault it selected (`oneiron hosted`, [`hosted_command`]). An OAuth
//! selection's hand-over reads its hand-over sign-in's tier and origin
//! first, and hands the file to the bridge ([`hand_over_queue`]).
//!
//! `oneiron continue --cloud` ([`continue_command`]) lives here too: it
//! reads the same hosted selection and calls its verbs through the same
//! bridge the recall speaks to.

mod bind;
mod continue_command;
mod focus_refresh;
mod hand_over_ask;
mod hand_over_queue;
mod hosted_command;
mod hosted_continue_sign_in;
mod hosted_selection;
mod hosted_sign_in;
mod recall;
mod session_binding;
mod tool_result;

pub use self::continue_command::continue_work;
#[cfg(oneiron_test_support)]
pub(crate) use self::continue_command::test_support as continue_test_support;
pub use self::hosted_command::hosted;

use std::fs;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use oneiron::ingest::history::HistorySource;
use oneiron::memory::RecallSource;
use serde_json::{Map, Value};

use self::bind::HandOverTarget;
use self::hosted_selection::{HostedDiscovery, HostedVault};
use self::recall::RecallAuth;
use self::session_binding::EarlierTurns;
use crate::cli::{HookArgs, HookBindArgs, HookEvent, HookHandOverArgs, HookHost, HookRecallArgs};

/// The most of the host's event read from stdin.
const MAX_EVENT_BYTES: u64 = 1 << 20;
/// How long the project's git root may take to find.
/// The longest first line of a Codex rollout read for its meta, which holds
/// the session's base instructions: tens of KiB.
const MAX_ROLLOUT_META_BYTES: u64 = 4 << 20;
/// What the vault line at `url` adds when no project is bound to the session's
/// folder (RECALL-SESSION-PROJECT; Engine ANSWER RECALL-SESSION-PROJECT-INTENT,
/// 26 Nov: Q2 = A, the bind command in the start hook's vault line; Q3 = A,
/// binding is the owner's act, so the line names who runs it). The command names
/// the vault by `--base-url`, so it binds the folder on the vault the line names,
/// whatever `ONEIRON_URL` holds where the owner runs it.
fn unbound_folder_words(url: &str) -> String {
    format!(
        " No project is bound to this folder, so a read that names no project reads no \
         claims here; the owner binds one by running `oneiron project bind <project-ref> \
         --base-url {url}` in this folder."
    )
}

pub fn hook(args: HookArgs) {
    let host = args.host;
    let said = match args.event {
        HookEvent::SessionStart(args) => context_reply(host, &session_start(host, &args)),
        HookEvent::Prompt(args) => context_reply(host, &prompt(host, &args)),
        HookEvent::ToolResult(args) => tool_result::tool_result(host, &args),
        HookEvent::FocusRefresh(args) => focus_refresh::focus_refresh(host, &args),
        HookEvent::HandOver(args) => {
            hand_over(host, &args);
            None
        }
        HookEvent::Bind(args) => Some(bind_json(&args)),
    };
    if let Some(said) = said {
        let _ = writeln!(std::io::stdout().lock(), "{said}");
    }
}

/// What a session or prompt hook prints for `host` to add to the session's
/// context: the lines as plain text where the host reads text (Claude Code,
/// Codex), else one JSON object holding them in the host's own field.
/// `None` when there is nothing to say, which every host reads as no action.
fn context_reply(host: HookHost, said: &[String]) -> Option<String> {
    if said.is_empty() {
        return None;
    }
    let text = said.join("\n");
    Some(match host {
        HookHost::ClaudeCode | HookHost::Codex | HookHost::Hermes => text,
        // Cursor's `sessionStart` output (cursor.com/docs/hooks).
        HookHost::Cursor => serde_json::json!({ "additional_context": text }).to_string(),
        // Copilot's `sessionStart` output, for both event-name formats
        // (docs.github.com/en/copilot/reference/hooks-reference).
        HookHost::Copilot => serde_json::json!({ "additionalContext": text }).to_string(),
    })
}

/// The `oneiron import` source that reads `host`'s session log.
const fn import_source(host: HookHost) -> HistorySource {
    match host {
        // Hermes asks only `bind`; a hand-over under its name reads a Claude
        // Code log, as every hand-over did before hosts had their own.
        HookHost::ClaudeCode | HookHost::Hermes => HistorySource::ClaudeCode,
        HookHost::Codex => HistorySource::Codex,
        HookHost::Cursor | HookHost::Copilot => HistorySource::HookTranscript,
    }
}

/// The session's project folder: the event's `cwd`, else the first of its
/// `workspace_roots` (Cursor's `sessionStart` names no `cwd`, and runs a
/// plugin's hook in the plugin's own folder), else this process's working
/// directory.
fn project_dir(event: &Map<String, Value>) -> Option<PathBuf> {
    let folder = |value: Option<&Value>| {
        value
            .and_then(Value::as_str)
            .filter(|folder| !folder.is_empty())
            .map(PathBuf::from)
    };
    folder(event.get("cwd"))
        .or_else(|| {
            folder(
                event
                    .get("workspace_roots")
                    .and_then(Value::as_array)
                    .and_then(|roots| roots.first()),
            )
        })
        .or_else(|| std::env::current_dir().ok())
}

fn session_start(host: HookHost, args: &HookRecallArgs) -> Vec<String> {
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
    // A session's hand-over sends its log only to the vault every start of
    // it bound.
    let session = session_id(host, &event);
    if let Some(session) = session {
        let earlier = earlier_turns(host, &event);
        session_binding::record(host, session, bound.hosted.as_ref(), &earlier);
    }
    let mut said = bound.lines;
    let Some(url) = bound.url else {
        return said;
    };
    let Some(auth) = recall_auth(bound.hosted.as_ref(), args.credential_file.as_deref()) else {
        return said;
    };
    let folder = project_dir(&event);
    // One `initialize`, no recall: in a folder with no project bound, a read
    // that names no project reads no claims, so the vault line says how the
    // owner binds one (Q2 = A).
    if let (Some(dir), Some(line)) = (folder.as_deref(), said.first_mut())
        && recall::folder_unbound(&oneiron, &url, auth, dir, deadline)
    {
        line.push_str(&unbound_folder_words(&url));
    }
    // A start keyed on nothing but the folder's name recalls nothing: on such a query no
    // relevance bar separates true lines from traps (RECALL-AB-THRESHOLD-DATA, 26 Nov: a true
    // note at 0.416 under two traps at 0.428 and 0.419). Given the task's words, the start
    // pushes what clears the owner's start bar (RECALL-CARRIER-THRESHOLD).
    let Some(query) = args
        .query
        .as_deref()
        .filter(|query| !query.trim().is_empty())
    else {
        return said;
    };
    let recall = recall::Recall {
        host,
        oneiron: &oneiron,
        url: &url,
        auth,
        workspace: folder.as_deref(),
        query,
        limit: args.limit,
        effort: args.effort,
        deadline,
        bar: RecallSource::Start,
        session,
        expect_vault: None,
    };
    said.extend(recall.block(
        &format!(
            "From your Oneiron vault, for \"{query}\" (recalled at session start; may be dated):"
        ),
        &recall::query_lead(query),
    ));
    said
}

/// The vault a session binds, as `{"url", "lines", "hosted"}`: `url` is null
/// when none answers, `lines` are what the session is told, the first naming
/// it, and `hosted` is the selected hosted vault step 3 bound (its origin,
/// vault id, auth mode and credential file, never a value in it), else null.
fn bind_json(args: &HookBindArgs) -> String {
    let deadline = deadline(args.common.timeout);
    let oneiron = oneiron(args.common.oneiron.as_deref());
    let bound = bind::session(
        args.url.as_deref(),
        &oneiron,
        args.common.settings_file.as_deref(),
        deadline,
    );
    serde_json::json!({ "url": bound.url, "lines": bound.lines, "hosted": bound.hosted })
        .to_string()
}

fn prompt(host: HookHost, args: &HookRecallArgs) -> Vec<String> {
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
    let folder = project_dir(&event);
    let recall = recall::Recall {
        host,
        oneiron: &oneiron,
        url: &url,
        auth,
        workspace: folder.as_deref(),
        query: &query,
        limit: args.limit,
        effort: args.effort,
        deadline,
        bar: RecallSource::Carrier,
        session: session_id(host, &event),
        expect_vault: None,
    };
    let lead = match args
        .query
        .as_deref()
        .filter(|given| !given.trim().is_empty())
    {
        Some(_) => recall::query_lead(&query),
        None => "From your Oneiron vault, for this prompt".to_owned(),
    };
    recall.block(
        "From your Oneiron vault, for this prompt (may be dated):",
        &lead,
    )
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

/// `oneiron import <source> <log> --queue`, by the source that reads the
/// host's logs ([`import_source`]): one small file in the queue of the
/// config named, else of the running local vault, else of the default
/// config, under the settings file named, else the running vault's own when
/// the import takes that vault's config. With no config named, the log goes
/// by what the session's starts bound ([`bind::hand_over_target`]): to the
/// selected hosted vault where every start bound that one and it is still
/// selected, through `vault.imports.hook_transcript` as the selection's own
/// credential (an OAuth selection's hand-over sign-in; while none stands,
/// the log waits in the vault's hand-over queue, [`hand_over_queue`]), by
/// the import that reads the host's logs, when the log is the event's own
/// session's and sits where the host keeps its logs
/// ([`continue_command::hand_over_hosted`]), with nothing queued here;
/// nowhere where they bound a hosted vault no longer selected, or more than
/// one vault. A send that fails is sent again whole by the session's next
/// hand-over, and the import lands only what is new. Its output is not the
/// host's.
fn hand_over(host: HookHost, args: &HookHandOverArgs) {
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
    let oneiron = oneiron(args.common.oneiron.as_deref());
    let deadline = deadline(args.common.timeout);
    // A config named here is a local queue's.
    let session = session_id(host, &event).filter(|_| args.config.is_none());
    let running = match (session, bind::hand_over_target(host, session)) {
        (Some(session), HandOverTarget::Hosted(vault)) => {
            let policy_ref = format!("policy:{}-hooks", host.as_str());
            let _ = continue_command::hand_over_hosted(
                &oneiron,
                &vault,
                host,
                session,
                Path::new(transcript),
                policy_ref,
                deadline,
            );
            return;
        }
        (_, HandOverTarget::Hosted(_) | HandOverTarget::Withheld) => return,
        (_, HandOverTarget::Local(running)) => running.unwrap_or_default(),
    };
    let mut command = oneiron_spawn::command(oneiron);
    command
        .args([
            "import",
            import_source(host).source_id(),
            transcript,
            "--queue",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // A named file stands over a found one. The running vault's settings
    // file goes over its own config alone, never over another config named
    // here (FIX 5602).
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

/// The session `host`'s event names, when it names one: Cursor's
/// `conversation_id`, which every Cursor event names (its `sessionStart`
/// names it again as `session_id`, its `stop` only so), else `session_id`.
fn session_id(host: HookHost, event: &Map<String, Value>) -> Option<&str> {
    let named = |field: &str| {
        event
            .get(field)
            .and_then(Value::as_str)
            .filter(|session| !session.is_empty())
    };
    match host {
        HookHost::Cursor => named("conversation_id").or_else(|| named("session_id")),
        _ => named("session_id"),
    }
}

/// Whether a session start of `host` goes on from turns that ran before it.
/// Cursor runs `sessionStart` only when a conversation is created
/// (cursor.com/docs/agent/hooks), so its starts never do. Any other host's
/// does unless its `source` names a new session: `startup` or `clear` (Claude
/// Code, Codex), `startup` or `new` (Copilot); a resume, a compaction, or no
/// `source` named, goes on.
fn resumed(host: HookHost, event: &Map<String, Value>) -> bool {
    host != HookHost::Cursor
        && !matches!(
            event.get("source").and_then(Value::as_str),
            Some("startup" | "clear" | "new")
        )
}

/// The turns a start of `host`'s session goes on from: the session's own
/// when it is [`resumed`]; for a Codex start of a new session, what its
/// rollout begins with ([`codex_rollout_start`]); else none.
fn earlier_turns(host: HookHost, event: &Map<String, Value>) -> EarlierTurns {
    if resumed(host, event) {
        return EarlierTurns::Own;
    }
    match host {
        HookHost::Codex => codex_rollout_start(event),
        _ => EarlierTurns::None,
    }
}

/// The turns a Codex rollout at the event's `transcript_path` begins with.
/// Codex starts a fork (`codex fork`, `/fork`, `/side`, an edited earlier
/// prompt, a changed folder) with `source` `startup` and names no parent in
/// the event, but before the hook runs it writes the fork's rollout: its own
/// `session_meta` line first, naming the session it was forked from as
/// `forked_from_id`, then a copy of that session's turns. Codex writes a
/// session's rollout, its own meta first, before the hook gets its path
/// (`hook_transcript_path`), so a rollout not named is no local log and
/// holds no turn. A named one not there, empty, or whose first line is not
/// the session's own whole `session_meta` (an object payload whose `id` is
/// the event's `session_id` and whose `forked_from_id` is absent, null or a
/// session id, as Codex's own meta type reads it) holds turns the start
/// cannot tell the session of (REVIEW-9973).
fn codex_rollout_start(event: &Map<String, Value>) -> EarlierTurns {
    let Some(rollout) = event
        .get("transcript_path")
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
    else {
        return EarlierTurns::None;
    };
    // Not blocking on a FIFO named in place of the rollout.
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(rollout)
    {
        Ok(file) => file,
        Err(_) => return EarlierTurns::Own,
    };
    if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
        return EarlierTurns::Own;
    }
    let mut line = Vec::new();
    if BufReader::new(file.take(MAX_ROLLOUT_META_BYTES))
        .read_until(b'\n', &mut line)
        .is_err()
    {
        return EarlierTurns::Own;
    }
    let Ok(meta) = serde_json::from_slice::<Value>(&line) else {
        return EarlierTurns::Own;
    };
    let session = event.get("session_id").and_then(Value::as_str);
    let payload = meta
        .get("payload")
        .and_then(Value::as_object)
        .filter(|_| meta.get("type").and_then(Value::as_str) == Some("session_meta"))
        .filter(|payload| {
            session.is_some() && payload.get("id").and_then(Value::as_str) == session
        });
    match payload.map(|payload| payload.get("forked_from_id")) {
        Some(None | Some(Value::Null)) => EarlierTurns::None,
        Some(Some(Value::String(parent))) if !parent.is_empty() => {
            EarlierTurns::CopiedFrom(parent.clone())
        }
        _ => EarlierTurns::Own,
    }
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
