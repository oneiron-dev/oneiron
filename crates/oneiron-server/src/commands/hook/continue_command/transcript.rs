//! The session `oneiron continue --cloud` sends: one Claude Code session log
//! and its subagents' logs, each gzip-compressed in standard base64, as
//! `vault.imports.hook_transcript` takes them. The hooks' hand-over to a
//! selected hosted vault sends the log its event names the same way
//! ([`read_hook_log`]).
//!
//! The log is the one `--transcript` names, as the hook's `transcript_path`
//! does, or else the newest session log of the project folder Claude Code
//! keeps for the working directory (or the nearest parent inside the repo
//! that has one) whose recorded working directory git places in this repo:
//! `<config>/projects/<path with each character that is not an ASCII letter
//! or digit as '-'>/<session id>.jsonl`, where `<config>` is
//! `$CLAUDE_CONFIG_DIR` or `~/.claude`. A log of a folder above the repo, of
//! a repo nested in it, or of another repo whose path folds to the same
//! name, is never sent. Its subagents' logs are the `agent-*.jsonl` files
//! anywhere under `<session id>/subagents/` beside it, a workflow run's
//! folder included.
//!
//! Below `<config>/projects` (below the folder of a log the person names,
//! whose path is theirs to follow), every folder on the way to the log, the
//! session's folder beside it, and every folder and log under that, is
//! opened relative to the one above and never through a link, as the local
//! import's drain reads a queued session; a link there is passed over, so
//! nothing outside the session's own folders is sent. Finding the newest
//! log passes over a project folder or a log that is a link the same way.
//! Each log is read through one descriptor, opened without blocking and
//! checked to be a regular file, so a FIFO or device at the path, even one
//! put there after it was listed, never blocks the command. A log with a
//! line that is not a whole JSON record (the last one cut mid-write, say) is
//! not sent: the importer would land the rest without it.
//!
//! The logs go in calls the selection's carrier takes ([`calls_within`]).

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{BufRead as _, Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime};

use base64::Engine as _;
use oneiron::ingest::history::{
    HOOK_TRANSCRIPT_MAX_BYTES, HOOK_TRANSCRIPT_MAX_SUBAGENTS, HookSubagentTranscript,
    HookTranscriptImportRequest,
};
use rustix::fs::{CWD, Dir, Mode, OFlags, openat};

use crate::commands::hook::hosted_selection::HostedAuthMode;
use crate::commands::mcp_bridge;
use crate::files_intake::confined;

/// A session log, read and encoded.
pub(super) struct SessionLogs {
    /// The session's own log.
    pub(super) path: PathBuf,
    pub(super) request: HookTranscriptImportRequest,
    /// The session log's length in bytes, as the vault inflates it.
    log_bytes: usize,
    /// Each subagent log's length in bytes, as the vault inflates it, in
    /// the request's order.
    subagent_bytes: Vec<usize>,
}

/// The session log `named`, else the newest of `dir`'s project folder, and
/// its subagents' logs. The git that finds the repo ends by `deadline`.
pub(super) fn read(
    named: Option<&Path>,
    dir: &Path,
    deadline: Instant,
) -> anyhow::Result<SessionLogs> {
    let Some(named) = named else {
        let projects = projects_dir()?;
        let path = newest_session(&projects, dir, deadline)?;
        return read_below(&projects, &path);
    };
    // The path the person names is theirs to follow, as in any path typed;
    // nothing below the log's own folder is.
    let real = std::fs::canonicalize(named)
        .map_err(|error| anyhow::anyhow!("read {}: {error}", named.display()))?;
    let folder = real.parent().ok_or_else(|| not_a_session_log(named))?;
    let mut logs = read_below(folder, &real)?;
    logs.path = named.to_path_buf();
    Ok(logs)
}

/// The hooks' hand-over: the session log at `path`, which a Claude Code
/// event of the session `session` names, and its subagents' logs. The log
/// must be that session's own (`<session>.jsonl`), so an event never sends
/// another session's log where its own session's starts bound, and must sit
/// below Claude Code's `projects` folder, as a queued log must sit below
/// the local import's root.
pub(super) fn read_hook_log(path: &Path, session: &str) -> anyhow::Result<SessionLogs> {
    anyhow::ensure!(
        path.file_name() == Some(OsStr::new(&format!("{session}.jsonl"))),
        "{} is not the log of session {session}, whose event named it",
        path.display()
    );
    read_below(&projects_dir()?, path)
}

/// The calls that land `logs`: each spec at most `carried` bytes, as the
/// selection's carrier takes one call, and its logs at most
/// [`HOOK_TRANSCRIPT_MAX_BYTES`] inflated, as the vault takes one. The
/// session's log goes with all its subagents' logs in one call where they
/// fit, else with them shared out in order over several calls, each with
/// the session's log again, which the import lands once. A session's log
/// too long for a call by itself, or with any one of its subagents' logs,
/// is refused before anything is sent, so no call goes that could never
/// land.
pub(super) fn calls_within(
    logs: &SessionLogs,
    carried: usize,
) -> anyhow::Result<Vec<HookTranscriptImportRequest>> {
    let alone = HookTranscriptImportRequest {
        session: logs.request.session.clone(),
        transcript_gzip_base64: logs.request.transcript_gzip_base64.clone(),
        subagents: Vec::new(),
    };
    let base = serde_json::to_vec(&alone)?.len();
    let fits =
        |bytes: usize, inflated: usize| bytes <= carried && inflated <= HOOK_TRANSCRIPT_MAX_BYTES;
    anyhow::ensure!(
        fits(base, logs.log_bytes),
        "{} is too long for one call to the hosted vault over this sign-in (at most {carried} \
         bytes encoded and {HOOK_TRANSCRIPT_MAX_BYTES} inflated); import the session on the \
         machine it ran on: oneiron import claude-code {}",
        logs.path.display(),
        logs.path.display()
    );
    let mut calls = Vec::new();
    let mut batch = Vec::new();
    let (mut bytes, mut inflated) = (base, logs.log_bytes);
    for (subagent, &raw) in logs.request.subagents.iter().zip(&logs.subagent_bytes) {
        // Its entry and the comma before it.
        let entry = serde_json::to_vec(subagent)?.len() + 1;
        anyhow::ensure!(
            fits(base + entry, logs.log_bytes + raw),
            "{}'s subagent log {} is too long to go with it in one call to the hosted vault \
             over this sign-in (at most {carried} bytes encoded and {HOOK_TRANSCRIPT_MAX_BYTES} \
             inflated); import the session on the machine it ran on: oneiron import \
             claude-code {}",
            logs.path.display(),
            subagent.stem,
            logs.path.display()
        );
        if !fits(bytes + entry, inflated + raw) {
            calls.push(HookTranscriptImportRequest {
                subagents: std::mem::take(&mut batch),
                ..alone.clone()
            });
            (bytes, inflated) = (base, logs.log_bytes);
        }
        batch.push(subagent.clone());
        bytes += entry;
        inflated += raw;
    }
    calls.push(HookTranscriptImportRequest {
        subagents: batch,
        ..alone
    });
    Ok(calls)
}

/// What `oneiron mcp` adds to a call's spec on the way: the JSON-RPC line
/// around it, the `_meta` the bridge adds, and the socket's frame.
const CALL_ENVELOPE_BYTES: usize = 16 * 1024;

/// The longest spec one call carries for a selection signed in in `mode`.
/// The owner's calls go over the vault's socket alone, so within its frame;
/// any other's go over HTTP past the socket's frame, so within the longest
/// line `oneiron mcp` reads.
pub(super) fn carried_bytes(mode: HostedAuthMode) -> usize {
    let line = match mode {
        HostedAuthMode::Owner => mcp_bridge::SOCKET_MAX_OUTBOUND_FRAME,
        HostedAuthMode::Slip | HostedAuthMode::OAuth => mcp_bridge::MAX_FRAME_BYTES,
    };
    line - CALL_ENVELOPE_BYTES
}

/// The session log at `path`, below `root`, and its subagents' logs, read
/// and encoded, every folder and log below `root` opened through no link
/// ([`confined`]).
fn read_below(root: &Path, path: &Path) -> anyhow::Result<SessionLogs> {
    let session = path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".jsonl"))
        .filter(|stem| session_id(stem))
        .ok_or_else(|| not_a_session_log(path))?
        .to_owned();
    let relative = path.strip_prefix(root).map_err(|_| {
        anyhow::anyhow!(
            "{} is not under {}, where Claude Code keeps its session logs",
            path.display(),
            root.display()
        )
    })?;
    let (folder, session_log) = confined::open_below(root, relative)?;
    let (transcript_gzip_base64, log_bytes) = encoded(session_log, path)?;
    let (subagents, subagent_bytes) = match confined::open_dir_in(&folder, OsStr::new(&session))? {
        Some(own) => subagent_logs(&own, &path.with_extension(""))?,
        None => (Vec::new(), Vec::new()),
    };
    Ok(SessionLogs {
        path: path.to_path_buf(),
        request: HookTranscriptImportRequest {
            session,
            transcript_gzip_base64,
            subagents,
        },
        log_bytes,
        subagent_bytes,
    })
}

/// The subagents' logs of the session whose folder is open at `own`, shown
/// as `shown`: every `agent-*.jsonl` anywhere under its `subagents` folder,
/// in name order, a workflow run's folder included, each with its length
/// before it was encoded; none when it has no such folder.
fn subagent_logs(
    own: &OwnedFd,
    shown: &Path,
) -> anyhow::Result<(Vec<HookSubagentTranscript>, Vec<usize>)> {
    let Some(folder) = confined::open_dir_in(own, OsStr::new("subagents"))? else {
        return Ok((Vec::new(), Vec::new()));
    };
    let shown = shown.join("subagents");
    let mut logs: Vec<HookSubagentTranscript> = Vec::new();
    let mut lengths: Vec<usize> = Vec::new();
    let mut visit = |log: &Path, file: File| -> anyhow::Result<()> {
        let Some(stem) = log
            .file_stem()
            .and_then(OsStr::to_str)
            .filter(|stem| subagent_stem(stem))
        else {
            return Ok(());
        };
        anyhow::ensure!(
            logs.len() < HOOK_TRANSCRIPT_MAX_SUBAGENTS,
            "{} holds more than the {HOOK_TRANSCRIPT_MAX_SUBAGENTS} subagent logs one call carries",
            shown.display()
        );
        anyhow::ensure!(
            !logs.iter().any(|sent| sent.stem == stem),
            "two subagent logs under {} are named {stem}.jsonl, and the vault takes one",
            shown.display()
        );
        let (transcript_gzip_base64, length) = encoded(file, log)?;
        logs.push(HookSubagentTranscript {
            stem: stem.to_owned(),
            transcript_gzip_base64,
        });
        lengths.push(length);
        Ok(())
    };
    confined::walk(&folder, &shown, confined::LOGS, &mut visit)?;
    Ok((logs, lengths))
}

/// The refusal of a log at `path` not named as a session's own.
fn not_a_session_log(path: &Path) -> anyhow::Error {
    anyhow::anyhow!(
        "{} is not a Claude Code session log (<session id>.jsonl)",
        path.display()
    )
}

/// The newest session log under `projects` of the project folder Claude
/// Code keeps for `dir` or its nearest parent inside the repo that has one,
/// among the logs whose recorded working directory git places in this repo
/// ([`in_repo`]). Below `projects`, a project folder or a log that is a link
/// is passed over and the search goes on, as reading it would refuse it
/// ([`confined`]).
pub(super) fn newest_session(
    projects: &Path,
    dir: &Path,
    deadline: Instant,
) -> anyhow::Result<PathBuf> {
    let dir = std::fs::canonicalize(dir)?;
    let top = std::fs::canonicalize(super::hand_off::repo_top(&dir, deadline)?)?;
    // `projects` is in the person's config folder, theirs to reach through a
    // link; nothing below it is.
    let root = openat(
        CWD,
        projects,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .ok();
    for name in dir
        .ancestors()
        .take_while(|path| path.starts_with(&top))
        .map(project_folder_name)
    {
        let Some(folder) = root.as_ref().and_then(|root| {
            confined::open_dir_in(root, OsStr::new(&name))
                .ok()
                .flatten()
        }) else {
            continue;
        };
        let shown = projects.join(&name);
        let mut logs = session_logs_in(&folder, &shown);
        logs.sort_by_key(|(modified, _)| std::cmp::Reverse(*modified));
        for (_, log) in logs {
            let path = shown.join(&log);
            let Ok(file) = confined::open_file(&folder, &log, &path) else {
                continue;
            };
            if recorded_dir(file).is_some_and(|recorded| in_repo(&recorded, &top, deadline)) {
                return Ok(path);
            }
        }
    }
    anyhow::bail!(
        "no Claude Code session log of the repo at {} was found under {}; name one with \
         --transcript <path>",
        top.display(),
        projects.display()
    )
}

/// The session logs in the open project folder `folder`, shown as `shown`:
/// each regular file there named `<session id>.jsonl`, never a link, with
/// when it was last written.
fn session_logs_in(folder: &OwnedFd, shown: &Path) -> Vec<(SystemTime, OsString)> {
    let Ok(entries) = Dir::read_from(folder) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = OsStr::from_bytes(entry.file_name().to_bytes()).to_owned();
            let session_log = name
                .to_str()
                .and_then(|name| name.strip_suffix(".jsonl"))
                .is_some_and(session_id);
            if !session_log {
                return None;
            }
            let file = confined::open_file(folder, &name, &shown.join(&name)).ok()?;
            let modified = file.metadata().ok()?.modified().ok()?;
            Some((modified, name))
        })
        .collect()
}

/// Whether git's top directory for `dir` is `top` itself: `dir` is in this
/// repo, not in a repo nested inside it or beside it. A directory that no
/// longer exists, or that is in no repo, is not.
fn in_repo(dir: &Path, top: &Path, deadline: Instant) -> bool {
    super::hand_off::repo_top(dir, deadline)
        .ok()
        .and_then(|found| std::fs::canonicalize(found).ok())
        .is_some_and(|found| found == top)
}

/// The working directory the session log `log` records, from its first
/// entry that names one (`cwd`); `None` when no entry names one or the log
/// cannot be read.
fn recorded_dir(log: File) -> Option<PathBuf> {
    let lines = std::io::BufReader::new(log).lines();
    for line in lines {
        let line = line.ok()?;
        if !line.contains("\"cwd\"") {
            continue;
        }
        let Ok(entry) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        if let Some(cwd) = entry.get("cwd").and_then(serde_json::Value::as_str) {
            return Some(PathBuf::from(cwd));
        }
    }
    None
}

/// Claude Code's folder of project folders, in its config folder.
fn projects_dir() -> anyhow::Result<PathBuf> {
    Ok(claude_config_dir()?.join("projects"))
}

/// Claude Code's config folder: `$CLAUDE_CONFIG_DIR`, else `~/.claude`.
fn claude_config_dir() -> anyhow::Result<PathBuf> {
    if let Some(dir) = std::env::var_os("CLAUDE_CONFIG_DIR").filter(|dir| !dir.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("HOME is not set; name the session log with --transcript")
        })?;
    Ok(PathBuf::from(home).join(".claude"))
}

/// The name of the folder Claude Code keeps a working directory's sessions
/// in: its path with each character that is not an ASCII letter or digit as
/// `-`.
fn project_folder_name(dir: &Path) -> String {
    dir.to_string_lossy()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

/// Whether `stem` names a subagent's log: `agent-<id>`.
fn subagent_stem(stem: &str) -> bool {
    stem.len() > "agent-".len() && stem.starts_with("agent-")
}

/// A session id as Claude Code names its logs: 36 hex digits and dashes.
fn session_id(stem: &str) -> bool {
    stem.len() == 36 && stem.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// The bytes of the log `file`, shown as `path`, gzip-compressed, in
/// standard base64, once every record of them is whole ([`whole_records`]),
/// and how many there were.
fn encoded(mut file: File, path: &Path) -> anyhow::Result<(String, usize)> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))?;
    whole_records(path, &bytes)?;
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&bytes)?;
    let text = base64::engine::general_purpose::STANDARD.encode(gzip.finish()?);
    Ok((text, bytes.len()))
}

/// Refuses a log with a line that is not a whole JSON record as the
/// importer reads one: a JSON object on each line that is not blank, in the
/// text the importer decodes (invalid UTF-8 replaced). The last record of a
/// log being written can be cut mid-write, and the importer would count it
/// unreadable and land the rest, so the session would go on without it.
fn whole_records(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let text = String::from_utf8_lossy(bytes);
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let whole =
            serde_json::from_str::<serde_json::Value>(line).is_ok_and(|record| record.is_object());
        anyhow::ensure!(
            whole,
            "line {} of {} is not a whole JSON record (one cut mid-write, say), so the session \
             cannot go on whole elsewhere; let its turn end, then run the command again",
            index + 1,
            path.display()
        );
    }
    Ok(())
}
