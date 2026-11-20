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
//! nothing outside the session's own folders is sent. Each log is read
//! through one descriptor, opened without blocking and checked to be a
//! regular file, so a FIFO or device at the path, even one put there after
//! it was listed, never blocks the command. A log with a line that is not a
//! whole JSON record (the last one cut mid-write, say) is not sent: the
//! importer would land the rest without it.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufRead as _, Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Instant;

use base64::Engine as _;
use oneiron::ingest::history::{
    HOOK_TRANSCRIPT_MAX_SUBAGENTS, HookSubagentTranscript, HookTranscriptImportRequest,
};

use crate::files_intake::confined;

/// A session log, read and encoded.
pub(super) struct SessionLogs {
    /// The session's own log.
    pub(super) path: PathBuf,
    pub(super) request: HookTranscriptImportRequest,
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
/// event names, and its subagents' logs. The log must sit below Claude
/// Code's `projects` folder, as a queued log must sit below the local
/// import's root.
pub(super) fn read_hook_log(path: &Path) -> anyhow::Result<SessionLogs> {
    read_below(&projects_dir()?, path)
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
    let transcript_gzip_base64 = encoded(session_log, path)?;
    let subagents = match confined::open_dir_in(&folder, OsStr::new(&session))? {
        Some(own) => subagent_logs(&own, &path.with_extension(""))?,
        None => Vec::new(),
    };
    Ok(SessionLogs {
        path: path.to_path_buf(),
        request: HookTranscriptImportRequest {
            session,
            transcript_gzip_base64,
            subagents,
        },
    })
}

/// The subagents' logs of the session whose folder is open at `own`, shown
/// as `shown`: every `agent-*.jsonl` anywhere under its `subagents` folder,
/// in name order, a workflow run's folder included; none when it has no
/// such folder.
fn subagent_logs(own: &OwnedFd, shown: &Path) -> anyhow::Result<Vec<HookSubagentTranscript>> {
    let Some(folder) = confined::open_dir_in(own, OsStr::new("subagents"))? else {
        return Ok(Vec::new());
    };
    let shown = shown.join("subagents");
    let mut logs: Vec<HookSubagentTranscript> = Vec::new();
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
        logs.push(HookSubagentTranscript {
            stem: stem.to_owned(),
            transcript_gzip_base64: encoded(file, log)?,
        });
        Ok(())
    };
    confined::walk(&folder, &shown, confined::LOGS, &mut visit)?;
    Ok(logs)
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
/// ([`in_repo`]).
pub(super) fn newest_session(
    projects: &Path,
    dir: &Path,
    deadline: Instant,
) -> anyhow::Result<PathBuf> {
    let dir = std::fs::canonicalize(dir)?;
    let top = std::fs::canonicalize(super::hand_off::repo_top(&dir, deadline)?)?;
    for folder in dir
        .ancestors()
        .take_while(|path| path.starts_with(&top))
        .map(|path| projects.join(project_folder_name(path)))
    {
        let Ok(entries) = std::fs::read_dir(&folder) else {
            continue;
        };
        let mut logs: Vec<_> = entries
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .and_then(|name| name.strip_suffix(".jsonl"))
                    .is_some_and(session_id)
            })
            .filter_map(|entry| {
                let modified = entry.metadata().ok()?.modified().ok()?;
                entry
                    .file_type()
                    .ok()?
                    .is_file()
                    .then(|| (modified, entry.path()))
            })
            .collect();
        logs.sort_by_key(|(modified, _)| std::cmp::Reverse(*modified));
        if let Some((_, path)) = logs.into_iter().find(|(_, path)| {
            recorded_dir(path).is_some_and(|recorded| in_repo(&recorded, &top, deadline))
        }) {
            return Ok(path);
        }
    }
    anyhow::bail!(
        "no Claude Code session log of the repo at {} was found under {}; name one with \
         --transcript <path>",
        top.display(),
        projects.display()
    )
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

/// The working directory a session log records, from its first entry that
/// names one (`cwd`); `None` when no entry names one or the log cannot be
/// read.
fn recorded_dir(log: &Path) -> Option<PathBuf> {
    let lines = std::io::BufReader::new(open_log(log).ok()?).lines();
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
/// standard base64, once every record of them is whole ([`whole_records`]).
fn encoded(mut file: File, path: &Path) -> anyhow::Result<String> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))?;
    whole_records(path, &bytes)?;
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&bytes)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(gzip.finish()?))
}

/// `path` opened for reading without blocking, once the open descriptor is
/// a regular file. Opening a FIFO with no writer would otherwise block, and
/// a check of the path before the open could see another file than the one
/// opened. A regular file reads the same either way.
fn open_log(path: &Path) -> anyhow::Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))?;
    let kind = file
        .metadata()
        .map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))?;
    anyhow::ensure!(
        kind.is_file(),
        "{} is not a regular file, so it is not a Claude Code session log",
        path.display()
    );
    Ok(file)
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
