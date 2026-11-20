//! The session `oneiron continue --cloud` sends: one Claude Code session log
//! and its subagents' logs, each gzip-compressed in standard base64, as
//! `vault.imports.hook_transcript` takes them. The hooks' hand-over to a
//! selected hosted vault sends the log its event names the same way
//! ([`read_log`]).
//!
//! The log is the one `--transcript` names, as the hook's `transcript_path`
//! does, or else the newest session log of the project folder Claude Code
//! keeps for the working directory (or the nearest parent inside the repo
//! that has one) whose recorded working directory git places in this repo:
//! `<config>/projects/<path with each character that is not an ASCII letter
//! or digit as '-'>/<session id>.jsonl`, where `<config>` is
//! `$CLAUDE_CONFIG_DIR` or `~/.claude`. A log of a folder above the repo, of
//! a repo nested in it, or of another repo whose path folds to the same
//! name, is never sent. Its subagents' logs are
//! `<session id>/subagents/agent-*.jsonl` beside it.
//!
//! Each log is read through one descriptor, opened without blocking and
//! checked to be a regular file, so a FIFO or device at the path, even one
//! put there after it was listed, never blocks the command. A log with a
//! line that is not a whole JSON record (the last one cut mid-write, say) is
//! not sent: the importer would land the rest without it.

use std::io::{BufRead as _, Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Instant;

use base64::Engine as _;
use oneiron::ingest::history::{
    HOOK_TRANSCRIPT_MAX_SUBAGENTS, HookSubagentTranscript, HookTranscriptImportRequest,
};

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
    let path = match named {
        Some(path) => path.to_path_buf(),
        None => newest_session(&claude_config_dir()?.join("projects"), dir, deadline)?,
    };
    read_log(path)
}

/// The session log at `path` and its subagents' logs, read and encoded.
pub(super) fn read_log(path: PathBuf) -> anyhow::Result<SessionLogs> {
    let session = path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".jsonl"))
        .filter(|stem| session_id(stem))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{} is not a Claude Code session log (<session id>.jsonl)",
                path.display()
            )
        })?
        .to_owned();
    let transcript_gzip_base64 = encoded(&path)?;
    let mut subagents = Vec::new();
    for log in subagent_logs(&path.with_extension("").join("subagents"))? {
        let stem = log
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or_default()
            .to_owned();
        subagents.push(HookSubagentTranscript {
            stem,
            transcript_gzip_base64: encoded(&log)?,
        });
    }
    Ok(SessionLogs {
        path,
        request: HookTranscriptImportRequest {
            session,
            transcript_gzip_base64,
            subagents,
        },
    })
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

/// The subagent logs in `folder`, by name; none when it does not exist.
fn subagent_logs(folder: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let entries = match std::fs::read_dir(folder) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => anyhow::bail!("read {}: {error}", folder.display()),
    };
    let mut logs: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_suffix(".jsonl"))
                .is_some_and(|stem| stem.len() > "agent-".len() && stem.starts_with("agent-"))
        })
        .collect();
    logs.sort();
    anyhow::ensure!(
        logs.len() <= HOOK_TRANSCRIPT_MAX_SUBAGENTS,
        "{} holds {} subagent logs, more than the {HOOK_TRANSCRIPT_MAX_SUBAGENTS} one call carries",
        folder.display(),
        logs.len()
    );
    Ok(logs)
}

/// A session id as Claude Code names its logs: 36 hex digits and dashes.
fn session_id(stem: &str) -> bool {
    stem.len() == 36 && stem.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// `path`'s bytes, gzip-compressed, in standard base64, once every record
/// of them is whole ([`whole_records`]).
fn encoded(path: &Path) -> anyhow::Result<String> {
    let mut bytes = Vec::new();
    open_log(path)?
        .read_to_end(&mut bytes)
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
