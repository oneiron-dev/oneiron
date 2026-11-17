//! The session `oneiron continue --cloud` sends: one Claude Code session log
//! and its subagents' logs, each gzip-compressed in standard base64, as
//! `vault.imports.hook_transcript` takes them.
//!
//! The log is the one `--transcript` names, as the hook's `transcript_path`
//! does, or else the newest session log of the project folder Claude Code
//! keeps for the working directory (or the nearest parent that has one):
//! `<config>/projects/<path with each character that is not an ASCII letter
//! or digit as '-'>/<session id>.jsonl`, where `<config>` is
//! `$CLAUDE_CONFIG_DIR` or `~/.claude`. Its subagents' logs are
//! `<session id>/subagents/agent-*.jsonl` beside it.

use std::io::Write as _;
use std::path::{Path, PathBuf};

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
/// its subagents' logs.
pub(super) fn read(named: Option<&Path>, dir: &Path) -> anyhow::Result<SessionLogs> {
    let path = match named {
        Some(path) => path.to_path_buf(),
        None => newest_session(dir)?,
    };
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

/// The newest session log of the project folder Claude Code keeps for `dir`
/// or its nearest parent that has one.
fn newest_session(dir: &Path) -> anyhow::Result<PathBuf> {
    let projects = claude_config_dir()?.join("projects");
    for folder in dir
        .ancestors()
        .map(|path| projects.join(project_folder_name(path)))
    {
        let Ok(entries) = std::fs::read_dir(&folder) else {
            continue;
        };
        let newest = entries
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
            .max_by_key(|(modified, _)| *modified);
        if let Some((_, path)) = newest {
            return Ok(path);
        }
    }
    anyhow::bail!(
        "no Claude Code session log was found for {} under {}; name one with --transcript <path>",
        dir.display(),
        projects.display()
    )
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

/// `path`'s bytes, gzip-compressed, in standard base64.
fn encoded(path: &Path) -> anyhow::Result<String> {
    let bytes =
        std::fs::read(path).map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))?;
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&bytes)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(gzip.finish()?))
}
