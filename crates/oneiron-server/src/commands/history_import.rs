//! `oneiron import <source> <path>`: the owner's own history, imported into a
//! stopped vault (ARCH-0027).
//!
//! This is the host's half. It reads only under the path it was given and
//! follows no symbolic link there; the engine decodes each file and lands each
//! conversation ([`oneiron::Vault::import_history`]). Holding the vault's writer
//! lease is the owner proof, as for every local owner command. The output is
//! one JSON document of counts on stdout: conversation ids and numbers, never
//! message text or titles.

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Instant;

use oneiron::consent::AuthenticatedOwner;
use oneiron::ingest::history::{
    HistoryConversation, HistoryDryRun, HistoryFile, HistoryImportReport, HistoryLedgerSnapshot,
    HistorySkips, HistorySource,
};
use serde::Serialize;

use crate::cli::ImportSourceArgs;
use crate::config::{ServeConfig, resolve_serve_config};

/// How far below the given path a history walk looks. A Claude Code subagent
/// log sits four below `~/.claude/projects`.
const MAX_WALK_DEPTH: usize = 6;

/// The largest file read whole: a session log, or an export's
/// `conversations.json` (inside its zip, too).
const MAX_FILE_BYTES: u64 = 4 << 30;

/// An export keeps its conversations in this file.
const EXPORT_CONVERSATIONS: &str = "conversations.json";

/// The files an import read, and the other `.jsonl` files it passed over
/// under the given folder (a workflow journal, a tool's prompt history).
#[derive(Serialize, Clone, Copy)]
struct Files {
    read: usize,
    passed: usize,
}

#[derive(Serialize, Default)]
struct Totals {
    conversations: usize,
    messages: u64,
    new: u64,
    skipped: u64,
    changed: u64,
    refused: u64,
    not_kept: HistorySkips,
}

#[derive(Serialize)]
struct ImportOutcome<'a> {
    source: &'static str,
    path: &'a Path,
    dry_run: bool,
    files: Files,
    totals: Totals,
    /// Messages of this source the vault's import ledger holds afterwards.
    ledger: usize,
    seconds: f64,
    conversations: Vec<HistoryImportReport>,
}

/// `oneiron import <source> <path> [--dry-run]`.
pub(super) fn import_history(source: HistorySource, args: ImportSourceArgs) -> anyhow::Result<()> {
    let ImportSourceArgs {
        path,
        dry_run,
        serve,
    } = args;
    let config = resolve_serve_config(&serve)?;
    let started = Instant::now();
    let (files, mut conversations) = decode(source, &path)?;
    // Earliest first, so a session's own lines land in it before a resumed
    // or forked session's copies of them are seen. A resumed Claude Code
    // session starts with copies of the original's lines, times and all; the
    // original ends first.
    conversations.sort_by_cached_key(|conversation| {
        let ended = conversation
            .messages
            .iter()
            .filter_map(|message| message.at_ms)
            .max();
        (
            conversation.started_at_ms.unwrap_or(u64::MAX),
            ended.unwrap_or(u64::MAX),
            conversation.native_id.clone(),
        )
    });
    progress(&format!(
        "read {} file(s): {} conversation(s)",
        files.read,
        conversations.len()
    ));

    let mut target = if dry_run {
        Target::Plan(open_snapshot(&config)?, HistoryDryRun::default())
    } else {
        let vault = open_vault(&config)?;
        let owner = crate::owner::local_owner(&vault)?;
        let imported_at = vault.now_recorded_at();
        Target::Land(Box::new((vault, owner, imported_at)))
    };
    let mut totals = Totals::default();
    let mut reports = Vec::with_capacity(conversations.len());
    for (done, conversation) in conversations.iter().enumerate() {
        let report = match &mut target {
            Target::Plan(snapshot, state) => snapshot.plan(source, conversation, state)?,
            Target::Land(landing) => {
                let (vault, owner, imported_at) = &**landing;
                vault
                    .import_history(owner, source, conversation, *imported_at)
                    .map_err(|error| anyhow::anyhow!("import stopped: {error}"))?
            }
        };
        totals.conversations += 1;
        totals.messages += u64::from(report.messages);
        totals.new += u64::from(report.new);
        totals.skipped += u64::from(report.skipped);
        totals.changed += u64::from(report.changed);
        totals.refused += u64::from(report.refused);
        totals.not_kept.add(&report.not_kept);
        reports.push(report);
        if (done + 1) % 100 == 0 {
            progress(&format!(
                "{} of {} conversations",
                done + 1,
                conversations.len()
            ));
        }
    }
    let outcome = ImportOutcome {
        source: source.source_id(),
        path: &path,
        dry_run,
        files,
        totals,
        ledger: match &target {
            Target::Plan(snapshot, _) => snapshot.ledger_len(source)?,
            Target::Land(landing) => landing.0.history_import_ledger_len(source)?,
        },
        seconds: started.elapsed().as_secs_f64(),
        conversations: reports,
    };
    let mut stdout = io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, &outcome)?;
    writeln!(stdout)?;
    Ok(())
}

/// Where conversations go: planned against a read-only ledger, or landed.
enum Target {
    Plan(HistoryLedgerSnapshot, HistoryDryRun),
    Land(Box<(oneiron::Vault, AuthenticatedOwner, u64)>),
}

/// The vault's ledger for a dry run, opened read-only: the vault itself is
/// never opened, so nothing in it is written, and a running `serve` is fine.
fn open_snapshot(config: &ServeConfig) -> anyhow::Result<HistoryLedgerSnapshot> {
    let path = &config.vault_path;
    anyhow::ensure!(
        path.join("data.mdb").is_file(),
        "vault {} does not exist; `oneiron init` creates one",
        path.display()
    );
    HistoryLedgerSnapshot::open(path)
        .map_err(|error| anyhow::anyhow!("read vault {}: {error}", path.display()))
}

fn progress(line: &str) {
    let _ = writeln!(io::stderr().lock(), "oneiron import: {line}");
}

/// Reads and decodes everything under `path`: one export file, or every
/// session log beneath a folder.
fn decode(source: HistorySource, path: &Path) -> anyhow::Result<(Files, Vec<HistoryConversation>)> {
    let decode_one = |text: &str, file: &HistoryFile, shown: &Path| {
        source
            .decode(text, file)
            .map_err(|error| anyhow::anyhow!("{}: {error}", shown.display()))
    };
    if matches!(source, HistorySource::Chatgpt | HistorySource::Claude) {
        let text = read_export(path)?;
        let file = HistoryFile {
            stem: EXPORT_CONVERSATIONS.to_owned(),
            parent: None,
        };
        return Ok((
            Files { read: 1, passed: 0 },
            decode_one(&text, &file, path)?,
        ));
    }
    let metadata = std::fs::metadata(path)
        .map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))?;
    if !metadata.is_dir() {
        // One log the person named.
        let file = File::open(path)
            .map_err(|error| anyhow::anyhow!("open {}: {error}", path.display()))?;
        let text = read_limited(file, path)?;
        let conversations = decode_one(&text, &history_file(source, path), path)?;
        return Ok((Files { read: 1, passed: 0 }, conversations));
    }
    let mut files = Files { read: 0, passed: 0 };
    let mut conversations = Vec::new();
    // Given the tool's whole home, only its history folder is read, never its
    // settings, prompt history or caches.
    let history = match source {
        HistorySource::ClaudeCode => "projects",
        _ => "sessions",
    };
    walk_logs(path, history, &mut |shown: &Path, file: File| {
        if !session_log_name(source, shown) {
            files.passed += 1;
            return Ok(());
        }
        let text = read_limited(file, shown)?;
        conversations.extend(decode_one(&text, &history_file(source, shown), shown)?);
        files.read += 1;
        Ok(())
    })?;
    Ok((files, conversations))
}

#[cfg(unix)]
mod confined;
#[cfg(unix)]
use confined::{open_in, walk_logs};

#[cfg(not(unix))]
fn walk_logs(
    path: &Path,
    _history: &str,
    _visit: &mut dyn FnMut(&Path, File) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    anyhow::bail!(
        "importing a folder ({}) needs a unix host; give one session log",
        path.display()
    )
}

#[cfg(not(unix))]
fn open_in(dir: &Path, name: &str) -> anyhow::Result<Option<File>> {
    let path = dir.join(name);
    Ok(std::fs::symlink_metadata(&path)
        .ok()
        .filter(std::fs::Metadata::is_file)
        .map(|_| File::open(&path))
        .transpose()?)
}

/// An export's conversations: the zip, its `conversations.json`, or the
/// unzipped folder holding it.
fn read_export(path: &Path) -> anyhow::Result<String> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))?;
    if metadata.is_dir() {
        let file = open_in(path, EXPORT_CONVERSATIONS)?
            .ok_or_else(|| anyhow::anyhow!("{} holds no {EXPORT_CONVERSATIONS}", path.display()))?;
        return read_limited(file, &path.join(EXPORT_CONVERSATIONS));
    }
    let zipped = path
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("zip"));
    if zipped {
        read_zipped_export(path)
    } else {
        let file = File::open(path)
            .map_err(|error| anyhow::anyhow!("open {}: {error}", path.display()))?;
        read_limited(file, path)
    }
}

/// The shallowest `conversations.json` inside an export zip.
fn read_zipped_export(path: &Path) -> anyhow::Result<String> {
    let file =
        File::open(path).map_err(|error| anyhow::anyhow!("open {}: {error}", path.display()))?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|error| anyhow::anyhow!("{} is not a readable zip: {error}", path.display()))?;
    let mut best: Option<(usize, usize)> = None;
    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        let Some(name) = entry.enclosed_name() else {
            continue;
        };
        if name
            .file_name()
            .is_some_and(|name| name == EXPORT_CONVERSATIONS)
        {
            let depth = name.components().count();
            if best.is_none_or(|(_, best_depth)| depth < best_depth) {
                best = Some((index, depth));
            }
        }
    }
    let (index, _) =
        best.ok_or_else(|| anyhow::anyhow!("{} holds no {EXPORT_CONVERSATIONS}", path.display()))?;
    let entry = archive.by_index(index)?;
    anyhow::ensure!(
        entry.size() <= MAX_FILE_BYTES,
        "{EXPORT_CONVERSATIONS} in {} is larger than {MAX_FILE_BYTES} bytes",
        path.display()
    );
    read_limited(entry, path)
}

/// Reads at most [`MAX_FILE_BYTES`], whatever a header claimed.
fn read_limited(reader: impl Read, path: &Path) -> anyhow::Result<String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))?;
    anyhow::ensure!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= MAX_FILE_BYTES,
        "{} is larger than {MAX_FILE_BYTES} bytes",
        path.display()
    );
    Ok(String::from_utf8(bytes)
        .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned()))
}

/// The session a Claude Code subagent log ran in: the folder above the
/// `subagents` folder it sits under (directly, or in a workflow run's folder).
fn subagent_session(log: &Path) -> Option<String> {
    let subagents = log
        .ancestors()
        .skip(1)
        .find(|dir| dir.file_name().is_some_and(|name| name == "subagents"))?;
    subagents
        .parent()
        .and_then(Path::file_name)
        .map(|session| session.to_string_lossy().into_owned())
}

/// The names the tools give their session logs: a Claude Code session id or a
/// subagent's `agent-<id>` (under `<session>/subagents/`, or beside the
/// sessions in older releases), a Codex `rollout-<time>-<id>`.
fn session_log_name(source: HistorySource, log: &Path) -> bool {
    let Some(name) = log.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    match source {
        HistorySource::ClaudeCode => {
            let stem = name.trim_end_matches(".jsonl");
            stem.starts_with("agent-")
                || (stem.len() == 36 && stem.chars().all(|c| c.is_ascii_hexdigit() || c == '-'))
        }
        _ => name.starts_with("rollout-"),
    }
}

/// A Claude Code log under `<session>/subagents/` is that session's subagent.
fn history_file(source: HistorySource, log: &Path) -> HistoryFile {
    let stem = log
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_default();
    let parent = (source == HistorySource::ClaudeCode)
        .then(|| subagent_session(log))
        .flatten();
    HistoryFile { stem, parent }
}

/// Opens the configured, existing vault; a running `serve` holds it.
fn open_vault(config: &ServeConfig) -> anyhow::Result<oneiron::Vault> {
    let path = &config.vault_path;
    anyhow::ensure!(
        path.join("data.mdb").is_file(),
        "vault {} does not exist; `oneiron init` creates one",
        path.display()
    );
    let mut vault_config = config.vault_config();
    vault_config.dict_search_paths =
        super::resolve_dict_search_paths(&config.dict_search_paths).paths;
    oneiron::Vault::open_owned(path, vault_config).map_err(|error| match error {
        oneiron::Error::ConcurrentWrite(oneiron::VAULT_WRITER_LEASE_HELD) => anyhow::anyhow!(
            "vault {} is open in a running `oneiron serve`; stop it, then import",
            path.display()
        ),
        error => anyhow::anyhow!("open vault {}: {error}", path.display()),
    })
}
