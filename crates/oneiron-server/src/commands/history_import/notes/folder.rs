//! `oneiron import folder attach|rescan|detach|list`: a folder of markdown
//! notes that stays attached to the vault (OF-554, ARCH-0027).
//!
//! `attach` is the owner's one act: it records the folder and lands its notes
//! as `import notes` would. From then on `oneiron serve` rescans every
//! attached folder every few minutes, starting when it starts, and `rescan`
//! does one by hand. A rescan reads the folder the way `import notes` reads
//! it, lands the new files, supersedes what changed files landed and
//! retracts (archives) the notes of files that left. Nothing is ever written
//! to the folder. `detach` stops the rescans; the notes stay.
//!
//! Stdout carries counts, never note text, titles or link targets.

use std::collections::{HashMap, HashSet};
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use oneiron::consent::AuthenticatedOwner;
use oneiron::note::{
    FolderFile, FolderFileState, FolderRescan, FolderRescanReport, FolderSource, ImportedFile,
    ImportedNote, ImportedNoteStanding,
};
use serde::Serialize;

use super::{MAX_FOLDER_BYTES, NoteCounts, TitleCounts};
use crate::cli::{ImportFolderAttachArgs, ImportFolderCommand};
use crate::config::{ServeConfig, resolve_serve_config};
use crate::server::SyncServer;

/// How often `oneiron serve` rescans the attached folders.
const RESCAN_TICK: Duration = Duration::from_secs(5 * 60);

#[derive(Serialize)]
struct Rescanned {
    folder: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    report: Option<FolderRescanReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct Listed {
    #[serde(flatten)]
    source: FolderSource,
    files: usize,
    retracted: usize,
    proposed: usize,
}

/// `oneiron import folder <attach|rescan|detach|list>`.
pub(in crate::commands) fn import_folder(command: ImportFolderCommand) -> anyhow::Result<()> {
    let mut stdout = io::stdout().lock();
    match command {
        ImportFolderCommand::Attach(args) => {
            let ImportFolderAttachArgs {
                path,
                include,
                kind,
                serve,
            } = *args;
            let folder = canonical_folder(&path)?;
            let vault = super::super::open_vault(&resolve_serve_config(&serve)?)?;
            let owner = crate::owner::local_owner(&vault)?;
            let source = vault.attach_folder_source(&owner, &folder, include, &kind)?;
            let rescanned = rescanned(&vault, &owner, &source);
            serde_json::to_writer_pretty(&mut stdout, &(&source, &rescanned))?;
        }
        ImportFolderCommand::Rescan(args) => {
            let vault = super::super::open_vault(&resolve_serve_config(&args.serve)?)?;
            let owner = crate::owner::local_owner(&vault)?;
            let sources = match &args.path {
                Some(path) => {
                    let folder = canonical_folder(path)?;
                    vec![vault.folder_source(&folder)?.ok_or_else(|| {
                        anyhow::anyhow!("{folder} is not attached; `import folder attach` it")
                    })?]
                }
                None => vault.folder_sources()?,
            };
            let rescanned = sources
                .iter()
                .map(|source| rescanned(&vault, &owner, source))
                .collect::<Vec<_>>();
            serde_json::to_writer_pretty(&mut stdout, &rescanned)?;
        }
        ImportFolderCommand::Detach(args) => {
            // A folder that is gone is detached by the name it was attached by.
            let folder = canonical_folder(&args.path)
                .unwrap_or_else(|_| args.path.to_string_lossy().into_owned());
            let vault = super::super::open_vault(&resolve_serve_config(&args.serve)?)?;
            let owner = crate::owner::local_owner(&vault)?;
            let detached = vault.detach_folder_source(&owner, &folder)?;
            anyhow::ensure!(detached, "{folder} is not attached");
            serde_json::to_writer_pretty(
                &mut stdout,
                &serde_json::json!({ "folder": folder, "detached": true }),
            )?;
        }
        ImportFolderCommand::List(args) => {
            let vault = super::super::open_vault(&resolve_serve_config(&args.serve)?)?;
            let listed = vault
                .folder_sources()?
                .into_iter()
                .map(|source| {
                    let files = vault.folder_source_files(&source.folder)?;
                    let count = |wanted: fn(&FolderFileState) -> bool| {
                        files.iter().filter(|file| wanted(&file.state)).count()
                    };
                    Ok(Listed {
                        retracted: count(|state| *state == FolderFileState::Retracted),
                        proposed: count(|state| matches!(state, FolderFileState::Proposed { .. })),
                        files: files.len(),
                        source,
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            serde_json::to_writer_pretty(&mut stdout, &listed)?;
        }
    }
    writeln!(stdout)?;
    Ok(())
}

/// Rescans attached folders from `oneiron serve` (a local vault only: a
/// hosted or relay node has no folder beside it).
pub(in crate::commands) struct FolderRescans;

impl FolderRescans {
    pub(in crate::commands) fn from_config(config: &ServeConfig) -> Option<Self> {
        (config.privacy_posture == oneiron::HostingPrivacyPosture::SelfHostLocal).then_some(Self)
    }

    /// Rescans every attached folder at start and every [`RESCAN_TICK`],
    /// one pass at a time, off the async runtime.
    pub(in crate::commands) fn spawn(self, server: Arc<SyncServer>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(RESCAN_TICK);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let server = Arc::clone(&server);
                let pass = tokio::task::spawn_blocking(move || rescan_all(server.vault())).await;
                let error = match pass {
                    Ok(Ok(())) => continue,
                    Ok(Err(error)) => format!("{error:#}"),
                    Err(error) => error.to_string(),
                };
                tracing::warn!(error = %error, "folder source rescan failed");
            }
        })
    }
}

fn rescan_all(vault: &oneiron::Vault) -> anyhow::Result<()> {
    let sources = vault.folder_sources()?;
    if sources.is_empty() {
        return Ok(());
    }
    let owner = crate::owner::local_owner(vault)?;
    for source in &sources {
        match rescan(vault, &owner, source) {
            Ok(report) => {
                let moved = report.landed
                    + report.superseded
                    + report.proposed
                    + report.retracted
                    + report.restored
                    + report.failed;
                if moved > 0 {
                    tracing::info!(
                        folder = %source.folder,
                        landed = report.landed,
                        superseded = report.superseded,
                        proposed = report.proposed,
                        retracted = report.retracted,
                        restored = report.restored,
                        failed = report.failed,
                        "folder source rescanned"
                    );
                }
            }
            Err(error) => {
                let error = format!("{error:#}");
                tracing::warn!(folder = %source.folder, error = %error, "folder source rescan failed");
            }
        }
    }
    Ok(())
}

fn rescanned(
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    source: &FolderSource,
) -> Rescanned {
    let (report, error) = match rescan(vault, owner, source) {
        Ok(report) => (Some(report), None),
        Err(error) => (None, Some(format!("{error:#}"))),
    };
    Rescanned {
        folder: source.folder.clone(),
        report,
        error,
    }
}

/// One rescan: the folder read as `import notes` reads it, the files the
/// source includes, each against the vault and the ledger.
fn rescan(
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    source: &FolderSource,
) -> anyhow::Result<FolderRescanReport> {
    let folder = Path::new(&source.folder);
    // An unmounted or moved folder retracts nothing.
    anyhow::ensure!(
        folder.is_dir(),
        "{} is not a folder now; nothing was rescanned",
        source.folder
    );
    let mut counts = NoteCounts::default();
    let mut notes = super::read_folder(folder, &mut counts, MAX_FOLDER_BYTES)?;
    notes.retain(|note| included(&source.include, &note.path));
    let ledger = vault.folder_source_files(&source.folder)?;
    let seen = notes
        .iter()
        .map(|note| note.path.as_str())
        .collect::<HashSet<_>>();
    // Only a file that is gone retracts: one the read passed over (too large,
    // blank, hard-linked) is still there.
    let missing = ledger
        .iter()
        .filter(|file| file.state != FolderFileState::Retracted)
        .filter(|file| !seen.contains(file.path.as_str()))
        .filter(|file| std::fs::symlink_metadata(folder.join(&file.path)).is_err())
        .map(|file| file.path.clone())
        .collect::<Vec<_>>();
    anyhow::ensure!(
        !notes.is_empty() || missing.is_empty(),
        "{} reads empty; nothing was retracted. Detach it to let its notes go",
        source.folder
    );
    let standings = vault.imported_note_standings(
        &source.folder,
        &notes
            .iter()
            .map(|note| ImportedFile {
                path: &note.path,
                markdown: &note.markdown,
                decoded: &note.decoded,
            })
            .collect::<Vec<_>>(),
    )?;
    let earlier_titles = super::earlier_titles(vault, &source.folder, &notes, &standings)?;
    let (links, _) = super::resolve_links(&notes, &standings, &earlier_titles);
    let mut known_kinds = HashMap::new();
    let mut taken = HashSet::new();
    let mut titles = TitleCounts::default();
    let mut new = Vec::new();
    let mut present = Vec::new();
    for (note, standing) in notes.iter_mut().zip(&standings) {
        let markdown = std::mem::take(&mut note.markdown);
        if *standing != ImportedNoteStanding::New {
            present.push(FolderFile {
                path: note.path.clone(),
                markdown,
            });
            continue;
        }
        let known = note.label.as_ref().is_some_and(|label| {
            *known_kinds
                .entry(label.clone())
                .or_insert_with(|| vault.note_kind(label).is_ok())
        });
        let kind = match &note.label {
            Some(label) if known => label.clone(),
            _ => source.kind.clone(),
        };
        let title = super::choose_title(vault, owner, note, &mut taken, &mut titles)?;
        new.push(ImportedNote {
            path: note.path.clone(),
            kind,
            title,
            written_at: note.written_at,
            markdown,
        });
    }
    Ok(vault.rescan_folder_source(
        owner,
        FolderRescan {
            folder: source.folder.clone(),
            new,
            links,
            present,
            missing,
        },
    )?)
}

/// `path` as a source names it: canonical, a folder, UTF-8.
fn canonical_folder(path: &Path) -> anyhow::Result<String> {
    let folder = std::fs::canonicalize(path)
        .map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))?;
    anyhow::ensure!(folder.is_dir(), "{} is not a folder", path.display());
    folder
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("{} is not a UTF-8 path", folder.display()))
}

/// Whether the source includes `path`: no patterns is every note; else one
/// pattern matches it (`*` within a name, `**` across folders, `?` one
/// character).
fn included(patterns: &[String], path: &str) -> bool {
    let path = path.chars().collect::<Vec<_>>();
    patterns.is_empty()
        || patterns
            .iter()
            .any(|pattern| glob(&pattern.chars().collect::<Vec<_>>(), &path))
}

fn glob(pattern: &[char], path: &[char]) -> bool {
    match pattern {
        [] => path.is_empty(),
        ['*', '*', '/', rest @ ..] => {
            glob(rest, path)
                || (0..path.len())
                    .filter(|&at| path[at] == '/')
                    .any(|at| glob(rest, &path[at + 1..]))
        }
        ['*', '*', rest @ ..] => (0..=path.len()).any(|at| glob(rest, &path[at..])),
        ['*', rest @ ..] => (0..=path.len())
            .take_while(|&at| at == 0 || path[at - 1] != '/')
            .any(|at| glob(rest, &path[at..])),
        ['?', rest @ ..] => path.first().is_some_and(|&c| c != '/') && glob(rest, &path[1..]),
        [c, rest @ ..] => path.first() == Some(c) && glob(rest, &path[1..]),
    }
}
