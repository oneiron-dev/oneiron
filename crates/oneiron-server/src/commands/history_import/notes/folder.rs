//! `oneiron import folder attach|rescan|detach|list`: a folder of markdown
//! notes and PDFs that stays attached to the vault (OF-554, ARCH-0027).
//!
//! `attach` is the owner's one act: it records the folder and lands its notes
//! as `import notes` would. From then on `oneiron serve` rescans every
//! attached folder every few minutes, starting when it starts, and `rescan`
//! does one by hand. A rescan reads the folder the way `import notes` reads
//! it, lands the new files, supersedes what changed files landed and
//! retracts (archives) the notes of files that left. Nothing is ever written
//! to the folder. `detach` stops the rescans; the notes stay. The reading
//! and the rescan are the host's intake (`crate::files_intake`).
//!
//! Stdout carries counts, never note text, titles or link targets.

use std::io::{self, Write};

use oneiron::note::{FolderFileState, FolderSource};
use serde::Serialize;

use crate::cli::{ImportFolderAttachArgs, ImportFolderCommand};
use crate::config::resolve_serve_config;
use crate::files_intake::{canonical_folder, rescanned};

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
