//! `oneiron files attach|rescan|detach|list|files`: the Files world on a
//! stopped vault (FIX 6942). `attach` is the owner's opt-in and standing act:
//! the first one bears this install's Files world, read on this install only
//! with no sealed copy, and every one lands its folder's files in it as the
//! host's intake reads them (`crate::files_intake`). From then on `oneiron
//! serve` rescans each with the other attached folders. A running server
//! answers the same at `vault.files.sources.*`, and every answer here is that
//! row's.
//!
//! Stdout carries ids, paths and counts, never a file's text.

use std::io::{self, Write};

use oneiron::authority::ActSurface;
use oneiron::note::{DEFAULT_FILES_EXCLUDE, FolderSource};
use oneiron::task_verb::sdk::{
    self, FilesRescanAnswer, FilesSourceDetachRequest, FilesSourceFilesRequest,
    FilesSourceListRequest,
};
use serde::Serialize;

use crate::cli::{FilesAttachArgs, FilesCommand};
use crate::config::{ServeArgs, resolve_serve_config};
use crate::files_intake::{canonical_folder, files_attached, files_rescan};

/// What `oneiron files` says instead while a server holds the vault.
const INSTEAD: &str = "or call vault.files.sources.* on it";

/// `oneiron files <attach|rescan|detach|list|files>`.
pub fn files(command: FilesCommand) -> anyhow::Result<()> {
    match command {
        FilesCommand::Attach(args) => {
            let FilesAttachArgs {
                path,
                include,
                exclude,
                no_default_exclude,
                kind,
                serve,
            } = *args;
            let folder = canonical_folder(&path)?;
            let (vault, owner) = open(&serve)?;
            let exclude = if no_default_exclude {
                Some(exclude)
            } else if exclude.is_empty() {
                None
            } else {
                Some(
                    DEFAULT_FILES_EXCLUDE
                        .iter()
                        .map(|pattern| (*pattern).to_owned())
                        .chain(exclude)
                        .collect(),
                )
            };
            let (world, source) = vault.attach_files_source(
                &owner,
                ActSurface::ThisInstall,
                &folder,
                include,
                exclude,
                kind.as_deref(),
            )?;
            emit(&files_attached(&vault, &owner, world, &source)?)
        }
        FilesCommand::Rescan(args) => {
            let (vault, owner) = open(&args.serve)?;
            let sources = match &args.path {
                Some(path) => vec![files_source_at(&vault, &canonical_folder(path)?)?],
                None => vault.files_sources()?,
            };
            let rescans = sources
                .iter()
                .filter_map(|source| {
                    let id = source.files.as_ref()?.source;
                    Some(files_rescan(&vault, &owner, source, id))
                })
                .collect();
            emit(&FilesRescanAnswer { rescans })
        }
        FilesCommand::Detach(args) => {
            // A folder that is gone is detached by the name it was attached by.
            let folder = canonical_folder(&args.path)
                .unwrap_or_else(|_| args.path.to_string_lossy().into_owned());
            let (vault, owner) = open(&args.serve)?;
            let source = files_id(&files_source_at(&vault, &folder)?)?;
            let detached =
                sdk::detach_files_source_as(&vault, &owner, FilesSourceDetachRequest { source })?;
            anyhow::ensure!(detached.detached, "{folder} is not a Files folder");
            emit(&detached)
        }
        FilesCommand::List(args) => {
            let (vault, owner) = open(&args.serve)?;
            emit(&sdk::list_files_sources_as(
                &vault,
                &owner,
                FilesSourceListRequest::default(),
            )?)
        }
        FilesCommand::Files(args) => {
            let folder = canonical_folder(&args.path)
                .unwrap_or_else(|_| args.path.to_string_lossy().into_owned());
            let (vault, owner) = open(&args.serve)?;
            let source = files_id(&files_source_at(&vault, &folder)?)?;
            emit(&sdk::files_source_files_as(
                &vault,
                &owner,
                FilesSourceFilesRequest { source },
            )?)
        }
    }
}

/// The configured, stopped vault with this install's keys and machine
/// profile loaded (the world's settings are signed with them), and its local
/// owner.
fn open(
    serve: &ServeArgs,
) -> anyhow::Result<(oneiron::Vault, oneiron::consent::AuthenticatedOwner)> {
    let config = resolve_serve_config(serve)?;
    let vault =
        super::owner::open_stopped_vault_with(&config, super::owner::vault_config(&config), INSTEAD)?;
    let owner = crate::owner::local_owner(&vault)?;
    Ok((vault, owner))
}

/// The Files source attached at `folder`.
fn files_source_at(vault: &oneiron::Vault, folder: &str) -> anyhow::Result<FolderSource> {
    vault
        .folder_source(folder)?
        .filter(|source| source.files.is_some())
        .ok_or_else(|| anyhow::anyhow!("{folder} is not a Files folder; `oneiron files attach` it"))
}

fn files_id(source: &FolderSource) -> anyhow::Result<oneiron::EntityId> {
    source
        .files
        .as_ref()
        .map(|files| files.source)
        .ok_or_else(|| anyhow::anyhow!("{} is not a Files folder", source.folder))
}

fn emit(value: &impl Serialize) -> anyhow::Result<()> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, value)?;
    writeln!(stdout)?;
    Ok(())
}
