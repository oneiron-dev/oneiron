//! The host doors of the Files world's source rows (FIX 6942):
//! `vault.files.sources.attach`, `.rescan`, `.detach`, `.list` and `.files`.
//! `host_doors` re-exports them, so the generated HTTP facade handler and the
//! MCP dispatcher call them by the name every host door has. Each runs under
//! the vault owner's proof, as `/v1/owner` takes it, off the async runtime:
//! attach and rescan read the owner's folders on this host through its intake
//! (`crate::files_intake`), the same reads `oneiron files` and `oneiron
//! serve`'s rescans run. Attach is the owner's opt-in: the first one bears
//! this install's Files world.
//!
//! Each lists its rows (`host_door_lists`): the Files world its answer names,
//! and the notes and forks a ledger read names. The sources and their ledger
//! are side tables, which hold no row.

use std::path::Path;
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::{
    self, FilesRescanAnswer, FilesSourceAttachAnswer, FilesSourceAttachRequest,
    FilesSourceDetachAnswer, FilesSourceDetachRequest, FilesSourceFiles, FilesSourceFilesRequest,
    FilesSourceList, FilesSourceListRequest, FilesSourceRescanRequest,
};

use super::host_doors::{Listed, internal, owner_proof};
use crate::auth::CoreAuth;
use crate::files_intake::{canonical_folder, files_attached, files_rescan};
use crate::server::SyncServer;

/// `act` off the runtime under the owner's proof from the request, beside
/// the rows its answer derives from; a refusal lists none.
async fn as_owner_listing<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&SyncServer, &AuthenticatedOwner) -> MemoryResult<(T, Vec<EntityId>)>
    + Send
    + 'static,
) -> Listed<T> {
    let owner = match owner_proof(auth, server, verb) {
        Ok(owner) => owner,
        Err(refusal) => return (Err(refusal), Vec::new()),
    };
    let server = Arc::clone(server);
    match tokio::task::spawn_blocking(move || act(&*server, &owner)).await {
        Ok(Ok((answer, rows))) => (Ok(answer), rows),
        Ok(Err(refusal)) => (Err(refusal), Vec::new()),
        Err(_) => (Err(internal(verb)), Vec::new()),
    }
}

/// `vault.files.sources.attach`: the owner attaches a folder of this host to
/// its Files world, opting in on the first one, and its first rescan runs.
pub(crate) async fn vault_files_sources_attach(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: FilesSourceAttachRequest,
) -> Listed<FilesSourceAttachAnswer> {
    let surface = super::owner_binding::act_surface(auth);
    as_owner_listing(
        server,
        auth,
        "vault.files.sources.attach",
        move |server, owner| {
            let folder = canonical_folder(Path::new(&input.path)).map_err(|error| {
                MemoryError::new(
                    MEMORY_CODE_BAD_REQUEST,
                    format!("{error:#}"),
                    &["Name a folder this host can read."],
                )
            })?;
            let vault = server.vault();
            let (world, source) = vault.attach_files_source(
                owner,
                surface,
                &folder,
                input.include,
                input.exclude,
                input.kind.as_deref(),
            )?;
            let answer = files_attached(vault, owner, world, &source)?;
            Ok((answer, vec![world.world]))
        },
    )
    .await
}

/// `vault.files.sources.rescan`: one Files source rescanned now, or every
/// one.
pub(crate) async fn vault_files_sources_rescan(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: FilesSourceRescanRequest,
) -> Listed<FilesRescanAnswer> {
    as_owner_listing(
        server,
        auth,
        "vault.files.sources.rescan",
        move |server, owner| {
            let vault = server.vault();
            let sources = match input.source {
                Some(source) => vault.files_source(source)?.into_iter().collect(),
                None => vault.files_sources()?,
            };
            let mut rows = Vec::new();
            let mut rescans = Vec::new();
            for source in &sources {
                let Some(files) = &source.files else {
                    continue;
                };
                if !rows.contains(&files.world) {
                    rows.push(files.world);
                }
                rescans.push(files_rescan(vault, owner, source, files.source));
            }
            Ok((FilesRescanAnswer { rescans }, rows))
        },
    )
    .await
}

/// `vault.files.sources.detach`: no rescan reads the folder again and its
/// ledger goes; the notes it landed stay.
pub(crate) async fn vault_files_sources_detach(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: FilesSourceDetachRequest,
) -> Listed<FilesSourceDetachAnswer> {
    as_owner_listing(
        server,
        auth,
        "vault.files.sources.detach",
        move |server, owner| {
            let vault = server.vault();
            let rows = vault
                .files_source(input.source)?
                .and_then(|source| source.files)
                .map(|files| vec![files.world])
                .unwrap_or_default();
            Ok((sdk::detach_files_source_as(vault, owner, input)?, rows))
        },
    )
    .await
}

/// `vault.files.sources.list`: this install's Files world and every Files
/// source, with its ledger's counts.
pub(crate) async fn vault_files_sources_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: FilesSourceListRequest,
) -> Listed<FilesSourceList> {
    as_owner_listing(
        server,
        auth,
        "vault.files.sources.list",
        move |server, owner| {
            let list = sdk::list_files_sources_as(server.vault(), owner, input)?;
            let mut rows: Vec<EntityId> = list.world.iter().map(|world| world.world).collect();
            for source in &list.sources {
                if !rows.contains(&source.world) {
                    rows.push(source.world);
                }
            }
            Ok((list, rows))
        },
    )
    .await
}

/// `vault.files.sources.files`: every file one Files source's ledger holds.
pub(crate) async fn vault_files_sources_files(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: FilesSourceFilesRequest,
) -> Listed<FilesSourceFiles> {
    as_owner_listing(
        server,
        auth,
        "vault.files.sources.files",
        move |server, owner| {
            let vault = server.vault();
            let world = vault
                .files_source(input.source)?
                .and_then(|source| source.files)
                .map(|files| files.world);
            let files = sdk::files_source_files_as(vault, owner, input)?;
            let rows = world
                .into_iter()
                .chain(
                    files
                        .files
                        .iter()
                        .flat_map(|file| file.note.into_iter().chain(file.fork)),
                )
                .collect();
            Ok((files, rows))
        },
    )
    .await
}
