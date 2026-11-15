//! The host doors of the Files world's source rows (FIX 6942):
//! `vault.files.sources.attach`, `.convert`, `.rescan`, `.detach`, `.list`, `.files`,
//! `.exclude`, `.search` and `.ask` (in `ask`).
//! `host_doors` re-exports them, so the generated HTTP facade handler and the
//! MCP dispatcher call them by the name every host door has. Each runs under
//! the vault owner's proof, as `/v1/owner` takes it, off the async runtime:
//! attach and rescan read the owner's folders on this host through its intake
//! (`crate::files_intake`), the same reads `oneiron files` and `oneiron
//! serve`'s rescans run. Attach is the owner's opt-in: the first one bears
//! this install's Files world.
//!
//! Each lists its rows (`host_door_lists`): the Files world its answer names,
//! and the notes, forks and kept-original artifacts a ledger read names. The sources and their ledger
//! are side tables, which hold no row.

use std::path::Path;
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::{
    self, FilesDeviceAnswer, FilesRescanAnswer, FilesSourceAttachAnswer, FilesSourceAttachRequest,
    FilesSourceConvertRequest, FilesSourceDetachAnswer, FilesSourceDetachRequest,
    FilesSourceExcludeAnswer, FilesSourceExcludeRequest, FilesSourceFiles, FilesSourceFilesRequest,
    FilesSourceList, FilesSourceListRequest, FilesSourceRescanRequest, FilesSourceSearchAnswer,
    FilesSourceSearchRequest, FilesUnreachedDevice, FilesUnreachedWhy,
};

use super::FacadeApiError;
use super::host_doors::support::{Listed, internal, owner_proof};
use crate::auth::CoreAuth;
use crate::files_intake::{canonical_folder, files_attached, files_rescan};
use crate::server::SyncServer;

mod ask;
pub(crate) use ask::vault_files_sources_ask;

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
    match super::clock_ingress::run_blocking(move || act(&*server, &owner)).await {
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

/// Converts an attached notes source to Files, preserving its existing notes.
pub(crate) async fn vault_files_sources_convert(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: FilesSourceConvertRequest,
) -> Listed<FilesSourceAttachAnswer> {
    let surface = super::owner_binding::act_surface(auth);
    as_owner_listing(
        server,
        auth,
        "vault.files.sources.convert",
        move |server, owner| {
            let folder = canonical_folder(Path::new(&input.path)).map_err(|error| {
                MemoryError::new(
                    MEMORY_CODE_BAD_REQUEST,
                    format!("{error:#}"),
                    &["Name a folder this host can read."],
                )
            })?;
            let vault = server.vault();
            let (world, source) =
                vault.convert_folder_source_to_files(owner, surface, &folder, input.exclude)?;
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

/// `vault.files.sources.exclude`: a Files source's filters change without
/// detach and attach; its next rescan reads with them.
pub(crate) async fn vault_files_sources_exclude(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: FilesSourceExcludeRequest,
) -> Listed<FilesSourceExcludeAnswer> {
    as_owner_listing(
        server,
        auth,
        "vault.files.sources.exclude",
        move |server, owner| {
            let vault = server.vault();
            let answer = sdk::exclude_files_source_as(vault, owner, input)?;
            let rows = vault
                .files_source(answer.source)?
                .and_then(|source| source.files)
                .map(|files| vec![files.world])
                .unwrap_or_default();
            Ok((answer, rows))
        },
    )
    .await
}

/// `vault.files.sources.files`: one page of the files one Files source's
/// ledger holds.
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
                .chain(files.files.iter().flat_map(|file| {
                    file.note
                        .into_iter()
                        .chain(file.fork)
                        .chain(file.original.as_ref().map(|original| original.artifact))
                }))
                .collect();
            Ok((files, rows))
        },
    )
    .await
}

/// `vault.files.sources.search`: the owner's search of the Files world's
/// sources, the files whose name or path matches first, then those whose
/// text matches in meaning. The meaning tier is the owner's own recall of
/// the Files world through this server's recall pipeline, the one
/// `vault.retrieval.recall` runs, so the query is embedded where this host
/// embeds; a refused recall leaves the name tier's answer standing. With
/// `devices`, it asks the owner's other devices over this install's mesh
/// endpoint (ARCH-0027 #files-world: cross-device search) and merges their
/// answers with its own; with no endpoint, each is listed unreached. It lists
/// the Files world and each of this install's hits' notes.
pub(crate) async fn vault_files_sources_search(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: FilesSourceSearchRequest,
) -> Listed<FilesSourceSearchAnswer> {
    const VERB: &str = "vault.files.sources.search";
    let admitted = || -> MemoryResult<_> {
        let owner = owner_proof(auth, server, VERB)?;
        let caller =
            super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
        let recall = sdk::files_search_recall(server.vault(), &input)?;
        Ok((owner, caller, recall))
    };
    let (owner, (actor, class), recall) = match admitted() {
        Ok(admitted) => admitted,
        Err(refusal) => return (Err(refusal), Vec::new()),
    };
    let meaning = match recall {
        Some(request) => Some(
            server
                .recall_home_listing(
                    actor,
                    class,
                    auth.verified_slip().cloned(),
                    auth.destination(),
                    None,
                    request,
                    oneiron::memory::HomeRecallCaller::owner(),
                )
                .await
                .0,
        ),
        None => None,
    };
    let asked = input.clone();
    let searching = Arc::clone(server);
    let searched = super::clock_ingress::run_blocking(
        move || -> MemoryResult<(FilesSourceSearchAnswer, Vec<EntityId>, Vec<EntityId>)> {
            let vault = searching.vault();
            let machines = match &input.devices {
                Some(devices) => sdk::files_search_devices(vault, devices)?,
                None => Vec::new(),
            };
            let answer = sdk::search_files_sources_with(vault, &owner, input, meaning)?;
            let rows = vault
                .files_world()?
                .map(|files| files.world)
                .into_iter()
                .chain(answer.hits.iter().filter_map(|hit| hit.note))
                .collect::<Vec<_>>();
            Ok((answer, rows, machines))
        },
    )
    .await;
    let (answer, rows, machines) = match searched {
        Ok(Ok(searched)) => searched,
        Ok(Err(refusal)) => return (Err(refusal), Vec::new()),
        Err(_) => return (Err(internal(VERB)), Vec::new()),
    };
    if asked.devices.is_none() {
        return (Ok(answer), rows);
    }
    let (answered, unreached) = ask_other_devices(server, machines, &asked).await;
    (
        Ok(sdk::merge_files_search_answers(
            asked.limit,
            answer,
            answered,
            unreached,
        )),
        rows,
    )
}

/// The answers of the owner's `machines` to `request`, asked over this
/// install's mesh endpoint under the search's one deadline. With no endpoint
/// (the mesh listener is off, or this build has no mesh), each machine is
/// listed unreached.
#[cfg_attr(not(feature = "mesh"), allow(unused_variables))]
async fn ask_other_devices(
    server: &Arc<SyncServer>,
    machines: Vec<EntityId>,
    request: &FilesSourceSearchRequest,
) -> (Vec<FilesDeviceAnswer>, Vec<FilesUnreachedDevice>) {
    #[cfg(feature = "mesh")]
    if let Some(transport) = server.mesh_transport.get().cloned() {
        use oneiron_mesh_transport::files_search::{
            FILES_SEARCH_DEADLINE, ask_files_search_devices,
        };
        let transport: Arc<dyn oneiron_mesh_transport::MeshTransport> = transport;
        return ask_files_search_devices(transport, machines, request, FILES_SEARCH_DEADLINE).await;
    }
    let unreached = machines
        .into_iter()
        .map(|machine| FilesUnreachedDevice {
            machine,
            why: FilesUnreachedWhy::Unavailable,
        })
        .collect();
    (Vec::new(), unreached)
}
