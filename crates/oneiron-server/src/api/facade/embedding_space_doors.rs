//! The host doors of the owner's embedding-space rows (OF-370):
//! `vault.embedding_spaces.*`. `host_doors` re-exports them, so the generated
//! HTTP facade handler and the MCP dispatcher call them by the name every host
//! door has, and a tool call, a code-mode call and an SDK call meet the
//! admission `/v1/owner/embedding-spaces` (L05) has: the vault owner's proof
//! (`owner_routes::owner`). Each runs the engine fns that route runs. A move's
//! check runs this server's own probe towers through
//! `SyncServer::check_space_move`, as the route does, with no deadline: it
//! can take minutes.
use std::sync::Arc;

use oneiron::embed::SpaceMove;
use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::task_verb::sdk::{
    self, EmbeddingSpaceBindRequest, EmbeddingSpaceCandidateRequest, EmbeddingSpaceDeclareRequest,
    EmbeddingSpaceMoveChecked, EmbeddingSpaceMoveRequest, EmbeddingSpaceProbe,
    EmbeddingSpaceProbeDeleteRequest, EmbeddingSpaceProbeDeleted, EmbeddingSpaceProbePutRequest,
    EmbeddingSpaceProbes, EmbeddingSpaceRequest, EmbeddingSpacesView, EmptyRequest,
};

use super::legal_hold_doors::as_owner;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.embedding_spaces.list`: every space, slot, move and probe count.
pub(crate) async fn vault_embedding_spaces_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> MemoryResult<EmbeddingSpacesView> {
    as_owner(
        server,
        auth,
        "vault.embedding_spaces.list",
        |server, owner| sdk::read_embedding_spaces(server.vault(), owner),
    )
    .await
}

/// `vault.embedding_spaces.declare`: declares or widens one space.
pub(crate) async fn vault_embedding_spaces_declare(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: EmbeddingSpaceDeclareRequest,
) -> MemoryResult<EmbeddingSpacesView> {
    as_owner(
        server,
        auth,
        "vault.embedding_spaces.declare",
        move |server, owner| sdk::declare_embedding_space_as(server.vault(), owner, input),
    )
    .await
}

/// `vault.embedding_spaces.bind`: binds one kind slot, or returns it to its
/// default.
pub(crate) async fn vault_embedding_spaces_bind(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: EmbeddingSpaceBindRequest,
) -> MemoryResult<EmbeddingSpacesView> {
    as_owner(
        server,
        auth,
        "vault.embedding_spaces.bind",
        move |server, owner| sdk::bind_embedding_slot_as(server.vault(), owner, input),
    )
    .await
}

/// `vault.embedding_spaces.one_space`: the one-space preset.
pub(crate) async fn vault_embedding_spaces_one_space(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: EmbeddingSpaceRequest,
) -> MemoryResult<EmbeddingSpacesView> {
    as_owner(
        server,
        auth,
        "vault.embedding_spaces.one_space",
        move |server, owner| sdk::bind_one_embedding_space_as(server.vault(), owner, input),
    )
    .await
}

/// `vault.embedding_spaces.retire`: drops a space no slot binds and no open
/// move names.
pub(crate) async fn vault_embedding_spaces_retire(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: EmbeddingSpaceRequest,
) -> MemoryResult<EmbeddingSpacesView> {
    as_owner(
        server,
        auth,
        "vault.embedding_spaces.retire",
        move |server, owner| sdk::retire_embedding_space_as(server.vault(), owner, input),
    )
    .await
}

/// `vault.embedding_spaces.move`: starts a move; answers the move.
pub(crate) async fn vault_embedding_spaces_move(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: EmbeddingSpaceMoveRequest,
) -> MemoryResult<SpaceMove> {
    as_owner(
        server,
        auth,
        "vault.embedding_spaces.move",
        move |server, owner| sdk::begin_embedding_space_move_as(server.vault(), owner, input),
    )
    .await
}

/// `vault.embedding_spaces.move_check`: runs the move's probes now, through
/// both spaces' towers, and acts on the reading.
pub(crate) async fn vault_embedding_spaces_move_check(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: EmbeddingSpaceCandidateRequest,
) -> MemoryResult<EmbeddingSpaceMoveChecked> {
    let runtime = tokio::runtime::Handle::current();
    as_owner(
        server,
        auth,
        "vault.embedding_spaces.move_check",
        move |server, owner| {
            let moving = sdk::find_embedding_space_move(server.vault(), owner, &input.candidate)?;
            server
                .check_space_move(&runtime, &moving)
                .map(EmbeddingSpaceMoveChecked::from)
                .map_err(|refusal| MemoryError::bad_request(refusal.to_string()))
        },
    )
    .await
}

/// `vault.embedding_spaces.move_approve`: the owner's yes over a check that
/// did not read not worse.
pub(crate) async fn vault_embedding_spaces_move_approve(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: EmbeddingSpaceCandidateRequest,
) -> MemoryResult<EmbeddingSpacesView> {
    as_owner(
        server,
        auth,
        "vault.embedding_spaces.move_approve",
        move |server, owner| sdk::approve_embedding_space_move_as(server.vault(), owner, input),
    )
    .await
}

/// `vault.embedding_spaces.move_undo`: binds a swapped-in move's incumbent
/// again.
pub(crate) async fn vault_embedding_spaces_move_undo(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: EmbeddingSpaceCandidateRequest,
) -> MemoryResult<EmbeddingSpacesView> {
    as_owner(
        server,
        auth,
        "vault.embedding_spaces.move_undo",
        move |server, owner| sdk::undo_embedding_space_move_as(server.vault(), owner, input),
    )
    .await
}

/// `vault.embedding_spaces.move_abandon`: ends an open move with no swap.
pub(crate) async fn vault_embedding_spaces_move_abandon(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: EmbeddingSpaceCandidateRequest,
) -> MemoryResult<EmbeddingSpacesView> {
    as_owner(
        server,
        auth,
        "vault.embedding_spaces.move_abandon",
        move |server, owner| sdk::abandon_embedding_space_move_as(server.vault(), owner, input),
    )
    .await
}

/// `vault.embedding_spaces.probes.list`: every stored probe.
pub(crate) async fn vault_embedding_spaces_probes_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> MemoryResult<EmbeddingSpaceProbes> {
    as_owner(
        server,
        auth,
        "vault.embedding_spaces.probes.list",
        |server, owner| sdk::read_embedding_space_probes(server.vault(), owner),
    )
    .await
}

/// `vault.embedding_spaces.probes.put`: stores one probe.
pub(crate) async fn vault_embedding_spaces_probes_put(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: EmbeddingSpaceProbePutRequest,
) -> MemoryResult<EmbeddingSpaceProbe> {
    as_owner(
        server,
        auth,
        "vault.embedding_spaces.probes.put",
        move |server, owner| sdk::put_embedding_space_probe_as(server.vault(), owner, input),
    )
    .await
}

/// `vault.embedding_spaces.probes.delete`: removes one probe.
pub(crate) async fn vault_embedding_spaces_probes_delete(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: EmbeddingSpaceProbeDeleteRequest,
) -> MemoryResult<EmbeddingSpaceProbeDeleted> {
    as_owner(
        server,
        auth,
        "vault.embedding_spaces.probes.delete",
        move |server, owner| sdk::delete_embedding_space_probe_as(server.vault(), owner, input),
    )
    .await
}
