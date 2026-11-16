//! The host doors of the owner's embedding-space rows (OF-370):
//! `vault.embedding_spaces.*`. `host_doors` re-exports them, so the generated
//! HTTP facade handler and the MCP dispatcher call them by the name every host
//! door has, and a tool call, a code-mode call and an SDK call meet the
//! admission `/v1/owner/embedding-spaces` (L05) has: the vault owner's proof
//! (`owner_routes::owner`). Each runs the engine fns that route runs. A move's
//! check runs this server's own probe towers through
//! `SyncServer::check_space_move`, as the route does, with no deadline: it
//! can take minutes. The declare, bind, one-space, retire, move, undo,
//! abandon and probe-delete doors are generated from their rows (UC-01 PR
//! 2.2); the list, check, approve and probe list and put doors stay here.
//!
//! Every door but the check lists its rows (`host_door_lists`): a space, a
//! slot binding, a move and a probe live in the embedding setup's side
//! tables, which hold no row, so a change and the view it answers list
//! none, and a probe lists the documents it names. A check's reading is a
//! rank over every vector its probes reach, and goes unlisted.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::embed::SpaceProbe;
use oneiron::memory::MemoryError;
use oneiron::task_verb::sdk::{
    self, EmbeddingSpaceCandidateRequest, EmbeddingSpaceMoveChecked, EmbeddingSpaceProbe,
    EmbeddingSpaceProbePutRequest, EmbeddingSpaceProbes, EmbeddingSpacesView, EmptyRequest,
};

use super::host_doors::support::{Listed, MaybeListed};
use super::legal_hold_doors::{as_owner, as_owner_naming};
use crate::auth::CoreAuth;
use crate::server::{MediaEmbedRefusal, SyncServer};

/// A move check's refusal, a bad request; an owner's proof the check's write
/// no longer admits answers as every owner door does (FIX 8982).
fn move_check_refused(refusal: MediaEmbedRefusal) -> MemoryError {
    match refusal {
        MediaEmbedRefusal::Vault(error)
            if error.kind() == oneiron::ErrorKind::ConsentOwnerNotAuthenticated =>
        {
            MemoryError::from(error)
        }
        refusal => MemoryError::bad_request(refusal.to_string()),
    }
}

/// The documents a probe names: its source family, every row its query was written from
/// (FIX 9829) and every target.
fn probe_rows(probe: &SpaceProbe) -> impl Iterator<Item = EntityId> + '_ {
    std::iter::once(probe.family)
        .chain(probe.query_sources())
        .chain(probe.targets.iter().copied())
}

/// `vault.embedding_spaces.list`: every space, slot, move and probe count.
pub(crate) async fn vault_embedding_spaces_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<EmbeddingSpacesView> {
    as_owner_naming(
        server,
        auth,
        "vault.embedding_spaces.list",
        |server, owner| sdk::read_embedding_spaces(server.vault(), owner),
        |_| Vec::new(),
    )
    .await
}

/// `vault.embedding_spaces.move_check`: runs the move's probes now, through
/// both spaces' towers, and acts on the reading. Beside it, each live
/// probe's family and targets and every hit its reciprocal ranks stand on;
/// a check it waited on lists none (the move's stored check is a side
/// table), and a candidate still filling lists the pending document found.
pub(crate) async fn vault_embedding_spaces_move_check(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: EmbeddingSpaceCandidateRequest,
) -> MaybeListed<EmbeddingSpaceMoveChecked> {
    let runtime = tokio::runtime::Handle::current();
    let answer = as_owner(
        server,
        auth,
        "vault.embedding_spaces.move_check",
        move |server, owner| {
            let moving = sdk::find_embedding_space_move(server.vault(), owner, &input.candidate)?;
            server
                .check_space_move_listing(&runtime, &moving, Some(owner))
                .map(|(outcome, rows)| (EmbeddingSpaceMoveChecked::from(outcome), rows))
                .map_err(move_check_refused)
        },
    )
    .await;
    match answer {
        Ok((checked, rows)) => (Ok(checked), rows),
        Err(refusal) => (Err(refusal), Some(Vec::new())),
    }
}

/// `vault.embedding_spaces.move_approve`: the owner's yes over a check that
/// did not read not worse.
pub(crate) async fn vault_embedding_spaces_move_approve(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: EmbeddingSpaceCandidateRequest,
) -> Listed<EmbeddingSpacesView> {
    as_owner_naming(
        server,
        auth,
        "vault.embedding_spaces.move_approve",
        move |server, owner| {
            // FIX 6907: a third-party candidate's withheld documents do not
            // keep it filling.
            let egress = server.candidate_media_egress(&input.candidate);
            sdk::approve_embedding_space_move_admitted_as(
                server.vault(),
                owner,
                input,
                egress
                    .as_ref()
                    .map(|gate| gate as &dyn oneiron::embed::EgressPredicate),
            )
        },
        |_| Vec::new(),
    )
    .await
}

/// `vault.embedding_spaces.probes.list`: every stored probe.
pub(crate) async fn vault_embedding_spaces_probes_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<EmbeddingSpaceProbes> {
    as_owner_naming(
        server,
        auth,
        "vault.embedding_spaces.probes.list",
        |server, owner| sdk::read_embedding_space_probes(server.vault(), owner),
        |probes| {
            probes
                .probes
                .iter()
                .flat_map(|probe| probe_rows(&probe.probe))
                .collect()
        },
    )
    .await
}

/// `vault.embedding_spaces.probes.put`: stores one probe.
pub(crate) async fn vault_embedding_spaces_probes_put(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: EmbeddingSpaceProbePutRequest,
) -> Listed<EmbeddingSpaceProbe> {
    as_owner_naming(
        server,
        auth,
        "vault.embedding_spaces.probes.put",
        move |server, owner| sdk::put_embedding_space_probe_as(server.vault(), owner, input),
        |probe| probe_rows(&probe.probe).collect(),
    )
    .await
}
