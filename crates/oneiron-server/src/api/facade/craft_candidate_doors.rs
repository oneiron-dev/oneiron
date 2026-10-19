//! The host doors of the owner's review of residents' craft candidates
//! (OF-490): `vault.craft_candidates` and `.answer`. `host_doors` re-exports
//! them, so the generated HTTP facade handler and the MCP dispatcher call
//! them by the name every host door has, and a tool call, a code-mode call
//! and an SDK call meet one admission: the vault owner's proof, as
//! `/v1/owner/craft-candidates` takes it (`owner_routes::owner`). The engine
//! checks the owner again in the verdict's own write.
//!
//! Each lists its rows (`host_door_lists`): the candidates a list shows, and
//! the candidate and the verdict an answer lands. A refusal lists none.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::actor_claims::{
    self, CraftCandidateAnswer, CraftCandidatesRequest, CraftCandidatesView, CraftVerdictView,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{MemoryError, MemoryResult};

use super::host_doors::{Listed, internal};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `act` off the runtime, as the vault owner: every craft door reads or
/// writes LMDB.
async fn as_owner<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&SyncServer, &AuthenticatedOwner) -> oneiron::Result<T> + Send + 'static,
) -> MemoryResult<T> {
    let owner = super::owner_binding::facade_owner(server, auth, verb)?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || act(&*server, &owner).map_err(MemoryError::from))
        .await
        .map_err(|_| internal(verb))?
}

/// The rows hex ids name; a value that is no id names none.
fn rows<S: AsRef<str>>(ids: impl IntoIterator<Item = S>) -> Vec<EntityId> {
    ids.into_iter()
        .filter_map(|hex| EntityId::from_hex(hex.as_ref()).ok())
        .collect()
}

/// `vault.craft_candidates`: the candidates waiting on a verdict, newest
/// first.
pub(crate) async fn vault_craft_candidates(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CraftCandidatesRequest,
) -> Listed<CraftCandidatesView> {
    let answer = as_owner(
        server,
        auth,
        "vault.craft_candidates",
        move |server, owner| actor_claims::craft_candidates_as_owner(server.vault(), owner, &input),
    )
    .await;
    let listed = answer.as_ref().map_or_else(
        |_| Vec::new(),
        |view| rows(view.candidates.iter().map(|card| &card.candidate_id)),
    );
    (answer, listed)
}

/// `vault.craft_candidates.answer`: the owner approves or rejects one.
pub(crate) async fn vault_craft_candidates_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CraftCandidateAnswer,
) -> Listed<CraftVerdictView> {
    let answer = as_owner(
        server,
        auth,
        "vault.craft_candidates.answer",
        move |server, owner| {
            actor_claims::answer_craft_candidate_as_owner(server.vault(), owner, &input)
        },
    )
    .await;
    let listed = answer.as_ref().map_or_else(
        |_| Vec::new(),
        |view| rows([&view.candidate_id, &view.verdict_id]),
    );
    (answer, listed)
}
