//! The host door of `vault.coach.training_offers.sources` (FIX 11352): the
//! owner's read, before he prepares a training run, of the reservoir scope's
//! sources the run would hold to his consent tick, and of the pairs it would
//! carry and leave out. `host_doors` re-exports it, so the generated HTTP
//! facade handler and the MCP dispatcher call it by the name every host door
//! has. It takes the vault owner's proof as `/v1/owner` takes it, as
//! `door_admits` already did before any hook ran, and the engine read checks
//! the owner again in its own snapshot. It lists the source rows its answer
//! names. The prepare route stays as it is.

use std::sync::Arc;

use oneiron::edit_distance::reservoir::ReservoirSourcePreview;
use oneiron::task_verb::sdk::{ReservoirSourcesRequest, reservoir_sources_as};

use super::host_doors::support::{Listed, internal, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

const VERB: &str = "vault.coach.training_offers.sources";

/// `vault.coach.training_offers.sources`: the scope's ticked sources and
/// the pairs a run would carry and leave out under the ticks given.
pub(crate) async fn vault_coach_training_offers_sources(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ReservoirSourcesRequest,
) -> Listed<ReservoirSourcePreview> {
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(refusal) => return (Err(refusal), Vec::new()),
    };
    let server = Arc::clone(server);
    let answer = super::clock_ingress::run_blocking(move || {
        reservoir_sources_as(server.vault(), &owner, input)
    })
    .await
    .unwrap_or_else(|_| Err(internal(VERB)));
    let rows = answer.as_ref().map_or_else(
        |_| Vec::new(),
        |preview| preview.sources.iter().map(|row| row.source).collect(),
    );
    (answer, rows)
}
