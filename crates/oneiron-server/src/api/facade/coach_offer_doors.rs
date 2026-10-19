//! Typed owner doors for Coach offers and counted pilot evidence.
use super::host_doors::{Listed, MaybeListed, internal, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::skill_optimize::{offer_doors, offer_pilot};
use std::sync::Arc;

async fn owned<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&oneiron::Vault, &AuthenticatedOwner) -> oneiron::Result<T> + Send + 'static,
) -> MemoryResult<T> {
    let owner = owner_proof(auth, server, verb)?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || act(server.vault(), &owner).map_err(MemoryError::from))
        .await
        .map_err(|_| internal(verb))?
}

/// [`owned`] for a door whose answer is ids and control metadata only: the
/// pass's attempt, an answer's record, an undo's model, the owner's
/// candidate setups and a pilot's counts, measurement and card. It lists
/// complete and empty (`host_door_lists`).
async fn owned_control<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&oneiron::Vault, &AuthenticatedOwner) -> oneiron::Result<T> + Send + 'static,
) -> Listed<T> {
    (owned(server, auth, verb, act).await, Vec::new())
}

/// [`owned`] for a door that serves the Coach's drafted offers and their
/// checks: it lists the union of the source rows those snapshots keep
/// (FIX 5482), read from the answer itself, unknown (`None`) when any
/// snapshot's is.
async fn owned_sourced<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&oneiron::Vault, &AuthenticatedOwner) -> oneiron::Result<T> + Send + 'static,
    listed: impl FnOnce(&T) -> Option<Vec<oneiron::EntityId>>,
) -> MaybeListed<T> {
    let answer = owned(server, auth, verb, act).await;
    let rows = answer.as_ref().ok().and_then(listed);
    (answer, rows)
}

/// [`owned`] for a door that serves derived content whose rows are not
/// kept: the pilot prepare serves the cohort's released eval cases, and a
/// released case keeps none of the rows its text derives from (FIX 4780). It
/// lists (`host_door_lists`), but its list is unknown (`None`), never `[]`.
async fn owned_unlisted<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&oneiron::Vault, &AuthenticatedOwner) -> oneiron::Result<T> + Send + 'static,
) -> MaybeListed<T> {
    (owned(server, auth, verb, act).await, None)
}

pub(crate) async fn vault_coach_training_offers(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: offer_doors::OfferListRequest,
) -> MaybeListed<Vec<oneiron::skill_optimize::offer_doors::OfferView>> {
    owned_sourced(
        server,
        auth,
        "vault.coach.training_offers",
        move |vault, owner| offer_doors::list(vault, owner, input),
        |views: &Vec<offer_doors::OfferView>| offer_doors::listed_views(views),
    )
    .await
}

pub(crate) async fn vault_coach_training_offers_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: offer_doors::OfferRef,
) -> MaybeListed<Option<oneiron::skill_optimize::offer_doors::OfferView>> {
    owned_sourced(
        server,
        auth,
        "vault.coach.training_offers.get",
        move |vault, owner| offer_doors::get(vault, owner, input),
        |view: &Option<offer_doors::OfferView>| offer_doors::listed_views(view.as_slice()),
    )
    .await
}

pub(crate) async fn vault_coach_training_offers_trigger(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: offer_doors::OfferPassRequest,
) -> Listed<oneiron::skill_optimize::offer_doors::OfferPassRef> {
    owned_control(
        server,
        auth,
        "vault.coach.training_offers.trigger",
        move |vault, owner| offer_doors::trigger(vault, owner, input),
    )
    .await
}

pub(crate) async fn vault_coach_training_offers_result(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: offer_doors::OfferPassRef,
) -> MaybeListed<Option<oneiron::skill_optimize::offer_doors::OfferPassResult>> {
    owned_sourced(
        server,
        auth,
        "vault.coach.training_offers.result",
        move |vault, owner| offer_doors::result(vault, owner, input),
        |pass: &Option<offer_doors::OfferPassResult>| offer_doors::listed_pass(pass.as_ref()),
    )
    .await
}

pub(crate) async fn vault_coach_training_offers_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: offer_doors::OfferAnswerRequest,
) -> Listed<oneiron::skill_optimize::OfferAnswerRecord> {
    owned_control(
        server,
        auth,
        "vault.coach.training_offers.answer",
        move |vault, owner| offer_doors::answer(vault, owner, input),
    )
    .await
}

pub(crate) async fn vault_coach_training_offers_undo(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: offer_doors::OfferRef,
) -> Listed<oneiron::skill_optimize::offer_doors::OfferUndoReceipt> {
    owned_control(
        server,
        auth,
        "vault.coach.training_offers.undo",
        move |vault, owner| offer_doors::undo(vault, owner, input),
    )
    .await
}

pub(crate) async fn vault_coach_training_offers_candidates(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: offer_pilot::OfferCandidateQuery,
) -> Listed<Vec<oneiron::skill_optimize::offer_pilot::OfferCandidateRecord>> {
    owned_control(
        server,
        auth,
        "vault.coach.training_offers.candidates",
        move |vault, owner| offer_pilot::candidates(vault, owner, input),
    )
    .await
}

pub(crate) async fn vault_coach_training_offers_candidates_prepare(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: offer_pilot::OfferCandidateSetup,
) -> Listed<oneiron::skill_optimize::offer_pilot::OfferCandidateRecord> {
    owned_control(
        server,
        auth,
        "vault.coach.training_offers.candidates.prepare",
        move |vault, owner| offer_pilot::prepare_candidate(vault, owner, input),
    )
    .await
}

pub(crate) async fn vault_coach_training_offers_pilots_prepare(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: offer_pilot::OfferPilotPrepare,
) -> MaybeListed<oneiron::skill_optimize::offer_pilot::OfferPilotPrepared> {
    owned_unlisted(
        server,
        auth,
        "vault.coach.training_offers.pilots.prepare",
        move |vault, owner| offer_pilot::prepare_pilot(vault, owner, input),
    )
    .await
}

pub(crate) async fn vault_coach_training_offers_pilots_complete(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: offer_pilot::OfferPilotComplete,
) -> Listed<oneiron::skill_optimize::offer_pilot::OfferPilot> {
    owned_control(
        server,
        auth,
        "vault.coach.training_offers.pilots.complete",
        move |vault, owner| offer_pilot::complete_pilot(vault, owner, input),
    )
    .await
}

pub(crate) async fn vault_coach_training_offers_pilots_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: offer_pilot::OfferPilotRef,
) -> Listed<Option<oneiron::skill_optimize::offer_pilot::OfferPilot>> {
    owned_control(
        server,
        auth,
        "vault.coach.training_offers.pilots.get",
        move |vault, owner| offer_pilot::pilot(vault, owner, input),
    )
    .await
}
