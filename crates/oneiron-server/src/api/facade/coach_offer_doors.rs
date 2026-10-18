//! Typed owner doors for Coach offers and counted pilot evidence.
use super::host_doors::{internal, owner_proof};
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

pub(crate) async fn vault_coach_training_offers(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: offer_doors::OfferListRequest,
) -> MemoryResult<Vec<oneiron::skill_optimize::offer_doors::OfferView>> {
    owned(
        server,
        auth,
        "vault.coach.training_offers",
        move |vault, owner| offer_doors::list(vault, owner, input),
    )
    .await
}

pub(crate) async fn vault_coach_training_offers_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: offer_doors::OfferRef,
) -> MemoryResult<Option<oneiron::skill_optimize::offer_doors::OfferView>> {
    owned(
        server,
        auth,
        "vault.coach.training_offers.get",
        move |vault, owner| offer_doors::get(vault, owner, input),
    )
    .await
}

pub(crate) async fn vault_coach_training_offers_trigger(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: offer_doors::OfferPassRequest,
) -> MemoryResult<oneiron::skill_optimize::offer_doors::OfferPassRef> {
    owned(
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
) -> MemoryResult<Option<oneiron::skill_optimize::offer_doors::OfferPassResult>> {
    owned(
        server,
        auth,
        "vault.coach.training_offers.result",
        move |vault, owner| offer_doors::result(vault, owner, input),
    )
    .await
}

pub(crate) async fn vault_coach_training_offers_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: offer_doors::OfferAnswerRequest,
) -> MemoryResult<oneiron::skill_optimize::OfferAnswerRecord> {
    owned(
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
) -> MemoryResult<oneiron::skill_optimize::offer_doors::OfferUndoReceipt> {
    owned(
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
) -> MemoryResult<Vec<oneiron::skill_optimize::offer_pilot::OfferCandidateRecord>> {
    owned(
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
) -> MemoryResult<oneiron::skill_optimize::offer_pilot::OfferCandidateRecord> {
    owned(
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
) -> MemoryResult<oneiron::skill_optimize::offer_pilot::OfferPilotPrepared> {
    owned(
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
) -> MemoryResult<oneiron::skill_optimize::offer_pilot::OfferPilot> {
    owned(
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
) -> MemoryResult<Option<oneiron::skill_optimize::offer_pilot::OfferPilot>> {
    owned(
        server,
        auth,
        "vault.coach.training_offers.pilots.get",
        move |vault, owner| offer_pilot::pilot(vault, owner, input),
    )
    .await
}
