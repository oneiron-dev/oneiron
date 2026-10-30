//! Typed owner doors for Coach offers and counted pilot evidence.
use super::host_doors::support::{Listed, MaybeListed, internal, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::skill_optimize::{offer_doors, offer_pilot};
use std::sync::Arc;

/// While this holds, pilot complete and get list the rows a pilot's frozen
/// sets keep (FIX 5761): its measurement's. False (as before): they list
/// none, so no off-device answer they gave changes. Prepare forwards its
/// release's rows whatever this says (FIX 8171).
const PILOT_ROWS_NARROW_ANSWERS: bool = false;

async fn owned<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&oneiron::Vault, &AuthenticatedOwner) -> oneiron::Result<T> + Send + 'static,
) -> MemoryResult<T> {
    let owner = owner_proof(auth, server, verb)?;
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || {
        act(server.vault(), &owner).map_err(MemoryError::from)
    })
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
/// (FIX 5482, FIX 8171), read from the answer itself, forwarded as they are:
/// unknown (`None`) only when a snapshot's is. A refusal carries nothing and
/// lists none (FIX 6080).
async fn owned_sourced<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&oneiron::Vault, &AuthenticatedOwner) -> oneiron::Result<T> + Send + 'static,
    listed: impl FnOnce(&T) -> Option<Vec<oneiron::EntityId>>,
) -> MaybeListed<T> {
    let answer = owned(server, auth, verb, act).await;
    let rows = answer.as_ref().map_or_else(|_| Some(Vec::new()), listed);
    (answer, rows)
}

/// A pilot door's answer beside its listing as before, or, while
/// [`PILOT_ROWS_NARROW_ANSWERS`] holds, the pilot's frozen set (FIX 5761).
fn pilot_listed<T>(
    (answer, before): Listed<T>,
    pilot: impl FnOnce(&T) -> Option<Vec<oneiron::EntityId>>,
) -> MaybeListed<T> {
    let rows = match &answer {
        Ok(found) if PILOT_ROWS_NARROW_ANSWERS => pilot(found),
        _ => Some(before),
    };
    (answer, rows)
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
    // The release commits whole; its rows are read from the answer, so no
    // source failure fails the prepare (FIX 5761), and are forwarded as they
    // are (FIX 8171): unknown only when the release's are.
    owned_sourced(
        server,
        auth,
        "vault.coach.training_offers.pilots.prepare",
        move |vault, owner| offer_pilot::prepare_pilot(vault, owner, input),
        offer_pilot::listed_prepared,
    )
    .await
}

pub(crate) async fn vault_coach_training_offers_pilots_complete(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: offer_pilot::OfferPilotComplete,
) -> MaybeListed<oneiron::skill_optimize::offer_pilot::OfferPilot> {
    let answer = owned_control(
        server,
        auth,
        "vault.coach.training_offers.pilots.complete",
        move |vault, owner| offer_pilot::complete_pilot(vault, owner, input),
    )
    .await;
    pilot_listed(answer, offer_pilot::listed_pilot)
}

pub(crate) async fn vault_coach_training_offers_pilots_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: offer_pilot::OfferPilotRef,
) -> MaybeListed<Option<oneiron::skill_optimize::offer_pilot::OfferPilot>> {
    let answer = owned_control(
        server,
        auth,
        "vault.coach.training_offers.pilots.get",
        move |vault, owner| offer_pilot::pilot(vault, owner, input),
    )
    .await;
    // No pilot found lists none.
    pilot_listed(answer, |found: &Option<offer_pilot::OfferPilot>| {
        found
            .as_ref()
            .map_or(Some(Vec::new()), offer_pilot::listed_pilot)
    })
}
