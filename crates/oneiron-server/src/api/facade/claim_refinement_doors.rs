//! The owner's claim-refinement doors under the caller's owner proof (FIX
//! [SKILL-HUB-PROMOTION-VERBS]): the held-out reserve of a claim base and the
//! offer of one session-branch edit. The merge stays the owner's approve route
//! (`POST /v1/owner/claims/refinements/{candidate}/approve`).
use std::sync::Arc;

use oneiron::task_verb::sdk::{self, *};

use super::host_doors::support::Listed;
use super::hub_doors::owner_call;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.claims.refinements.holdouts.reserve`: it lists the base and every
/// label it reserved.
pub(crate) async fn vault_claims_refinements_holdouts_reserve(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ClaimRefinementHoldoutRequest,
) -> Listed<oneiron::task_verb::sdk::ClaimRefinementHoldoutReserved> {
    owner_call(
        server,
        auth,
        "vault.claims.refinements.holdouts.reserve",
        move |server, owner| {
            let answer =
                sdk::claim_refinement_holdout_reserve_as_owner(server.vault(), owner, &input)?;
            let rows = std::iter::once(answer.base)
                .chain(answer.labels.iter().copied())
                .collect();
            Ok((answer, rows))
        },
    )
    .await
}

/// `vault.claims.refinements.offer`: it lists the base it read, the resident
/// it checked and the branch claim it staged.
pub(crate) async fn vault_claims_refinements_offer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ClaimRefinementOfferRequest,
) -> Listed<oneiron::task_verb::sdk::ClaimRefinementOffered> {
    owner_call(
        server,
        auth,
        "vault.claims.refinements.offer",
        move |server, owner| {
            let answer = sdk::claim_refinement_offer_as_owner(server.vault(), owner, &input)?;
            let rows = vec![answer.base, answer.resident, answer.candidate];
            Ok((answer, rows))
        },
    )
    .await
}
