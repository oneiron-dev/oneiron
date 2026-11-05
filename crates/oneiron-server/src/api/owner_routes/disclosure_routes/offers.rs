//! The owner's open-offer list, using the singular offer's frozen view.

use std::sync::Arc;

use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{MethodRouter, get};
use oneiron::consent::ContactDisclosureProposal;
use oneiron::consent::widen::WidenProposal;
use serde::{Deserialize, Serialize};

use super::{
    CONTACT_CLEARANCE_REVOKE_COMMAND, CoreAuth, OfferView, OwnerReply, OwnerResult, OwnerRoute,
    SyncServer, blocking, contact_clearance_ref, hex_bytes, owner, query_params,
};

pub(super) fn route() -> (OwnerRoute, MethodRouter<Arc<SyncServer>>) {
    (
        OwnerRoute {
            method: "get",
            path: "/disclosure/offers",
            summary: "This owner's open contact-disclosure offers, in reference-ordered pages.",
            row: None,
            shape: None,
        },
        get(offers),
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OffersQuery {
    after: Option<String>,
    limit: usize,
}

#[derive(Debug, Serialize)]
struct OffersPage {
    offers: Vec<OfferView>,
    next_after: Option<String>,
}

async fn offers(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<OffersQuery>, QueryRejection>,
) -> OwnerReply<OffersPage> {
    let owner = owner(&auth, &server)?;
    let query = query_params(query)?;
    let page = blocking(move || -> OwnerResult<OffersPage> {
        let (offers, next_after) = server.vault().contact_disclosure_offers(
            &owner,
            query.after.as_deref(),
            query.limit,
        )?;
        Ok(OffersPage {
            offers: offers.into_iter().map(OfferView::from).collect(),
            next_after,
        })
    })
    .await?;
    Ok(Json(page))
}

impl From<(WidenProposal, ContactDisclosureProposal)> for OfferView {
    fn from((widen, proposal): (WidenProposal, ContactDisclosureProposal)) -> Self {
        let offer = proposal.offer;
        Self {
            canonical_delta: hex_bytes(&widen.canonical_delta),
            proposal_ref: widen.proposal_ref,
            proposer: widen.proposer,
            owner_ref: widen.owner_ref,
            created_at: widen.created_at,
            expires_at: widen.expires_at,
            contact: offer.contact_ref.to_hex(),
            grant_ref: contact_clearance_ref(&offer.contact_ref),
            revoke_command: CONTACT_CLEARANCE_REVOKE_COMMAND,
            scope: offer.scope,
            purpose: offer.purpose,
            channel: offer.channel,
            beneficiary: offer.beneficiary_ref,
            ask: offer.ask_ref,
            prior_clearance_digest: hex_bytes(&proposal.prior_clearance_digest),
        }
    }
}
