//! Joining: the inquiry edge a member seat carries from joining
//! (federation.md #inquiry-first-build). The member's offer and what its
//! prepare answers, the WORLD the join's pact fixes, whether a seat already
//! carries its edge, the live Connect that refuses an edge, and the unbound
//! edge an earlier prepare left.

use crate::Vault;
use crate::authority::{
    AuthorityFold, AuthorityVaultId, ConnectOffer, FederationGrantActivation,
    federation_grant_activation,
};
use crate::entity_id::{EntityId, derived_domains, is_foreign_world_id_range};
use crate::error::Result;
use crate::federation::{
    ConnectMemberLeaveBinding, decode_federation_grant_body, require_one_connect_per_peer,
};
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

use super::super::record::InquiryKeep;
use super::super::terms::{InquiryKeepModes, InquiryTerms, InquiryTierCeiling};
use super::lookup::inquiry_edge_in_txn;
use super::{InquiryEdge, PROPOSE_VERB_CLASS, inquiry_edge_scope, refused};

/// A member's inquiry edge offered to a company at joining: the member's
/// own name for the edge, and the member host's signed
/// half of the Connect that binds the edge to the company's reciprocal
/// grant. The Connect names that WORLD before the company writes it: the
/// pact's id fixes it (`derived_domains::INQUIRY_JOIN_WORLD`). It carries
/// the pact's scope opening key, so it travels between the two hosts and is
/// never logged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InquiryJoinOffer {
    /// The member's name, as the member's offer gives it. The company names
    /// the edge's WORLD for the seat's PERSON as it holds it, never for this
    /// (FIX INQUIRY-EDGE-ONE-PER-SEAT).
    pub member_name: String,
    /// The member host's half of the Connect.
    pub connect: ConnectOffer,
}

/// What [`Vault::prepare_inquiry_edge_for_join`] answers: the member's edge,
/// and the offer the company takes with the seat.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InquiryJoinPrepared {
    /// The member's inquiry edge to the company, inert until the company's
    /// counter is applied on its grant.
    pub edge: InquiryEdge,
    /// The offer the company's accept takes.
    pub offer: InquiryJoinOffer,
}

/// How many derivations [`inquiry_join_world`] tries for an id outside the
/// received-foreign range; each lands in it one time in sixteen.
const JOIN_WORLD_DERIVATIONS: u64 = 64;

/// The company's WORLD of the inquiry edge the Connect pact `pact_id` with
/// the company `company_vault_id` binds at joining: derived from both, so the
/// member's host names it in its offer before the company's accept writes
/// it. The first derivation outside the received-foreign range, since the
/// WORLD is the company's own.
pub(super) fn inquiry_join_world(
    company_vault_id: &AuthorityVaultId,
    pact_id: &[u8; 32],
) -> Result<EntityId> {
    for counter in 0..JOIN_WORLD_DERIVATIONS {
        let id = EntityId::derive(
            derived_domains::INQUIRY_JOIN_WORLD,
            &[company_vault_id, pact_id, &counter.to_le_bytes()],
        )?;
        if !is_foreign_world_id_range(id) {
            return Ok(id);
        }
    }
    Err(refused("no local WORLD id derives from this Connect pact"))
}

/// Whether the live grant `grant` is `seat`'s inquiry edge on the company
/// side, as [`Vault::join_inquiry_edge_in_txn`] mints it: bound to end with
/// that seat, and `propose` alone over the one WORLD the id of its pact
/// `pact_id` fixes ([`inquiry_join_world`]). A Connect grant the member's
/// leave releases for any other reason is no inquiry edge (review round 2
/// of #9195).
pub(super) fn is_seat_inquiry_grant_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    local: &AuthorityVaultId,
    grant: &EntityId,
    pact_id: &[u8; 32],
    seat: ConnectMemberLeaveBinding,
) -> Result<bool> {
    let LiveEntityRow::Live {
        entity_type: ENTITY_TYPE_FEDERATION_GRANT,
        body,
    } = live_entity_row_in_txn(&vault.store, txn, grant)?
    else {
        return Ok(false);
    };
    let Ok(body) = decode_federation_grant_body(&body) else {
        return Ok(false);
    };
    let reciprocal = inquiry_edge_scope(inquiry_join_world(local, pact_id)?, PROPOSE_VERB_CLASS);
    Ok(body.detach_on_member_leave == Some(seat)
        && body.authority_scope.worlds == reciprocal.worlds
        && body.authority_scope.verbs == reciprocal.verbs)
}

/// Whether `seat` already carries a live inquiry edge here: a grant its
/// member's leave releases that is the seat's inquiry edge
/// ([`is_seat_inquiry_grant_in_txn`]) for a pact that binds it, with that
/// pact Active or Suspended. An unpacted grant joins no edge, and a terminal
/// pact has ended its edge.
pub(super) fn seat_carries_inquiry_edge_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    local: &AuthorityVaultId,
    seat: ConnectMemberLeaveBinding,
) -> Result<bool> {
    for grant in
        vault.live_bound_connect_grants_in_txn(txn, seat.shared_vault_id, seat.person_ref)?
    {
        let live = match federation_grant_activation(fold, &grant) {
            FederationGrantActivation::Active => true,
            FederationGrantActivation::Inactive(status) => !status.is_terminal(),
            FederationGrantActivation::Unpacted => false,
        };
        if !live {
            continue;
        }
        for pact_id in fold
            .federation_grant_bindings
            .get(&grant)
            .into_iter()
            .flatten()
        {
            if is_seat_inquiry_grant_in_txn(vault, txn, local, &grant, pact_id, seat)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Refuses an inquiry edge to `company` while this vault has a live Connect
/// with it: the grant row is never widened in place and a re-scope only
/// narrows, so the member disconnects that Connect first (Engine ruling
/// INQUIRE-EDGE-JOIN = A).
pub(super) fn refuse_live_connect_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    company: &AuthorityVaultId,
) -> Result<()> {
    let fold = vault.authority_fold_readonly_in_txn(txn)?;
    if require_one_connect_per_peer(&fold, company, None).is_err() {
        return Err(refused(
            "this vault already has a live Connect with that company, and an inquiry \
             edge cannot join it yet: disconnect that Connect first, then mint the edge",
        ));
    }
    Ok(())
}

/// The inquiry edge to `company` on the member defaults
/// ([`InquiryEdgeRequest::member_defaults`](super::InquiryEdgeRequest::member_defaults)),
/// with no expiry, that no pact
/// binds yet: what an earlier prepare left when its offer was lost or never
/// accepted. The next prepare offers it again rather than minting a second
/// edge. An unbound edge the owner minted on other terms is never offered:
/// the join advertises the defaults, which the member changes after it.
pub(super) fn unbound_inquiry_edge_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    company: &AuthorityVaultId,
) -> Result<Option<InquiryEdge>> {
    let fold = vault.authority_fold_readonly_in_txn(txn)?;
    for entry in crate::ports::EntityStoreRead::port_entity_ids_by_type(
        &vault.store,
        txn,
        ENTITY_TYPE_FEDERATION_GRANT,
        None,
    )? {
        let grant = entry?;
        if fold.federation_grant_bindings.contains_key(&grant) {
            continue;
        }
        if let Some(edge) = inquiry_edge_in_txn(vault, txn, &grant)?
            && edge.company_vault_id == *company
            && edge.expires_at.is_none()
            && has_member_default_terms(&edge.terms)
        {
            return Ok(Some(edge));
        }
    }
    Ok(None)
}

/// Whether `terms` are the member defaults an edge minted by
/// [`InquiryEdgeRequest::member_defaults`](super::InquiryEdgeRequest::member_defaults)
/// holds; the opened WORLD aside.
fn has_member_default_terms(terms: &InquiryTerms) -> bool {
    terms.tier_ceiling == InquiryTierCeiling::default()
        && terms.check_in_modes == InquiryKeepModes::default()
        && terms.keep_allowed == InquiryKeep::default()
}
