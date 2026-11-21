//! The live inquiry edge a grant names.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::{FederationGrant, FederationGrantScope, decode_federation_grant_body};
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

use super::{InquiryEdge, refused};

/// The inquiry edge `grant` names, with the grant it decodes from, when it
/// is a live inquiry edge here. "Live" is the grant's row: its expiry, its
/// withdrawal and its pact are the caller's to check.
pub(in crate::inquiry) fn inquiry_edge_grant_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    grant: &EntityId,
) -> Result<Option<(InquiryEdge, FederationGrant)>> {
    let LiveEntityRow::Live {
        entity_type: ENTITY_TYPE_FEDERATION_GRANT,
        body,
    } = live_entity_row_in_txn(&vault.store, txn, grant)?
    else {
        return Ok(None);
    };
    let decoded = decode_federation_grant_body(&body)?;
    let (FederationGrantScope::Connect { peer_vault_id }, Some(terms)) =
        (&decoded.scope, decoded.inquiry_terms)
    else {
        return Ok(None);
    };
    let edge = InquiryEdge {
        grant: *grant,
        company_vault_id: *peer_vault_id,
        guest_actor: decoded.member_ref,
        authority_scope: decoded.authority_scope.clone(),
        terms,
        expires_at: decoded.expires_at,
    };
    Ok(Some((edge, decoded)))
}

/// The inquiry edge `grant` names, when it is a live inquiry edge here.
pub(in crate::inquiry) fn inquiry_edge_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    grant: &EntityId,
) -> Result<Option<InquiryEdge>> {
    Ok(inquiry_edge_grant_in_txn(vault, txn, grant)?.map(|(edge, _)| edge))
}

pub(super) fn require_inquiry_edge_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    grant: &EntityId,
) -> Result<InquiryEdge> {
    inquiry_edge_in_txn(vault, txn, grant)?
        .ok_or_else(|| refused("that grant is not a live inquiry edge of this vault"))
}
