//! Transaction-bound NOTE selector admission. No cached subscription is authority.

use super::codec::SyncSelector;
use super::document_admission::{DocumentGrant, authorize_in_txn};
use crate::error::Result;
use crate::federation::{FederationGrantRole, FederationGrantScope};
use crate::{EntityId, Vault};

pub(crate) fn admit_note_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    scope: FederationGrantScope,
    selector: &SyncSelector,
    writer: Option<EntityId>,
) -> Result<()> {
    let DocumentGrant { grant, fold, empty } =
        authorize_in_txn(vault, txn, scope, selector, writer)?;
    // NOTE has no legal FacetOf source stamp. Do not guess a one-hop closure
    // from a stale window in a write transaction; narrowed facet lanes refuse.
    if selector.facet_filter_active(empty) {
        return Err(denied());
    }
    let raw = vault.get_raw_in(txn, &id)?.ok_or_else(denied)?;
    let header = crate::batch::EntityMetadataHeader::parse(&raw).ok_or_else(denied)?;
    if header.entity_type != crate::registry::ENTITY_TYPE_NOTE
        || vault.local_hard_delete_marker_exists_in_txn(txn, &id)?
        || vault.store.off_record_sessions.contains_entity(&id)?
    {
        return Err(denied());
    }
    let birth = crate::note::decode_note_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])?;
    if let Some(actor) = writer
        && actor != birth.author_ref
        && (grant.role != FederationGrantRole::Owner
            || fold.vault_id.is_none()
            || fold.vault_root_is_conflicted()
            || !crate::authority::actor_binding_is_active(&fold, &actor, "human"))
    {
        // The embedded unrooted host fallback is not remote owner authority.
        return Err(denied());
    }
    if super::scope::entity_selector_decision(
        &id,
        &raw,
        scope,
        selector,
        &Default::default(),
        empty,
        &Default::default(),
    )
    .is_none()
    {
        return Err(denied());
    }
    Ok(())
}

fn denied() -> crate::Error {
    crate::Error::sync_protocol(crate::error::SyncProtocolValidation::DocumentAdmissionDenied)
}
