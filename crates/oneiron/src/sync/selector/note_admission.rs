//! Transaction-bound NOTE selector admission. No cached subscription is authority.

use super::codec::SyncSelector;
use super::document_admission::{admit_selected_in_txn, authorize_in_txn};
use crate::error::Result;
use crate::federation::{FederationDirectionScope, FederationGrantRole, FederationGrantScope};
use crate::{EntityId, Vault};

/// Admits NOTE `id` through `selector` and returns the position it resolved.
pub(crate) fn admit_note_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    scope: FederationGrantScope,
    selector: &SyncSelector,
    writer: Option<EntityId>,
) -> Result<FederationDirectionScope> {
    let admission = authorize_in_txn(vault, txn, scope, selector, writer)?;
    let raw = vault.get_raw_in(txn, &id)?.ok_or_else(denied)?;
    let header = crate::batch::EntityMetadataHeader::parse(&raw).ok_or_else(denied)?;
    if header.entity_type != crate::registry::ENTITY_TYPE_NOTE
        || vault.local_hard_delete_marker_exists_in_txn(txn, &id)?
        || vault.store.off_record_sessions.contains_entity(&id)?
    {
        return Err(denied());
    }
    let birth = crate::note::decode_note_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])?;
    let fold = &admission.fold;
    if let Some(actor) = writer
        && actor != birth.author_ref
        && (admission.grant.role != FederationGrantRole::Owner
            || fold.vault_id.is_none()
            || fold.vault_root_is_conflicted()
            || !crate::authority::actor_binding_is_active(fold, &actor, "human"))
    {
        // The embedded unrooted host fallback is not remote owner authority.
        return Err(denied());
    }
    admit_selected_in_txn(vault, txn, id, scope, selector, &admission)?;
    Ok(admission.position)
}

fn denied() -> crate::Error {
    crate::Error::sync_protocol(crate::error::SyncProtocolValidation::DocumentAdmissionDenied)
}
