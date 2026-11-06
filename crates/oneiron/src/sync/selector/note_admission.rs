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
    admit_note_in_txn_with_scope(vault, txn, id, scope, selector, writer, None)
}

pub(crate) fn admit_note_in_txn_with_scope(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    scope: FederationGrantScope,
    selector: &SyncSelector,
    writer: Option<EntityId>,
    credential_scope: Option<&crate::federation::Scope>,
) -> Result<FederationDirectionScope> {
    let mut admission = authorize_in_txn(vault, txn, scope, selector, writer)?;
    if let Some(bound) = credential_scope {
        admission.grant.authority_scope = admission.grant.authority_scope.meet(bound);
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
    let fold = &admission.fold;
    // An erased birth author is no one: it never authenticates a writer, who
    // then needs the independent owner check below.
    if let Some(actor) = writer
        && !birth.author_ref.is(actor)
        && (admission.grant.role != FederationGrantRole::Owner
            || fold.vault_id.is_none()
            || fold.vault_root_is_conflicted()
            || !crate::authority::actor_binding_is_active(fold, &actor, "human"))
    {
        // The embedded unrooted host fallback is not remote owner authority.
        return Err(denied());
    }
    admit_selected_in_txn(vault, txn, id, selector, &admission)?;
    Ok(admission.position.into_scope())
}

fn denied() -> crate::Error {
    crate::Error::sync_protocol(crate::error::SyncProtocolValidation::DocumentAdmissionDenied)
}
