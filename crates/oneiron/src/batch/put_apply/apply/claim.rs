use super::*;

/// A sync replay deliberately bypasses the local claim gate. If it changes a
/// claim with a persisted critical-confirm attachment, that attachment binds
/// the old body and cannot authorize the new one. Delete it in this same write
/// transaction and demote an inbound Auto status; notably, do not derive a
/// replacement binding from the changed peer body. Returns the demoted body's
/// bytes, which the put stores instead of `data`, and leaves
/// `decoded_claim_body` holding the demoted body.
pub(super) fn reconcile_replicated_critical_confirm(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    data: &[u8],
    decoded_claim_body: &mut Option<ClaimBody>,
) -> Result<Option<Vec<u8>>> {
    let body_changed = crate::ports::EntityStoreRead::port_entity_raw(store, wtxn, &id)?
        .map(|old| {
            old.get(ENTITY_METADATA_HEADER_LEN..)
                .ok_or(Error::CorruptedIndex("entity header"))
                .map(|body| body != data)
        })
        .transpose()?
        // A live attachment can outlast an entity row during deletion or
        // rematerialization; recreating that row is an overwrite of the
        // ceremony-bound state, not an authority restoration.
        .unwrap_or(true);
    if crate::gate::reconcile_critical_write_confirm_on_replicated_overwrite(
        store,
        wtxn,
        id,
        data,
        body_changed,
    )? {
        let mut reconciled = decoded_claim_body
            .as_ref()
            .ok_or(Error::InvariantViolation("validated CLAIM body missing"))?
            .clone();
        if reconciled.approval == ClaimApprovalStatus::Auto {
            reconciled.approval = ClaimApprovalStatus::Proposed;
        }
        *decoded_claim_body = Some(reconciled.clone());
        Ok(Some(crate::claim::encode_claim_body(&reconciled)?))
    } else {
        Ok(None)
    }
}
