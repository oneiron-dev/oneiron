use super::*;

/// The side rows P5 stages with the body: the SKILL hub-origin marker, the
/// optimizer-birth marker, and the AGENT id pin.
pub(super) struct StagedMarkers {
    pub(super) hub_origin_marker: Option<crate::side_table::StagedRow>,
    pub(super) optimizer_birth_marker: Option<crate::side_table::StagedRow>,
    pub(super) agent_id_pin: Option<crate::side_table::StagedRow>,
}

/// P5: audit the put and stage the body — claim attachments, markers, the
/// entity body row, and the ASSET body file arm.
pub(super) fn audit_and_stage_body(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    data: &[u8],
    fixed: &super::admission::FixedPut<'_>,
    dispatch: &super::admission::Dispatch,
    body_changed: bool,
    previous_skill_record: &Option<crate::skill::SkillRecord>,
    markers: StagedMarkers,
) -> Result<()> {
    if body_changed && let Some(body) = dispatch.decoded_claim_body.as_ref() {
        if fixed.replicated {
            crate::gate::attach_replicated_critical_confirm_in_txn(store, wtxn, &fixed.id, body)?;
        }
        // A claim whose owner has not answered stays held through any new
        // revision, and its owner is shown an item for this one.
        crate::gate::show_owner_answer_item_in_txn(store, wtxn, &fixed.id, Some(body))?;
    }

    // Past every check that can reject this row remotely: a replicated row
    // under a provisional id retires the local provisional entity only when
    // it lands (see `release_held_id_in_txn`).
    if fixed.replicated {
        crate::tagging::release_held_id_in_txn(store, wtxn, &fixed.id)?;
    }
    crate::ports::withdraw_before_rewrite_in_txn(store, wtxn, &fixed.id)?;
    crate::ingest::invalidate_docs_source_before_put(
        store,
        wtxn,
        &fixed.id,
        fixed.entity_type,
        data,
        fixed.options.storage.asset_file,
    )?;
    crate::ports::keep_worlds_of_unmade_epoch_in_txn(
        store,
        wtxn,
        &fixed.id,
        fixed.entity_type,
        data,
    )?;

    // ONE-1449 MATERIAL-6 R1: staged in the SAME transaction as the body it
    // marks, so a rolled-back create leaves no marker and a committed one can
    // never be re-presented as an ordinary birth. Only a genuine optimizer-born
    // create at an unmarked id produces a row here.
    stage_optional_side_row(store, wtxn, markers.optimizer_birth_marker)?;
    stage_optional_side_row(store, wtxn, markers.agent_id_pin)?;
    crate::ports::audit_entity_put_in_txn(
        store,
        wtxn,
        crate::ports::EntityPutAudit {
            id: fixed.id,
            entity_type: fixed.entity_type,
            occurred: fixed.occurred,
            learned_at: fixed.learned_at,
            data,
            envelope: fixed.write_envelope,
            transition: fixed.transition,
        },
    )?;
    crate::gate::manifest_authenticity::update_manifest_origin(
        store,
        wtxn,
        &fixed.id,
        fixed.entity_type,
        data,
        fixed.replicated,
    )?;
    crate::ingest::invalidate_blob_fingerprint(store, wtxn, &fixed.id)?;
    if body_changed && let Some(body) = dispatch.decoded_claim_body.as_ref() {
        crate::dreamer_consolidation::mark_person_about_moved_in_txn(store, wtxn, fixed.id, body)?;
    }
    stage_claim_projection(
        store,
        wtxn,
        fixed.id,
        dispatch.decoded_claim_body.as_ref(),
        fixed.replicated,
    )?;
    stage_optional_side_row(store, wtxn, markers.hub_origin_marker)?;
    crate::skill_hub::stage_source_custody_put(
        store,
        wtxn,
        &fixed.id,
        fixed.entity_type,
        data,
        previous_skill_record.as_ref(),
        dispatch.new_skill_record.as_ref(),
    )?;
    crate::skill_hub::stage_refinement_carrier_put(
        store,
        wtxn,
        &fixed.id,
        fixed.entity_type,
        data,
    )?;
    if fixed.entity_type == ENTITY_TYPE_CHANNEL_IDENTITY {
        crate::channel_identity::maintain_assignment_put(store, wtxn, &fixed.id, data)?;
    }
    // OF-272: the write unit re-keys the identity's slot before it commits.
    crate::channel_identity::note_claim_put_for_rekey(
        store,
        wtxn,
        &fixed.id,
        dispatch.decoded_claim_body.as_ref(),
    )?;
    if fixed.entity_type == ENTITY_TYPE_COMM_RECORD {
        crate::comm::maintain_pending_stop_put(store, wtxn, &fixed.id, data)?;
    }
    // A local put over an erased row is a sanctioned recreation: the row it
    // writes is live, so the fence goes in the same commit. A row that still
    // has its body is fenced by an accepted delete awaiting its retry, and a
    // local edit does not withdraw that delete.
    if !fixed.replicated
        && store.port_deletion_marked(wtxn, DeletionMarker::RowFence, &fixed.id)?
        && crate::ports::EntityStoreRead::port_entity_raw_wiped(store, wtxn, &fixed.id)?
            .is_none_or(|old| old.len() == ENTITY_METADATA_HEADER_LEN)
    {
        crate::deletion::ROW_DELETION_FENCE.delete(store, wtxn, &HexId(fixed.id))?;
    }
    stage_entity_body_row(
        store,
        wtxn,
        &fixed.id,
        fixed.entity_type,
        fixed.occurred,
        fixed.learned_at,
        data,
    )?;
    if fixed.entity_type == crate::registry::ENTITY_TYPE_ASSET {
        crate::store::stage_asset_body_in_txn(
            store,
            wtxn,
            &fixed.id,
            data,
            fixed.options.storage.asset_file,
        )?;
    } else if fixed.options.storage.asset_file.is_some() {
        return Err(Error::InvariantViolation(
            "only an ASSET's body lives in an asset body file",
        ));
    }
    Ok(())
}
