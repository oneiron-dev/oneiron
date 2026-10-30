use super::*;

/// What the old-record read decides: whether the body and the consolidation
/// changed, the previous SKILL record, and the optimizer-birth marker a
/// genuine optimizer create stages with its body.
pub(super) struct OldRecord {
    pub(super) body_changed: bool,
    pub(super) consolidation_dirty: bool,
    /// Whether the row was stored before this put (FIX 11925).
    pub(super) stored_before: bool,
    pub(super) previous_skill_record: Option<crate::skill::SkillRecord>,
    pub(super) optimizer_birth_marker: Option<crate::side_table::StagedRow>,
}

/// P4: read the old record — compare bodies, deindex stale text, judge the
/// overwrite per kind, and admit genuine SKILL and AGENT_DEF creates.
pub(super) fn apply_old_record(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    data: &[u8],
    fixed: &super::admission::FixedPut<'_>,
    dispatch: &super::admission::Dispatch,
    portable_agent_source: &mut Option<(EntityId, Vec<u8>)>,
) -> Result<OldRecord> {
    let mut body_changed = true;
    let mut consolidation_dirty = true;
    let mut stored_before = false;
    let mut previous_skill_record = None;
    // ONE-1449 MATERIAL-6 R1: the optimizer-birth marker this create must
    // either match or be born with. Computed by the SKILL create arm below
    // while the transaction is still borrowed for reads, and staged at the
    // pre-write site further down — the same check-here / mutate-there split
    // the ONE-1604-D1 eviction above takes, and for the same reason: the arm
    // that decides holds a read borrow of `wtxn`.
    let mut optimizer_birth_marker = None;
    if let Some(old_record) =
        crate::ports::EntityStoreRead::port_entity_raw_wiped(store, wtxn, &fixed.id)?
    {
        stored_before = true;
        let (old_type, old_occurred, old_learned) = parse_entity_metadata(&old_record)?;
        previous_skill_record = super::super::decode_previous_skill_record(old_type, &old_record)?;
        // ONE-1141 + ONE-1168 (ARCH-0031 amendment): body-changing overwrites
        // must not leave stale BM25F postings live. Replicated/LWW overwrites
        // always deindex the loser because sync carries no `BatchOp::Text`.
        // Local overwrites do the same unless this batch has a later same-id
        // Text op; a Text that already ran may describe an earlier body and
        // must not cover this overwrite. If a later Text is present,
        // `index_text` remains the self-deindex authority. Token source: the
        // body-independent `text_forward` row — `deindex_text` reads only it
        // and is a no-op for never-indexed entities. Byte-compare guard:
        // same-bytes replay must NOT touch the index, and metadata-only
        // (occurred/learned) changes are not body changes.
        body_changed = old_record[ENTITY_METADATA_HEADER_LEN..] != *data;
        consolidation_dirty = body_changed || old_learned != fixed.learned_at;
        // Retaining an indexed text revision is not permission to retain a
        // withdrawn claim or a replicated LWW loser in the search index.
        // Local, still-surfaceable text edits alone await idle publication.
        let withdrawn_claim = dispatch
            .decoded_claim_body
            .as_ref()
            .is_some_and(|body| !crate::claim::claim_surfaceable(body));
        let should_deindex_stale_text = body_changed
            && (withdrawn_claim
                || fixed.replicated
                || (!fixed.options.indexing.later_text_op_covers
                    // A custody body is never decoded here; its string
                    // fields made the answer true before.
                    && fixed.entity_type != crate::registry::ENTITY_TYPE_SECRET_CUSTODY
                    && !crate::vault::entity_revision::storage_manages_text(
                        store, wtxn, &fixed.id, data,
                    )?));
        let old_code_artifact_body =
            if old_type == crate::registry::ENTITY_TYPE_CODE_ARTIFACT && body_changed {
                Some(old_record[ENTITY_METADATA_HEADER_LEN..].to_vec())
            } else {
                None
            };
        if old_type != fixed.entity_type {
            return Err(Error::Registry(RegistryError::EntityTypeImmutable {
                id: fixed.id,
                existing: old_type,
                attempted: fixed.entity_type,
            }));
        }
        // ONE-1686: MESSAGE identity is an idempotency key, not an update
        // handle. Executor retries deliberately re-PUT the same deterministic
        // id before replay-record CAS; byte-identical bodies converge, while a
        // race or divergent retry at the same run/order must never overwrite
        // the winner's bubble and leave the replay log describing other text.
        // This shared chokepoint covers witness, promote replay and every
        // internal local path. Replicated MESSAGEs have already failed closed
        // above, and public raw puts never reach this arm.
        if old_type == ENTITY_TYPE_MESSAGE && body_changed {
            return Err(Error::Record(RecordError::InvalidWitnessMessageBody(
                "an existing MESSAGE fixed.id is bound to its original canonical body",
            )));
        }
        if old_type == ENTITY_TYPE_TASK {
            validate_immutable_task_record(
                &old_record,
                old_occurred,
                old_learned,
                fixed.occurred,
                fixed.learned_at,
                data,
                body_changed,
            )?;
        }
        if old_type == ENTITY_TYPE_SKILL && body_changed {
            let updated = dispatch
                .new_skill_record
                .as_ref()
                .ok_or(Error::InvariantViolation("validated SKILL record missing"))?;
            validate_skill_body_overwrite(
                &fixed.id,
                &old_record[ENTITY_METADATA_HEADER_LEN..],
                updated,
                fixed.hub_sync_imported,
                fixed.replicated,
                fixed.hub_admission,
            )?;
        }
        if old_type == ENTITY_TYPE_AGENT_DEF && body_changed {
            let updated =
                dispatch
                    .new_agent_definition
                    .as_ref()
                    .ok_or(Error::InvariantViolation(
                        "validated AGENT_DEF record missing",
                    ))?;
            // No legacy-opaque escape hatch (contrast SKILL): AGENT_DEF is a
            // brand-new kind with no pre-existing bodies, so a prior body that
            // fails to decode is corruption — fail closed.
            let prior_body = &old_record[ENTITY_METADATA_HEADER_LEN..];
            let prior = crate::agent_def::decode_agent_definition(prior_body)?;
            crate::agent_def::validate_agent_definition_update(&prior, updated)?;
        }
        if old_type == crate::registry::ENTITY_TYPE_CODE_ARTIFACT
            && body_changed
            && crate::code_revision::has_finalized_code_revision_in_txn(store, wtxn, &fixed.id)?
        {
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "finalized code revision artifacts are immutable",
            )));
        }
        if let Some(old_code_artifact_body) = old_code_artifact_body {
            crate::codebase::reconcile_codebase_snapshot_after_code_artifact_put(
                store,
                wtxn,
                &fixed.id,
                &old_code_artifact_body,
                data,
            )?;
        }
        if should_deindex_stale_text {
            crate::bm25::deindex_text(store, wtxn, &fixed.id)?;
        }

        super::super::put_staging::remove_prior_temporal_index_rows(
            store,
            wtxn,
            &fixed.id,
            old_occurred,
            old_learned,
            fixed.occurred,
            fixed.learned_at,
        )?;
    } else if fixed.entity_type == ENTITY_TYPE_AGENT_DEF && !fixed.replicated {
        // ONE-1890 mirror of the SKILL create gate below, one entity type
        // over: LOCAL creates only, so genuine creates are gated and updates
        // stay on the arm above. Fork lineage must name a real type-17 parent
        // ROW, and the child's ceiling may not widen beyond that parent's
        // STORED ceiling — the relocated no-widen check, which necessarily
        // lives here because body-only validation cannot load the parent row.
        // The gate-time clamp (GATE-HALF) covers the same bound live.
        let created = dispatch
            .new_agent_definition
            .as_ref()
            .ok_or(Error::InvariantViolation(
                "validated AGENT_DEF record missing",
            ))?;
        validate_local_agent_definition_create(store, wtxn, &fixed.id, created)?;
        *portable_agent_source =
            crate::agent_def::bind_agent_birth_in_txn(store, wtxn, &fixed.id, created)?;
    } else if fixed.entity_type == ENTITY_TYPE_SKILL {
        let created = dispatch
            .new_skill_record
            .as_ref()
            .ok_or(Error::InvariantViolation("validated SKILL record missing"))?;
        // ONE-1449 MATERIAL-6 R1: origin is a birth fact that outlives the
        // BODY, not just the record. The update arm above freezes optimizer
        // origin for the life of an entity — but a delete ends that life while
        // the id, its verdict ledger and its gate history all survive, so a
        // same-id recreate used to re-present an optimizer-born id as a virgin
        // ordinary candidate and walk it to `active` through the owner's door.
        // The durable marker refuses exactly that, and is born here for a
        // genuine optimizer create.
        //
        // On EVERY create road, sync remat included (ONE-1449 K3 M-5). The
        // marker is a fact about the ID, and a replica that first meets an
        // optimizer-born id through remat holds the same id, the same gate
        // history and the same laundering road: leaving it unmarked there let
        // a local delete plus an ordinary same-id create walk it to `active`
        // through the owner's door, and that laundered body then travelled
        // back. Marking is not "re-deciding settled remote state" — the row
        // itself is written exactly as the peer sent it, and a peer that sent
        // an origin this id has already recorded differently is refused by the
        // same rule a local recreate is, which is a remote rejection the sync
        // door quarantines rather than a divergence it hides.
        optimizer_birth_marker = crate::skill_optimize::optimizer_birth_marker_for_create_in_txn(
            store,
            &*wtxn,
            &fixed.id,
            created,
            fixed.replicated,
        )?;
        // The birth law itself is LOCAL-only, and stays that way: sync remat
        // keeps writing already-lifecycled records.
        if !fixed.replicated {
            validate_local_skill_create(store, &*wtxn, &fixed.id, created)?;
        }
    }
    Ok(OldRecord {
        body_changed,
        consolidation_dirty,
        stored_before,
        previous_skill_record,
        optimizer_birth_marker,
    })
}
