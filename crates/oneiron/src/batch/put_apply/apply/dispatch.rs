use super::*;

/// What the type dispatch carries out of P2 besides the verdicts: the body
/// buffers the TASK and pad arms produce, and the side rows the SKILL and
/// AGENT arms stage with the body in P5.
pub(super) struct DispatchCarry {
    pub(super) task_body_without_streaks: Option<Vec<u8>>,
    pub(super) pad_stored_body: Option<Vec<u8>>,
    pub(super) hub_origin_marker: Option<crate::side_table::StagedRow>,
    pub(super) agent_id_pin: Option<crate::side_table::StagedRow>,
}

/// P2: run the CLAIM gate and the per-kind arms, assigning the dispatch
/// verdicts and carrying the arms' buffers and side rows.
pub(super) fn dispatch_put_type(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    data: &[u8],
    fixed: &super::admission::FixedPut<'_>,
    dispatch: &mut super::admission::Dispatch,
    revision: &mut super::admission::RevisionSlot,
    incoming_claim_body: Option<ClaimBody>,
) -> Result<DispatchCarry> {
    let mut hub_origin_marker = None;
    let mut agent_id_pin = None;
    // STO-03: `Some` only when the incoming TASK body named a derived streak
    // counter, i.e. only on the sync door — the body that gets stored instead.
    let mut task_body_without_streaks = None;
    // KS-5: the reference a pad row stores once custody took its pad.
    let mut pad_stored_body = None;
    if let Some(body) = incoming_claim_body {
        if let Some(prior) =
            crate::ports::EntityStoreRead::port_entity_raw_wiped(store, wtxn, &fixed.id)?
            && prior.get(ENTITY_METADATA_HEADER_LEN..) != Some(data)
        {
            crate::blob_artifact::esign::reject_event_delete(store, wtxn, &fixed.id)?;
        }
        if body.predicate.starts_with("esign.") {
            if fixed.replicated {
                return Err(Error::InvalidClaimBody(
                    "esign events require the local authenticated organ",
                ));
            }
            if let Some(prior) =
                crate::ports::EntityStoreRead::port_entity_raw_wiped(store, wtxn, &fixed.id)?
                && prior.get(ENTITY_METADATA_HEADER_LEN..) != Some(data)
            {
                return Err(Error::InvalidClaimBody("esign events are append-only"));
            }
        }
        crate::subject_model::validate_subject_model_claim_in_txn(store, wtxn, &body)?;
        crate::thread_passport::validate_thread_claim_in_txn(
            store,
            wtxn,
            &fixed.id,
            &body,
            fixed.replicated,
        )?;
        dispatch.is_lexical_query_hint_claim =
            body.predicate == crate::claim::PREDICATE_LEXICAL_QUERY_HINT;
        if dispatch.is_lexical_query_hint_claim {
            super::super::lexical_hint::validate_lexical_query_hint(
                store,
                wtxn,
                fixed.id,
                &body,
                fixed.replicated,
            )?;
        }
        if let Some(prior) =
            crate::ports::EntityStoreRead::port_entity_raw_wiped(store, wtxn, &fixed.id)?
            && crate::batch::EntityMetadataHeader::parse(&prior)
                .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_CLAIM)
            && crate::claim::decode_claim_body(&prior[ENTITY_METADATA_HEADER_LEN..], true)
                .is_ok_and(|stored| stored.scope_facet != body.scope_facet)
        {
            return Err(Error::Registry(RegistryError::FacetStampImmutable {
                src: fixed.id,
            }));
        }
        if body.session_tag.is_some()
            && !fixed.replicated
            && !fixed.claim_gate_prechecked
            && !fixed
                .refinement_admission
                .is_some_and(|proof| proof.binds_claim(&fixed.id, data))
            && !fixed.write_envelope.is_some_and(|envelope| {
                crate::claim::session_claim_producer(&body) == Some(envelope.actor().entity_ref())
            })
        {
            return Err(Error::InvalidClaimBody(
                "sess requires an envelope-bound producer actor",
            ));
        }
        if !(fixed.replicated
            || dispatch.is_lexical_query_hint_claim
                && fixed.options.decision.internal_lexical_query_hint
            || fixed.claim_gate_prechecked)
        {
            let policy = fixed.write_policy.ok_or(Error::InvariantViolation(
                "local claim write policy snapshot missing",
            ))?;
            if fixed.allow_reserved_predicate {
                crate::gate::check_reserved_claim_policy(&body, fixed.write_envelope, policy)?;
            } else {
                crate::gate::check_claim_policy_for_write_with_preflight_decision(
                    store,
                    wtxn,
                    &fixed.id,
                    crate::gate::ClaimGateWrite::plain(&body, fixed.write_envelope)
                        .with_transition(fixed.transition)
                        .with_owner_authored(fixed.owner_authored),
                    policy,
                    fixed.options.gate_write_mode(),
                    fixed.options.decision.preflight,
                )?;
            }
        }
        dispatch.decoded_claim_body = Some(body);
    } else if fixed.entity_type == crate::registry::ENTITY_TYPE_NOTE {
        super::super::validate_note_birth_put(store, wtxn, &fixed.id, data)?;
    } else if fixed.entity_type == crate::registry::ENTITY_TYPE_MESSAGE {
        super::super::claim_admission::validate_witness_message_body(data, fixed.replicated)?;
    } else if fixed.entity_type == crate::registry::ENTITY_TYPE_CODE_ARTIFACT {
        crate::code_artifact::validate_code_artifact_body_bytes(data)?;
    } else if fixed.entity_type == crate::registry::ENTITY_TYPE_BLOB_ARTIFACT {
        crate::blob_artifact::validate_blob_artifact_body_bytes(data)?;
    } else if fixed.entity_type == crate::registry::ENTITY_TYPE_WORLD_KEY_PAD {
        pad_stored_body = crate::world_keys::admit_pad_put_in_txn(store, wtxn, &fixed.id, data)?;
    } else if fixed.entity_type == crate::registry::ENTITY_TYPE_AUTHORITY_LOG {
        if fixed.replicated {
            validate_replicated_authority_log_for_local_vault(
                store,
                wtxn,
                &fixed.id,
                data,
                fixed.posture,
            )?;
        } else {
            crate::authority::validate_authority_log_entry_body_bytes(data)?;
        }
        let entry = crate::authority::decode_authority_log_entry_body(data)?;
        let entry_hash = crate::authority::authority_entry_hash(&entry)?;
        // ONE-1604-D1 chokepoint: every materialization path funnels through
        // here, so the store-key bind, the append-only guard, and the
        // cross-type dominance verdict are computed on every import/replay
        // door in one place. The CHECK runs here (it can still reject); the
        // eviction it authorizes is deferred to the pre-write site below.
        dispatch.authority_dominates_key_squatter =
            check_authority_log_store_key(store, wtxn, &fixed.id, &entry_hash, data)?
                == AuthorityLogKeyOccupant::CrossTypeSquatter;
        // H72: every store door, local or replicated, holds rows no key that
        // may vouch signed. A vouched key's rows land (FIX 8564); strangers'
        // past their shared bound wait (rule 5), a replica retrying each drain.
        match crate::authority::authority_door(store, wtxn, &entry)? {
            crate::authority::AuthorityDoor::Lands => {}
            crate::authority::AuthorityDoor::AtBound => {
                let signer = crate::authority::authority_signer_label(entry.signer_key());
                return Err(Error::Record(RecordError::AuthorityLogFull {
                    id: fixed.id,
                    signer,
                }));
            }
            crate::authority::AuthorityDoor::Unowned => {
                return Err(Error::Record(RecordError::AuthorityLogSignerPending {
                    id: fixed.id,
                }));
            }
        }
        dispatch.authority_entry_hash_pin = Some(entry_hash);
        dispatch.authority_entry_observation = Some(entry);
    } else if crate::workspace_roster::is_project_revision_type(store, fixed.entity_type) {
        let put = crate::workspace_roster::check_revision_put(
            store,
            wtxn,
            fixed.id,
            data,
            fixed.replicated,
            fixed.posture,
        )?;
        revision.squatter = put.squatter;
        revision.put = Some(put);
    } else if fixed.entity_type == crate::registry::ENTITY_TYPE_FEDERATION_GRANT {
        crate::federation::validate_federation_grant_body_bytes(data)?;
    } else if fixed.entity_type == crate::registry::ENTITY_TYPE_ACCESS_GRANT {
        crate::access_grant::validate_access_grant_body_bytes(data)?;
    } else if fixed.entity_type == ENTITY_TYPE_COUNTERPARTY_CONTACT {
        crate::counterparty_contact::validate_counterparty_contact_body_bytes(data)?;
    } else if fixed.entity_type == ENTITY_TYPE_COMM_RECORD {
        crate::comm::validate_comm_record_body_bytes(data)?;
    } else if fixed.entity_type == ENTITY_TYPE_DIAGNOSTIC {
        crate::self_heal::validate_diagnostic_event_admission(&fixed.id, fixed.occurred, data)?;
        crate::self_heal::reject_off_record_diagnostic_sources(store, data)?;
    } else if fixed.entity_type == ENTITY_TYPE_OUTBOUND_GRANT {
        // A standing outbound grant is a standing consent Grant row; no
        // entity of this kind is written.
        return Err(Error::Registry(RegistryError::MaintenanceKindNotWritable(
            fixed.entity_type,
        )));
    } else if fixed.entity_type == ENTITY_TYPE_PSYCH_PROFILE {
        crate::psych_profile::validate_psych_profile_body_bytes(data)?;
    } else if fixed.entity_type == ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT {
        crate::persona_snapshot::validate_persona_snapshot_export_body_bytes(data)?;
    } else if fixed.entity_type == crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
        crate::identity_topology::validate_identity_topology_event_body_bytes(data)?;
    } else if fixed.entity_type == crate::registry::ENTITY_TYPE_SKILL_HUB {
        crate::skill_hub::decode_skill_hub_record(data)?;
    } else if fixed.entity_type == crate::registry::ENTITY_TYPE_CLAIM_CLASS_DESCRIPTOR {
        crate::comm::decode_claim_class_descriptor(data)?;
    } else if fixed.entity_type == crate::registry::ENTITY_TYPE_MODEL {
        // SCAN C046: a MODEL body is the engine's pinned shape on every door.
        // A replica's that fails it is the peer's bytes, refused as a claim
        // body is (quarantined, the batch goes on), never stored to wedge
        // the model substrate.
        crate::provenance::decode_model_entity_body(data)
            .map_err(|_| Error::InvalidClaimBody("MODEL entity body"))?;
    } else if fixed.entity_type == ENTITY_TYPE_SKILL {
        let decoded = crate::skill::decode_skill_record(data)?;
        crate::skill::resident::validate_owner_put_in_txn(
            store,
            wtxn,
            &fixed.id,
            &decoded,
            fixed.replicated,
        )?;
        hub_origin_marker = crate::skill_hub::check_hub_skill_put(
            store,
            &*wtxn,
            &fixed.id,
            &decoded,
            fixed.hub_sync_imported,
            fixed.hub_admission,
        )?;
        dispatch.new_skill_record = Some(decoded);
    } else if fixed.entity_type == ENTITY_TYPE_AGENT_DEF {
        let decoded = crate::agent_def::decode_agent_definition(data)?;
        // ONE-1890 `sys.*` reservation and the H215 id pin, at the one arm
        // that holds both the decoded body and its destination row id — ALL
        // puts, mirroring SKILL's decode-site capture of `new_skill_record`.
        crate::agent_def::validate_reserved_logical_id(&fixed.id, &decoded)?;
        agent_id_pin =
            crate::agent_def::agent_id_pin_for_put_in_txn(store, wtxn, &fixed.id, &decoded)?;
        dispatch.new_agent_definition = Some(decoded);
    } else if fixed.entity_type == crate::registry::ENTITY_TYPE_WORKFLOW {
        dispatch.new_workflow = Some(crate::agent_def::workflow::validate_workflow_put(
            store,
            wtxn,
            &fixed.id,
            data,
            fixed.replicated,
        )?);
    } else if fixed.entity_type == ENTITY_TYPE_TASK {
        // The role's TREE invariants are not judged here: `ChildOf` nesting
        // belongs to the batch's one final-state gate
        // (`validate_child_of_batch`), which already sees this put and every
        // pair it re-judges. A second per-op rule reading half-applied state
        // could only disagree with it.
        crate::habit::task_role_from_body_bytes(data)?;
        // STO-03: the streak counters are DERIVED, so an inbound value is
        // discarded here — at the one arm every road to a TASK body converges
        // on, for every role. The public doors already refused the keys
        // (`validate_public_raw_put`), but the sync door deliberately does not
        // run that check, so a peer's envelope reaches this point still
        // carrying them. Stripping only `Habit` would leave the door open on
        // every other role: the tail reducer visits `Habit` rows alone, so a
        // peer-minted counter on a `Task` or `HabitCheckin` row would simply
        // be stored and never overwritten.
        task_body_without_streaks = crate::habit::strip_streak_fields(data)?;
    }
    Ok(DispatchCarry {
        task_body_without_streaks,
        pad_stored_body,
        hub_origin_marker,
        agent_id_pin,
    })
}
