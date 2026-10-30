use super::*;

/// Inputs to `apply_put` that no phase mutates: the row identity, the admit
/// flags, and the borrowed context the put is judged against.
pub(super) struct FixedPut<'a> {
    pub(super) id: EntityId,
    pub(super) entity_type: u8,
    pub(super) occurred: crate::temporal::TimeRange,
    pub(super) learned_at: u64,
    pub(super) options: crate::batch::put_apply::request::PutOptions,
    pub(super) origin: crate::batch::BaseWriteOrigin<'a>,
    pub(super) write_policy: Option<&'a crate::gate::PolicyManifestResolution>,
    pub(super) write_envelope: Option<&'a crate::write_envelope::WriteEnvelope>,
    pub(super) hub_admission: Option<&'a crate::skill_hub::HubAdmissionProof>,
    pub(super) refinement_admission: Option<&'a crate::skill_hub::RefinementAdmissionProof>,
    pub(super) transition: Option<&'a crate::batch::VerifiedClaimTransition>,
    pub(super) posture: crate::HostingPrivacyPosture,
    pub(super) owner_authored: Option<&'a crate::consent::OwnerAuthoredWrite>,
    /// The authority rows the put's batch carries beside it, which a
    /// replicated AUTHORITY_LOG row is judged with (FIX 11764).
    pub(super) authority_beside: Option<crate::authority::RowsBeside<'a>>,
    /// The own-device lane the sync ingest door gave a replicated MESSAGE
    /// row, which the witness check reads for this row and these bytes only
    /// (FIX 9600).
    pub(super) own_device: Option<&'a VerifiedOwnDeviceLane>,
    pub(super) replicated: bool,
    pub(super) allow_reserved_predicate: bool,
    pub(super) hub_sync_imported: bool,
    pub(super) claim_gate_prechecked: bool,
    pub(super) mutation_recorded_at: u64,
}

/// Body buffers the staged `data` slice borrows, in shadow order. The parent
/// holds them so the slice stays borrowed across phases.
#[derive(Default)]
pub(super) struct Owners {
    pub(super) normalized_policy: Option<Vec<u8>>,
    pub(super) project: Option<Vec<u8>>,
    pub(super) task_body_without_streaks: Option<Vec<u8>>,
    pub(super) pad_stored_body: Option<Vec<u8>>,
    pub(super) escalated_skill_body: Option<Vec<u8>>,
}

/// Type-dispatch verdicts the CLAIM and per-kind arms produce for the later
/// phases. Body buffers the arms produce travel in `DispatchCarry` instead.
pub(super) struct Dispatch {
    pub(super) is_lexical_query_hint_claim: bool,
    pub(super) new_skill_record: Option<crate::skill::SkillRecord>,
    pub(super) new_agent_definition: Option<crate::agent_def::AgentDefinition>,
    pub(super) new_workflow: Option<crate::agent_def::workflow::WorkflowDefinition>,
    pub(super) decoded_claim_body: Option<ClaimBody>,
    pub(super) authority_entry_hash_pin: Option<crate::authority::AuthorityEntryHash>,
    pub(super) authority_entry_observation: Option<crate::authority::AuthorityLogEntry>,
    pub(super) authority_dominates_key_squatter: bool,
}

/// The admitted companion revision and its squatter verdict.
pub(super) struct RevisionSlot {
    pub(super) put: Option<crate::workspace_roster::RevisionPut>,
    pub(super) squatter: bool,
}

/// Everything P1 admitted: the immutable inputs, the first body buffers, the
/// dispatch verdicts, the revision slot, and the values later phases move.
pub(super) struct Admission<'a> {
    pub(super) fixed: FixedPut<'a>,
    pub(super) owners: Owners,
    pub(super) dispatch: Dispatch,
    pub(super) revision: RevisionSlot,
    pub(super) incoming_claim_body: Option<ClaimBody>,
    pub(super) project_revisions: Vec<(EntityId, Vec<u8>)>,
    pub(super) portable_agent_source: Option<(EntityId, Vec<u8>)>,
}

/// P1: admit the put — unpack the request, run the carrier guards and claim
/// admission, and set up the verdicts the type dispatch assigns.
pub(super) fn admit_put<'a>(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    request: PutRequest<'a>,
    authority_beside: Option<crate::authority::RowsBeside<'a>>,
    own_device: Option<&'a VerifiedOwnDeviceLane>,
) -> Result<Admission<'a>> {
    let PutRequest {
        row:
            PutRow {
                id,
                entity_type,
                occurred,
                learned_at,
                data,
            },
        options,
        context:
            PutContext {
                origin,
                write_policy,
                write_envelope,
                hub_admission,
                refinement_admission,
                transition,
                posture,
                owner_authored,
            },
    } = request;
    let Replication {
        replicated,
        reserved_predicate: allow_reserved_predicate,
    } = options.replication;
    let hub_sync_imported = options.hub.sync_imported;
    let claim_gate_prechecked = options.decision.prechecked;
    // A record kept only for a refused privacy erasure takes no change while
    // an order forbids its use: the refusal is `use_restricted` naming the
    // order's bound, or absence while that order is secret (OF-470 C6,
    // WILL-PLAN L01 row 03).
    if let Some(refusal) = store.use_restricted_in_txn(wtxn, &id)? {
        return Err(refusal);
    }
    crate::dreamer_runner::authority::guard_actor_put(id, entity_type, data, occurred, learned_at)?;
    super::super::super::person_substrate::validate_scope_identity(id)?;
    // Normalize before body comparison, short-id hashing and scope stamping so
    // every index names the bytes actually stored. Malformed policy stays intact
    // and is diagnosed fail-closed by the policy resolver, never defaulted away.
    let normalized_policy = super::super::put_staging::normalized_policy_scope(entity_type, data);
    let data = normalized_policy.as_deref().unwrap_or(data);
    let project = stage_project_put(store, wtxn, id, entity_type, data, replicated, posture)?;
    let data = project.as_deref().unwrap_or(data);
    let carriers = PutCarrierContext::new(
        entity_type,
        occurred,
        learned_at,
        replicated,
        origin,
        posture,
    );
    validate_put_carriers(store, wtxn, id, data, carriers)?;
    let project_revisions =
        crate::workspace_roster::capture_project_put(store, wtxn, id, entity_type, data)?;
    let mutation_recorded_at = crate::ports::recorded_at_in_txn(store, wtxn)?;
    super::super::put_staging::validate_source_carriers(
        store,
        wtxn,
        (id, entity_type, data, occurred, learned_at),
    )?;
    let portable_agent_source = None;
    store.guard_pack_map_carrier_put_in_txn(wtxn, &id, entity_type, data)?;
    store.guard_pack_instance_identity_in_txn(wtxn, &id, entity_type, data)?;
    // Publication admission reuses the write-door decode and must precede
    // gate receipts, debits, and every other write effect.
    let incoming_claim_body = super::super::claim_admission::admit_claim_put(
        store,
        wtxn,
        id,
        super::super::claim_admission::ClaimPutAdmission {
            entity_type,
            occurred,
            learned_at,
            data,
            allow_reserved_predicate,
            write_envelope,
            replicated,
            posture,
            transition,
        },
    )?;
    // ARCH-0052 D2: this is the shared entity materialization choke point for
    // public/typed puts, claim candidates, and replicated replay. A base row
    // at a live overlay member's id would publish the room into base, so it
    // rejects here — before any validation or side effect can mint an index
    // row, gate receipt, or entity body. The one exemption is a promote-replay
    // transaction rematerializing its OWN session's closure, carried on the
    // same write origin the K4 decode-point guard reads.
    reject_overlay_member_base_write(store, &id, origin)?;
    // A provisional entity's id is held for its confirmation, on the same
    // choke point, so no local claim candidate lands under it either. A
    // replicated row takes the id at the pre-write site below.
    if !replicated {
        crate::tagging::refuse_held_id_in_txn(store, wtxn, &id)?;
    }
    validate_refinement_admission(
        store,
        wtxn,
        &id,
        entity_type,
        data,
        refinement_admission,
        transition,
    )?;
    crate::claim::validate_claim_write_target_in_txn(store, wtxn, &id, allow_reserved_predicate)?;
    // Type-byte validation runs in `apply_ops` (public-vs-maintenance gate:
    // public writes reject engine-authored system kinds, the sync
    // rematerialization path admits it via `allow_maintenance`). apply_put is
    // reached only after that gate, so it does not re-validate the type byte.
    // D18: every type-0 (CLAIM) write — put_entity, both batch builders, and
    // sync replay — is structurally validated before any byte is staged.
    // Registered maintenance kinds with pinned body schemas get the same
    // fail-closed treatment on every path that can admit their type byte.
    // Bodies of all other type bytes stay opaque at the storage layer.
    //
    // PERSON holds identity and a FACET is a scenario mask: the one local
    // identity-body refusal runs once here, ahead of the per-kind arms.
    crate::batch::validate_local_identity_body(entity_type, data)?;
    let is_lexical_query_hint_claim = false;
    let new_skill_record = None;
    let new_agent_definition = None;
    let new_workflow = None;
    let decoded_claim_body = None;
    let authority_entry_hash_pin: Option<crate::authority::AuthorityEntryHash> = None;
    let authority_entry_observation = None;
    // ONE-1604-D1 dominance VERDICT, recorded by the AUTHORITY_LOG arm below
    // and acted on only at the pre-write site: see the eviction comment there
    // for why the mutation cannot ride along with the check.
    let authority_dominates_key_squatter = false;
    let revision_put = None;
    // H215: an id that has been an agent stays one, across a delete too.
    crate::agent_def::refuse_agent_id_retype_in_txn(store, wtxn, &id, entity_type)?;
    Ok(Admission {
        fixed: FixedPut {
            id,
            entity_type,
            occurred,
            learned_at,
            options,
            origin,
            write_policy,
            write_envelope,
            hub_admission,
            refinement_admission,
            transition,
            posture,
            owner_authored,
            authority_beside,
            own_device,
            replicated,
            allow_reserved_predicate,
            hub_sync_imported,
            claim_gate_prechecked,
            mutation_recorded_at,
        },
        owners: Owners {
            normalized_policy,
            project,
            ..Default::default()
        },
        dispatch: Dispatch {
            is_lexical_query_hint_claim,
            new_skill_record,
            new_agent_definition,
            new_workflow,
            decoded_claim_body,
            authority_entry_hash_pin,
            authority_entry_observation,
            authority_dominates_key_squatter,
        },
        revision: RevisionSlot {
            put: revision_put,
            squatter: false,
        },
        incoming_claim_body,
        project_revisions,
        portable_agent_source,
    })
}
