//! The `apply_put` entity-put chokepoint: validation, claim gate, type dispatch, and staging.

use std::collections::BTreeSet;

use super::owned_body::guard_storage_owned_body;
use heed::RwTxn;

use super::{
    AppliedPut, AuthorityLogKeyOccupant, BaseWriteOrigin, CompanionRetiredHistoryOverlay,
    ENTITY_METADATA_HEADER_LEN, apply_short_id_plan, authority_observation_secs_for_write,
    check_authority_log_store_key, delete_short_id_rows_for_id,
    evict_authority_log_store_key_squatter, parse_entity_metadata, plan_short_id_update,
    reject_overlay_member_base_write, stage_claim_projection, stage_entity_body_row,
    stage_entity_index_rows, stage_optimizer_birth_marker_row, validate_companion_register_put,
    validate_local_agent_definition_create, validate_local_skill_create,
    validate_replicated_authority_log_for_local_vault, validate_skill_body_overwrite,
    validate_task_checkin_immutable,
};
use crate::claim::ClaimApprovalStatus;
use crate::companion::ENTITY_TYPE_COMPANION_REGISTER;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, ErrorKind, RecordError, RegistryError, Result};
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_CHANNEL_IDENTITY, ENTITY_TYPE_CLAIM,
    ENTITY_TYPE_COMM_RECORD, ENTITY_TYPE_COUNTERPARTY_CONTACT, ENTITY_TYPE_DIAGNOSTIC,
    ENTITY_TYPE_MESSAGE, ENTITY_TYPE_OUTBOUND_GRANT, ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT,
    ENTITY_TYPE_PSYCH_PROFILE, ENTITY_TYPE_SKILL, ENTITY_TYPE_TASK,
};
use crate::secret_custody::plan_replicated_name_index;
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteEnvelope;

#[expect(
    clippy::too_many_arguments,
    reason = "decomposing would obscure direct LMDB write logic"
)]
pub(in crate::batch) fn apply_put(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: EntityId,
    entity_type: u8,
    occurred: TimeRange,
    learned_at: u64,
    data: &[u8],
    allow_reserved_predicate: bool,
    replicated: bool,
    hub_sync_imported: bool,
    hub_admission: Option<&crate::skill_hub::HubAdmissionProof>,
    has_later_covering_text_op: bool,
    write_policy: Option<&crate::gate::PolicyManifestResolution>,
    write_envelope: Option<&WriteEnvelope>,
    internal_lexical_query_hint: bool,
    record_gate_decisions: bool,
    persist_gate_pending_consent: bool,
    can_resolve_pending_consent: bool,
    include_source_in_gate_input: bool,
    claim_gate_prechecked: bool,
    preflight_gate_decision_id: Option<crate::store::GateDecisionId>,
    companion_retired_histories: Option<&CompanionRetiredHistoryOverlay>,
    origin: BaseWriteOrigin<'_>,
) -> Result<AppliedPut> {
    super::super::person_substrate::validate_scope_identity(id)?;
    // Normalize before body comparison, short-id hashing and scope stamping so
    // every index names the bytes actually stored. Malformed policy stays intact
    // and is diagnosed fail-closed by the policy resolver, never defaulted away.
    let normalized_policy = if entity_type == crate::registry::ENTITY_TYPE_POLICY_MANIFEST {
        crate::gate::normalize_policy_manifest_scope(data)
    } else {
        None
    };
    let data = normalized_policy.as_deref().unwrap_or(data);
    super::put_staging::validate_scope_carriers(store, wtxn, id, entity_type, data, origin)?;
    guard_storage_owned_body(store, wtxn, &id, entity_type, occurred, data, replicated)?;
    super::put_staging::validate_domain_carriers(store, wtxn, id, entity_type, data, replicated)?;
    let mutation_recorded_at = crate::ports::recorded_at_in_txn(store, wtxn)?;
    crate::skill_hub::pack_catalog::validate_pack_source_put(store, wtxn, &id, entity_type, data)?;
    crate::skill_hub::validate_hub_source_carrier_put(store, wtxn, &id, entity_type, data)?;
    crate::agent_def::validate_birth_source_put(store, wtxn, &id, entity_type, data)?;
    crate::receipt::validate_receipt_archive_put(store, wtxn, &id, entity_type, data)?;
    let mut portable_agent_source = None;
    store.guard_pack_map_carrier_put_in_txn(wtxn, &id, entity_type, data)?;
    store.guard_pack_instance_identity_in_txn(wtxn, &id, entity_type, data)?;
    // Publication admission reuses the write-door decode and must precede
    // gate receipts, debits, and every other write effect.
    let incoming_claim_body = super::claim_admission::admit_claim_put(
        store,
        wtxn,
        id,
        super::claim_admission::ClaimPutAdmission {
            entity_type,
            occurred,
            learned_at,
            data,
            allow_reserved_predicate,
            write_envelope,
            replicated,
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
    let custody_name_index =
        plan_replicated_name_index(store, wtxn, &id, entity_type, data, replicated)?;
    let mut is_lexical_query_hint_claim = false;
    let mut new_skill_record = None;
    let mut hub_origin_marker = None;
    let mut new_agent_definition = None;
    // STO-03: `Some` only when the incoming TASK body named a derived streak
    // counter, i.e. only on the sync door — the body that gets stored instead.
    let mut task_body_without_streaks = None;
    let mut decoded_claim_body = None;
    let mut authority_entry_hash_pin: Option<crate::authority::AuthorityEntryHash> = None;
    let mut authority_entry_observation = None;
    // ONE-1604-D1 dominance VERDICT, recorded by the AUTHORITY_LOG arm below
    // and acted on only at the pre-write site: see the eviction comment there
    // for why the mutation cannot ride along with the check.
    let mut authority_dominates_key_squatter = false;
    if let Some(body) = incoming_claim_body {
        if let Some(prior) = store.entities.get(wtxn, id.as_bytes())?
            && prior.get(ENTITY_METADATA_HEADER_LEN..) != Some(data)
        {
            crate::blob_artifact::esign::reject_event_delete(store, wtxn, &id)?;
        }
        if body.predicate.starts_with("esign.") {
            if replicated {
                return Err(Error::InvalidClaimBody(
                    "esign events require the local authenticated organ",
                ));
            }
            if let Some(prior) = store.entities.get(wtxn, id.as_bytes())?
                && prior.get(ENTITY_METADATA_HEADER_LEN..) != Some(data)
            {
                return Err(Error::InvalidClaimBody("esign events are append-only"));
            }
        }
        crate::subject_model::validate_subject_model_claim_in_txn(store, wtxn, &body)?;
        crate::thread_passport::validate_thread_claim_in_txn(store, wtxn, &id, &body, replicated)?;
        is_lexical_query_hint_claim = body.predicate == crate::claim::PREDICATE_LEXICAL_QUERY_HINT;
        if is_lexical_query_hint_claim {
            super::lexical_hint::validate_lexical_query_hint(store, wtxn, id, &body, replicated)?;
        }
        if body.session_tag.is_some()
            && !replicated
            && !claim_gate_prechecked
            && !write_envelope.is_some_and(|envelope| {
                crate::claim::session_claim_producer(&body) == Some(envelope.actor().entity_ref())
            })
        {
            return Err(Error::InvalidClaimBody(
                "sess requires an envelope-bound producer actor",
            ));
        }
        if !(replicated
            || is_lexical_query_hint_claim && internal_lexical_query_hint
            || claim_gate_prechecked)
        {
            let policy = write_policy.ok_or(Error::InvariantViolation(
                "local claim write policy snapshot missing",
            ))?;
            if allow_reserved_predicate {
                crate::gate::check_reserved_claim_policy(&body, write_envelope, policy)?;
            } else {
                crate::gate::check_claim_policy_for_write_with_preflight_decision(
                    store,
                    wtxn,
                    &id,
                    crate::gate::ClaimGateWrite::plain(&body, write_envelope),
                    policy,
                    crate::gate::GateWriteMode {
                        record_decision: record_gate_decisions,
                        persist_pending_consent: persist_gate_pending_consent,
                        resolve_pending: true,
                        can_resolve_pending_consent,
                        include_source_in_gate_input,
                    },
                    preflight_gate_decision_id,
                )?;
            }
        }
        decoded_claim_body = Some(body);
    } else if entity_type == crate::registry::ENTITY_TYPE_NOTE {
        validate_note_birth_put(store, wtxn, &id, data)?;
    } else if entity_type == crate::registry::ENTITY_TYPE_MESSAGE {
        validate_witness_message_body(data, replicated)?;
    } else if entity_type == crate::registry::ENTITY_TYPE_CODE_ARTIFACT {
        crate::code_artifact::validate_code_artifact_body_bytes(data)?;
    } else if entity_type == crate::registry::ENTITY_TYPE_BLOB_ARTIFACT {
        crate::blob_artifact::validate_blob_artifact_body_bytes(data)?;
    } else if entity_type == crate::registry::ENTITY_TYPE_AUTHORITY_LOG {
        if replicated {
            validate_replicated_authority_log_for_local_vault(store, wtxn, &id, data)?;
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
        authority_dominates_key_squatter =
            check_authority_log_store_key(store, wtxn, &id, &entry_hash, data)?
                == AuthorityLogKeyOccupant::CrossTypeSquatter;
        authority_entry_hash_pin = Some(entry_hash);
        authority_entry_observation = Some(entry);
    } else if entity_type == crate::registry::ENTITY_TYPE_FEDERATION_GRANT {
        crate::federation::validate_federation_grant_body_bytes(data)?;
    } else if entity_type == crate::registry::ENTITY_TYPE_ACCESS_GRANT {
        crate::access_grant::validate_access_grant_body_bytes(data)?;
    } else if entity_type == ENTITY_TYPE_CHANNEL_IDENTITY {
        crate::channel_identity::validate_channel_identity_body_bytes(data)?;
    } else if entity_type == ENTITY_TYPE_COUNTERPARTY_CONTACT {
        crate::counterparty_contact::validate_counterparty_contact_body_bytes(data)?;
    } else if entity_type == ENTITY_TYPE_COMM_RECORD {
        crate::comm::validate_comm_record_body_bytes(data)?;
    } else if entity_type == ENTITY_TYPE_DIAGNOSTIC {
        crate::self_heal::validate_diagnostic_event_admission(&id, occurred, data)?;
    } else if entity_type == ENTITY_TYPE_OUTBOUND_GRANT {
        crate::outbound_grant::validate_standing_outbound_grant_body_bytes(data)?;
    } else if entity_type == ENTITY_TYPE_PSYCH_PROFILE {
        crate::psych_profile::validate_psych_profile_body_bytes(data)?;
    } else if entity_type == ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT {
        crate::persona_snapshot::validate_persona_snapshot_export_body_bytes(data)?;
    } else if entity_type == crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
        crate::identity_topology::validate_identity_topology_event_body_bytes(data)?;
    } else if entity_type == crate::registry::ENTITY_TYPE_SKILL_HUB {
        crate::skill_hub::decode_skill_hub_record(data)?;
    } else if entity_type == ENTITY_TYPE_SKILL {
        let decoded = crate::skill::decode_skill_record(data)?;
        hub_origin_marker = crate::skill_hub::check_hub_skill_put(
            store,
            &*wtxn,
            &id,
            &decoded,
            hub_sync_imported,
            hub_admission,
        )?;
        new_skill_record = Some(decoded);
    } else if entity_type == ENTITY_TYPE_AGENT_DEF {
        let decoded = crate::agent_def::decode_agent_definition(data)?;
        // ONE-1890 `sys.*` reservation, at the one arm that holds both the
        // decoded body and its destination row id — ALL puts, mirroring
        // SKILL's decode-site capture of `new_skill_record`.
        crate::agent_def::validate_reserved_logical_id(&id, &decoded)?;
        new_agent_definition = Some(decoded);
    } else if entity_type == crate::registry::ENTITY_TYPE_WORKFLOW {
        crate::agent_def::workflow::validate_workflow_put(store, wtxn, &id, data, replicated)?;
    } else if entity_type == ENTITY_TYPE_COMPANION_REGISTER {
        return Err(Error::InvalidClaimBody(
            "CompanionRecord storage retired; use PERSON/FACET",
        ));
    } else if entity_type == crate::registry::ENTITY_TYPE_FACET
        && crate::companion::is_identity_facet_body(data)
    {
        validate_companion_register_put(store, wtxn, &id, data, companion_retired_histories)?;
    } else if entity_type == ENTITY_TYPE_TASK {
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
    if occurred.start > occurred.end {
        return Err(Error::InvalidTimeRange {
            start: occurred.start,
            end: occurred.end,
        });
    }
    // ONE-1604-D1 dominance MUTATION (fix-leg 2, P2): every side-effect-free
    // check that can reject this row REMOTELY has now run — including the
    // envelope's time-range validation directly above. That ordering is the
    // whole point: `InvalidTimeRange` is a `remote_rejection_reason`, so
    // Observer B quarantines it and COMMITS the transaction (sync/bridge.rs
    // quarantine-and-continue). An eviction performed before that check would
    // therefore survive the rejection as a durable side effect — a rejected
    // authority row would empty the key it failed to claim. A rejected input
    // must be a pure no-op, so the squatter is deindexed only here, past the
    // last remotely-rejectable gate.
    //
    // Placed BEFORE short-id planning and the old-record arm below (rather
    // than at the `store.entities.put` line) because both read the row this
    // eviction removes: the old-record arm would otherwise reject the
    // dominant row with `EntityTypeImmutable`, and a short-id plan built from
    // the squatter's rows would outlive them. Everything still fallible
    // between here and the write is LOCAL-class (storage/overflow), which
    // aborts the whole batch instead of committing — so it cannot strand this
    // mutation either.
    let evicted_shell_sources = if authority_dominates_key_squatter {
        evict_authority_log_store_key_squatter(store, wtxn, &id)?
    } else {
        BTreeSet::new()
    };
    // ONE-1892: the SKILL activation scan consult, at the one arm every road
    // to a SKILL body converges on. The typed update door is not the
    // chokepoint — `put_entity` and a raw `batch().put` land an already-
    // `active` body here without passing it — so the escalation from `auto`
    // to `proposed` (a dial, never a refusal) is computed here instead.
    //
    // LOCAL writes only: a replicated row carries a peer's already-settled
    // consent and re-deciding it would diverge the replicas, and the hub-sync
    // door copies the local approval stamp verbatim, so it never presents a
    // transition to escalate.
    //
    // Placed BEFORE short-id planning because the plan hashes the body bytes
    // into the ARCH-0019 row-n3 disambiguator: an escalation applied after it
    // would stage a body the short-id row no longer describes.
    let escalated_skill_body;
    let data = match new_skill_record.as_mut() {
        Some(updated) if !replicated && !hub_sync_imported => {
            if crate::skill_scan::escalate_activation_approval_in_txn(store, &*wtxn, &id, updated)?
            {
                escalated_skill_body = crate::skill::encode_skill_record(updated)?;
                &escalated_skill_body[..]
            } else {
                data
            }
        }
        _ => data,
    };
    // STO-03: the sanitized TASK body replaces the inbound one from here on —
    // before short-id planning hashes it and before the old-record comparison
    // decides whether the body changed, so nothing downstream ever sees the
    // discarded counters.
    let data = task_body_without_streaks.as_deref().unwrap_or(data);
    // A sync replay deliberately bypasses the local claim gate. If it changes
    // a claim with a persisted critical-confirm attachment, that attachment
    // binds the old body and cannot authorize the new one. Delete it in this
    // same write transaction and demote an inbound Auto status; notably, do
    // not derive a replacement binding from the changed peer body.
    let reconciled_critical_claim_body = if replicated && entity_type == ENTITY_TYPE_CLAIM {
        let body_changed = store
            .entities
            .get(wtxn, id.as_bytes())?
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
            &id,
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
            decoded_claim_body = Some(reconciled.clone());
            Some(crate::claim::encode_claim_body(&reconciled)?)
        } else {
            None
        }
    } else {
        None
    };
    let data = reconciled_critical_claim_body.as_deref().unwrap_or(data);
    // The AUTHORITY_LOG arm above already decoded the body and hashed it for
    // the store-key bind; reuse that hash instead of decoding a second time.
    let authority_first_seen_key = authority_entry_hash_pin
        .as_ref()
        .map(crate::authority::authority_first_seen_sync_key);
    // Maintenance-classified kinds (REDACTION_AUDIT) carry no short ID (static
    // registry `short_id_prefix: None`), matching the engine's direct receipt writer.
    // Only the internal sync path reaches here with such a kind (public puts are
    // rejected in `apply_ops`); skip short-id planning, which would otherwise
    // fail with `InvalidEntityType` on the missing prefix.
    let short_id_prefix = if is_lexical_query_hint_claim {
        None
    } else if crate::registry::zone_of(entity_type) == crate::registry::TypeByteZone::PackHandle {
        Some(store.pack_short_id_prefix_in_txn(wtxn, entity_type, data)?)
    } else {
        store.short_id_prefix(entity_type).ok()
    };
    let short_id_plan = if let Some(short_id_prefix) = short_id_prefix {
        Some(plan_short_id_update(
            store,
            &*wtxn,
            &id,
            entity_type,
            &short_id_prefix,
            data,
        )?)
    } else {
        None
    };

    let mut body_changed = true;
    let mut previous_skill_record = None;
    // ONE-1449 MATERIAL-6 R1: the optimizer-birth marker this create must
    // either match or be born with. Computed by the SKILL create arm below
    // while the transaction is still borrowed for reads, and staged at the
    // pre-write site further down — the same check-here / mutate-there split
    // the ONE-1604-D1 eviction above takes, and for the same reason: the arm
    // that decides holds a read borrow of `wtxn`.
    let mut optimizer_birth_marker = None;
    if let Some(old_record) = store.entities.get(wtxn, id.as_bytes())? {
        let (old_type, old_occurred, old_learned) = parse_entity_metadata(&old_record)?;
        previous_skill_record = decode_previous_skill_record(old_type, &old_record)?;
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
        // Retaining an indexed text revision is not permission to retain a
        // withdrawn claim in the search index. Lifecycle/approval takes effect
        // immediately; only still-surfaceable text edits await idle publication.
        let withdrawn_claim = decoded_claim_body
            .as_ref()
            .is_some_and(|body| !crate::claim::claim_surfaceable(body));
        let should_deindex_stale_text = body_changed
            && (withdrawn_claim
                || ((replicated || !has_later_covering_text_op)
                    && !crate::vault::entity_revision::storage_manages_text(
                        store, wtxn, &id, data,
                    )?));
        let old_code_artifact_body =
            if old_type == crate::registry::ENTITY_TYPE_CODE_ARTIFACT && body_changed {
                Some(old_record[ENTITY_METADATA_HEADER_LEN..].to_vec())
            } else {
                None
            };
        if old_type != entity_type {
            return Err(Error::Registry(RegistryError::EntityTypeImmutable {
                id,
                existing: old_type,
                attempted: entity_type,
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
                "an existing MESSAGE id is bound to its original canonical body",
            )));
        }
        if old_type == ENTITY_TYPE_TASK {
            validate_task_checkin_immutable(
                &old_record,
                old_occurred,
                old_learned,
                occurred,
                learned_at,
                data,
                body_changed,
            )?;
        }
        if old_type == ENTITY_TYPE_SKILL && body_changed {
            let updated = new_skill_record
                .as_ref()
                .ok_or(Error::InvariantViolation("validated SKILL record missing"))?;
            validate_skill_body_overwrite(
                &id,
                &old_record[ENTITY_METADATA_HEADER_LEN..],
                updated,
                hub_sync_imported,
                replicated,
                hub_admission,
            )?;
        }
        if old_type == ENTITY_TYPE_AGENT_DEF && body_changed {
            let updated = new_agent_definition
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
            && crate::code_revision::has_finalized_code_revision_in_txn(store, wtxn, &id)?
        {
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "finalized code revision artifacts are immutable",
            )));
        }
        if let Some(old_code_artifact_body) = old_code_artifact_body {
            crate::codebase::reconcile_codebase_snapshot_after_code_artifact_put(
                store,
                wtxn,
                &id,
                &old_code_artifact_body,
                data,
            )?;
        }
        if should_deindex_stale_text {
            crate::bm25::deindex_text(store, wtxn, &id)?;
        }

        super::put_staging::remove_prior_temporal_index_rows(
            store,
            wtxn,
            &id,
            old_occurred,
            old_learned,
            occurred,
            learned_at,
        )?;
    } else if entity_type == ENTITY_TYPE_AGENT_DEF && !replicated {
        // ONE-1890 mirror of the SKILL create gate below, one entity type
        // over: LOCAL creates only, so genuine creates are gated and updates
        // stay on the arm above. Fork lineage must name a real type-17 parent
        // ROW, and the child's ceiling may not widen beyond that parent's
        // STORED ceiling — the relocated no-widen check, which necessarily
        // lives here because body-only validation cannot load the parent row.
        // The gate-time clamp (GATE-HALF) covers the same bound live.
        let created = new_agent_definition
            .as_ref()
            .ok_or(Error::InvariantViolation(
                "validated AGENT_DEF record missing",
            ))?;
        validate_local_agent_definition_create(store, wtxn, &id, created)?;
        portable_agent_source =
            crate::agent_def::bind_agent_birth_in_txn(store, wtxn, &id, created)?;
    } else if entity_type == ENTITY_TYPE_SKILL {
        let created = new_skill_record
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
            store, &*wtxn, &id, created,
        )?;
        // The birth law itself is LOCAL-only, and stays that way: sync remat
        // keeps writing already-lifecycled records.
        if !replicated {
            validate_local_skill_create(store, &*wtxn, &id, created)?;
        }
    }

    // ONE-1449 MATERIAL-6 R1: staged in the SAME transaction as the body it
    // marks, so a rolled-back create leaves no marker and a committed one can
    // never be re-presented as an ordinary birth. Only a genuine optimizer-born
    // create at an unmarked id produces a row here.
    stage_optimizer_birth_marker_row(store, wtxn, optimizer_birth_marker)?;
    crate::ports::audit_entity_put_in_txn(
        store,
        wtxn,
        crate::ports::EntityPutAudit {
            id,
            entity_type,
            occurred,
            learned_at,
            data,
            envelope: write_envelope,
        },
    )?;
    crate::gate::manifest_authenticity::update_manifest_origin(
        store,
        wtxn,
        &id,
        entity_type,
        data,
        replicated,
    )?;
    crate::ingest::invalidate_blob_fingerprint(store, wtxn, &id)?;
    stage_claim_projection(store, wtxn, id, decoded_claim_body.as_ref())?;
    if let Some((key, value)) = hub_origin_marker {
        store.vault_meta.put(wtxn, &key, &value)?;
    }
    crate::skill_hub::stage_source_custody_put(
        store,
        wtxn,
        &id,
        entity_type,
        data,
        previous_skill_record.as_ref(),
        new_skill_record.as_ref(),
    )?;
    stage_entity_body_row(store, wtxn, &id, entity_type, occurred, learned_at, data)?;
    if entity_type == ENTITY_TYPE_TASK {
        crate::task_verb::index_owner_fact(store, wtxn, &id, Some(data))?;
        if body_changed {
            crate::task_verb::note_task_write(store, wtxn, id, data)?;
        }
    }
    if entity_type == crate::registry::ENTITY_TYPE_TURN {
        crate::conversation_dag::stage_session_carrier(store, wtxn, id, data)?;
    }
    crate::secret_custody::stage_replicated_name_index(store, wtxn, &id, custody_name_index)?;
    if let Some(record) = new_skill_record.as_ref() {
        super::put_staging::stage_skill_index_rows(
            store,
            wtxn,
            &id,
            previous_skill_record.as_ref(),
            record,
        )?;
    }
    if let Some(body) = decoded_claim_body.as_ref() {
        super::put_staging::stage_claim_projection_indexes(store, wtxn, &id, body, learned_at)?;
    }
    if let Some(key) = authority_first_seen_key {
        observe_authority_put(
            store,
            wtxn,
            &key,
            authority_entry_observation.as_ref(),
            authority_entry_hash_pin.as_ref(),
            replicated,
            mutation_recorded_at,
        )?;
    }

    stage_entity_index_rows(store, wtxn, &id, entity_type, occurred, learned_at)?;
    crate::federation::record_scope::stamp_put(store, wtxn, id, entity_type, data, replicated)?;
    if entity_type == crate::registry::ENTITY_TYPE_FACET {
        super::super::facet_identity::reconcile_identity_facet(
            store, wtxn, id, data, occurred, learned_at,
        )?;
    }
    if entity_type == crate::registry::ENTITY_TYPE_PERSON {
        super::super::person_substrate::ensure_person_substrate(
            store, wtxn, id, occurred, learned_at,
        )?;
    }
    crate::agent_def::stage_birth_custody_put(store, wtxn, &id, entity_type, data)?;
    crate::receipt::stage_receipt_archive_put(store, wtxn, &id, entity_type, data)?;

    if let Some(plan) = short_id_plan {
        apply_short_id_plan(store, wtxn, &id, plan)?;
    } else if is_lexical_query_hint_claim {
        delete_short_id_rows_for_id(store, wtxn, &id)?;
    }
    let mut cleared_pending_embedding = false;
    let mut had_vector_mutation = false;
    if is_lexical_query_hint_claim {
        cleared_pending_embedding = store.clear_pending_embedding(wtxn, &id)?;
        let had_hnsw = store.hnsw_neighbors.get(wtxn, id.as_bytes())?.is_some();
        had_vector_mutation = store.vectors.delete(wtxn, id.as_bytes())? || had_hnsw;
        crate::hnsw::hnsw_deindex(store, wtxn, &id)?;
    }
    let pending_embedding_token =
        if entity_type == crate::registry::ENTITY_TYPE_CLAIM && !is_lexical_query_hint_claim {
            // Mint the new invalidation token even while idle publication is
            // pending. The worker skips these revisions; old completions must
            // still observe that their token no longer owns the current body.
            let has_current_pending = store.has_current_pending_embedding_in_txn(wtxn, &id)?;
            let has_vector = store.vectors.get(wtxn, id.as_bytes())?.is_some();
            if !body_changed && has_vector && !has_current_pending {
                None
            } else {
                Some(store.mark_pending_embedding(wtxn, &id, data)?)
            }
        } else {
            None
        };
    Ok(AppliedPut {
        portable_agent_source,
        pending_embedding_token,
        cleared_pending_embedding,
        had_vector_mutation,
        is_lexical_query_hint_claim,
        evicted_shell_sources,
    })
}

// The ledger is immutable birth identity, never a second text plane. This
// shared guard covers local writes and replicated/window rematerialization.
fn validate_note_birth_put(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    data: &[u8],
) -> Result<()> {
    crate::note::decode_note_body_in_txn(store, txn, data)?;
    if let Some(old) = store.entities.get(txn, id.as_bytes())?
        && old.get(ENTITY_METADATA_HEADER_LEN..) != Some(data)
    {
        return Err(Error::Record(RecordError::InvalidNoteBody(
            "NOTE birth body is immutable",
        )));
    }
    Ok(())
}

fn validate_witness_message_body(data: &[u8], replicated: bool) -> Result<()> {
    // ONE-1686 (RT-04): the witness ENVELOPE law, at the one arm every
    // road to a MESSAGE body converges on — the witness door, promote
    // replay, and sync rematerialization alike. The AUTHORITY half
    // (which actor may write which author bucket) is answered before
    // staging by `gate::check_witness_message_ceiling`, which is the only
    // way to reach `TxnBatchBuilder::put_witness_message`; what is left
    // for a chokepoint that holds bytes and no actor is proving the bytes
    // ARE the canonical envelope those axes encode. A local row already
    // is one by construction (the put consumes the door's own output), so
    // this costs the witness path nothing and closes every other road.
    //
    // Placed BEFORE any store mutation in this function, so a refusal on
    // either road leaves nothing partial behind for the caller's
    // quarantine-and-continue to clean up.
    if replicated {
        // The REPLICATED road has no actor to run the ceiling against and
        // the protocol carries no verified source actor or peer signer at
        // this door, so it fails closed for every author bucket: see
        // `gate::validate_replicated_witness_message_body`.
        crate::gate::validate_replicated_witness_message_body(data)?;
    } else {
        crate::gate::validate_canonical_witness_message_body(data)?;
    }
    Ok(())
}

fn decode_previous_skill_record(
    old_type: u8,
    old_record: &[u8],
) -> Result<Option<crate::skill::SkillRecord>> {
    if old_type != ENTITY_TYPE_SKILL {
        return Ok(None);
    }
    let prior_body = &old_record[ENTITY_METADATA_HEADER_LEN..];
    match crate::skill::decode_skill_record(prior_body) {
        Ok(record) => Ok(Some(record)),
        Err(error)
            if error.kind() == ErrorKind::InvalidSkillBody
                && crate::skill::is_legacy_opaque_skill_body(prior_body) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}
/// Keep first observation, signer maximum and replay advisory in the same put transaction.
fn observe_authority_put(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    key: &str,
    entry: Option<&crate::authority::AuthorityLogEntry>,
    hash: Option<&crate::authority::AuthorityEntryHash>,
    replicated: bool,
    mutation_recorded_at: u64,
) -> Result<()> {
    let observed_secs = authority_observation_secs_for_write(store, wtxn, mutation_recorded_at)?;
    if store.sync_state.get(wtxn, key)?.is_none() {
        let first_seen = crate::authority::encode_authority_first_seen_secs(observed_secs);
        store.sync_state.put(wtxn, key, &first_seen)?;
    }
    if let (Some(entry), Some(hash)) = (entry, hash) {
        let first_observation = crate::authority::record_authority_sequence_observation_in_txn(
            store, wtxn, entry, hash,
        )?;
        if replicated && first_observation {
            crate::authority::observe_authority_replay_in_txn(
                store,
                wtxn,
                &entry.signer.public_key,
                observed_secs,
            )?;
        }
    }
    Ok(())
}
