use super::*;

use std::collections::BTreeSet;

use heed::RwTxn;

use crate::claim::ClaimApprovalStatus;
use crate::companion::ENTITY_TYPE_COMPANION_REGISTER;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, ErrorKind, Result};
use crate::habit::TaskRole;
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_CHANNEL_IDENTITY, ENTITY_TYPE_CLAIM,
    ENTITY_TYPE_COMM_RECORD, ENTITY_TYPE_COUNTERPARTY_CONTACT, ENTITY_TYPE_MESSAGE,
    ENTITY_TYPE_OUTBOUND_GRANT, ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT, ENTITY_TYPE_PSYCH_PROFILE,
    ENTITY_TYPE_SKILL, ENTITY_TYPE_TASK,
};
use crate::store::{ManifestDbs, Store};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteEnvelope;

/// The final `BatchOp::Put` this batch stages for one entity: where it lands
/// in op order, its type byte, and — for a TASK only — the body its role is
/// decoded from. Non-TASK bodies are not retained: the type byte is all the
/// tree validator ever asks of them, so a non-TASK domain is never forced
/// through `TaskRole` decoding.
#[derive(Debug, Clone)]
pub(super) struct BatchEntityPut {
    pub(super) seq: usize,
    pub(super) entity_type: u8,
    pub(super) task_body: Option<Vec<u8>>,
}

/// One entity as the batch LEAVES it — the state `ChildOf` validation answers
/// "does this parent exist, and what role does it carry" against.
///
/// Final state, not pre-state: a parent created anywhere in the same batch
/// exists, and a parent the batch deletes without re-putting does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EffectiveEntity {
    Missing,
    NonTask(u8),
    Task(TaskRole),
}

pub(super) struct AppliedPut {
    pub(super) pending_embedding_token: Option<Vec<u8>>,
    pub(super) cleared_pending_embedding: bool,
    pub(super) had_vector_mutation: bool,
    pub(super) is_lexical_query_hint_claim: bool,
    /// Shell-edge sources an ONE-1604-D1 dominance eviction orphaned, for the
    /// caller's explicit-source reconciliation. Empty on every other path.
    pub(super) evicted_shell_sources: BTreeSet<EntityId>,
}

/// Every gate a SKILL body OVERWRITE passes at this chokepoint.
///
/// Extracted from [`apply_put`] rather than inlined: this arm answers one
/// question ("may this body replace that one?") and three doors ask it.
///
/// A legacy-opaque prior body is the one exemption, as it has always been —
/// there is no decoded predecessor to judge an update against, so the upgrade
/// is admitted and the record's shape is validated on its own terms.
///
/// # Errors
///
/// [`Error::InvalidSkillBody`] from the substrate update gate, the hub-sync
/// door's variant of it, or ONE-1449's admission gate.
fn validate_skill_body_overwrite(
    store: &Store,
    wtxn: &RwTxn<'_>,
    id: &EntityId,
    prior_body: &[u8],
    updated: &crate::skill::SkillRecord,
    hub_sync_imported: bool,
    replicated: bool,
) -> Result<()> {
    match crate::skill::decode_skill_record(prior_body) {
        Ok(prior) if hub_sync_imported => {
            crate::skill::validate_hub_sync_skill_update(&prior, updated)
        }
        Ok(prior) => {
            crate::skill::validate_skill_update(&prior, updated)?;
            // ONE-1449's admission gate, placed HERE for the reason ONE-1892's
            // scan consult is: this is the arm every SKILL body update
            // converges on, so `put_entity`, a raw `batch().put`, the typed
            // update door and sync replay are bound by one rule rather than
            // four. The substrate update gate above already judges a
            // replicated row against its predecessor; exempting THIS gate
            // alone (ONE-1449 K3 M-6) let a peer's row edit optimizer origin
            // provenance and flip an optimizer-born candidate to `active` with
            // no verdict anywhere — a fail-open the local doors are closed to.
            // Which half of the rule a road can be held to is the gate's own
            // question to answer, so the road travels with the call rather
            // than deciding here whether to make it.
            crate::skill_optimize::check_optimizer_admission_in_txn(
                store, wtxn, id, &prior, updated, replicated,
            )
        }
        Err(error)
            if error.kind() == ErrorKind::InvalidSkillBody
                && crate::skill::is_legacy_opaque_skill_body(prior_body) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// The ONE-1735 birth law for a LOCAL SKILL create.
///
/// Extracted from [`apply_put`] for the reason [`validate_skill_body_overwrite`]
/// is: this answers one question ("may this id be BORN with this body?"), and
/// the create arm now asks two — the origin marker, which every road carries,
/// and this, which only a local create is held to. Legacy-opaque upgrades take
/// the update arm instead (a prior record exists), so this sees genuine creates
/// only. New skills are born candidate, and fork lineage must name a real
/// type-7 SKILL parent (the `DerivedFrom` edge is door-authored and cannot
/// precede this create in the txn, so it is not required here).
///
/// # Errors
///
/// [`Error::InvalidSkillBody`] for a create that is not born candidate or whose
/// `forkedFrom` names itself, a missing row, or a row of another kind.
fn validate_local_skill_create(
    store: &Store,
    wtxn: &RwTxn<'_>,
    id: &EntityId,
    created: &crate::skill::SkillRecord,
) -> Result<()> {
    if created.lifecycle_status != crate::skill::SkillLifecycle::Candidate {
        return Err(Error::InvalidSkillBody(
            "new skills are born candidate; the admission gate activates them",
        ));
    }
    let Some(parent) = created.forked_from else {
        return Ok(());
    };
    if parent == *id {
        return Err(Error::InvalidSkillBody(
            "forkedFrom cannot name the fork itself",
        ));
    }
    let parent_raw =
        store
            .entities
            .get(wtxn, parent.as_bytes())?
            .ok_or(Error::InvalidSkillBody(
                "forkedFrom parent must exist as a type-7 SKILL",
            ))?;
    let parent_header =
        EntityMetadataHeader::parse(&parent_raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if parent_header.entity_type != ENTITY_TYPE_SKILL {
        return Err(Error::InvalidSkillBody(
            "forkedFrom parent must exist as a type-7 SKILL",
        ));
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "decomposing would obscure direct LMDB write logic"
)]
pub(super) fn apply_put(
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
    // ARCH-0052 D2: this is the shared entity materialization choke point for
    // public/typed puts, claim candidates, and replicated replay. A base row
    // at a live overlay member's id would publish the room into base, so it
    // rejects here — before any validation or side effect can mint an index
    // row, gate receipt, or entity body. The one exemption is a promote-replay
    // transaction rematerializing its OWN session's closure, carried on the
    // same write origin the K4 decode-point guard reads.
    reject_overlay_member_base_write(store, &id, origin)?;
    // Type-byte validation runs in `apply_ops` (the public-vs-maintenance gate:
    // public writes reject engine-authored system kinds, the sync
    // rematerialization path admits it via `allow_maintenance`). apply_put is
    // reached only after that gate, so it does not re-validate the type byte.
    //
    // D18: every type-0 (CLAIM) write — put_entity, both batch builders, and
    // sync replay — is structurally validated before any byte is staged.
    // Registered maintenance kinds with pinned body schemas get the same
    // fail-closed treatment on every path that can admit their type byte.
    // Bodies of all other type bytes stay opaque at the storage layer.
    let mut is_lexical_query_hint_claim = false;
    let mut new_skill_record = None;
    let mut new_agent_definition = None;
    // STO-03: `Some` only when the incoming TASK body named a derived streak
    // counter, i.e. only on the sync door — the body that gets stored instead.
    let mut task_body_without_streaks = None;
    let mut decoded_claim_body = None;
    let mut authority_entry_hash_pin: Option<crate::authority::AuthorityEntryHash> = None;
    // ONE-1604-D1 dominance VERDICT, recorded by the AUTHORITY_LOG arm below
    // and acted on only at the pre-write site: see the eviction comment there
    // for why the mutation cannot ride along with the check.
    let mut authority_dominates_key_squatter = false;
    if entity_type == crate::registry::ENTITY_TYPE_CLAIM {
        let body = crate::claim::validate_claim_body_and_decode(data, allow_reserved_predicate)?;
        is_lexical_query_hint_claim = body.predicate == crate::claim::PREDICATE_LEXICAL_QUERY_HINT;
        if is_lexical_query_hint_claim {
            if !id
                .as_bytes()
                .starts_with(&crate::claim::LEXICAL_QUERY_HINT_ID_PREFIX)
            {
                return Err(Error::InvalidClaimBody(
                    "lexical query hint claim id must use LH prefix",
                ));
            }
            let hint_value = crate::claim::decode_lexical_query_hint_value(&body.value)?;
            let target = hint_value.target;
            let expected_id = lexical_query_hint_claim_id(&target, &hint_value.query)?;
            if expected_id != id {
                return Err(Error::InvalidClaimBody(
                    "lexical query hint claim id must match target and query",
                ));
            }
            if !body.stale {
                return Err(Error::InvalidClaimBody(
                    "lexical query hint claims must be stale",
                ));
            }
            if body.lifecycle != crate::claim::ClaimLifecycleStatus::Active {
                return Err(Error::InvalidClaimBody(
                    "lexical query hint claims must be active",
                ));
            }
            if target == id {
                return Err(Error::InvalidClaimBody(
                    "lexical query hint target must not be self",
                ));
            }
            if let Some(target_raw) = store.entities.get(wtxn, target.as_bytes())? {
                let Some(target_header) = EntityMetadataHeader::parse(&target_raw) else {
                    return Err(Error::CorruptedIndex("entity header"));
                };
                if target_header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
                    return Err(Error::InvalidClaimBody(
                        "lexical query hint target must be claim",
                    ));
                }
                let Ok(target_body) = crate::claim::decode_claim_body(
                    &target_raw[ENTITY_METADATA_HEADER_LEN..],
                    true,
                ) else {
                    return Err(Error::InvalidClaimBody(
                        "lexical query hint target must be claim",
                    ));
                };
                if target_body.predicate == crate::claim::PREDICATE_LEXICAL_QUERY_HINT {
                    return Err(Error::InvalidClaimBody(
                        "lexical query hint target must not be synthetic hint",
                    ));
                }
            } else if !replicated {
                return Err(Error::InvalidClaimBody(
                    "lexical query hint target must be claim",
                ));
            }
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
            } else if let Some(write_envelope) = write_envelope {
                crate::gate::check_claim_policy_for_write_with_preflight_decision(
                    store,
                    wtxn,
                    &id,
                    &body,
                    Some(write_envelope),
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
            } else {
                crate::gate::check_claim_policy_for_write_with_preflight_decision(
                    store,
                    wtxn,
                    &id,
                    &body,
                    None,
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
    } else if entity_type == crate::registry::ENTITY_TYPE_MESSAGE {
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
    } else if entity_type == ENTITY_TYPE_OUTBOUND_GRANT {
        crate::outbound_grant::validate_standing_outbound_grant_body_bytes(data)?;
    } else if entity_type == ENTITY_TYPE_PSYCH_PROFILE {
        crate::psych_profile::validate_psych_profile_body_bytes(data)?;
    } else if entity_type == ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT {
        crate::persona_snapshot::validate_persona_snapshot_export_body_bytes(data)?;
    } else if entity_type == crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
        crate::identity_topology::validate_identity_topology_event_body_bytes(data)?;
    } else if entity_type == ENTITY_TYPE_SKILL {
        new_skill_record = Some(crate::skill::decode_skill_record(data)?);
    } else if entity_type == ENTITY_TYPE_AGENT_DEF {
        let decoded = crate::agent_def::decode_agent_definition(data)?;
        // ONE-1890 `sys.*` reservation, at the one arm that holds both the
        // decoded body and its destination row id — ALL puts, mirroring
        // SKILL's decode-site capture of `new_skill_record`.
        crate::agent_def::validate_reserved_logical_id(&id, &decoded)?;
        new_agent_definition = Some(decoded);
    } else if entity_type == ENTITY_TYPE_COMPANION_REGISTER {
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
    let data = match task_body_without_streaks.as_deref() {
        Some(stripped) => stripped,
        None => data,
    };
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
        if old_type == ENTITY_TYPE_SKILL {
            let prior_body = &old_record[ENTITY_METADATA_HEADER_LEN..];
            previous_skill_record = match crate::skill::decode_skill_record(prior_body) {
                Ok(record) => Some(record),
                Err(error)
                    if error.kind() == ErrorKind::InvalidSkillBody
                        && crate::skill::is_legacy_opaque_skill_body(prior_body) =>
                {
                    None
                }
                Err(error) => return Err(error),
            };
        }
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
        let should_deindex_stale_text = body_changed && (replicated || !has_later_covering_text_op);
        let old_code_artifact_body =
            if old_type == crate::registry::ENTITY_TYPE_CODE_ARTIFACT && body_changed {
                Some(old_record[ENTITY_METADATA_HEADER_LEN..].to_vec())
            } else {
                None
            };
        if old_type != entity_type {
            return Err(Error::EntityTypeImmutable {
                id,
                existing: old_type,
                attempted: entity_type,
            });
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
            return Err(Error::InvalidWitnessMessageBody(
                "an existing MESSAGE id is bound to its original canonical body",
            ));
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
                store,
                wtxn,
                &id,
                &old_record[ENTITY_METADATA_HEADER_LEN..],
                updated,
                hub_sync_imported,
                replicated,
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
            return Err(Error::InvalidCodeArtifactBody(
                "finalized code revision artifacts are immutable",
            ));
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

        if old_occurred.end.saturating_sub(old_occurred.start) > LONG_INTERVAL_THRESHOLD_SECS {
            let old_long_interval_key = Store::encode_temporal_key(old_occurred.end, &id);
            store
                .temporal_long_intervals
                .delete(wtxn, &old_long_interval_key)?;
        }

        if old_occurred.start != occurred.start {
            let old_start_key = Store::encode_temporal_key(old_occurred.start, &id);
            store.temporal_occurred_start.delete(wtxn, &old_start_key)?;
        }

        let old_is_range = old_occurred.start != old_occurred.end;
        let new_is_range = occurred.start != occurred.end;
        if old_is_range && (!new_is_range || old_occurred.end != occurred.end) {
            let old_end_key = Store::encode_temporal_key(old_occurred.end, &id);
            store.temporal_occurred_end.delete(wtxn, &old_end_key)?;
        }

        if old_learned != learned_at {
            let old_learned_key = Store::encode_temporal_key(old_learned, &id);
            store.temporal_learned.delete(wtxn, &old_learned_key)?;
        }
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
        if let Some(parent) = created.forked_from {
            if parent == id {
                return Err(Error::InvalidAgentDefBody(
                    "forkedFrom cannot name the fork itself",
                ));
            }
            let parent_raw =
                store
                    .entities
                    .get(wtxn, parent.as_bytes())?
                    .ok_or(Error::InvalidAgentDefBody(
                        "forkedFrom parent must exist as a type-17 AGENT_DEF",
                    ))?;
            let parent_header = EntityMetadataHeader::parse(&parent_raw)
                .ok_or(Error::CorruptedIndex("entity header"))?;
            if parent_header.entity_type != ENTITY_TYPE_AGENT_DEF {
                return Err(Error::InvalidAgentDefBody(
                    "forkedFrom parent must exist as a type-17 AGENT_DEF",
                ));
            }
            let parent_definition = crate::agent_def::decode_agent_definition(
                &parent_raw[ENTITY_METADATA_HEADER_LEN..],
            )?;
            if created.ceiling.widens_beyond(parent_definition.ceiling) {
                return Err(Error::InvalidAgentDefBody(
                    "forked agent ceiling cannot widen beyond its parent row ceiling",
                ));
            }
        }
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
    stage_entity_body_row(store, wtxn, &id, entity_type, occurred, learned_at, data)?;
    if let Some(record) = new_skill_record.as_ref() {
        crate::skill_hub::maintain_skill_content_hash_index_for_put(
            store,
            wtxn,
            &id,
            previous_skill_record
                .as_ref()
                .and_then(|previous| previous.content_hash),
            record.content_hash,
        )?;
        // ONE-1447: the reverse "which skills cite this message" index, kept at
        // the same chokepoint as the content-hash index so every road that can
        // land a SKILL body — typed doors, hub import, sync remat — maintains
        // it without a call site of its own.
        crate::skill_convert::maintain_skill_source_index_for_put(
            store,
            wtxn,
            &id,
            previous_skill_record.as_ref(),
            record,
        )?;
    }
    if let Some(body) = decoded_claim_body.as_ref() {
        crate::dreamer_runner::index_dreamer_milestone_claim_for_put(
            store, wtxn, &id, body, learned_at,
        )?;
        crate::llm::index_dreamer_step_claim_for_put(store, wtxn, &id, body, learned_at)?;
    }
    if let Some(key) = authority_first_seen_key {
        let observed_secs =
            authority_observation_secs_for_write(store, wtxn, crate::unix_seconds_now())?;
        if store.sync_state.get(wtxn, key.as_str())?.is_none() {
            let first_seen = crate::authority::encode_authority_first_seen_secs(observed_secs);
            store.sync_state.put(wtxn, key.as_str(), &first_seen)?;
        }
    }

    stage_entity_index_rows(store, wtxn, &id, entity_type, occurred, learned_at)?;

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
        pending_embedding_token,
        cleared_pending_embedding,
        had_vector_mutation,
        is_lexical_query_hint_claim,
        evicted_shell_sources,
    })
}

/// Stages the ONE-1449 MATERIAL-6 R1 optimizer-birth marker row, if this put
/// produced one, in the caller's transaction and immediately before the body
/// row it marks. `None` writes nothing.
///
/// # Errors
///
/// The `vault_meta` write's own error, propagated before the body write.
fn stage_optimizer_birth_marker_row(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    optimizer_birth_marker: Option<(Vec<u8>, Vec<u8>)>,
) -> Result<()> {
    if let Some((key, value)) = optimizer_birth_marker {
        store.vault_meta.put(wtxn, &key, &value)?;
    }
    Ok(())
}

/// Stages one entity's body row: the ARCH-0019 metadata header followed by the
/// caller's body bytes (ONE-1728 K11).
///
/// Target-parameterized, so a session witness writes the SAME header layout
/// into the overlay that base writes durably — promote replays the row without
/// re-encoding it.
pub(super) fn stage_entity_body_row(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    occurred: TimeRange,
    learned_at: u64,
    data: &[u8],
) -> Result<()> {
    let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + data.len());
    payload.push(entity_type);
    payload.extend_from_slice(&occurred.start.to_be_bytes());
    payload.extend_from_slice(&occurred.end.to_be_bytes());
    payload.extend_from_slice(&learned_at.to_be_bytes());
    payload.extend_from_slice(data);
    store.entities().put(wtxn, id.as_bytes(), &payload)?;
    Ok(())
}

/// Stages the type and temporal index rows every materialized entity carries
/// (ONE-1728 K11). Target-parameterized alongside [`stage_entity_body_row`]:
/// the session's type/temporal readers compose over these overlay rows, so an
/// in-room enumeration or time-range walk sees the turn it just witnessed.
///
/// `occurred`/`learned_at` are the WITNESSING write's own stamps — never
/// restamped here — so a promoted row lands in the month window it belongs to
/// (ARCH-0052 D4).
pub(super) fn stage_entity_index_rows(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<()> {
    let type_key = Store::encode_type_key(entity_type, id);
    store.type_index().put(wtxn, &type_key, &[])?;

    let occurred_start_key = Store::encode_temporal_key(occurred.start, id);
    store
        .temporal_occurred_start()
        .put(wtxn, &occurred_start_key, &[])?;

    if occurred.start != occurred.end {
        let occurred_end_key = Store::encode_temporal_key(occurred.end, id);
        store
            .temporal_occurred_end()
            .put(wtxn, &occurred_end_key, &[])?;
    }

    let learned_key = Store::encode_temporal_key(learned_at, id);
    store.temporal_learned().put(wtxn, &learned_key, &[])?;

    if occurred.end.saturating_sub(occurred.start) > LONG_INTERVAL_THRESHOLD_SECS {
        let long_interval_key = Store::encode_temporal_key(occurred.end, id);
        let occurred_start_value = occurred.start.to_be_bytes();
        store
            .temporal_long_intervals()
            .put(wtxn, &long_interval_key, &occurred_start_value)?;
    }
    Ok(())
}

/// Stages one edge's paired `edges_out`/`edges_in` rows (ONE-1728 K11).
///
/// PAIRED-WRITE INVARIANT: both directions carry byte-identical value bytes.
/// Extracted from [`apply_edge_with_created_at`] so the session path cannot
/// drift from it — a caller that wrote only one direction would leave the
/// overlay's edge readers asymmetric and promote a half-edge.
pub(super) fn stage_edge_rows(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    src: &EntityId,
    kind: EdgeKind,
    tgt: &EntityId,
    value: &[u8],
) -> Result<()> {
    let key_out = Store::encode_edge_key(src, kind, tgt);
    let key_in = Store::encode_edge_key(tgt, kind, src);
    store.edges_out().put(wtxn, &key_out, value)?;
    store.edges_in().put(wtxn, &key_in, value)?;
    Ok(())
}
