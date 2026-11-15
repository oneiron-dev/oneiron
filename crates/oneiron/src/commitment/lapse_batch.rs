//! Crate-private Open-to-Lapsed batch grounding and apply halves.

use std::collections::{HashMap, VecDeque};

use crate::batch::{ApplyOpsGateMode, BatchOp, EntityMetadataHeader, apply_ops_with_gate_mode};
use crate::claim::transition::{
    ClaimTransitionKind, TransitionDelta, stage_machine_claim_transition,
};
use crate::claim::{ClaimBody, ClaimLifecycleStatus};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope};

use super::codec::commitment_claim_candidate_from_body;
use super::{CommitmentStatus, PREDICATE_COMMITMENT_RECORD, decode_commitment_value};
use crate::error::ClaimError;

/// The receipt identities a batch preflight recorded, per claim id, in order.
type PreflightDecisionIds = HashMap<EntityId, VecDeque<Option<crate::store::GateDecisionId>>>;

/// One grounded Open→Lapsed transition, derived but not yet written.
///
/// The gate preflight and the apply arm of `BatchOp::CommitmentGapDecay`
/// derive this from the SAME stored row inside the SAME transaction, so the
/// claim and body the gate judges are byte-for-byte the ones the apply writes.
pub(crate) struct PendingCommitmentLapse {
    /// The claim the lapse writes ([`lapse_claim_id`]).
    pub(crate) id: EntityId,
    /// The commitment that lapses.
    pub(crate) commitment: EntityId,
    pub(crate) candidate: ClaimCandidate,
    pub(crate) occurred: TimeRange,
}

pub(crate) use crate::write_envelope::commitment_transition::{lapse_claim_id, lapse_claim_ids};

/// Grounds every named commitment and derives its post-transition Lapsed
/// candidate, in the caller's transaction.
///
/// Runs the same predicate / lifecycle / transition checks as
/// [`Vault::update_commitment_status`], read through the store rather than the
/// vault so the batch apply chokepoint can call it with the handles it already
/// holds. Fail-closed and ALL-OR-NOTHING by construction: one missing,
/// non-CLAIM, non-commitment, closed, or already-terminal member returns a
/// typed error for the whole set before any op is staged.
pub(crate) fn pending_commitment_lapses_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    ids: &[EntityId],
) -> Result<Vec<PendingCommitmentLapse>> {
    let mut pending = Vec::with_capacity(ids.len());
    for id in ids {
        let raw = store
            .port_entity_record(txn, id)?
            .map(|row| row.encode())
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
            return Err(Error::InvalidClaimBody("entity is not a type-0 CLAIM"));
        }
        // Reserved predicates decode so the exact-match below can refuse them
        // by NAME rather than by an opaque decode failure.
        let body = crate::claim::decode_claim_body(
            &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            true,
        )?;
        if body.lifecycle != ClaimLifecycleStatus::Active {
            return Err(Error::Claim(ClaimError::ClaimAlreadyClosed {
                status: body.lifecycle,
            }));
        }
        if body.predicate != PREDICATE_COMMITMENT_RECORD {
            return Err(Error::InvalidClaimBody(
                "claim predicate is not commitment.record",
            ));
        }
        let mut record = decode_commitment_value(&body.value)?;
        if !record.status.can_transition_to(CommitmentStatus::Lapsed) {
            return Err(Error::InvalidClaimBody(
                "commitment status transition requires open source status",
            ));
        }
        record.status = CommitmentStatus::Lapsed;
        let claim = lapse_claim_id(id)?;
        if store.port_entity_present(txn, &claim)? {
            return Err(Error::InvalidClaimBody(
                "commitment lapse successor id already exists",
            ));
        }
        pending.push(PendingCommitmentLapse {
            id: claim,
            commitment: *id,
            candidate: commitment_claim_candidate_from_body(&body, &record)?,
            occurred: TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
        });
    }
    Ok(pending)
}

/// Applies every selected Open→Lapsed transition inside the caller's write
/// transaction (CMT-4, ONE-1541).
///
/// The apply half of `BatchOp::CommitmentGapDecay`. Commit ownership stays
/// with the caller, which is what makes the selected set all-or-nothing: a
/// stale or non-open member aborts before any op is staged, and a gate refusal
/// on a later id rolls back the earlier writes.
///
/// `write_policy` is the caller's resolved local-CLAIM snapshot. It is
/// REQUIRED rather than optional-in-practice: `contains_local_claim_put`
/// recognizes this op precisely so the snapshot exists here, and an absent one
/// means that recognition was lost, which is a fail-closed invariant violation
/// rather than a reason to write ungated.
///
/// Each lapse is a successor claim that supersedes its commitment
/// ([`lapse_through_successors_in_txn`]).
#[expect(
    clippy::too_many_arguments,
    reason = "the lapse helper threads the batch apply chokepoint's existing handles verbatim"
)]
pub(crate) fn lapse_commitments_in_txn(
    store: &crate::store::Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    wtxn: &mut heed::RwTxn<'_>,
    ids: &[EntityId],
    envelope: &WriteEnvelope,
    learned_at: u64,
    text_index_trusted: bool,
    write_policy: Option<&crate::gate::PolicyManifestResolution>,
    preflight_gate_decision_ids: PreflightDecisionIds,
) -> Result<()> {
    if write_policy.is_none() {
        return Err(Error::InvariantViolation(
            "local claim write policy snapshot missing",
        ));
    }
    lapse_through_successors_in_txn(
        store,
        config,
        analyzer,
        wtxn,
        ids,
        envelope,
        learned_at,
        text_index_trusted,
        preflight_gate_decision_ids,
    )
}

/// [`lapse_commitments_in_txn`] through status chains (FIX 9726): each
/// selected commitment's Lapsed record is a new successor claim, and the
/// successor supersedes the commitment, all staged in the caller's
/// transaction, so a refused batch lands none of it.
///
/// The preflight judged and recorded each lapse under its successor's id
/// ([`lapse_claim_id`]), so the successor's apply consumes that receipt
/// identity instead of minting another. A System writer's envelope is signed
/// per successor with the signer the host retained for it, as the preflight
/// signed it ([`lapse_envelope_for`]).
#[expect(
    clippy::too_many_arguments,
    reason = "the lapse helper threads the batch apply chokepoint's existing handles verbatim"
)]
fn lapse_through_successors_in_txn(
    store: &crate::store::Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    wtxn: &mut heed::RwTxn<'_>,
    ids: &[EntityId],
    envelope: &WriteEnvelope,
    learned_at: u64,
    text_index_trusted: bool,
    preflight_gate_decision_ids: PreflightDecisionIds,
) -> Result<()> {
    let pending = pending_commitment_lapses_in_txn(store, &*wtxn, ids)?;
    if pending.is_empty() {
        return Ok(());
    }
    let mut links = Vec::with_capacity(pending.len());
    let mut ops = Vec::with_capacity(pending.len() * 2);
    for lapse in pending {
        let successor = lapse.id;
        let envelope = lapse_envelope_for(store, &*wtxn, &lapse, envelope)?;
        ops.push(BatchOp::ClaimCandidate {
            id: successor,
            candidate: Box::new(lapse.candidate),
            envelope,
            occurred: lapse.occurred,
            learned_at,
            internal_lexical_query_hint: false,
        });
        ops.push(BatchOp::ReconcileLexicalQueryHints {
            source: successor,
            keep: Vec::new(),
        });
        links.push((successor, lapse.commitment));
    }
    apply_ops_with_gate_mode(
        store,
        config,
        analyzer,
        wtxn,
        ops,
        text_index_trusted,
        ApplyOpsGateMode::new(false, true)
            .with_source_in_gate_input()
            .with_preflight_gate_decision_ids(preflight_gate_decision_ids),
    )?;
    for (successor, commitment) in links {
        supersede_with_successor_in_txn(
            store,
            config,
            analyzer,
            wtxn,
            (successor, commitment),
            envelope.actor(),
            learned_at,
            text_index_trusted,
        )?;
    }
    Ok(())
}

/// The envelope one lapse successor is written under: `envelope` itself, or,
/// for a System writer (the housekeeping pass's commitment lapse writer), a
/// copy signed over this successor's body with the signer the host retained
/// for the writer. The batch preflight and the apply both call this, so the
/// Gate judges the bytes the apply stores. Without a retained signer the copy
/// stays unsigned and the write door refuses the MACHINE author.
pub(crate) fn lapse_envelope_for(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    lapse: &PendingCommitmentLapse,
    envelope: &WriteEnvelope,
) -> Result<WriteEnvelope> {
    let mut signed = envelope.clone();
    crate::authority::sign_retained_machine_claim_for_store_in_txn(
        store,
        txn,
        &lapse.id,
        &lapse.candidate,
        &mut signed,
    )?;
    Ok(signed)
}

/// Supersedes `predecessor` with `successor` in the caller's transaction, as
/// [`Vault::supersede_claim_in_txn`](crate::Vault::supersede_claim_in_txn)
/// does, for the batch apply, which holds the store and not the vault.
///
/// The predecessor closes `superseded` at `now`, a MACHINE-born one inside
/// its own validity window, and the `supersedes` edge and the revision pair
/// land with it. A MACHINE-born predecessor closes through the host's signed
/// close, attributed to `writer` when the lapse is a System writer's (the
/// housekeeping pass's commitment lapse writer) and to the owner otherwise,
/// as before. Every write stages in the caller's transaction, so a refusal
/// takes the whole batch down with it.
#[expect(
    clippy::too_many_arguments,
    reason = "the lapse helper threads the batch apply chokepoint's existing handles verbatim"
)]
fn supersede_with_successor_in_txn(
    store: &crate::store::Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    wtxn: &mut heed::RwTxn<'_>,
    (successor, predecessor): (EntityId, EntityId),
    writer: WriteActor,
    now: u64,
    text_index_trusted: bool,
) -> Result<()> {
    let (successor_body, _) = active_claim_parts_in(store, &*wtxn, &successor)?;
    let (mut body, header) = active_claim_parts_in(store, &*wtxn, &predecessor)?;
    crate::Vault::require_source_trust_supersession_rights(&successor_body, &body)?;
    // As the claim supersession: before its occurred start the predecessor
    // closes at that start, and the supersession keeps the real `now`. A
    // MACHINE-born predecessor keeps its own validity end, which its signed
    // history requires: a projected instance's window is its due instant,
    // and the sweep runs after it.
    let machine = crate::authority::machine_claim_needs_history(store, &*wtxn, &body)?;
    let end = if machine {
        crate::claim::transition::machine_close_end(&body, now)
    } else {
        now
    };
    let closed_end = end.max(header.occurred_start);
    let revisions = crate::claim::supersession_diff::capture_in_store_txn(
        store,
        &*wtxn,
        predecessor,
        successor,
    )?;
    body.lifecycle = ClaimLifecycleStatus::Superseded;
    body.valid_to = Some(end);
    if machine {
        let (closer, closer_class) = match writer.actor_class() {
            EdgeActorClass::System => (writer.entity_ref(), EdgeActorClass::System),
            EdgeActorClass::Human | EdgeActorClass::Agent => (
                crate::vault::embedded_owner_actor_id()?,
                EdgeActorClass::Human,
            ),
        };
        body = stage_machine_claim_transition(
            store,
            config,
            analyzer,
            wtxn,
            predecessor,
            ClaimTransitionKind::SupersedeClose,
            TransitionDelta::ValidTo(end),
            closer,
            closer_class,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            text_index_trusted,
        )?;
    }
    let ops = vec![
        BatchOp::Put {
            id: predecessor,
            entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            occurred: TimeRange {
                start: header.occurred_start,
                end: closed_end,
            },
            learned_at: header.learned_at,
            row_version: None,
            data: crate::claim::encode_claim_body(&body)?,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        },
        BatchOp::EdgeWithCreatedAt {
            src: successor,
            kind: EdgeKind::Supersedes,
            tgt: predecessor,
            weight: crate::vault::SUPERSEDES_DEFAULT_WEIGHT,
            created_at: now,
            vad: oneiron_contracts::affect::Vad::NEUTRAL,
            provenance: None,
        },
    ];
    let (binding, transition) = crate::batch::ClaimMaterialization::verified_lifecycle_closed_by(
        store, &*wtxn, &ops[0], None, now,
    )?;
    let gate_mode = ApplyOpsGateMode::new(false, true)
        .with_claim_materializations(binding.into_iter().collect())
        .with_verified_claim_transitions(vec![transition]);
    apply_ops_with_gate_mode(
        store,
        config,
        analyzer,
        wtxn,
        ops,
        text_index_trusted,
        gate_mode,
    )?;
    crate::claim::supersession_diff::store_in_store_txn(
        store,
        wtxn,
        predecessor,
        successor,
        revisions,
    )
}

/// One stored CLAIM's body and header, refused unless its `life` is still
/// `active`.
fn active_claim_parts_in(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<(ClaimBody, EntityMetadataHeader)> {
    let raw = store
        .port_entity_record(txn, id)?
        .map(|row| row.encode())
        .ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return Err(Error::InvalidClaimBody("entity is not a type-0 CLAIM"));
    }
    let body =
        crate::claim::decode_claim_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..], true)?;
    if body.lifecycle != ClaimLifecycleStatus::Active {
        return Err(Error::Claim(ClaimError::ClaimAlreadyClosed {
            status: body.lifecycle,
        }));
    }
    Ok((body, header))
}
