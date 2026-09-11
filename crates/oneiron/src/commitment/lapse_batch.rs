//! Crate-private Open-to-Lapsed batch grounding and apply halves.

use crate::batch::{ApplyOpsGateMode, BatchOp, EntityMetadataHeader, apply_ops_with_gate_mode};
use crate::claim::ClaimLifecycleStatus;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteEnvelope};

use super::codec::commitment_claim_candidate_from_body;
use super::{CommitmentStatus, PREDICATE_COMMITMENT_RECORD, decode_commitment_value};
use crate::error::ClaimError;

/// One grounded Open→Lapsed transition, derived but not yet written.
///
/// The gate preflight and the apply arm of `BatchOp::CommitmentGapDecay`
/// derive this from the SAME stored row inside the SAME transaction, so the
/// body the gate judges is byte-for-byte the body the apply writes.
pub(crate) struct PendingCommitmentLapse {
    pub(crate) id: EntityId,
    pub(crate) candidate: ClaimCandidate,
    pub(crate) occurred: TimeRange,
}

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
            .entities
            .get(txn, id.as_bytes())?
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
        pending.push(PendingCommitmentLapse {
            id: *id,
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
    preflight_gate_decision_ids: std::collections::HashMap<
        EntityId,
        std::collections::VecDeque<Option<crate::store::GateDecisionId>>,
    >,
) -> Result<()> {
    if write_policy.is_none() {
        return Err(Error::InvariantViolation(
            "local claim write policy snapshot missing",
        ));
    }
    let pending = pending_commitment_lapses_in_txn(store, &*wtxn, ids)?;
    if pending.is_empty() {
        return Ok(());
    }
    let mut ops = Vec::with_capacity(pending.len() * 2);
    for lapse in pending {
        ops.push(BatchOp::ClaimCandidate {
            id: lapse.id,
            candidate: Box::new(lapse.candidate),
            envelope: envelope.clone(),
            occurred: lapse.occurred,
            learned_at,
            internal_lexical_query_hint: false,
        });
        ops.push(BatchOp::ReconcileLexicalQueryHints {
            source: lapse.id,
            keep: Vec::new(),
        });
    }
    // Decisions were already recorded by the batch preflight, which is what
    // makes a denial survive rollback; recording again here would mint a
    // second Gate receipt per lapsed instance. The preflight identities ride
    // through so a pending bind reuses its own receipt instead of a fresh one.
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
    )
}
