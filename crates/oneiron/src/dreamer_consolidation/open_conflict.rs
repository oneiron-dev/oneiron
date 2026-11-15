//! A judge outage is an open question, persisted through the shared write gate.
use super::evidence::{VerifiedCandidate, VerifiedEvidenceSet};
use super::{ConflictSet, conflict_open_marker_id};
use crate::provenance::birth::RowBirth;
use crate::provenance::made_by::MadeByClass;
use crate::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EntityId, Result,
    SourceLineage, TimeRange, Vault, WriteActor, WriteEnvelope, WriteProvenance,
};
use rmpv::Value;

/// One open-conflict marker as its conflict, members and decisions make it,
/// built without a write. [`write_open_marker_in_txn`] lands it.
struct OpenMarkerParts {
    /// The marker's id: its attempt's and its conflict identity's.
    id: EntityId,
    /// The marker claim, carrying its members' joined evidence.
    candidate: ClaimCandidate,
    /// The provenance every marker carries. The writer adds the import
    /// review when the evidence is imported words.
    provenance: Vec<(Value, Value)>,
    /// The members' verified evidence, joined.
    verified: VerifiedEvidenceSet,
    /// The joined evidence's source meet.
    meet: ClaimSource,
    /// The marker's birth (Rule A); `None` when it names no input.
    birth: Option<RowBirth>,
}

#[expect(
    clippy::too_many_arguments,
    reason = "the conflict, its members and decisions join the writer's fence and clock"
)]
pub(super) fn park_open_conflict(
    vault: &Vault,
    actor: WriteActor,
    attempt: crate::attempt_queue::AttemptId,
    conflict: &ConflictSet,
    members: &[&VerifiedCandidate],
    decisions: &[super::KeptDecision],
    fence: &super::resources::ConsolidationFence,
    now: u64,
) -> Result<EntityId> {
    let parts = open_marker_parts(actor, attempt, conflict, members, decisions, now)?;
    let id = parts.id;
    vault.with_write_txn_grouped(|txn| {
        crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        fence.validate_in_txn(vault, txn)?;
        write_open_marker_in_txn(vault, txn, actor, parts, now)
    })?;
    Ok(id)
}

/// Builds the marker that leaves `conflict` open for `attempt`: its id, its
/// claim with the members' joined evidence and retained alternatives, its
/// provenance with the decisions that left it open, and its birth. It reads
/// and writes no row.
///
/// # Errors
///
/// A conflict with no member evidence, a marker id, scope or decision that
/// does not encode, and a member whose facts do not decode.
fn open_marker_parts(
    actor: WriteActor,
    attempt: crate::attempt_queue::AttemptId,
    conflict: &ConflictSet,
    members: &[&VerifiedCandidate],
    decisions: &[super::KeptDecision],
    now: u64,
) -> Result<OpenMarkerParts> {
    let id = conflict_open_marker_id(conflict, attempt)?;
    let mut verified: Option<VerifiedEvidenceSet> = None;
    for member in members {
        verified = Some(verified.map_or_else(
            || member.evidence.clone(),
            |old| old.union(&member.evidence),
        ));
    }
    let verified = verified
        .ok_or_else(|| super::support::invalid_consolidation("open conflict has no evidence"))?;
    let meet = verified.meet();
    let evidence = verified.envelope(Vec::new());
    // Each candidate the round drops rides whole beside its id (FIX 496), so
    // a responder sees its value and may keep it. A member that does not
    // encode leaves the marker as it was before, never unwritten.
    let alternatives = match super::retained_conflict::alternatives_entry(members, attempt) {
        Ok(entry) => Some(entry),
        Err(_) => {
            tracing::warn!(
                target: "oneiron::dreamer",
                subject = %conflict.identity.subject.to_hex(),
                "an open conflict's candidates were not retained"
            );
            None
        }
    };
    let mut provenance = vec![
        (Value::from("surface"), Value::from("dreamer")),
        (
            Value::from("run"),
            Value::from(crate::entity_id::bytes_to_hex_lower(attempt.as_bytes())),
        ),
    ];
    // The decisions that left it open ride beside it (ARCH-0076).
    if !decisions.is_empty() {
        provenance.push((
            Value::from(crate::dreamer_promotion::PROMOTION_PROVENANCE_DECISIONS_KEY),
            super::provenance::kept_decisions_value(decisions)?,
        ));
    }
    let mut candidate = ClaimCandidate::new(
        crate::claim::PREDICATE_CONFLICT_OPEN,
        ClaimSubject::Entity(conflict.identity.subject),
        Value::Map(
            vec![
                (
                    Value::from("predicate"),
                    if members.iter().all(|member| {
                        super::conflict::candidate_facts(&member.candidate)
                            .is_ok_and(|facts| facts.predicate == conflict.identity.predicate)
                    }) {
                        Value::from(conflict.identity.predicate.clone())
                    } else {
                        Value::Nil
                    },
                ),
                (
                    Value::from("predicates"),
                    Value::Array(
                        members
                            .iter()
                            .map(|member| {
                                super::conflict::candidate_facts(&member.candidate)
                                    .map(|facts| Value::from(facts.predicate))
                            })
                            .collect::<Result<Vec<_>>>()?,
                    ),
                ),
                (
                    Value::from("prior_head"),
                    conflict
                        .prior_head
                        .map_or(Value::Nil, |id| Value::Binary(id.as_bytes().to_vec())),
                ),
                (
                    Value::from("prior_heads"),
                    Value::Array(
                        conflict
                            .prior_heads
                            .iter()
                            .map(|id| Value::Binary(id.as_bytes().to_vec()))
                            .collect(),
                    ),
                ),
                (
                    Value::from("candidates"),
                    Value::Array(
                        members
                            .iter()
                            .map(|c| Value::Binary(c.claim_id.as_bytes().to_vec()))
                            .collect(),
                    ),
                ),
            ]
            .into_iter()
            .chain(alternatives)
            .collect(),
        ),
        1.0,
    )
    .with_evidence(evidence);
    if let Some(world) = conflict.identity.world {
        candidate = candidate.with_world(world);
    }
    candidate = candidate.with_relationships(conflict.identity.rel.clone());
    candidate = candidate
        .with_scope(super::persistence::identity_scope(&conflict.identity)?)
        .with_evidence_taint(meet)?;
    // Rule A: the marker is concluded from its members' verified evidence, the
    // MESSAGEs it cites and the heads they dispute, every one of them.
    let birth = {
        let inputs: Vec<EntityId> = verified
            .refs()
            .into_iter()
            .chain(verified.cited_messages())
            .chain(conflict.prior_heads.iter().copied())
            .collect();
        RowBirth::written(
            actor,
            MadeByClass::Concluded,
            "dreamer.conflict",
            &inputs,
            &[],
            now,
        )
    };
    Ok(OpenMarkerParts {
        id,
        candidate,
        provenance,
        verified,
        meet,
        birth,
    })
}

/// Lands `parts` in `txn` as `actor`, at `now`: the marker as a proposal
/// through the shared write gate, signed as a retained machine claim, with
/// its birth and its dependencies on the MESSAGE words it cites. The caller
/// owns the write: its clock, and any fence it holds.
///
/// # Errors
///
/// The gate's refusal, a provenance that does not encode, and storage
/// errors.
fn write_open_marker_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: WriteActor,
    parts: OpenMarkerParts,
    now: u64,
) -> Result<()> {
    let OpenMarkerParts {
        id,
        candidate,
        mut provenance,
        verified,
        meet,
        birth,
    } = parts;
    // An open question over imported words waits in their import's review,
    // beside the claims drawn from them.
    if meet == ClaimSource::Imported
        && let Some(review) = crate::ingest::history::imported_evidence_in_txn(
            vault,
            txn,
            &verified.refs(),
            &verified.cited_messages(),
        )?
        .review
    {
        provenance.push((
            Value::from(crate::gate::DREAMER_PROVENANCE_IMPORT_REVIEW_KEY),
            Value::from(review),
        ));
    }
    let mut envelope = WriteEnvelope::with_lineage(
        actor,
        meet,
        WriteProvenance::new(Value::Map(provenance))?,
        ClaimApprovalStatus::Proposed,
        SourceLineage::of(ClaimSource::Generated).with(meet),
    );
    vault.sign_retained_machine_claim_in_txn(&*txn, &id, &candidate, &mut envelope)?;
    vault
        .batch_in()
        .claim_candidate(
            &id,
            candidate,
            &envelope,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .apply_recording_gate_decisions(txn)?;
    // The marker's id is the attempt's: a retry keeps its first birth.
    if let Some(birth) = &birth {
        crate::provenance::birth::stamp_birth_if_absent_in_txn(&vault.store, txn, &id, birth)?;
    }
    verified.record_message_dependencies_in_txn(vault, txn, &id)
}
