//! The nightly writer (OF-498d): how the merge and each of its link
//! continuations land. A draft carries its proposals' scope stamps, refs and
//! taint; the proposals' raw bytes are read again before the commit; each
//! claim is written under the Dreamer's lineage, signed and through the gate;
//! and the attempt's result goes into the result ledger in the same commit.

use rmpv::Value;

use super::{MERGED, MergeResult, Proposal};
use crate::attempt_queue::AttemptId;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimSource, ScopedRead as ClaimRead, claim_evidence_taint,
};
use crate::dreamer_runner::{DreamerAttemptStatus, DreamerRunnerStore};
use crate::write_envelope::WriteActor;
use crate::{
    ClaimCandidate, EntityId, Error, Result, SourceLineage, TimeRange, Vault, WriteEnvelope,
    WriteProvenance,
};

/// One claim a nightly attempt writes: its candidate and the meet of its
/// sources.
pub(in crate::dreamer_consolidation) type Draft = Result<(ClaimCandidate, ClaimSource)>;

/// Where one nightly attempt lands: as whom, for which attempt, under which
/// id domain and when.
pub(in crate::dreamer_consolidation) struct NightlyWrite<'a> {
    pub(in crate::dreamer_consolidation) vault: &'a Vault,
    pub(in crate::dreamer_consolidation) actor: WriteActor,
    pub(in crate::dreamer_consolidation) attempt: &'a DreamerAttemptStatus,
    /// The domain each written claim's id derives under, beside the attempt
    /// and the claim's index among its drafts.
    pub(in crate::dreamer_consolidation) ids: &'static [u8],
    /// Unix seconds.
    pub(in crate::dreamer_consolidation) now: u64,
}

impl NightlyWrite<'_> {
    /// Writes each draft, in order, as its claim, and returns their ids: under
    /// the Dreamer's lineage, signed and through the gate, each asking Auto
    /// approval but an open conflict card, which asks Proposed. A draft that
    /// failed fails the commit.
    pub(in crate::dreamer_consolidation) fn claims_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        drafts: Vec<Draft>,
    ) -> Result<Vec<EntityId>> {
        let mut outputs = Vec::with_capacity(drafts.len());
        for (index, draft) in drafts.into_iter().enumerate() {
            let (candidate, meet) = draft?;
            let id = crate::codebase::entity_id_from_hash_material(
                self.ids,
                &[
                    self.attempt.attempt.id.as_bytes(),
                    &(index as u64).to_be_bytes(),
                ],
            )?;
            let requested = if candidate.predicate() == crate::claim::PREDICATE_CONFLICT_OPEN {
                ClaimApprovalStatus::Proposed
            } else {
                ClaimApprovalStatus::Auto
            };
            let mut envelope = WriteEnvelope::with_lineage(
                self.actor,
                meet,
                WriteProvenance::new(Value::Map(vec![
                    ("surface".into(), "dreamer".into()),
                    (
                        "run".into(),
                        self.attempt
                            .attempt
                            .run_id
                            .clone()
                            .unwrap_or_else(|| {
                                crate::entity_id::bytes_to_hex_lower(
                                    self.attempt.attempt.id.as_bytes(),
                                )
                            })
                            .into(),
                    ),
                ]))?,
                requested,
                SourceLineage::of(ClaimSource::Generated).with(meet),
            );
            self.vault
                .sign_retained_machine_claim_in_txn(txn, &id, &candidate, &mut envelope)?;
            self.vault
                .batch_in()
                .claim_candidate(
                    &id,
                    candidate,
                    &envelope,
                    TimeRange {
                        start: self.now,
                        end: self.now,
                    },
                    self.now,
                )
                .apply_recording_gate_decisions(txn)?;
            outputs.push(id);
        }
        Ok(outputs)
    }

    /// Records `result` as this attempt's in the result ledger.
    pub(in crate::dreamer_consolidation) fn result_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        result: &MergeResult,
    ) -> Result<()> {
        MERGED.put(&self.vault.store, txn, &self.attempt.attempt.id, result)
    }
}

/// Refuses the commit when any of `proposals` changed since its raw bytes
/// were read: the attempt commits again on resume.
pub(in crate::dreamer_consolidation) fn recheck_in_txn(
    read: &ClaimRead<'_>,
    txn: &heed::RoTxn<'_>,
    proposals: &[&Proposal],
) -> Result<()> {
    for proposal in proposals {
        if read.entity_raw_live_in(txn, &proposal.id)?.as_ref() != Some(&proposal.raw) {
            return Err(Error::ConcurrentWrite(
                "nightly proposal changed before merge",
            ));
        }
    }
    Ok(())
}

/// What a nightly attempt that already landed completes with: its own units,
/// or none once every step it paid for is charged. None when it has not
/// landed.
pub(in crate::dreamer_consolidation) fn landed_units_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
) -> Result<Option<u64>> {
    let Some(result) = MERGED.get(&vault.store, txn, &attempt)? else {
        return Ok(None);
    };
    let mut paid = !result.step_hashes.is_empty();
    for hash in &result.step_hashes {
        paid &= DreamerRunnerStore::new(vault).checkpoint_step_charged(attempt, hash)?;
    }
    Ok(Some(if paid { 0 } else { result.completed_units }))
}

/// `candidate` with the exposure of `body`, its proposal group's, the refs
/// of `members` as its evidence, and the meet of their sources as its taint.
pub(in crate::dreamer_consolidation) fn scoped_draft(
    candidate: ClaimCandidate,
    body: &ClaimBody,
    members: &[&Proposal],
) -> Draft {
    let meet = members.iter().fold(ClaimSource::Generated, |meet, member| {
        crate::dreamer_consolidation::source_meet(
            meet,
            claim_evidence_taint(&member.body)
                .or(member.body.source)
                .unwrap_or(ClaimSource::Generated),
        )
    });
    let mut candidate = candidate
        .with_scope_stamps(body.scope_facet, body.scope_project)
        .with_evidence(Value::Map(vec![(
            "refs".into(),
            Value::Array(
                members
                    .iter()
                    .map(|member| Value::Binary(member.id.as_bytes().to_vec()))
                    .collect(),
            ),
        )]));
    if let Some(world) = body.world {
        candidate = candidate.with_world(world);
    }
    if let Some(rel) = body.rel {
        candidate = candidate.with_relationship(rel);
    }
    if let Some(scope) = crate::claim::without_initial_weight(body.scope.clone()) {
        candidate = candidate.with_scope(scope);
    }
    Ok((candidate.with_evidence_taint(meet)?, meet))
}
