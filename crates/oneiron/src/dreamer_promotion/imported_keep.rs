//! A kept alternative from imported words (FIX 5754): the selected landing's
//! review route.
//!
//! A retained alternative whose evidence meets at `Imported` never requests
//! Auto (ARCH-0027 trust tier). A Keep of it is staged where a promotion of
//! the same words lands: Proposed, in the review of the import its cited
//! words came from, with that review on its provenance and its audience as
//! the owner chose for the import's topic. The owner approves or declines it
//! there as one act with the rest of that import. Nothing here settles its
//! conflict or supersedes a member: the marker stays open beside it.

use rmpv::Value;

use super::{
    DreamerRunContext, EvidenceRef, PromotionCandidate, promotion_provenance,
    public_evidence_value, scope_with_taint, store_pending_group,
};
use crate::Vault;
use crate::claim::{ClaimApprovalStatus, ClaimSource, claim_evidence_taint};
use crate::dreamer_consolidation::evidence::VerifiedEvidenceSet;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::provenance::birth::RowBirth;
use crate::provenance::made_by::MadeByClass;
use crate::write_envelope::{SourceLineage, WriteEnvelope, WriteProvenance};

/// Stages `candidate` Proposed in `review`, the import its words came from
/// (with none, its round's run), in the settlement's transaction, with
/// `verified`, its evidence as bound there, and `public_refs`, the document
/// citations the caller already admitted. Refuses unless the Gate leaves it
/// Proposed in an owner review, as written.
pub(super) fn stage_kept_alternative_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    run: &DreamerRunContext,
    candidate: PromotionCandidate,
    verified: &VerifiedEvidenceSet,
    review: Option<&str>,
    public_refs: &[EvidenceRef],
) -> Result<()> {
    let source = ClaimSource::Imported;
    let refs = verified.refs();
    let cited = verified.cited_messages();
    let mut envelope = WriteEnvelope::with_lineage(
        run.agent_actor,
        source,
        WriteProvenance::new(promotion_provenance(
            run,
            &candidate.provenance_chain,
            review,
            &candidate.decisions,
        )?)?,
        ClaimApprovalStatus::Proposed,
        SourceLineage::of(ClaimSource::Generated).with(source),
    );
    // Rule A: concluded from the evidence that survived admission and the
    // MESSAGEs it cites, as a promotion is.
    let inputs: Vec<EntityId> = refs.iter().chain(&cited).copied().collect();
    let birth = RowBirth::written(
        run.agent_actor,
        MadeByClass::Concluded,
        "dreamer.promotion",
        &inputs,
        &[],
        candidate.learned_at,
    );
    let mut evidence_value = verified
        .clone()
        .restrict(source)
        .envelope(candidate.provenance_chain.clone());
    if !public_refs.is_empty() {
        let Value::Map(fields) = &mut evidence_value else {
            return Err(Error::InvalidClaimBody("promotion evidence is not a map"));
        };
        fields.push((
            Value::from("evidence_refs"),
            public_evidence_value(public_refs)?,
        ));
    }
    let default_facet = vault.default_facet_in_txn(txn)?;
    let probe = candidate
        .candidate
        .clone()
        .into_claim_body(&envelope, default_facet)?;
    let mut scope = scope_with_taint(probe.scope.clone(), source);
    // OF-492: words from an import of a topic the owner answered are born
    // into the audience they chose, before they are signed.
    if let Some(review) = review {
        scope = crate::federation::record_scope::stamp_import_audience_birth(
            vault, txn, scope, review,
        )?;
    }
    let hints = candidate.candidate.lexical_hints().to_vec();
    let claim_candidate = candidate
        .candidate
        .with_evidence(evidence_value)
        .with_scope(scope);
    vault.sign_retained_machine_claim_in_txn(
        txn,
        &candidate.claim_id,
        &claim_candidate,
        &mut envelope,
    )?;
    let hints: Vec<&str> = hints.iter().map(String::as_str).collect();
    vault
        .batch_in()
        .claim_candidate_with_lexical_hints(
            &candidate.claim_id,
            claim_candidate,
            &envelope,
            candidate.occurred,
            candidate.learned_at,
            &hints,
        )
        .made_by(&candidate.claim_id, birth)
        .apply_recording_gate_decisions(txn)?;
    crate::entity_doc::retain_promotion_evidence_in_txn(
        vault,
        txn,
        &candidate.claim_id,
        public_refs,
    )?;
    // Re-read inside the write: never Auto, and never Proposed where no
    // owner review holds it.
    let staged =
        vault
            .get_claim_in_txn(txn, &candidate.claim_id)?
            .ok_or(Error::InvalidClaimBody(
                "the kept alternative is missing inside its own write transaction",
            ))?;
    if staged.approval != ClaimApprovalStatus::Proposed
        || store_pending_group(vault, txn, &candidate.claim_id)?.is_none()
        || staged.predicate != probe.predicate
        || staged.source != Some(source)
        || claim_evidence_taint(&staged) != Some(source)
    {
        return Err(Error::InvalidClaimBody(
            "a kept alternative from imported words lands only in an owner review",
        ));
    }
    verified.record_message_dependencies_in_txn(vault, txn, &candidate.claim_id)?;
    crate::dreamer_consolidation::strength::record_verified_in_txn(
        vault,
        txn,
        candidate.claim_id,
        verified,
        run.now_ms,
    )
}
