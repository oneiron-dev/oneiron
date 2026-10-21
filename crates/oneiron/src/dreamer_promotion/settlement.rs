//! The selected landing (OF-023, FIX 496): a consolidation round's retained
//! alternative that a conflict settlement keeps lands in the settlement's own
//! transaction, through the same admission, source and taint computation,
//! signature, birth, MESSAGE dependencies and Gate a promotion uses, and is
//! re-read before the settlement goes on.
//!
//! It requests Auto, as every native promotion does. A Gate refusal, or any
//! landing that is not Auto as written, refuses the settlement, so its marker
//! stays open. A responder's choice is the settlement's own answer: it never
//! turns the alternative's computed source into a stated one. Evidence that
//! meets at `Imported` lands only through its import's review, never here:
//! it is staged there instead, as a promotion of the same words is
//! (`imported_keep.rs`, FIX 5754). When the Gate holds the Auto landing on a
//! typed reason the responder's Keep approves, the responder's door retries
//! once: the same alternative is born Proposed here and approved by the
//! responder in the same transaction (`settle/keep_approval.rs`, FIX 5753).

use rmpv::Value;

use super::imported_keep::KeptConflictLink;
use super::{
    DreamerRunContext, PromotionCandidate, evidence_ref_refusal_in_txn, promotion_provenance,
    public_evidence_refs, public_evidence_value, scope_with_taint,
};
use crate::Vault;
use crate::claim::{ClaimApprovalStatus, ClaimSource, claim_evidence_taint};
use crate::dreamer_consolidation::KeepAs;
use crate::dreamer_consolidation::evidence::VerifiedEvidenceSet;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::provenance::birth::RowBirth;
use crate::provenance::made_by::MadeByClass;
use crate::write_envelope::{SourceLineage, WriteEnvelope, WriteProvenance};

/// Where a kept alternative went: landed Auto, or staged Proposed in the
/// review of the import its words came from (`None`: its round's run).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeptLanding {
    Landed,
    ImportReview(Option<String>),
}

/// Lands `candidate`, the alternative a settlement keeps, with `verified`,
/// its evidence as bound in this same transaction. Refuses when its id is
/// already a record, its evidence is no longer admissible, or the Gate does
/// not grant Auto. Evidence that meets at `Imported` is staged in its
/// import's review instead, linked by `link` to the conflict it was kept for
/// (FIX 6152). `keep_as` lands it Auto, noting a hold the responder may
/// approve, or Proposed and approved by the responder (FIX 5753).
pub(crate) fn land_kept_alternative_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    run: &DreamerRunContext,
    candidate: PromotionCandidate,
    verified: &VerifiedEvidenceSet,
    link: KeptConflictLink,
    keep_as: KeepAs<'_>,
) -> Result<KeptLanding> {
    if run.run_id.trim().is_empty() {
        return Err(Error::InvalidClaimBody("promotion run id is blank"));
    }
    if crate::ports::EntityStoreRead::port_entity_present(&vault.store, txn, &candidate.claim_id)? {
        return Err(Error::InvalidClaimBody(
            "the kept alternative's id is already a record",
        ));
    }
    let refs = verified.refs();
    for entry in &refs {
        if evidence_ref_refusal_in_txn(vault, txn, entry)?.is_some() {
            return Err(Error::InvalidClaimBody(
                "the kept alternative's evidence is no longer admissible",
            ));
        }
    }
    let public_refs = public_evidence_refs(candidate.candidate.evidence())?;
    for reference in &public_refs {
        let source = crate::entity_doc::promotion_evidence_source_in_txn(vault, txn, reference)?;
        if !refs.contains(&source) {
            return Err(Error::InvalidClaimBody(
                "document citation has no admissible source ref",
            ));
        }
    }
    let cited = verified.cited_messages();
    let source = verified.meet();
    let import = crate::ingest::history::imported_evidence_in_txn(vault, txn, &refs, &cited)?;
    if source == ClaimSource::Imported || import.imported {
        super::imported_keep::stage_kept_alternative_in_txn(
            vault,
            txn,
            run,
            candidate,
            verified,
            super::imported_keep::StagedIn {
                review: import.review.as_deref(),
                link,
            },
            &public_refs,
        )?;
        return Ok(KeptLanding::ImportReview(import.review));
    }
    let lineage = match source {
        ClaimSource::ToolOutput => SourceLineage::of(ClaimSource::Generated).with(source),
        _ => SourceLineage::of(ClaimSource::Generated),
    };
    let mut envelope = WriteEnvelope::with_lineage(
        run.agent_actor,
        source,
        WriteProvenance::new(promotion_provenance(
            run,
            &candidate.provenance_chain,
            None,
            &candidate.decisions,
        )?)?,
        keep_as.requested(),
        lineage,
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
            public_evidence_value(&public_refs)?,
        ));
    }
    let default_facet = vault.default_facet_in_txn(txn)?;
    let probe = candidate
        .candidate
        .clone()
        .into_claim_body(&envelope, default_facet)?;
    let hints = candidate.candidate.lexical_hints().to_vec();
    let claim_candidate = candidate
        .candidate
        .with_evidence(evidence_value)
        .with_scope(scope_with_taint(probe.scope.clone(), source));
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
        .apply_recording_gate_decisions(txn)
        .inspect_err(|error| keep_as.note_refusal(error))?;
    crate::entity_doc::retain_promotion_evidence_in_txn(
        vault,
        txn,
        &candidate.claim_id,
        &public_refs,
    )?;
    keep_as.approve_in_txn(vault, txn, candidate.claim_id, run.now_ms)?;
    // Re-read inside the write: the alternative stands Auto, as written, or
    // Approved by the responder.
    let landed =
        vault
            .get_claim_in_txn(txn, &candidate.claim_id)?
            .ok_or(Error::InvalidClaimBody(
                "the kept alternative is missing inside its own write transaction",
            ))?;
    if landed.approval != keep_as.landed()
        || landed.predicate != probe.predicate
        || landed.source != Some(source)
        || claim_evidence_taint(&landed) != Some(source)
    {
        return Err(Error::InvalidClaimBody(
            "the kept alternative was not granted Auto as written",
        ));
    }
    // A landing the responder approved is no Auto write of the Dreamer's.
    if landed.approval == ClaimApprovalStatus::Auto {
        crate::own_rate::count_in_txn(
            &vault.store,
            txn,
            crate::own_rate::OwnRateKind::AutoWrite,
            run.agent_actor.entity_ref(),
            vault.store.clock.now_recorded_at(),
            crate::own_rate::auto_write_rate(),
        )?;
    }
    verified.record_message_dependencies_in_txn(vault, txn, &candidate.claim_id)?;
    crate::dreamer_consolidation::strength::record_verified_in_txn(
        vault,
        txn,
        candidate.claim_id,
        verified,
        run.now_ms,
    )?;
    Ok(KeptLanding::Landed)
}
