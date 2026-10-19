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
//! meets at `Imported` lands only through its import's review, never here.

use rmpv::Value;

use super::{
    DreamerRunContext, PromotionCandidate, evidence_ref_refusal_in_txn, promotion_provenance,
    public_evidence_refs, public_evidence_value, scope_with_taint,
};
use crate::Vault;
use crate::claim::{ClaimApprovalStatus, ClaimSource, claim_evidence_taint};
use crate::dreamer_consolidation::evidence::VerifiedEvidenceSet;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::provenance::birth::RowBirth;
use crate::provenance::made_by::MadeByClass;
use crate::write_envelope::{SourceLineage, WriteEnvelope, WriteProvenance};

/// Lands `candidate`, the alternative a settlement keeps, with `verified`,
/// its evidence as bound in this same transaction. Refuses when its id is
/// already a record, its evidence is no longer admissible or meets at
/// `Imported`, or the Gate does not grant Auto.
pub(crate) fn land_kept_alternative_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    run: &DreamerRunContext,
    candidate: PromotionCandidate,
    verified: &VerifiedEvidenceSet,
) -> Result<()> {
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
    if source == ClaimSource::Imported
        || crate::ingest::history::imported_evidence_in_txn(vault, txn, &refs, &cited)?.imported
    {
        return Err(Error::InvalidClaimBody(
            "an alternative from imported words lands only through its import's review",
        ));
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
        ClaimApprovalStatus::Auto,
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
        .apply_recording_gate_decisions(txn)?;
    crate::entity_doc::retain_promotion_evidence_in_txn(
        vault,
        txn,
        &candidate.claim_id,
        &public_refs,
    )?;
    // Re-read inside the write: the alternative stands Auto, as written.
    let landed =
        vault
            .get_claim_in_txn(txn, &candidate.claim_id)?
            .ok_or(Error::InvalidClaimBody(
                "the kept alternative is missing inside its own write transaction",
            ))?;
    if landed.approval != ClaimApprovalStatus::Auto
        || landed.predicate != probe.predicate
        || landed.source != Some(source)
        || claim_evidence_taint(&landed) != Some(source)
    {
        return Err(Error::InvalidClaimBody(
            "the kept alternative was not granted Auto as written",
        ));
    }
    crate::own_rate::count_in_txn(
        &vault.store,
        txn,
        crate::own_rate::OwnRateKind::AutoWrite,
        run.agent_actor.entity_ref(),
        vault.store.clock.now_recorded_at(),
        crate::own_rate::auto_write_rate(),
    )?;
    verified.record_message_dependencies_in_txn(vault, txn, &candidate.claim_id)?;
    crate::dreamer_consolidation::strength::record_verified_in_txn(
        vault,
        txn,
        candidate.claim_id,
        verified,
        run.now_ms,
    )
}
