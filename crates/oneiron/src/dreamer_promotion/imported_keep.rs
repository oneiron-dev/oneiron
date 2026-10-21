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
//!
//! Its provenance names the conflict's marker and the alternative it was
//! kept from ([`KeptConflictLink`], FIX 6152), so a Keep staged at a fresh id
//! after a revert stands as a member of that conflict, and the owner may
//! approve and keep it there in one step (FIX 6151).

use rmpv::Value;

use super::{
    DreamerRunContext, EvidenceRef, PromotionCandidate, promotion_provenance,
    public_evidence_value, scope_with_taint, store_pending_group,
};
use crate::Vault;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimSource, claim_evidence_taint};
use crate::dreamer_consolidation::evidence::VerifiedEvidenceSet;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::provenance::birth::RowBirth;
use crate::provenance::made_by::MadeByClass;
use crate::write_envelope::{
    SourceLineage, WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY, WriteEnvelope, WriteProvenance,
};

/// The provenance key naming the conflict marker a staged Keep answers.
const KEPT_CONFLICT_MARKER_KEY: &str = "kept_conflict_marker";
/// The provenance key naming the retained alternative a staged Keep was
/// made of: its selector.
const KEPT_SELECTOR_KEY: &str = "kept_selector";

/// What a Keep staged in its import's review answers (FIX 6152): the
/// conflict's marker and the retained alternative it was kept from, its
/// selector. Its provenance carries both, so the staged claim reads as a
/// member of that conflict wherever it landed, and as standing for that
/// alternative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeptConflictLink {
    pub(crate) marker: EntityId,
    pub(crate) selector: EntityId,
}

impl KeptConflictLink {
    /// The link a staged Keep's provenance carries; `None` for any other
    /// claim. Only the Dreamer stages a Keep: a claim another writer wrote
    /// names no conflict here, whatever its provenance says.
    pub(crate) fn of_claim(body: &ClaimBody) -> Option<Self> {
        let Some(Value::Map(fields)) = &body.evidence else {
            return None;
        };
        let provenance = fields
            .iter()
            .find(|(key, _)| key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY))
            .map(|(_, value)| value)?;
        let link = Self {
            marker: crate::dreamer_consolidation::marker_ids(provenance, KEPT_CONFLICT_MARKER_KEY)
                .next()?,
            selector: crate::dreamer_consolidation::marker_ids(provenance, KEPT_SELECTOR_KEY)
                .next()?,
        };
        let dreamer = crate::dreamer_runner::authority::dreamer_actor_id().ok()?;
        (crate::memory::claim_author(body) == Some(dreamer)).then_some(link)
    }

    /// `provenance`, a promotion's map, with this link beside its entries.
    fn stamped(self, provenance: Value) -> Result<Value> {
        let Value::Map(mut entries) = provenance else {
            return Err(Error::InvalidClaimBody("promotion provenance is not a map"));
        };
        entries.push((
            Value::from(KEPT_CONFLICT_MARKER_KEY),
            Value::Binary(self.marker.as_bytes().to_vec()),
        ));
        entries.push((
            Value::from(KEPT_SELECTOR_KEY),
            Value::Binary(self.selector.as_bytes().to_vec()),
        ));
        Ok(Value::Map(entries))
    }
}

/// Where a kept alternative is staged and what it answers: the import review
/// it waits in (`None`: its round's run), and its conflict link.
pub(super) struct StagedIn<'a> {
    pub(super) review: Option<&'a str>,
    pub(super) link: KeptConflictLink,
}

/// Stages `candidate` Proposed in `staged_in`'s review, the import its words
/// came from (with none, its round's run), in the settlement's transaction,
/// with `verified`, its evidence as bound there, and `public_refs`, the
/// document citations the caller already admitted. Its provenance links it to
/// the conflict it was kept for. Refuses unless the Gate leaves it Proposed in
/// an owner review, as written.
pub(super) fn stage_kept_alternative_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    run: &DreamerRunContext,
    candidate: PromotionCandidate,
    verified: &VerifiedEvidenceSet,
    staged_in: StagedIn<'_>,
    public_refs: &[EvidenceRef],
) -> Result<()> {
    let review = staged_in.review;
    let source = ClaimSource::Imported;
    let refs = verified.refs();
    let cited = verified.cited_messages();
    let mut envelope = WriteEnvelope::with_lineage(
        run.agent_actor,
        source,
        WriteProvenance::new(staged_in.link.stamped(promotion_provenance(
            run,
            &candidate.provenance_chain,
            review,
            &candidate.decisions,
        )?)?)?,
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
