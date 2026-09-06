//! Dreamer promotion write path (ONE-1290, WP-011) — the ONE promotion
//! door for consolidated beliefs (design D7).
//!
//! Every promotion is a per-op gated write: one candidate, one
//! `evaluate_gate` evaluation, one write txn (commit or roll back together
//! with its optional supersession) — never batched across candidates
//! (1183-D2). The writer constructs the envelope itself (callers cannot pass
//! one), stamps surviving evidence into the candidate, applies the GATE-05
//! taint rules including the E1 supersession taint fold (a tainted head
//! superseded by a clean candidate keeps its taint — no laundering), and
//! verifies every landed claim by re-read before the caller may complete the
//! attempt (Hermes gate 9c). A future import-promotion flow consumes THIS
//! writer.
//!
//! ONE-1710 changed WHAT is stamped, not who may stamp it (ARCH-0067 §7,
//! "peer-answer trust is provenance, not friction"):
//!
//! * the claim's `src` is COMPUTED from the candidate's evidence meet folded
//!   with any superseded head's taint — never the old hardcoded `Generated`.
//!   A peer-answer-derived claim therefore lands truthfully as `tool_output`
//!   instead of `generated` with a hidden caveat, and `verify_landed`
//!   compares against that computed source;
//! * the engine-owned `scope.evidence_taint` is stamped for EVERY
//!   consolidation claim, not only the tainted classes, so the
//!   source/lineage relationship is structurally inspectable — and the
//!   central `validate_claim_source_lineage` guard can compare the two on
//!   every write door;
//! * the approval REQUEST is `Auto` for every candidate. There are no
//!   approval queues on this path: a write the gate does not grant Auto is
//!   rolled back and reported as a per-candidate REJECTION, never converted
//!   into a pending approval item. `PromotionOutcome.pended` is therefore
//!   structurally empty here.
//!
//! The actor axis is untouched: the Dreamer stays visible as the writing
//! actor in the envelope/provenance while the epistemic source describes the
//! evidence. Actor and source are separate axes.

use rmpv::Value;

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::claim::{
    CLAIM_SCOPE_EVIDENCE_TAINT_KEY, ClaimApprovalStatus, ClaimSource, claim_evidence_admissible,
    claim_evidence_taint, claim_source_widens_beyond,
};
use crate::dreamer_consolidation::{
    ConsolidationEvidenceEnvelope, ConsolidationProvenanceHop, encode_consolidation_evidence,
    source_meet,
};
use crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::llm::AutoChecker;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::write_envelope::{WriteActor, WriteEnvelope, WriteProvenance};

// PromotionCandidate is DEFINED by its producer (dreamer_consolidation,
// ONE-1289 — orchestrator ruling); this module is its designed home for
// consumers.
pub use crate::dreamer_consolidation::PromotionCandidate;

/// Identity of the Dreamer run performing a promotion pass.
#[derive(Debug, Clone)]
pub struct DreamerRunContext {
    pub run_id: String,
    pub attempt_id: AttemptId,
    /// The dreamer agent actor (`EdgeActorClass::Agent`).
    pub agent_actor: WriteActor,
    pub now_ms: u64,
}

/// Per-candidate outcome of one promotion pass.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PromotionOutcome {
    /// Landed with `Auto` approval (gate-granted).
    pub landed: Vec<EntityId>,
    /// STRUCTURALLY EMPTY since ONE-1710 (ARCH-0067 §7: "no approval
    /// queues"). The field survives for callers that pattern-match the
    /// outcome, but consolidation never routes a candidate here: a write the
    /// gate declines to grant Auto is rolled back and lands in `rejected`,
    /// so no owner-review row is ever minted behind the Dreamer's back.
    pub pended: Vec<EntityId>,
    /// Not written (typed reason per candidate); the loop continues.
    pub rejected: Vec<(EntityId, String)>,
}

/// Promotes consolidated candidates as vault claims through the gate
/// chokepoint — one candidate per write txn, in input order.
///
/// Caller contract (Hermes gate 9c): the attempt may be `complete()`d ONLY
/// when `rejected` is empty — a landed-verification mismatch fails the
/// attempt, never acks. Milestones are the caller's (CheckpointReached before
/// the pass, Done/Failed after); this writer emits none.
pub fn promote_consolidated_claims(
    vault: &Vault,
    run: &DreamerRunContext,
    candidates: Vec<PromotionCandidate>,
) -> Result<PromotionOutcome> {
    promote_consolidated_claims_with_checker(vault, run, candidates, None)
}

/// [`promote_consolidated_claims`] with the host's auto checker consulted
/// before each candidate's Auto request may land (ONE-1296).
///
/// The checker is asked only when the vault's policy manifest names one; a
/// vault whose manifest carries no `auto_checker` knob behaves exactly as it
/// did before this door existed, whatever the host passes here. A hold, and
/// every way a checker can fail to answer, refuses the candidate's Auto
/// request — which on THIS path means the write rolls back and the candidate
/// is reported in `rejected` (ARCH-0067 §7: consolidation mints no
/// owner-review rows behind the Dreamer's back), rather than landing a claim
/// nothing approved.
///
/// This is the ticket's ONE production injection point. Every other claim
/// write door passes no checker at all.
pub fn promote_consolidated_claims_with_checker(
    vault: &Vault,
    run: &DreamerRunContext,
    candidates: Vec<PromotionCandidate>,
    checker: Option<&dyn AutoChecker>,
) -> Result<PromotionOutcome> {
    let mut outcome = PromotionOutcome::default();

    for candidate in candidates {
        let claim_id = candidate.claim_id;
        match promote_one(vault, run, candidate, checker) {
            // `promote_one` rolls back anything the gate did not grant Auto,
            // so the non-Auto arm is unreachable defence-in-depth: it stays a
            // REJECTION rather than silently minting the approval queue row
            // ONE-1710 removed.
            Ok(ClaimApprovalStatus::Auto) => outcome.landed.push(claim_id),
            Ok(other) => outcome.rejected.push((
                claim_id,
                format!(
                    "landed verification failed: approval {} is not auto",
                    other.as_str()
                ),
            )),
            Err(reason) => outcome.rejected.push((claim_id, reason)),
        }
    }

    Ok(outcome)
}

/// One candidate: evidence admission → envelope → taint (incl. E1 fold) →
/// one wtxn (claim + optional supersession) → landed verification.
/// Returns the landed approval lane, or a typed rejection reason.
fn promote_one(
    vault: &Vault,
    run: &DreamerRunContext,
    candidate: PromotionCandidate,
    checker: Option<&dyn AutoChecker>,
) -> std::result::Result<ClaimApprovalStatus, String> {
    // 1. Evidence admission (GATE-11 write-path consumption): drop refs
    // resolving to evidence-inadmissible CLAIM entities and refs that do
    // not resolve at all; zero survivors is a typed rejection.
    let mut surviving: Vec<EntityId> = Vec::new();
    let mut dropped: Vec<EntityId> = Vec::new();
    for entry in &candidate.evidence_turn_refs {
        match evidence_ref_admissible(vault, entry) {
            Ok(true) => surviving.push(*entry),
            Ok(false) => dropped.push(*entry),
            Err(error) => return Err(format!("evidence resolution failed: {error}")),
        }
    }
    if surviving.is_empty() {
        let mut reason = "no admissible evidence refs".to_owned();
        if !dropped.is_empty() {
            reason.push_str(&format!(
                " (dropped {} inadmissible/unresolvable refs)",
                dropped.len()
            ));
        }
        return Err(reason);
    }

    // 2. Source (§3) — COMPUTED, never chosen. The candidate's evidence meet
    // folds with any superseded head's taint (the E1 supersession fold: a
    // tainted head superseded by a clean candidate keeps its taint — no
    // laundering), and the result becomes BOTH the envelope source and the
    // engine-owned taint stamp.
    let old_head_taint = match candidate.supersedes.as_ref() {
        Some(old_id) => vault
            .get_claim(old_id)
            .map_err(|error| format!("supersedes head read failed: {error}"))?
            .as_ref()
            .and_then(claim_evidence_taint),
        None => None,
    };
    let computed_meet = effective_evidence_source(candidate.evidence_meet, old_head_taint);
    let source = computed_meet;

    // 3. Envelope — constructed HERE; callers cannot pass one. Provenance
    // keeps exactly the shape dreamer_run_id_from_provenance parses and
    // gains the typed lineage only when there is one, so a candidate with no
    // external chain writes byte-identical provenance to before.
    let envelope = WriteEnvelope::new(
        run.agent_actor,
        source,
        WriteProvenance::new(promotion_provenance(run, &candidate.provenance_chain))
            .map_err(|error| error.to_string())?,
        // Auto for every candidate (ARCH-0067 §7). The gate may still
        // refuse; it may never turn this into an owner-review row.
        ClaimApprovalStatus::Auto,
    );

    // Surviving evidence + the typed chain + the computed meet ride the
    // candidate's structured evidence payload: the envelope evidence map's
    // candidate_evidence entry that GATE-12's evidence floor reads, and the
    // machine-readable record of WHICH answer TURN and consult TASK the
    // claim descends from. `refs` is exactly the post-admission survivors.
    let evidence_value = encode_consolidation_evidence(&ConsolidationEvidenceEnvelope {
        refs: surviving,
        chain: candidate.provenance_chain,
        source_meet: source,
    });

    // `ClaimCandidate` exposes no scope accessor, so the probe body is how
    // the writer reads the candidate's own scope before re-stamping it.
    let probe_body = candidate.candidate.clone().into_claim_body(&envelope);
    let claim_candidate = candidate
        .candidate
        .with_evidence(evidence_value)
        // Stamped for EVERY consolidation claim, not only the tainted
        // classes (§4): the central lineage guard compares src against this
        // key, so leaving it absent would leave a claim whose lineage
        // nothing can check.
        .with_scope(scope_with_taint(probe_body.scope.clone(), source));

    // Defence in depth (§5): the runtime validator at the write chokepoint
    // is authoritative; this catches an internal regression that lets the
    // encoded source drift above the computed meet in debug/test builds.
    debug_assert!(!claim_source_widens_beyond(
        claim_candidate
            .clone()
            .into_claim_body(&envelope)
            .source
            .expect("consolidation envelope must stamp a source"),
        computed_meet
    ));

    // 4. ONE wtxn: the claim write composed with its optional supersession
    // — commit or roll back BOTH (the landed torn-window contract).
    // GATE-007 (Generated over UserStated) surfaces here per-candidate.
    let write = vault.with_write_txn(|wtxn| {
        vault
            .batch_in()
            .claim_candidate(
                &candidate.claim_id,
                claim_candidate,
                &envelope,
                candidate.occurred,
                candidate.learned_at,
            )
            .apply_recording_gate_decisions_with_checker(wtxn, checker)?;
        if let Some(old_id) = candidate.supersedes.as_ref() {
            vault.supersede_claim_in_txn(wtxn, &candidate.claim_id, old_id, run.now_ms)?;
        }
        // No approval queues (§4/§9): if the gate narrowed the Auto request,
        // the whole transaction — claim, supersession, decision receipt and
        // the pending consent row it would have minted — rolls back, and the
        // candidate is reported as rejected instead. The already-stored
        // answer TURN is untouched: it never shared this transaction.
        let landed =
            vault
                .get_claim_in_txn(&*wtxn, &candidate.claim_id)?
                .ok_or(Error::InvalidClaimBody(
                    "consolidation claim is missing inside its own write transaction",
                ))?;
        if landed.approval != ClaimApprovalStatus::Auto {
            return Err(Error::InvalidClaimBody(
                "consolidation write was not granted Auto; no approval queue is created",
            ));
        }
        Ok(())
    });
    if let Err(error) = write {
        return Err(format!("gated write rejected: {error}"));
    }

    // 5. Landed verification (Hermes gate 9c): re-read and match, else the
    // candidate is rejected and the caller must not complete the attempt.
    verify_landed(vault, &candidate.claim_id, &probe_body.predicate, source)
}

/// The candidate meet folded with the superseded head's taint, through the
/// canonical `dreamer_consolidation::source_meet` lattice — one law, one
/// implementation. Absent a superseded head the candidate meet stands.
fn effective_evidence_source(
    candidate_meet: ClaimSource,
    old_head_taint: Option<ClaimSource>,
) -> ClaimSource {
    match old_head_taint {
        Some(old) => source_meet(candidate_meet, old),
        None => candidate_meet,
    }
}

/// Envelope provenance: the exact map `dreamer_run_id_from_provenance`
/// parses, plus the typed peer lineage when the candidate carries one. The
/// parser ignores unknown keys, so the addition is compatible; an empty
/// chain adds nothing at all.
fn promotion_provenance(run: &DreamerRunContext, chain: &[ConsolidationProvenanceHop]) -> Value {
    let mut entries = vec![
        (
            Value::from("surface"),
            Value::from(DREAMER_RUNNER_ATTEMPT_KIND),
        ),
        (Value::from("run"), Value::from(run.run_id.as_str())),
        (
            Value::from("job_id"),
            Value::from(bytes_to_hex_lower(run.attempt_id.as_bytes())),
        ),
    ];
    if !chain.is_empty() {
        entries.push((
            Value::from(PROMOTION_PROVENANCE_CHAIN_KEY),
            Value::Array(
                chain
                    .iter()
                    .map(|hop| {
                        let mut hop_entries = vec![
                            (Value::from("kind"), Value::from(hop.kind.as_str())),
                            (
                                Value::from("entity_ref"),
                                Value::Binary(hop.entity_ref.as_bytes().to_vec()),
                            ),
                        ];
                        if let Some(actor) = hop.actor_ref {
                            hop_entries.push((
                                Value::from("actor_ref"),
                                Value::Binary(actor.as_bytes().to_vec()),
                            ));
                        }
                        Value::Map(hop_entries)
                    })
                    .collect(),
            ),
        ));
    }
    Value::Map(entries)
}

/// Envelope-provenance key carrying the typed consolidation lineage.
pub const PROMOTION_PROVENANCE_CHAIN_KEY: &str = "peer_answer_chain";

/// Re-reads a landed claim and checks it is the claim we wrote. A missing
/// or mismatched read moves the candidate to `rejected`. The source is
/// compared against the COMPUTED meet the writer stamped — never a
/// hardcoded class.
fn verify_landed(
    vault: &Vault,
    claim_id: &EntityId,
    expected_predicate: &str,
    expected_source: ClaimSource,
) -> std::result::Result<ClaimApprovalStatus, String> {
    let Some(body) = vault
        .get_claim(claim_id)
        .map_err(|error| format!("landed verification read failed: {error}"))?
    else {
        return Err("landed verification failed: claim missing after commit".to_owned());
    };
    if body.predicate != expected_predicate {
        return Err("landed verification failed: predicate mismatch".to_owned());
    }
    if body.source != Some(expected_source) {
        return Err("landed verification failed: source stamp mismatch".to_owned());
    }
    if claim_evidence_taint(&body) != Some(expected_source) {
        return Err("landed verification failed: evidence taint stamp mismatch".to_owned());
    }
    Ok(body.approval)
}

/// True when the evidence ref may corroborate: TURN and other non-claim
/// entities pass; a type-0 CLAIM must pass `claim_evidence_admissible`
/// (GATE-11 — Generated-origin claims contribute zero); an unresolvable
/// ref is dropped fail-closed.
fn evidence_ref_admissible(vault: &Vault, entry: &EntityId) -> Result<bool> {
    let Some(entity_type) = vault.get_entity_type(entry)? else {
        return Ok(false);
    };
    if entity_type != ENTITY_TYPE_CLAIM {
        return Ok(true);
    }
    let Some(body) = vault.get_claim(entry)? else {
        return Ok(false);
    };
    Ok(claim_evidence_admissible(&body))
}

/// Appends the engine-owned `evidence_taint` scope entry, preserving the
/// candidate's existing scope map (a caller-supplied taint entry is
/// overwritten — the writer owns this key).
///
/// Since ONE-1710 every consolidation class is stamped, not only the two
/// at/below the taint floor. `evidence_taint_blocks_consolidation` is
/// unchanged, so a `Generated` stamp still blocks nothing: only `ToolOutput`
/// and `Imported` remain barred from recursively laundering themselves.
fn scope_with_taint(existing: Option<Value>, taint: ClaimSource) -> Value {
    let mut entries = match existing {
        Some(Value::Map(entries)) => entries,
        _ => Vec::new(),
    };
    entries.retain(|(key, _)| key.as_str() != Some(CLAIM_SCOPE_EVIDENCE_TAINT_KEY));
    entries.push((
        Value::from(CLAIM_SCOPE_EVIDENCE_TAINT_KEY),
        Value::from(taint.as_str()),
    ));
    Value::Map(entries)
}

/// [`crate::dreamer_consolidation::ConsolidationSink`] adapter: routes the
/// consolidation executor's surviving candidates through THIS writer — the
/// one promotion door. Accumulates per-bucket outcomes; the caller checks
/// `outcome.rejected` before completing the attempt (Hermes gate 9c).
pub struct PromotionWriterSink<'a> {
    pub vault: &'a Vault,
    pub run: DreamerRunContext,
    pub outcome: PromotionOutcome,
    /// The host's auto checker for every candidate this sink promotes
    /// (ONE-1296). Absent by default: a sink built with [`Self::new`] promotes
    /// exactly as it did before the knob existed.
    pub checker: Option<&'a dyn AutoChecker>,
}

impl<'a> PromotionWriterSink<'a> {
    #[must_use]
    pub fn new(vault: &'a Vault, run: DreamerRunContext) -> Self {
        Self {
            vault,
            run,
            outcome: PromotionOutcome::default(),
            checker: None,
        }
    }

    /// Binds the host's auto checker to this sink.
    #[must_use]
    pub fn with_checker(mut self, checker: &'a dyn AutoChecker) -> Self {
        self.checker = Some(checker);
        self
    }
}

impl crate::dreamer_consolidation::ConsolidationSink for PromotionWriterSink<'_> {
    fn accept(&mut self, candidates: Vec<PromotionCandidate>) -> Result<()> {
        let outcome = promote_consolidated_claims_with_checker(
            self.vault,
            &self.run,
            candidates,
            self.checker,
        )?;
        self.outcome.landed.extend(outcome.landed);
        self.outcome.pended.extend(outcome.pended);
        self.outcome.rejected.extend(outcome.rejected);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
