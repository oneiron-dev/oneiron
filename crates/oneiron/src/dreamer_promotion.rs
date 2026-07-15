//! Dreamer promotion write path (ONE-1290, WP-011) — the ONE promotion
//! door for consolidated beliefs (design D7).
//!
//! Every promotion is a per-op gated write: one candidate, one
//! `evaluate_gate` evaluation, one write txn (commit or roll back together
//! with its optional supersession) — never batched across candidates
//! (1183-D2). The writer constructs the envelope itself (source=Generated
//! mandatory, Proposed request ceiling; callers cannot pass one), stamps
//! surviving evidence into the candidate, applies the GATE-05 taint rules
//! including the E1 supersession taint fold (a tainted head superseded by a
//! clean candidate keeps its taint — no laundering), and verifies every
//! landed claim by re-read before the caller may complete the attempt (Hermes
//! gate 9c). A future import-promotion flow consumes THIS writer.

use rmpv::Value;

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::claim::{
    CLAIM_SCOPE_EVIDENCE_TAINT_KEY, ClaimApprovalStatus, ClaimSource, claim_evidence_admissible,
    claim_evidence_taint,
};
use crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;
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
    /// Landed in the `Proposed` lane (pending human review).
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
    let mut outcome = PromotionOutcome::default();

    for candidate in candidates {
        let claim_id = candidate.claim_id;
        match promote_one(vault, run, candidate) {
            Ok(approval) => match approval {
                ClaimApprovalStatus::Auto => outcome.landed.push(claim_id),
                _ => outcome.pended.push(claim_id),
            },
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

    // 2. Envelope — constructed HERE; callers cannot pass one. Provenance
    // is exactly the shape dreamer_run_id_from_provenance parses.
    let provenance = Value::Map(vec![
        (
            Value::from("surface"),
            Value::from(DREAMER_RUNNER_ATTEMPT_KIND),
        ),
        (Value::from("run"), Value::from(run.run_id.as_str())),
        (
            Value::from("job_id"),
            Value::from(bytes_to_hex_lower(run.attempt_id.as_bytes())),
        ),
    ]);
    let envelope = WriteEnvelope::new(
        run.agent_actor,
        ClaimSource::Generated,
        WriteProvenance::new(provenance).map_err(|error| error.to_string())?,
        ClaimApprovalStatus::Proposed,
    );

    // Surviving evidence is stamped into the candidate — it becomes the
    // envelope evidence map's candidate_evidence entry that GATE-12's
    // evidence floor reads; no other component supplies it.
    let evidence_value = Value::Array(
        surviving
            .iter()
            .map(|id| Value::Binary(id.as_bytes().to_vec()))
            .collect(),
    );

    // 3. Taint (D10) + the E1 supersession taint fold (R3): the old head's
    // taint folds into the effective meet BEFORE stamping, so a tainted
    // head superseded by a clean candidate keeps its taint.
    let old_head_taint = match candidate.supersedes.as_ref() {
        Some(old_id) => vault
            .get_claim(old_id)
            .map_err(|error| format!("supersedes head read failed: {error}"))?
            .as_ref()
            .and_then(claim_evidence_taint),
        None => None,
    };
    let effective_taint = effective_taint(candidate.evidence_meet, old_head_taint);

    let probe_body = candidate.candidate.clone().into_claim_body(&envelope);
    let mut claim_candidate = candidate.candidate.clone().with_evidence(evidence_value);
    if let Some(taint) = effective_taint {
        // Forced Proposed lane rides the envelope's Proposed request
        // ceiling (structural — the gate can only narrow, never widen a
        // Proposed request into Auto for a tainted write).
        claim_candidate =
            claim_candidate.with_scope(scope_with_taint(probe_body.scope.clone(), taint));
    }

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
            .apply_recording_gate_decisions(wtxn)?;
        if let Some(old_id) = candidate.supersedes.as_ref() {
            vault.supersede_claim_in_txn(wtxn, &candidate.claim_id, old_id, run.now_ms)?;
        }
        Ok(())
    });
    if let Err(error) = write {
        return Err(format!("gated write rejected: {error}"));
    }

    // 5. Landed verification (Hermes gate 9c): re-read and match, else the
    // candidate is rejected and the caller must not complete the attempt.
    verify_landed(vault, &candidate.claim_id, &probe_body.predicate)
}

/// Re-reads a landed claim and checks it is the claim we wrote. A missing
/// or mismatched read moves the candidate to `rejected`.
fn verify_landed(
    vault: &Vault,
    claim_id: &EntityId,
    expected_predicate: &str,
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
    if body.source != Some(ClaimSource::Generated) {
        return Err("landed verification failed: source stamp mismatch".to_owned());
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

/// The taint-relevant slice of the D10 meet: only `ToolOutput` and
/// `Imported` (the two classes at/below the taint floor) stamp; `Imported`
/// is the lattice bottom and wins a fold. The full lattice stays homed in
/// `dreamer_consolidation::evidence_trust_meet`.
fn effective_taint(
    evidence_meet: ClaimSource,
    old_head_taint: Option<ClaimSource>,
) -> Option<ClaimSource> {
    let mut worst: Option<ClaimSource> = None;
    for class in [Some(evidence_meet), old_head_taint].into_iter().flatten() {
        let tainted = matches!(class, ClaimSource::ToolOutput | ClaimSource::Imported);
        if !tainted {
            continue;
        }
        worst = Some(match (worst, class) {
            (Some(ClaimSource::Imported), _) | (_, ClaimSource::Imported) => ClaimSource::Imported,
            _ => class,
        });
    }
    worst
}

/// Appends the engine-owned `evidence_taint` scope entry, preserving the
/// candidate's existing scope map (a caller-supplied taint entry is
/// overwritten — the writer owns this key).
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
}

impl<'a> PromotionWriterSink<'a> {
    #[must_use]
    pub fn new(vault: &'a Vault, run: DreamerRunContext) -> Self {
        Self {
            vault,
            run,
            outcome: PromotionOutcome::default(),
        }
    }
}

impl crate::dreamer_consolidation::ConsolidationSink for PromotionWriterSink<'_> {
    fn accept(&mut self, candidates: Vec<PromotionCandidate>) -> Result<()> {
        let outcome = promote_consolidated_claims(self.vault, &self.run, candidates)?;
        self.outcome.landed.extend(outcome.landed);
        self.outcome.pended.extend(outcome.pended);
        self.outcome.rejected.extend(outcome.rejected);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
