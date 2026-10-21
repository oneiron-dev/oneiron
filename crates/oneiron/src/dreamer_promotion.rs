//! Dreamer promotion write path (ONE-1290, WP-011) — the ONE promotion
//! door for consolidated beliefs (design D7).
//!
//! Every promotion is a per-op gated write: one candidate, one
//! `evaluate_gate` evaluation, one write txn (commit or roll back together
//! with its optional deferred closure binding) — never batched across candidates
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
//! * ordinary creates request `Auto` and roll back on refusal. Destructive
//!   replacements share the deferred closure gate with memory upserts: every
//!   replacement first persists Proposed. Only a later Auto or owner grant
//!   writes the edge and its runner-owned provenance companion.
//! * a claim whose evidence meets at `Imported` never requests `Auto`
//!   (ARCH-0027 trust tier): it lands Proposed in the review of the import its
//!   words came from (`ingest::history::history_import_review_id`), which the
//!   owner approves or declines as one act. The gate holds the same floor for
//!   every Dreamer write, whatever any source_trust row says.
//!
//! The actor axis is untouched: the Dreamer stays visible as the writing
//! actor in the envelope/provenance while the epistemic source describes the
//! evidence. Actor and source are separate axes.

use rmpv::Value;

mod admission;
mod attempt_sink;
pub use admission::{CursorSpan, EvidenceKind, EvidenceRef, PromotionEvidenceReason};
pub(crate) use admission::{
    evidence_ref_refusal_in_txn, public_evidence_refs, public_evidence_value,
};
mod corrections;
mod imported_keep;
mod resolved_outputs;
mod scoped;
mod settlement;
mod writer;
/// What the live policy lets the vault's Dreamer do (see
/// `Vault::dreamer_weave_reach` and the owner's `Vault::grant_dreamer_weave`).
pub use crate::gate::DreamerWeaveReach;
pub use attempt_sink::AttemptPromotionSink;
pub(crate) use imported_keep::KeptConflictLink;
pub use scoped::promote_scoped_consolidation;
pub(crate) use settlement::{KeptLanding, land_kept_alternative_in_txn};
use writer::promote_one;

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::claim::{
    CLAIM_SCOPE_EVIDENCE_TAINT_KEY, ClaimApprovalStatus, ClaimSource, claim_evidence_taint,
    claim_source_widens_beyond,
};
use crate::dreamer_consolidation::evidence::VerifiedEvidenceSet;
use crate::dreamer_consolidation::{
    ConsolidationEvidenceEnvelope, ConsolidationProvenanceHop, encode_consolidation_evidence,
    source_meet,
};
use crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::llm::BoundedAutoChecker;
use crate::provenance::birth::RowBirth;
use crate::provenance::made_by::MadeByClass;
#[cfg(test)]
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION};
use crate::write_envelope::{SourceLineage, WriteActor, WriteEnvelope, WriteProvenance};

// PromotionCandidate is DEFINED by its producer (dreamer_consolidation,
// ONE-1289 — orchestrator ruling); this module is its designed home for
// consumers.
pub use crate::dreamer_consolidation::PromotionCandidate;

/// Identity of the Dreamer run performing a promotion pass.
#[derive(Debug, Clone)]
pub struct DreamerRunContext {
    pub run_id: String,
    pub attempt_id: AttemptId,
    /// The vault Dreamer authority (`Vault::dreamer_authority`), never a facet actor.
    pub agent_actor: WriteActor,
    pub now_ms: u64,
}

/// Per-candidate outcome of one promotion pass.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PromotionOutcome {
    /// Landed with `Auto` approval (gate-granted).
    pub landed: Vec<EntityId>,
    /// All destructive replacements, conflict markers and claims from
    /// imported evidence, retained as Proposed. Ordinary create refusals still
    /// go to `rejected`.
    pub pended: Vec<EntityId>,
    /// Existing heads that imported evidence restated: not attached, because
    /// imported material reaches the vault only through the owner's review;
    /// and declined claims the same imported words yielded again, not
    /// proposed again.
    pub held: Vec<EntityId>,
    /// Not written (typed reason per candidate); the loop continues.
    pub rejected: Vec<(EntityId, String)>,
}

/// Promotes consolidated candidates as vault claims through the gate
/// chokepoint — one candidate per write txn, in input order.
///
/// Do not consolidate claim VAD here: every landed claim is Auto with a
/// Generated, ToolOutput, or Imported evidence meet and fails the canonical
/// consolidation read gate. VAD population belongs after an existing vetting
/// door commits Approved, not at promotion. Ordinary promotions without pending
/// consent have no such door and remain unvetted.
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
/// write door passes no checker at all. The concrete [`BoundedAutoChecker`]
/// makes capacity, timeout, and panic isolation mandatory. The host resolves
/// the manifest's opaque selector and supplies its matching implementation.
pub fn promote_consolidated_claims_with_checker(
    vault: &Vault,
    run: &DreamerRunContext,
    candidates: Vec<PromotionCandidate>,
    checker: Option<&BoundedAutoChecker>,
) -> Result<PromotionOutcome> {
    if run.agent_actor != vault.dreamer_actor_for_attempt(run.attempt_id)? {
        return Err(Error::InvalidConfig(
            "promotion actor is not the queued Dreamer authority".into(),
        ));
    }
    let mut outcome = PromotionOutcome::default();

    for candidate in candidates {
        let claim_id = candidate.claim_id;
        match promote_one(vault, run, candidate, checker, None, None) {
            // Ordinary creates roll back unless granted Auto. Replacements
            // explicitly stage Proposed; any other status is a rejection.
            Ok(ClaimApprovalStatus::Auto) => outcome.landed.push(claim_id),
            Ok(ClaimApprovalStatus::Proposed) => outcome.pended.push(claim_id),
            Ok(other) => outcome.rejected.push((
                claim_id,
                format!(
                    "landed verification failed: approval {} is not auto",
                    other.as_str()
                ),
            )),
            Err(rejection) => outcome.rejected.push((claim_id, rejection.reason)),
        }
    }

    Ok(outcome)
}

/// The review group of the pending-consent row `claim` waits in, if any.
fn store_pending_group(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    claim: &EntityId,
) -> Result<Option<String>> {
    Ok(vault
        .store
        .pending_gate_consent_in_txn(txn, claim)?
        .and_then(|row| row.dreamer_run_id))
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
/// parses, plus the typed peer lineage when the candidate carries one and the
/// import review a claim from imported evidence waits in. The parser ignores
/// unknown keys, so the additions are compatible; an empty chain adds nothing
/// at all.
fn promotion_provenance(
    run: &DreamerRunContext,
    chain: &[ConsolidationProvenanceHop],
    import_review: Option<&str>,
    decisions: &[crate::dreamer_consolidation::KeptDecision],
) -> Result<Value> {
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
    if let Some(review) = import_review {
        entries.push((
            Value::from(crate::gate::DREAMER_PROVENANCE_IMPORT_REVIEW_KEY),
            Value::from(review),
        ));
    }
    if !decisions.is_empty() {
        entries.push((
            Value::from(PROMOTION_PROVENANCE_DECISIONS_KEY),
            crate::dreamer_consolidation::kept_decisions_value(decisions)?,
        ));
    }
    Ok(Value::Map(entries))
}

/// Envelope-provenance key carrying the typed consolidation lineage.
pub const PROMOTION_PROVENANCE_CHAIN_KEY: &str = "peer_answer_chain";

/// Envelope-provenance key carrying the typed decisions behind a Dreamer
/// write (ARCH-0076): each whole decision, and the ask it went up as.
pub const PROMOTION_PROVENANCE_DECISIONS_KEY: &str = "decisions";

/// The same typed evidence decision returned by the public evidence read.
fn evidence_ref_admissible(vault: &Vault, entry: &EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    Ok(evidence_ref_refusal_in_txn(vault, &txn, entry)?.is_none())
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
    pub checker: Option<&'a BoundedAutoChecker>,
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
    pub fn with_checker(mut self, checker: &'a BoundedAutoChecker) -> Self {
        self.checker = Some(checker);
        self
    }
}

impl crate::dreamer_consolidation::ConsolidationSink for PromotionWriterSink<'_> {
    fn accept_scoped(
        &mut self,
        write: crate::dreamer_consolidation::ScopedConsolidationWrite,
    ) -> Result<()> {
        let outcome = promote_scoped_consolidation(self.vault, &self.run, write, self.checker)?;
        let refused = !outcome.rejected.is_empty();
        self.outcome.landed.extend(outcome.landed);
        self.outcome.pended.extend(outcome.pended);
        self.outcome.held.extend(outcome.held);
        self.outcome.rejected.extend(outcome.rejected);
        if refused {
            return Err(Error::InvalidClaimBody(
                "scoped consolidation write refused",
            ));
        }
        Ok(())
    }

    fn accept(&mut self, candidates: Vec<PromotionCandidate>) -> Result<()> {
        let outcome = promote_consolidated_claims_with_checker(
            self.vault,
            &self.run,
            candidates,
            self.checker,
        )?;
        self.outcome.landed.extend(outcome.landed);
        self.outcome.pended.extend(outcome.pended);
        self.outcome.held.extend(outcome.held);
        self.outcome.rejected.extend(outcome.rejected);
        Ok(())
    }
}

/// The landed re-read as its tests read it: the rejection's text alone.
#[cfg(test)]
fn verify_landed(
    vault: &Vault,
    claim_id: &EntityId,
    expected_predicate: &str,
    expected_source: ClaimSource,
) -> std::result::Result<ClaimApprovalStatus, String> {
    writer::verify_landed(vault, claim_id, expected_predicate, expected_source)
        .map_err(|rejection| rejection.reason)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) fn evidence_ref_admissible_for_test(vault: &Vault, entry: &EntityId) -> Result<bool> {
    evidence_ref_admissible(vault, entry)
}
