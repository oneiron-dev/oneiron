//! Evidence door and ordered idempotent projection from evidence to judgments and edit proposals.

use crate::Vault;
use crate::error::Result;

use super::codec::{
    CURSOR, EDIT_PROPOSAL, EVIDENCE, EvidenceRow, JUDGMENT, evidence_after,
    next_evidence_sequence_in_txn, validate_evidence,
};
use super::judge::{AttributionJudge, RuleAttributionJudge, verdict_subject};
use super::types::{AttributionJudgment, OutcomeEvidence, SkillEditProposal};

// ---------------------------------------------------------------------------
// Evidence door + projector
// ---------------------------------------------------------------------------

/// Records one outcome for later attribution, returning its sequence.
///
/// Recording never classifies: the projector owns the verdict, so evidence can
/// be captured on the hot path and routed in a later pass (the ARCH-0035
/// posture, and the reason a re-run can be replayed against a fixed judge).
pub fn record_attribution_evidence(vault: &Vault, evidence: &OutcomeEvidence) -> Result<u64> {
    validate_evidence(vault, evidence)?;
    vault.with_write_txn(|txn| record_evidence_in_txn(vault, txn, evidence))
}

/// The sweep validates first, then commits the evidence and receipt marker together.
pub(super) fn record_evidence_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    evidence: &OutcomeEvidence,
) -> Result<u64> {
    let sequence = next_evidence_sequence_in_txn(vault, txn)?;
    EVIDENCE.put(
        &vault.store,
        txn,
        &sequence,
        &EvidenceRow {
            sequence,
            evidence: evidence.clone(),
        },
    )?;
    Ok(sequence)
}

/// Reads the projector cursor: the highest evidence sequence already routed.
/// An absent row IS cursor 0 (bootstrap).
pub fn read_attribution_cursor(vault: &Vault) -> Result<u64> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(CURSOR.get(&vault.store, &rtxn, &())?.unwrap_or(0))
}

/// Runs one ordered, idempotent attribution pass over evidence recorded after
/// `since_cursor`, using the deterministic tier.
///
/// Returns the judgments minted by THIS pass. Re-running with the same cursor
/// re-routes the same evidence to the same verdicts; running with the persisted
/// cursor ([`read_attribution_cursor`]) processes only what is new.
pub fn run_attribution_projector(
    vault: &Vault,
    since_cursor: u64,
) -> Result<Vec<AttributionJudgment>> {
    run_attribution_projector_with_judge(vault, since_cursor, &RuleAttributionJudge)
}

/// [`run_attribution_projector`] with an explicit judge — the seam the LLM
/// tier and the audit harness both use.
///
/// Abstained evidence is left unjudged but still ADVANCES the cursor: an
/// abstention is a completed routing decision ("this evidence attributes to
/// nobody"), not a retryable failure, so it must not re-enter every pass.
pub fn run_attribution_projector_with_judge(
    vault: &Vault,
    since_cursor: u64,
    judge: &dyn AttributionJudge,
) -> Result<Vec<AttributionJudgment>> {
    let pending = evidence_after(vault, since_cursor)?;
    let mut judgments = Vec::new();
    let mut highest = since_cursor;
    for (sequence, evidence) in pending {
        highest = highest.max(sequence);
        let Some(verdict) = judge.judge(&evidence)? else {
            continue;
        };
        let Some(subject) = verdict_subject(verdict, &evidence) else {
            continue;
        };
        judgments.push(AttributionJudgment {
            sequence,
            verdict,
            subject,
            evidence_receipts: vec![evidence.receipt_ref.clone()],
            at: evidence.at,
        });
    }

    vault.with_write_txn(|wtxn| {
        for judgment in &judgments {
            JUDGMENT.put(&vault.store, wtxn, &judgment.sequence, judgment)?;
            if let Some(proposal) = edit_proposal_for(judgment) {
                EDIT_PROPOSAL.put(&vault.store, wtxn, &proposal.judgment_sequence, &proposal)?;
            }
        }
        if highest > since_cursor {
            CURSOR.put(&vault.store, wtxn, &(), &highest)?;
        }
        Ok(())
    })?;

    Ok(judgments)
}

/// Every persisted judgment, in routing order. ONE-1738 and ONE-1739 consume
/// this: it is the stack seam.
pub fn attribution_judgments(vault: &Vault) -> Result<Vec<AttributionJudgment>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(JUDGMENT
        .scan(&vault.store, &rtxn)?
        .into_iter()
        .map(|(_, judgment)| judgment)
        .collect())
}

/// Every minted skill EDIT PROPOSAL awaiting the gated apply, in mint order.
///
/// These are PERSISTED rows, not a filtered view of the judgments: a
/// discovery's consequence is a durable artifact that survives this process,
/// so the surface that applies it (the `dreamer_promotion` envelope precedent
/// / `supersede_skill_record` archive law) has something to pick up. Minting
/// is not applying — ONE-1737 stops at the proposal.
pub fn pending_edit_proposals(vault: &Vault) -> Result<Vec<SkillEditProposal>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(EDIT_PROPOSAL
        .scan(&vault.store, &rtxn)?
        .into_iter()
        .map(|(_, proposal)| proposal)
        .collect())
}

/// The proposal a judgment mints, or `None` when its verdict routes to a
/// claim instead (§4: only discovery becomes an edit proposal).
fn edit_proposal_for(judgment: &AttributionJudgment) -> Option<SkillEditProposal> {
    judgment
        .verdict
        .mints_edit_proposal()
        .then(|| SkillEditProposal {
            judgment_sequence: judgment.sequence,
            skill: judgment.subject,
            evidence_receipts: judgment.evidence_receipts.clone(),
            at: judgment.at,
        })
}
