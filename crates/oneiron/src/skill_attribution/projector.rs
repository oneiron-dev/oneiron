//! Evidence door and ordered idempotent projection from evidence to judgments and edit proposals.

use crate::Vault;
use crate::error::Result;

use super::codec::{
    CURSOR, EDIT_PROPOSAL, EVIDENCE, EvidenceRow, JUDGMENT, evidence_after,
    next_evidence_sequence_in_txn, validate_evidence,
};
use super::judge::{AttributionJudge, RuleAttributionJudge, verdict_subject};
use super::split::{classify_split, unclear_floor};
use super::types::{
    AttributionJudgment, AttributionLane, AttributionVerdict, JudgeRequest, OutcomeEvidence,
    SkillEditProposal,
};
use super::unclear::{UnclearAttribution, delete_unclear_in_txn, put_unclear_in_txn};

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
///
/// A failed attempt carries no edit, so the judge answers once and the split
/// is one label at 100%. An `environment` answer blames nobody and leaves no
/// row; an `unclear` one — the judge's own, a label held below the
/// `attribution_unclear_floor` setting, or `preference_shift`, which this lane
/// does not admit — leaves no judgment and files the evidence in the unclear
/// ledger instead.
pub fn run_attribution_projector_with_judge(
    vault: &Vault,
    since_cursor: u64,
    judge: &dyn AttributionJudge,
) -> Result<Vec<AttributionJudgment>> {
    let pending = evidence_after(vault, since_cursor)?;
    let floor = unclear_floor(vault)?;
    let mut judgments = Vec::new();
    let mut unclear = Vec::new();
    let mut highest = since_cursor;
    for (sequence, evidence) in pending {
        highest = highest.max(sequence);
        let request = JudgeRequest {
            lane: AttributionLane::Attempt,
            evidence: &evidence,
            hunks: &[],
            floor,
        };
        let Some(split) = classify_split(judge, &request, &[])? else {
            continue;
        };
        // One region, so one label holds the whole outcome.
        let Some(verdict) = split.sole() else {
            continue;
        };
        if verdict == AttributionVerdict::Unclear {
            unclear.push((
                sequence,
                UnclearAttribution {
                    lane: AttributionLane::Attempt,
                    reference: sequence.to_string(),
                    evidence_receipts: vec![evidence.receipt_ref.clone()],
                    notes: split.unclear,
                    at: evidence.at,
                },
            ));
            continue;
        }
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
        for (sequence, row) in &unclear {
            // A sequence some earlier judge already routed keeps that verdict:
            // judgments are never rescored, so a note must not contradict one.
            if !JUDGMENT.contains(&vault.store, wtxn, sequence)? {
                put_unclear_in_txn(vault, wtxn, row)?;
            }
        }
        for judgment in &judgments {
            if let Some(revision) = judge.judge_revision() {
                super::judge_supersession::ensure_current_attribution_judge_in_txn(
                    vault, &*wtxn, revision,
                )?;
            }
            if let Some(existing) = JUDGMENT.get(&vault.store, wtxn, &judgment.sequence)? {
                if existing != *judgment {
                    return Err(crate::error::Error::InvalidClaimBody(
                        "an attribution judgment cannot be rescored",
                    ));
                }
                // Unknown is immutable too: a retry under a newly installed
                // judge must never claim the old verdict as its own.
                continue;
            }
            if let Some(revision) = judge.judge_revision() {
                super::judge_supersession::stamp_judge_revision(
                    vault,
                    wtxn,
                    judgment.sequence,
                    revision,
                )?;
            }
            JUDGMENT.put(&vault.store, wtxn, &judgment.sequence, judgment)?;
            // A replay that now settles what an earlier pass held: the outcome
            // is judged, so it no longer waits in the unclear ledger.
            delete_unclear_in_txn(
                vault,
                wtxn,
                AttributionLane::Attempt,
                &judgment.sequence.to_string(),
            )?;
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
    attribution_judgments_in_txn(vault, &rtxn)
}

pub(super) fn attribution_judgments_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<AttributionJudgment>> {
    Ok(JUDGMENT
        .scan(&vault.store, txn)?
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
