//! Evidence door and ordered idempotent projection from evidence to judgments and edit proposals.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::skill_optimize::union_source_rows;

use super::codec::{
    CURSOR, EDIT_PROPOSAL, EVIDENCE, EvidenceRow, JUDGMENT, evidence_after,
    next_evidence_sequence_in_txn, validate_evidence,
};
use super::decision_receipts::keep_decision_receipts_in_txn;
use super::judge::{AttributionDecisions, verdict_subject};
use super::split::{classify_split_traced, measure_split_notes, unclear_floor_sourced};
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
    vault.with_write_txn_grouped(|txn| record_evidence_in_txn(vault, txn, evidence))
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
/// `since_cursor`, using the deterministic rule tier.
///
/// Returns the judgments minted by THIS pass. Re-running with the same cursor
/// re-routes the same evidence to the same verdicts; running with the persisted
/// cursor ([`read_attribution_cursor`]) processes only what is new.
pub fn run_attribution_projector(
    vault: &Vault,
    since_cursor: u64,
) -> Result<Vec<AttributionJudgment>> {
    run_attribution_projector_with_decisions(vault, since_cursor, None)
}

/// [`run_attribution_projector`] through the host's decisions — the seam the
/// model tier uses; `None` is the rule tier. Each judgment is stamped with the
/// exact revision that answered it, when one provider answered all of it, and
/// the receipts of the decisions that gave it are kept beside it, once
/// ([`super::attribution_decision_receipts`], FIX 11512).
///
/// Abstained evidence is left unjudged but still ADVANCES the cursor: an
/// abstention is a completed routing decision ("this evidence attributes to
/// nobody"), not a retryable failure, so it must not re-enter every pass.
///
/// A failed attempt carries no edit, so the judge answers once and the split
/// is one label at 100%. An `environment` answer blames nobody and leaves no
/// judgment row; an `unclear` one — the judge's own, a label held below the
/// `attribution_unclear_floor` setting, or `preference_shift`, which this lane
/// does not admit — leaves no judgment and files the evidence in the unclear
/// ledger instead. Every settled label, those two included, is kept as the
/// attempt's cause in the same write as the cursor (OF-568 L10), charging
/// nobody; those two keep their decision receipts beside it (FIX 12075).
pub fn run_attribution_projector_with_decisions(
    vault: &Vault,
    since_cursor: u64,
    decisions: Option<&AttributionDecisions<'_>>,
) -> Result<Vec<AttributionJudgment>> {
    let pending = evidence_after(vault, since_cursor)?;
    let mut judgments = Vec::new();
    // Each judgment's judge revision and decision receipts, in step.
    let mut stamps = Vec::new();
    let mut unclear = Vec::new();
    let mut causes = Vec::new();
    let mut highest = since_cursor;
    for (sequence, evidence) in pending {
        highest = highest.max(sequence);
        // The floor where this outcome ran, at its receipt's project and
        // type (FIX 2957).
        let (floor, floor_rows) = unclear_floor_sourced(vault, Some(&evidence.receipt_ref))?;
        // The rows a model-tier note reads (FIX 7101); the rule tier writes
        // no note, so it reads none.
        let sources = if decisions.is_some() {
            union_source_rows([evidence_rows(vault, &evidence), floor_rows])
        } else {
            None
        };
        let request = JudgeRequest {
            lane: AttributionLane::Attempt,
            evidence: &evidence,
            hunks: &[],
            floor,
            sources: sources.as_deref(),
        };
        let (classified, trace) = classify_split_traced(decisions, &request, &[])?;
        let Some((split, revision)) = classified else {
            continue;
        };
        measure_split_notes(vault, &split);
        // One region, so one label holds the whole outcome.
        let Some(verdict) = split.sole() else {
            continue;
        };
        // Every settled label is kept before subject routing drops the ones
        // that charge nobody, `environment` and `unclear` among them
        // (OF-568 L10). Those two leave no judgment row, so their decision
        // receipts are kept beside the cause (FIX 12075).
        let held = matches!(
            verdict,
            AttributionVerdict::Unclear | AttributionVerdict::Environment
        );
        causes.push((
            sequence,
            evidence.clone(),
            verdict,
            split.share_of(verdict),
            revision.clone(),
            held.then(|| trace.receipts.clone()),
        ));
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
            // The write below adopts the stored row's id on a re-route, so a
            // replay still compares equal and stays idempotent.
            row_id: vault.store.clock.entity_id()?,
            verdict,
            subject: Some(subject),
            evidence_receipts: vec![evidence.receipt_ref.clone()],
            at: evidence.at,
        });
        stamps.push((revision, trace.receipts));
    }

    vault.with_write_txn(|wtxn| {
        for (sequence, row) in &unclear {
            // A sequence some earlier judge already routed keeps that verdict:
            // judgments are never rescored, so a note must not contradict one.
            if !JUDGMENT.contains(&vault.store, wtxn, sequence)? {
                put_unclear_in_txn(vault, wtxn, row)?;
            }
        }
        for (judgment, (revision, receipts)) in judgments.iter_mut().zip(&stamps) {
            // An erase since this pass read the evidence left it naming no
            // one: its judgment is not made (FIX 8988).
            if !still_names_in_txn(vault, wtxn, judgment)? {
                continue;
            }
            if let Some(revision) = revision {
                super::judge_supersession::ensure_current_attribution_judge_in_txn(
                    vault, &*wtxn, revision,
                )?;
            }
            if let Some(existing) = JUDGMENT.get(&vault.store, wtxn, &judgment.sequence)? {
                // A re-route names the stored row: the id is the row's, not the pass's.
                judgment.row_id = existing.row_id;
                if existing != *judgment {
                    return Err(crate::error::Error::InvalidClaimBody(
                        "an attribution judgment cannot be rescored",
                    ));
                }
                // Unknown is immutable too: a retry under a newly installed
                // judge must never claim the old verdict as its own.
                continue;
            }
            if let Some(revision) = revision {
                super::judge_supersession::stamp_judge_revision(
                    vault,
                    wtxn,
                    judgment.sequence,
                    revision,
                )?;
            }
            JUDGMENT.put(&vault.store, wtxn, &judgment.sequence, judgment)?;
            // The row is immutable, so its decisions' receipts are kept
            // beside it (FIX 11512).
            keep_decision_receipts_in_txn(vault, wtxn, judgment.sequence, receipts)?;
            // A replay that now settles what an earlier pass held: the outcome
            // is judged, so it no longer waits in the unclear ledger.
            delete_unclear_in_txn(
                vault,
                wtxn,
                AttributionLane::Attempt,
                &judgment.sequence.to_string(),
            )?;
            mint_edit_proposal_in_txn(vault, wtxn, judgment)?;
        }
        // In the cursor's write: a cause that fails to land leaves its
        // evidence for the next pass.
        for (sequence, evidence, label, share, revision, receipts) in &causes {
            // The evidence as it stands in this write, so an erase since the
            // read is not undone (FIX 8988).
            let current = EVIDENCE.get(&vault.store, wtxn, sequence)?;
            // An unclear or environment outcome's decision receipts, keyed by
            // its sequence as its judgment's would be (FIX 12075): kept only
            // while its evidence stands as the judge read it, and never beside
            // a judgment an earlier pass made.
            if let Some(receipts) = receipts
                && current
                    .as_ref()
                    .is_some_and(|row| row.evidence == *evidence)
                && !JUDGMENT.contains(&vault.store, wtxn, sequence)?
            {
                keep_decision_receipts_in_txn(vault, wtxn, *sequence, receipts)?;
            }
            let evidence = current.as_ref().map_or(evidence, |row| &row.evidence);
            super::causes::put_attribution_cause_in_txn(
                vault,
                wtxn,
                *sequence,
                evidence,
                *label,
                *share,
                revision.as_deref(),
            )?;
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

pub(crate) fn attribution_judgments_in_txn(
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

/// Mints the skill EDIT PROPOSAL a discovery routes to, in the caller's
/// transaction — the one minting path both lanes take. The attempt lane mints
/// beside the judgment it persists; the amendment lane mints beside its own
/// judgment row, under a sequence drawn by [`draw_proposal_sequence_in_txn`],
/// so the two lanes' proposals share one keyspace and never collide. Any other
/// verdict mints nothing.
pub(crate) fn mint_edit_proposal_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    judgment: &AttributionJudgment,
) -> Result<()> {
    if let Some(mut proposal) = edit_proposal_for(judgment, vault.store.clock.entity_id()?) {
        // A re-judged amendment re-mints under its held sequence: the row keeps its id.
        if let Some(held) = EDIT_PROPOSAL.get(&vault.store, wtxn, &proposal.judgment_sequence)? {
            proposal.row_id = held.row_id;
        }
        EDIT_PROPOSAL.put(&vault.store, wtxn, &proposal.judgment_sequence, &proposal)?;
    }
    Ok(())
}

/// Draws a fresh sequence for a proposal minted outside this lane's evidence
/// ledger, from the same counter evidence sequences come from.
pub(crate) fn draw_proposal_sequence_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
) -> Result<u64> {
    next_evidence_sequence_in_txn(vault, wtxn)
}

/// Withdraws the pending proposal minted under `sequence`.
///
/// Only the amendment lane calls this. Its judgments are overwritten when an
/// amendment is judged again, and a proposal the new judgment no longer stands
/// behind must not keep waiting for the gated apply. Attempt judgments are
/// never rescored, so their proposals never move.
pub(crate) fn withdraw_edit_proposal_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    sequence: u64,
) -> Result<()> {
    EDIT_PROPOSAL.delete(&vault.store, wtxn, &sequence)?;
    Ok(())
}

/// The proposal a judgment mints under `row_id`, or `None` when its verdict
/// routes to a claim instead (§4: only discovery becomes an edit proposal).
fn edit_proposal_for(
    judgment: &AttributionJudgment,
    row_id: EntityId,
) -> Option<SkillEditProposal> {
    let skill = judgment.subject?;
    judgment
        .verdict
        .mints_edit_proposal()
        .then(|| SkillEditProposal {
            judgment_sequence: judgment.sequence,
            row_id,
            skill,
            evidence_receipts: judgment.evidence_receipts.clone(),
            at: judgment.at,
        })
}

/// Whether the evidence `judgment` was routed from still names its subject
/// in `txn`, as its skill or its actor.
fn still_names_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    judgment: &AttributionJudgment,
) -> Result<bool> {
    let Some(subject) = judgment.subject else {
        return Ok(false);
    };
    Ok(EVIDENCE
        .get(&vault.store, txn, &judgment.sequence)?
        .is_some_and(|row| {
            row.evidence.skill == Some(subject) || row.evidence.actor == Some(subject)
        }))
}

/// The rows `evidence`'s terminal pack receipt stands on, as the receipt
/// trace cites them (FIX 7101). `None` with no receipt or trace, or when the
/// read fails: a capture never fails the pass.
fn evidence_rows(vault: &Vault, evidence: &OutcomeEvidence) -> Option<Vec<EntityId>> {
    read_evidence_rows(vault, evidence).unwrap_or_else(|error| {
        tracing::debug!(kind = ?error.kind(), "an attribution request's sources were not read");
        None
    })
}

fn read_evidence_rows(vault: &Vault, evidence: &OutcomeEvidence) -> Result<Option<Vec<EntityId>>> {
    let receipt = {
        let rtxn = vault.store.env.read_txn()?;
        crate::receipt::attempt_pack_receipt_in_txn(&vault.store, &rtxn, &evidence.receipt_ref)?
    };
    let Some(receipt) = receipt else {
        return Ok(None);
    };
    Ok(
        super::trace::receipt_attribution_trace_sourced(vault, &receipt)?
            .and_then(|(_, rows)| rows),
    )
}
