//! The round loop: triage, weave, blind Borda ranking, stop condition, winner commit.

use std::collections::BTreeSet;

use crate::Vault;
use crate::critic::{CritiqueVerdict, LensCatalog, triage_critiques};
use crate::error::{Error, Result};

use super::evidence::{
    DreamerTournamentEvidenceStore, put_critique_artifact_in_txn, tournament_evidence,
    tournament_weave_evidence,
};

use super::types::{
    DREAMER_TOURNAMENT_MAX_ROUNDS_K, DreamerTournamentBlindJudgeContext,
    DreamerTournamentBordaBallot, DreamerTournamentBranchVerdict, DreamerTournamentRun,
    DreamerTournamentRunResult, DreamerTournamentStopReason, DreamerTournamentSynthesisVerdict,
    DreamerTournamentWinner, MAX_TOURNAMENT_BALLOTS, RankedCandidate, SynthesizedCandidate,
};
use super::validate::{invalid_tournament, validate_ballot, validate_run, validate_weave_parents};
pub fn run_dreamer_claim_tournament(
    vault: &Vault,
    input: DreamerTournamentRun,
) -> Result<DreamerTournamentRunResult> {
    validate_run(&input)?;
    let catalog = LensCatalog::of366_seed()?;
    let evidence_store = DreamerTournamentEvidenceStore::new(vault);
    let mut branch_evidence = Vec::new();
    let mut critique_artifacts = Vec::new();
    let mut latest_blind_contexts = Vec::new();
    let mut latest_winner = None;
    let mut latest_winner_candidate = None;
    let mut rounds_executed = 0_u16;
    let mut stop_reason = DreamerTournamentStopReason::ExhaustedRounds;

    let max_rounds = input
        .max_rounds_k
        .min(DREAMER_TOURNAMENT_MAX_ROUNDS_K)
        .min(u16::try_from(input.rounds.len()).unwrap_or(u16::MAX));

    for (round_index, round) in input
        .rounds
        .iter()
        .enumerate()
        .take(usize::from(max_rounds))
    {
        let round_number = u16::try_from(round_index + 1)
            .map_err(|_| Error::IndexOverflow("tournament round index"))?;
        let mut synthesized = Vec::new();
        let mut partial_survivors = Vec::new();

        for branch in &round.branches {
            let triage = triage_critiques(&catalog, &branch.critiques, &input.reliabilities)?;
            let critique_ids = branch
                .critiques
                .iter()
                .map(|critique| critique.artifact_id.clone())
                .collect::<Vec<_>>();
            critique_artifacts.extend(branch.critiques.iter().cloned());

            match triage.verdict {
                CritiqueVerdict::Discard => {
                    if branch.synthesis.verdict != DreamerTournamentSynthesisVerdict::Discarded {
                        return Err(invalid_tournament(
                            "discard triage requires discard synthesis verdict",
                        ));
                    }
                    let evidence = tournament_evidence(
                        &input.run_id,
                        &branch.author,
                        DreamerTournamentBranchVerdict::Discarded,
                        Some(branch.synthesis.artifact_id.clone()),
                        &critique_ids,
                        &triage,
                    )?;
                    branch_evidence.push(evidence);
                }
                CritiqueVerdict::Accept => {
                    if branch.synthesis.verdict != DreamerTournamentSynthesisVerdict::Survivor {
                        return Err(invalid_tournament(
                            "accept triage requires survivor synthesis verdict",
                        ));
                    }
                    let evidence = tournament_evidence(
                        &input.run_id,
                        &branch.author,
                        DreamerTournamentBranchVerdict::Survivor,
                        Some(branch.synthesis.artifact_id.clone()),
                        &critique_ids,
                        &triage,
                    )?;
                    branch_evidence.push(evidence);
                    synthesized.push(SynthesizedCandidate {
                        candidate: branch.author.clone(),
                    });
                }
                CritiqueVerdict::Revise => {
                    if branch.synthesis.verdict != DreamerTournamentSynthesisVerdict::Refined {
                        return Err(invalid_tournament(
                            "revise triage requires refined synthesis verdict",
                        ));
                    }
                    let refined = branch.synthesis.refined.clone().ok_or_else(|| {
                        invalid_tournament(
                            "refined synthesis verdict requires a refined tournament candidate",
                        )
                    })?;
                    let evidence = tournament_evidence(
                        &input.run_id,
                        &refined,
                        DreamerTournamentBranchVerdict::Refined,
                        Some(branch.synthesis.artifact_id.clone()),
                        &critique_ids,
                        &triage,
                    )?;
                    branch_evidence.push(evidence);
                    partial_survivors.push(refined.clone());
                    synthesized.push(SynthesizedCandidate { candidate: refined });
                }
            }
        }

        if partial_survivors.len() == 2 {
            let weave = round.two_parent_weave.clone().ok_or_else(|| {
                invalid_tournament("two partial tournament survivors require an LMX weave")
            })?;
            validate_weave_parents(&partial_survivors, &weave)?;
            let evidence = tournament_weave_evidence(&input.run_id, &weave)?;
            branch_evidence.push(evidence);
            synthesized.push(SynthesizedCandidate {
                candidate: weave.candidate,
            });
        } else if round.two_parent_weave.is_some() {
            return Err(invalid_tournament(
                "LMX weave requires exactly two partial tournament survivors",
            ));
        }

        if synthesized.is_empty() {
            return Err(invalid_tournament(
                "tournament round discarded all candidates before judging",
            ));
        }

        latest_blind_contexts = blind_contexts(&synthesized);
        let ranked = blind_borda_rank(&round.ballots, synthesized.len())?;
        let winner_rank = ranked
            .first()
            .ok_or_else(|| invalid_tournament("blind Borda ranking produced no winner"))?;
        let winner = &synthesized[winner_rank.index].candidate;
        latest_winner = Some(DreamerTournamentWinner {
            claim_id: winner.claim_id,
            candidate_ref: winner.candidate_ref.clone(),
            branch_attempt: winner.branch_attempt,
            score: winner_rank.score,
        });
        latest_winner_candidate = Some(winner.clone());
        rounds_executed = round_number;

        if has_top_consensus(&round.ballots) {
            stop_reason = DreamerTournamentStopReason::Consensus;
            break;
        }
        if round_number == DREAMER_TOURNAMENT_MAX_ROUNDS_K {
            stop_reason = DreamerTournamentStopReason::RoundCap;
            break;
        }
        if round_number == max_rounds {
            stop_reason = DreamerTournamentStopReason::ExhaustedRounds;
            break;
        }
    }

    let winner =
        latest_winner.ok_or_else(|| invalid_tournament("tournament did not execute any rounds"))?;
    let winner_candidate = latest_winner_candidate
        .ok_or_else(|| invalid_tournament("tournament winner candidate was not retained"))?;

    let mut wtxn = vault.store.env.write_txn()?;
    for critique in &critique_artifacts {
        put_critique_artifact_in_txn(vault, &mut wtxn, critique)?;
    }
    for evidence in &branch_evidence {
        evidence_store.put_in_txn(&mut wtxn, evidence)?;
    }
    vault
        .batch_in()
        .claim_candidate(
            &winner_candidate.claim_id,
            winner_candidate.claim.clone(),
            &input.envelope,
            input.occurred,
            input.learned_at,
        )
        .apply(&mut wtxn)?;
    wtxn.commit()?;

    Ok(DreamerTournamentRunResult {
        winner,
        rounds_executed,
        stop_reason,
        branch_evidence,
        blind_contexts: latest_blind_contexts,
    })
}

fn blind_contexts(candidates: &[SynthesizedCandidate]) -> Vec<DreamerTournamentBlindJudgeContext> {
    candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| DreamerTournamentBlindJudgeContext {
            blind_index: index,
            claim: candidate.candidate.judge_claim.claim.clone(),
            evidence_refs: candidate.candidate.judge_claim.evidence_refs.clone(),
        })
        .collect()
}

fn blind_borda_rank(
    ballots: &[DreamerTournamentBordaBallot],
    candidate_count: usize,
) -> Result<Vec<RankedCandidate>> {
    if ballots.is_empty() || ballots.len() > MAX_TOURNAMENT_BALLOTS {
        return Err(invalid_tournament(
            "tournament blind Borda requires 1..=32 ballots",
        ));
    }
    let mut judge_refs = BTreeSet::new();
    let mut scores = vec![0_u64; candidate_count];
    for ballot in ballots {
        validate_ballot(ballot, candidate_count)?;
        if !judge_refs.insert(ballot.judge_ref.as_str()) {
            return Err(invalid_tournament(
                "duplicate tournament blind Borda judge_ref",
            ));
        }
        for (rank, candidate_index) in ballot.ranking.iter().copied().enumerate() {
            let points = candidate_count
                .checked_sub(rank + 1)
                .ok_or(Error::ArithmeticOverflow("tournament Borda points"))?;
            scores[candidate_index] =
                scores[candidate_index]
                    .checked_add(u64::try_from(points).map_err(|_| {
                        Error::ArithmeticOverflow("tournament Borda points conversion")
                    })?)
                    .ok_or(Error::ArithmeticOverflow("tournament Borda scores"))?;
        }
    }
    let mut ranked = scores
        .into_iter()
        .enumerate()
        .map(|(index, score)| RankedCandidate { index, score })
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.index.cmp(&right.index))
    });
    Ok(ranked)
}

fn has_top_consensus(ballots: &[DreamerTournamentBordaBallot]) -> bool {
    let Some(first_top) = ballots.first().and_then(|ballot| ballot.ranking.first()) else {
        return false;
    };
    ballots
        .iter()
        .all(|ballot| ballot.ranking.first() == Some(first_top))
}
