//! OF-366 tournament claim-authoring runner primitives.
//!
//! The tournament is modeled as extra Dreamer run-tree steps. This module
//! keeps the steps deterministic and fixture-friendly: callers supply author
//! branches, MC-1 critique artifacts, synthesis outputs, and blind Borda
//! ballots. The winner is persisted through the normal claim-candidate write
//! path.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::critic::{
    CriticReliability, CritiqueArtifact, CritiqueArtifactStore, CritiqueTriage, CritiqueVerdict,
    LensCatalog, triage_critiques,
};
use crate::error::{Error, Result};
use crate::job_queue::JobId;
use crate::types::{ClaimCandidate, EntityId, TimeRange, WriteEnvelope};

pub const DREAMER_TOURNAMENT_BRANCH_EVIDENCE_SCHEMA_VERSION: u64 = 1;
pub const DREAMER_TOURNAMENT_MAX_ROUNDS_K: u16 = 2;
pub const DREAMER_TOURNAMENT_MIN_FANOUT_M: u16 = 2;
pub const DREAMER_TOURNAMENT_MAX_FANOUT_M: u16 = 3;

const DREAMER_TOURNAMENT_EVIDENCE_PREFIX: &[u8] = b"dreamer:tournament:v1:";
const MAX_TOURNAMENT_RUN_ID_BYTES: usize = 128;
const MAX_TOURNAMENT_CANDIDATE_REF_BYTES: usize = 128;
const MAX_TOURNAMENT_STRATEGY_BYTES: usize = 128;
const MAX_TOURNAMENT_JUDGE_TEXT_BYTES: usize = 8192;
const MAX_TOURNAMENT_EVIDENCE_REFS: usize = 64;
const MAX_TOURNAMENT_EVIDENCE_REF_BYTES: usize = 256;
const MAX_TOURNAMENT_BALLOTS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerTournamentJudgeClaim {
    pub claim: String,
    pub evidence_refs: Vec<String>,
}

impl DreamerTournamentJudgeClaim {
    pub fn new(claim: impl Into<String>, evidence_refs: Vec<String>) -> Result<Self> {
        let claim = Self {
            claim: claim.into(),
            evidence_refs,
        };
        validate_text(
            &claim.claim,
            MAX_TOURNAMENT_JUDGE_TEXT_BYTES,
            "tournament judge claim",
        )?;
        validate_evidence_refs(&claim.evidence_refs)?;
        Ok(claim)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DreamerTournamentCandidate {
    pub candidate_ref: String,
    pub branch_job: JobId,
    pub claim_id: EntityId,
    pub claim: ClaimCandidate,
    pub judge_claim: DreamerTournamentJudgeClaim,
    pub strategy: String,
    pub round: u16,
}

impl DreamerTournamentCandidate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        candidate_ref: impl Into<String>,
        branch_job: JobId,
        claim_id: EntityId,
        claim: ClaimCandidate,
        judge_claim: DreamerTournamentJudgeClaim,
        strategy: impl Into<String>,
        round: u16,
    ) -> Result<Self> {
        let candidate = Self {
            candidate_ref: candidate_ref.into(),
            branch_job,
            claim_id,
            claim,
            judge_claim,
            strategy: strategy.into(),
            round,
        };
        validate_candidate(&candidate)?;
        Ok(candidate)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DreamerTournamentBranch {
    pub author: DreamerTournamentCandidate,
    pub critiques: Vec<CritiqueArtifact>,
    pub refined: Option<DreamerTournamentCandidate>,
}

impl DreamerTournamentBranch {
    pub fn new(
        author: DreamerTournamentCandidate,
        critiques: Vec<CritiqueArtifact>,
        refined: Option<DreamerTournamentCandidate>,
    ) -> Result<Self> {
        let branch = Self {
            author,
            critiques,
            refined,
        };
        validate_branch(&branch)?;
        Ok(branch)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DreamerTournamentRound {
    pub branches: Vec<DreamerTournamentBranch>,
    pub two_parent_weave: Option<DreamerTournamentCandidate>,
    pub ballots: Vec<DreamerTournamentBordaBallot>,
}

impl DreamerTournamentRound {
    pub fn new(
        branches: Vec<DreamerTournamentBranch>,
        two_parent_weave: Option<DreamerTournamentCandidate>,
        ballots: Vec<DreamerTournamentBordaBallot>,
    ) -> Result<Self> {
        let round = Self {
            branches,
            two_parent_weave,
            ballots,
        };
        validate_round(&round)?;
        Ok(round)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerTournamentBordaBallot {
    pub judge_ref: String,
    /// Blind candidate indexes in the order presented by the runner.
    pub ranking: Vec<usize>,
}

impl DreamerTournamentBordaBallot {
    pub fn new(judge_ref: impl Into<String>, ranking: Vec<usize>) -> Result<Self> {
        let ballot = Self {
            judge_ref: judge_ref.into(),
            ranking,
        };
        validate_identifier(
            &ballot.judge_ref,
            MAX_TOURNAMENT_CANDIDATE_REF_BYTES,
            "tournament judge ref",
        )?;
        Ok(ballot)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DreamerTournamentRun {
    pub run_id: String,
    pub fanout_m: u16,
    pub max_rounds_k: u16,
    pub rounds: Vec<DreamerTournamentRound>,
    pub reliabilities: Vec<CriticReliability>,
    pub envelope: WriteEnvelope,
    pub occurred: TimeRange,
    pub learned_at: u64,
}

impl DreamerTournamentRun {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        run_id: impl Into<String>,
        fanout_m: u16,
        max_rounds_k: u16,
        rounds: Vec<DreamerTournamentRound>,
        reliabilities: Vec<CriticReliability>,
        envelope: WriteEnvelope,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<Self> {
        let run = Self {
            run_id: run_id.into(),
            fanout_m,
            max_rounds_k,
            rounds,
            reliabilities,
            envelope,
            occurred,
            learned_at,
        };
        validate_run(&run)?;
        Ok(run)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DreamerTournamentBranchVerdict {
    Survivor,
    Refined,
    Discarded,
    Weaved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DreamerTournamentBranchEvidence {
    pub schema_version: u64,
    pub run_id: String,
    pub candidate_ref: String,
    pub branch_job: JobId,
    pub claim_id: String,
    pub round: u16,
    pub verdict: DreamerTournamentBranchVerdict,
    pub critique_artifact_ids: Vec<String>,
    pub acted_on_artifact_ids: Vec<String>,
    pub hard_veto_artifact_ids: Vec<String>,
    pub out_of_scope_artifact_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerTournamentBlindJudgeContext {
    pub blind_index: usize,
    pub claim: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DreamerTournamentWinner {
    pub claim_id: EntityId,
    pub candidate_ref: String,
    pub branch_job: JobId,
    pub score: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DreamerTournamentStopReason {
    Consensus,
    RoundCap,
    ExhaustedRounds,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DreamerTournamentRunResult {
    pub winner: DreamerTournamentWinner,
    pub rounds_executed: u16,
    pub stop_reason: DreamerTournamentStopReason,
    pub branch_evidence: Vec<DreamerTournamentBranchEvidence>,
    pub blind_contexts: Vec<DreamerTournamentBlindJudgeContext>,
}

struct SynthesizedCandidate {
    candidate: DreamerTournamentCandidate,
}

#[derive(Debug, Clone, PartialEq)]
struct RankedCandidate {
    index: usize,
    score: u64,
}

pub struct DreamerTournamentEvidenceStore<'a> {
    vault: &'a Vault,
}

impl<'a> DreamerTournamentEvidenceStore<'a> {
    #[must_use]
    pub fn new(vault: &'a Vault) -> Self {
        Self { vault }
    }

    pub fn list_run(&self, run_id: &str) -> Result<Vec<DreamerTournamentBranchEvidence>> {
        validate_identifier(run_id, MAX_TOURNAMENT_RUN_ID_BYTES, "tournament run id")?;
        let rtxn = self.vault.store.env.read_txn()?;
        let prefix = tournament_evidence_run_prefix(run_id)?;
        let mut evidence = Vec::new();
        for row in self.vault.store.vault_meta.prefix_iter(&rtxn, &prefix)? {
            let (_key, raw) = row?;
            evidence.push(decode_tournament_evidence(raw)?);
        }
        evidence.sort_by(|left, right| {
            (left.round, left.candidate_ref.as_str())
                .cmp(&(right.round, right.candidate_ref.as_str()))
        });
        Ok(evidence)
    }

    fn put_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        evidence: &DreamerTournamentBranchEvidence,
    ) -> Result<()> {
        validate_evidence(evidence)?;
        let key = tournament_evidence_key(
            &evidence.run_id,
            evidence.branch_job,
            &evidence.candidate_ref,
        )?;
        let encoded = rmp_serde::to_vec_named(evidence)
            .map_err(|_| invalid_tournament("tournament evidence MessagePack encode failed"))?;
        self.vault.store.vault_meta.put(wtxn, &key, &encoded)?;
        Ok(())
    }
}

pub fn run_dreamer_claim_tournament(
    vault: &Vault,
    input: DreamerTournamentRun,
) -> Result<DreamerTournamentRunResult> {
    validate_run(&input)?;
    let catalog = LensCatalog::of366_seed()?;
    let critique_store = CritiqueArtifactStore::new(vault);
    let evidence_store = DreamerTournamentEvidenceStore::new(vault);
    let mut branch_evidence = Vec::new();
    let mut latest_blind_contexts = Vec::new();
    let mut latest_winner = None;
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
            for critique in &branch.critiques {
                critique_store.put(critique)?;
            }

            let triage = triage_critiques(&catalog, &branch.critiques, &input.reliabilities)?;
            let critique_ids = branch
                .critiques
                .iter()
                .map(|critique| critique.artifact_id.clone())
                .collect::<Vec<_>>();

            match triage.verdict {
                CritiqueVerdict::Discard => {
                    let evidence = tournament_evidence(
                        &input.run_id,
                        &branch.author,
                        DreamerTournamentBranchVerdict::Discarded,
                        &critique_ids,
                        &triage,
                    )?;
                    branch_evidence.push(evidence);
                }
                CritiqueVerdict::Accept => {
                    let evidence = tournament_evidence(
                        &input.run_id,
                        &branch.author,
                        DreamerTournamentBranchVerdict::Survivor,
                        &critique_ids,
                        &triage,
                    )?;
                    branch_evidence.push(evidence);
                    synthesized.push(SynthesizedCandidate {
                        candidate: branch.author.clone(),
                    });
                }
                CritiqueVerdict::Revise => {
                    let refined = branch.refined.clone().ok_or_else(|| {
                        invalid_tournament("revise triage requires a refined tournament candidate")
                    })?;
                    let evidence = tournament_evidence(
                        &input.run_id,
                        &refined,
                        DreamerTournamentBranchVerdict::Refined,
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
            let evidence = tournament_weave_evidence(&input.run_id, &weave)?;
            branch_evidence.push(evidence);
            synthesized.push(SynthesizedCandidate { candidate: weave });
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
            branch_job: winner.branch_job,
            score: winner_rank.score,
        });
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
    let winner_candidate = input
        .rounds
        .iter()
        .take(usize::from(rounds_executed))
        .flat_map(round_candidates)
        .find(|candidate| {
            candidate.claim_id == winner.claim_id && candidate.candidate_ref == winner.candidate_ref
        })
        .ok_or_else(|| invalid_tournament("tournament winner candidate was not retained"))?;

    let mut wtxn = vault.store.env.write_txn()?;
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

fn round_candidates(round: &DreamerTournamentRound) -> Vec<&DreamerTournamentCandidate> {
    let mut candidates = Vec::new();
    for branch in &round.branches {
        candidates.push(&branch.author);
        if let Some(refined) = &branch.refined {
            candidates.push(refined);
        }
    }
    if let Some(weave) = &round.two_parent_weave {
        candidates.push(weave);
    }
    candidates
}

fn tournament_evidence(
    run_id: &str,
    candidate: &DreamerTournamentCandidate,
    verdict: DreamerTournamentBranchVerdict,
    critique_artifact_ids: &[String],
    triage: &CritiqueTriage,
) -> Result<DreamerTournamentBranchEvidence> {
    let evidence = DreamerTournamentBranchEvidence {
        schema_version: DREAMER_TOURNAMENT_BRANCH_EVIDENCE_SCHEMA_VERSION,
        run_id: run_id.to_owned(),
        candidate_ref: candidate.candidate_ref.clone(),
        branch_job: candidate.branch_job,
        claim_id: candidate.claim_id.to_hex(),
        round: candidate.round,
        verdict,
        critique_artifact_ids: critique_artifact_ids.to_vec(),
        acted_on_artifact_ids: triage.acted_on_artifact_ids.clone(),
        hard_veto_artifact_ids: triage.hard_veto_artifact_ids.clone(),
        out_of_scope_artifact_ids: triage.out_of_scope_artifact_ids.clone(),
    };
    validate_evidence(&evidence)?;
    Ok(evidence)
}

fn tournament_weave_evidence(
    run_id: &str,
    weave: &DreamerTournamentCandidate,
) -> Result<DreamerTournamentBranchEvidence> {
    let evidence = DreamerTournamentBranchEvidence {
        schema_version: DREAMER_TOURNAMENT_BRANCH_EVIDENCE_SCHEMA_VERSION,
        run_id: run_id.to_owned(),
        candidate_ref: weave.candidate_ref.clone(),
        branch_job: weave.branch_job,
        claim_id: weave.claim_id.to_hex(),
        round: weave.round,
        verdict: DreamerTournamentBranchVerdict::Weaved,
        critique_artifact_ids: Vec::new(),
        acted_on_artifact_ids: Vec::new(),
        hard_veto_artifact_ids: Vec::new(),
        out_of_scope_artifact_ids: Vec::new(),
    };
    validate_evidence(&evidence)?;
    Ok(evidence)
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
    let mut scores = vec![0_u64; candidate_count];
    for ballot in ballots {
        validate_ballot(ballot, candidate_count)?;
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

fn validate_run(run: &DreamerTournamentRun) -> Result<()> {
    validate_identifier(
        &run.run_id,
        MAX_TOURNAMENT_RUN_ID_BYTES,
        "tournament run id",
    )?;
    if !(DREAMER_TOURNAMENT_MIN_FANOUT_M..=DREAMER_TOURNAMENT_MAX_FANOUT_M).contains(&run.fanout_m)
    {
        return Err(invalid_tournament("tournament fanout_m must be 2 or 3"));
    }
    if run.max_rounds_k == 0 || run.max_rounds_k > DREAMER_TOURNAMENT_MAX_ROUNDS_K {
        return Err(invalid_tournament("tournament max_rounds_k must be 1 or 2"));
    }
    if run.rounds.is_empty() {
        return Err(invalid_tournament("tournament requires at least one round"));
    }
    if run.rounds[0].branches.len() != usize::from(run.fanout_m) {
        return Err(invalid_tournament(
            "first tournament round must fork exactly fanout_m branches",
        ));
    }
    for round in &run.rounds {
        validate_round(round)?;
    }
    Ok(())
}

fn validate_round(round: &DreamerTournamentRound) -> Result<()> {
    if round.branches.is_empty()
        || round.branches.len() > usize::from(DREAMER_TOURNAMENT_MAX_FANOUT_M)
    {
        return Err(invalid_tournament(
            "tournament round must contain 1..=3 branches",
        ));
    }
    let mut refs = BTreeSet::new();
    for branch in &round.branches {
        validate_branch(branch)?;
        if !refs.insert(branch.author.candidate_ref.as_str()) {
            return Err(invalid_tournament(
                "duplicate tournament branch candidate_ref",
            ));
        }
    }
    if let Some(weave) = &round.two_parent_weave {
        validate_candidate(weave)?;
    }
    if round.ballots.is_empty() {
        return Err(invalid_tournament(
            "tournament round requires blind Borda ballots",
        ));
    }
    Ok(())
}

fn validate_branch(branch: &DreamerTournamentBranch) -> Result<()> {
    validate_candidate(&branch.author)?;
    if branch.critiques.is_empty() {
        return Err(invalid_tournament(
            "tournament branch requires MC-1 critique artifacts",
        ));
    }
    for critique in &branch.critiques {
        if critique.branch_job != branch.author.branch_job {
            return Err(invalid_tournament(
                "tournament critique branch_job must match author branch",
            ));
        }
        if critique.candidate_ref != branch.author.candidate_ref {
            return Err(invalid_tournament(
                "tournament critique candidate_ref must match author candidate",
            ));
        }
    }
    if let Some(refined) = &branch.refined {
        validate_candidate(refined)?;
        if refined.branch_job != branch.author.branch_job {
            return Err(invalid_tournament(
                "refined tournament candidate must stay on its source branch",
            ));
        }
        if refined.round < branch.author.round {
            return Err(invalid_tournament(
                "refined tournament candidate round must not precede author round",
            ));
        }
    }
    Ok(())
}

fn validate_candidate(candidate: &DreamerTournamentCandidate) -> Result<()> {
    validate_identifier(
        &candidate.candidate_ref,
        MAX_TOURNAMENT_CANDIDATE_REF_BYTES,
        "tournament candidate ref",
    )?;
    validate_identifier(
        &candidate.strategy,
        MAX_TOURNAMENT_STRATEGY_BYTES,
        "tournament strategy",
    )?;
    validate_text(
        &candidate.judge_claim.claim,
        MAX_TOURNAMENT_JUDGE_TEXT_BYTES,
        "tournament judge claim",
    )?;
    validate_evidence_refs(&candidate.judge_claim.evidence_refs)?;
    if candidate.round == 0 || candidate.round > DREAMER_TOURNAMENT_MAX_ROUNDS_K {
        return Err(invalid_tournament(
            "tournament candidate round must be 1 or 2",
        ));
    }
    Ok(())
}

fn validate_ballot(ballot: &DreamerTournamentBordaBallot, candidate_count: usize) -> Result<()> {
    validate_identifier(
        &ballot.judge_ref,
        MAX_TOURNAMENT_CANDIDATE_REF_BYTES,
        "tournament judge ref",
    )?;
    if candidate_count == 0 || ballot.ranking.len() != candidate_count {
        return Err(invalid_tournament(
            "blind Borda ballot must rank every candidate exactly once",
        ));
    }
    let mut seen = BTreeSet::new();
    for candidate in &ballot.ranking {
        if *candidate >= candidate_count || !seen.insert(*candidate) {
            return Err(invalid_tournament(
                "blind Borda ballot contains an invalid candidate index",
            ));
        }
    }
    Ok(())
}

fn validate_evidence(evidence: &DreamerTournamentBranchEvidence) -> Result<()> {
    if evidence.schema_version != DREAMER_TOURNAMENT_BRANCH_EVIDENCE_SCHEMA_VERSION {
        return Err(invalid_tournament(
            "unsupported tournament evidence schema_version",
        ));
    }
    validate_identifier(
        &evidence.run_id,
        MAX_TOURNAMENT_RUN_ID_BYTES,
        "tournament run id",
    )?;
    validate_identifier(
        &evidence.candidate_ref,
        MAX_TOURNAMENT_CANDIDATE_REF_BYTES,
        "tournament candidate ref",
    )?;
    validate_identifier(&evidence.claim_id, 32, "tournament evidence claim id")?;
    Ok(())
}

fn validate_identifier(value: &str, max_bytes: usize, field: &'static str) -> Result<()> {
    validate_text(value, max_bytes, field)?;
    if value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(invalid_tournament(
            "tournament identifier contains control bytes",
        ));
    }
    Ok(())
}

fn validate_text(value: &str, max_bytes: usize, field: &'static str) -> Result<()> {
    if value.is_empty() {
        return Err(invalid_tournament(
            "tournament text field must not be empty",
        ));
    }
    if value.len() > max_bytes {
        return Err(match field {
            "tournament judge claim" => invalid_tournament("tournament judge claim exceeds limit"),
            "tournament run id" => invalid_tournament("tournament run id exceeds limit"),
            "tournament candidate ref" => {
                invalid_tournament("tournament candidate ref exceeds limit")
            }
            "tournament strategy" => invalid_tournament("tournament strategy exceeds limit"),
            "tournament judge ref" => invalid_tournament("tournament judge ref exceeds limit"),
            _ => invalid_tournament("tournament text field exceeds limit"),
        });
    }
    Ok(())
}

fn validate_evidence_refs(refs: &[String]) -> Result<()> {
    if refs.len() > MAX_TOURNAMENT_EVIDENCE_REFS {
        return Err(invalid_tournament(
            "tournament evidence_refs exceeds 64 entries",
        ));
    }
    for evidence_ref in refs {
        validate_identifier(
            evidence_ref,
            MAX_TOURNAMENT_EVIDENCE_REF_BYTES,
            "tournament evidence ref",
        )?;
    }
    Ok(())
}

fn tournament_evidence_run_prefix(run_id: &str) -> Result<Vec<u8>> {
    validate_identifier(run_id, MAX_TOURNAMENT_RUN_ID_BYTES, "tournament run id")?;
    let run_id_len = u16::try_from(run_id.len())
        .map_err(|_| invalid_tournament("tournament run id exceeds limit"))?;
    let mut key = Vec::with_capacity(DREAMER_TOURNAMENT_EVIDENCE_PREFIX.len() + 2 + run_id.len());
    key.extend_from_slice(DREAMER_TOURNAMENT_EVIDENCE_PREFIX);
    key.extend_from_slice(&run_id_len.to_be_bytes());
    key.extend_from_slice(run_id.as_bytes());
    Ok(key)
}

fn tournament_evidence_key(
    run_id: &str,
    branch_job: JobId,
    candidate_ref: &str,
) -> Result<Vec<u8>> {
    validate_identifier(
        candidate_ref,
        MAX_TOURNAMENT_CANDIDATE_REF_BYTES,
        "tournament candidate ref",
    )?;
    let candidate_ref_len = u16::try_from(candidate_ref.len())
        .map_err(|_| invalid_tournament("tournament candidate ref exceeds limit"))?;
    let mut key = tournament_evidence_run_prefix(run_id)?;
    key.extend_from_slice(branch_job.as_bytes());
    key.extend_from_slice(&candidate_ref_len.to_be_bytes());
    key.extend_from_slice(candidate_ref.as_bytes());
    Ok(key)
}

fn decode_tournament_evidence(raw: &[u8]) -> Result<DreamerTournamentBranchEvidence> {
    let evidence: DreamerTournamentBranchEvidence = rmp_serde::from_slice(raw)
        .map_err(|_| Error::CorruptedIndex("dreamer tournament evidence"))?;
    validate_evidence(&evidence)?;
    Ok(evidence)
}

fn invalid_tournament(reason: &'static str) -> Error {
    Error::InvalidJobQueueRecord(reason)
}

#[cfg(test)]
mod tests {
    use rmpv::Value;

    use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
    use crate::critic::{
        CriticLens, CritiqueArtifact, CritiqueProvenance, CritiqueSeverity, CritiqueVerdict,
        LensCatalog,
    };
    use crate::types::{
        ENTITY_TYPE_PERSON, EdgeActorClass, VaultConfig, WriteActor, WriteProvenance,
    };

    use super::*;

    fn open_vault() -> (tempfile::TempDir, Vault) {
        crate::test_util::open_test_vault_with(VaultConfig::device())
    }

    fn occurred(at: u64) -> TimeRange {
        TimeRange { start: at, end: at }
    }

    fn test_envelope(vault: &Vault) -> Result<(EntityId, EntityId, WriteEnvelope)> {
        let actor = EntityId::now();
        let subject = EntityId::now();
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred(1), 1, b"actor")?;
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"subject")?;
        let envelope = WriteEnvelope::new(
            WriteActor::new(actor, EdgeActorClass::Agent),
            ClaimSource::Generated,
            WriteProvenance::new(Value::from("of366-tournament-fixture"))?,
            ClaimApprovalStatus::Approved,
        );
        Ok((actor, subject, envelope))
    }

    fn candidate(
        subject: EntityId,
        candidate_ref: &str,
        branch_job: JobId,
        claim_id: EntityId,
        claim_text: &str,
        strategy: &str,
        round: u16,
    ) -> Result<DreamerTournamentCandidate> {
        DreamerTournamentCandidate::new(
            candidate_ref,
            branch_job,
            claim_id,
            ClaimCandidate::new(
                "pattern.sleep",
                ClaimSubject::Entity(subject),
                Value::from(claim_text),
                0.8,
            )
            .with_evidence(Value::from(format!("evidence:{candidate_ref}"))),
            DreamerTournamentJudgeClaim::new(
                claim_text,
                vec!["obs:fixture:1".to_owned(), "obs:fixture:2".to_owned()],
            )?,
            strategy,
            round,
        )
    }

    fn critique(
        candidate: &DreamerTournamentCandidate,
        lens: &CriticLens,
        artifact_id: &str,
        verdict: CritiqueVerdict,
        severity: CritiqueSeverity,
        hard_check_passed: Option<bool>,
    ) -> Result<CritiqueArtifact> {
        CritiqueArtifact::new(
            artifact_id,
            "run-fixture",
            candidate.branch_job,
            candidate.candidate_ref.clone(),
            lens,
            CritiqueProvenance::new(
                format!("critic:{}", lens.id),
                "fixture-model",
                Some("rev1".to_owned()),
            )?,
            verdict,
            severity,
            hard_check_passed,
            candidate.judge_claim.evidence_refs.clone(),
            None,
            10,
        )
    }

    fn accept_branch(
        candidate: DreamerTournamentCandidate,
        groundedness: &CriticLens,
        artifact_id: &str,
    ) -> Result<DreamerTournamentBranch> {
        DreamerTournamentBranch::new(
            candidate.clone(),
            vec![critique(
                &candidate,
                groundedness,
                artifact_id,
                CritiqueVerdict::Accept,
                CritiqueSeverity::Info,
                Some(true),
            )?],
            None,
        )
    }

    #[test]
    fn fixture_corpus_tournament_writes_winner_through_normal_claim_path() -> Result<()> {
        let (_dir, vault) = open_vault();
        let (_actor, subject, envelope) = test_envelope(&vault)?;
        let catalog = LensCatalog::of366_seed()?;
        let groundedness = catalog.lens("groundedness", "claim_authoring").unwrap();

        let left = candidate(
            subject,
            "candidate-left",
            JobId::now(),
            EntityId::now(),
            "Sleep gets lighter after late caffeine in the fixture corpus.",
            "seed-a",
            1,
        )?;
        let right = candidate(
            subject,
            "candidate-right",
            JobId::now(),
            EntityId::now(),
            "Fixture evidence supports earlier caffeine cutoff improving sleep.",
            "seed-b",
            1,
        )?;
        let winner_id = right.claim_id;

        let run = DreamerTournamentRun::new(
            "run-fixture",
            2,
            2,
            vec![DreamerTournamentRound::new(
                vec![
                    accept_branch(left, groundedness, "groundedness_left")?,
                    accept_branch(right, groundedness, "groundedness_right")?,
                ],
                None,
                vec![
                    DreamerTournamentBordaBallot::new("judge-a", vec![1, 0])?,
                    DreamerTournamentBordaBallot::new("judge-b", vec![1, 0])?,
                ],
            )?],
            Vec::new(),
            envelope,
            occurred(20),
            21,
        )?;

        let result = run_dreamer_claim_tournament(&vault, run)?;
        assert_eq!(result.winner.claim_id, winner_id);
        assert_eq!(result.stop_reason, DreamerTournamentStopReason::Consensus);
        assert_eq!(result.rounds_executed, 1);

        let stored = vault.get_claim(&winner_id)?.expect("winner claim stored");
        assert_eq!(stored.predicate, "pattern.sleep");
        assert_eq!(stored.source, Some(ClaimSource::Generated));
        assert_eq!(stored.approval, ClaimApprovalStatus::Approved);
        assert_eq!(vault.claims_for_subject(&subject)?, vec![winner_id]);
        Ok(())
    }

    #[test]
    fn blind_judging_context_omits_strategy_and_round_metadata() -> Result<()> {
        let (_dir, vault) = open_vault();
        let (_actor, subject, envelope) = test_envelope(&vault)?;
        let catalog = LensCatalog::of366_seed()?;
        let groundedness = catalog.lens("groundedness", "claim_authoring").unwrap();
        let left = candidate(
            subject,
            "candidate-alpha",
            JobId::now(),
            EntityId::now(),
            "The corpus supports an evening routine pattern.",
            "strategy-secret-alpha",
            1,
        )?;
        let right = candidate(
            subject,
            "candidate-beta",
            JobId::now(),
            EntityId::now(),
            "The corpus supports a morning focus pattern.",
            "strategy-secret-beta",
            1,
        )?;

        let result = run_dreamer_claim_tournament(
            &vault,
            DreamerTournamentRun::new(
                "run-blind",
                2,
                2,
                vec![DreamerTournamentRound::new(
                    vec![
                        accept_branch(left, groundedness, "groundedness_alpha")?,
                        accept_branch(right, groundedness, "groundedness_beta")?,
                    ],
                    None,
                    vec![DreamerTournamentBordaBallot::new("judge", vec![0, 1])?],
                )?],
                Vec::new(),
                envelope,
                occurred(20),
                21,
            )?,
        )?;

        for context in result.blind_contexts {
            let debug = format!("{context:?}");
            assert!(!debug.contains("strategy-secret"));
            assert!(!debug.contains("round"));
            assert!(!debug.contains("candidate-alpha"));
            assert!(!debug.contains("candidate-beta"));
        }
        Ok(())
    }

    #[test]
    fn discard_path_preserves_branch_evidence_and_critique_artifacts() -> Result<()> {
        let (_dir, vault) = open_vault();
        let (_actor, subject, envelope) = test_envelope(&vault)?;
        let catalog = LensCatalog::of366_seed()?;
        let groundedness = catalog.lens("groundedness", "claim_authoring").unwrap();

        let rejected = candidate(
            subject,
            "candidate-rejected",
            JobId::now(),
            EntityId::now(),
            "Ungrounded fixture generalization.",
            "seed-a",
            1,
        )?;
        let survivor = candidate(
            subject,
            "candidate-survivor",
            JobId::now(),
            EntityId::now(),
            "Grounded fixture generalization.",
            "seed-b",
            1,
        )?;
        let rejected_branch_job = rejected.branch_job;
        let rejected_claim_id = rejected.claim_id;

        let rejected_branch = DreamerTournamentBranch::new(
            rejected.clone(),
            vec![critique(
                &rejected,
                groundedness,
                "groundedness_rejected",
                CritiqueVerdict::Discard,
                CritiqueSeverity::Blocking,
                Some(false),
            )?],
            None,
        )?;
        let run = DreamerTournamentRun::new(
            "run-discard",
            2,
            2,
            vec![DreamerTournamentRound::new(
                vec![
                    rejected_branch,
                    accept_branch(survivor, groundedness, "groundedness_survivor")?,
                ],
                None,
                vec![DreamerTournamentBordaBallot::new("judge", vec![0])?],
            )?],
            Vec::new(),
            envelope,
            occurred(20),
            21,
        )?;

        let result = run_dreamer_claim_tournament(&vault, run)?;
        assert!(
            result.branch_evidence.iter().any(|evidence| {
                evidence.candidate_ref == "candidate-rejected"
                    && evidence.claim_id == rejected_claim_id.to_hex()
                    && evidence.verdict == DreamerTournamentBranchVerdict::Discarded
                    && evidence.hard_veto_artifact_ids == vec!["groundedness_rejected"]
            }),
            "discarded candidate must stay in branch evidence"
        );
        let persisted = DreamerTournamentEvidenceStore::new(&vault).list_run("run-discard")?;
        assert!(persisted.iter().any(|evidence| {
            evidence.candidate_ref == "candidate-rejected"
                && evidence.verdict == DreamerTournamentBranchVerdict::Discarded
        }));
        let critiques = CritiqueArtifactStore::new(&vault).list_branch(rejected_branch_job)?;
        assert_eq!(critiques.len(), 1);
        assert_eq!(critiques[0].artifact_id, "groundedness_rejected");
        Ok(())
    }

    #[test]
    fn k_cap_and_early_stop_behave() -> Result<()> {
        let (_dir, vault) = open_vault();
        let (_actor, subject, envelope) = test_envelope(&vault)?;
        let catalog = LensCatalog::of366_seed()?;
        let groundedness = catalog.lens("groundedness", "claim_authoring").unwrap();

        let round1_left = candidate(
            subject,
            "r1-left",
            JobId::now(),
            EntityId::now(),
            "Round one left.",
            "seed-a",
            1,
        )?;
        let round1_right = candidate(
            subject,
            "r1-right",
            JobId::now(),
            EntityId::now(),
            "Round one right.",
            "seed-b",
            1,
        )?;
        let round2_left = candidate(
            subject,
            "r2-left",
            JobId::now(),
            EntityId::now(),
            "Round two left.",
            "seed-a",
            2,
        )?;
        let round2_right = candidate(
            subject,
            "r2-right",
            JobId::now(),
            EntityId::now(),
            "Round two right.",
            "seed-b",
            2,
        )?;
        let should_not_write = candidate(
            subject,
            "r3-left",
            JobId::now(),
            EntityId::now(),
            "Round three must not run.",
            "seed-a",
            2,
        )?;

        let result = run_dreamer_claim_tournament(
            &vault,
            DreamerTournamentRun::new(
                "run-k-cap",
                2,
                2,
                vec![
                    DreamerTournamentRound::new(
                        vec![
                            accept_branch(round1_left, groundedness, "r1_left_grounded")?,
                            accept_branch(round1_right, groundedness, "r1_right_grounded")?,
                        ],
                        None,
                        vec![
                            DreamerTournamentBordaBallot::new("judge-a", vec![0, 1])?,
                            DreamerTournamentBordaBallot::new("judge-b", vec![1, 0])?,
                        ],
                    )?,
                    DreamerTournamentRound::new(
                        vec![
                            accept_branch(round2_left, groundedness, "r2_left_grounded")?,
                            accept_branch(round2_right, groundedness, "r2_right_grounded")?,
                        ],
                        None,
                        vec![
                            DreamerTournamentBordaBallot::new("judge-a", vec![1, 0])?,
                            DreamerTournamentBordaBallot::new("judge-b", vec![0, 1])?,
                        ],
                    )?,
                    DreamerTournamentRound::new(
                        vec![accept_branch(
                            should_not_write.clone(),
                            groundedness,
                            "r3_left_grounded",
                        )?],
                        None,
                        vec![DreamerTournamentBordaBallot::new("judge-a", vec![0])?],
                    )?,
                ],
                Vec::new(),
                envelope,
                occurred(20),
                21,
            )?,
        )?;
        assert_eq!(result.rounds_executed, 2);
        assert_eq!(result.stop_reason, DreamerTournamentStopReason::RoundCap);
        assert!(vault.get_claim(&should_not_write.claim_id)?.is_none());

        let (_dir, vault) = open_vault();
        let (_actor, subject, envelope) = test_envelope(&vault)?;
        let left = candidate(
            subject,
            "early-left",
            JobId::now(),
            EntityId::now(),
            "Early stop left.",
            "seed-a",
            1,
        )?;
        let right = candidate(
            subject,
            "early-right",
            JobId::now(),
            EntityId::now(),
            "Early stop right.",
            "seed-b",
            1,
        )?;
        let late = candidate(
            subject,
            "late",
            JobId::now(),
            EntityId::now(),
            "Should not run after consensus.",
            "seed-a",
            2,
        )?;
        let result = run_dreamer_claim_tournament(
            &vault,
            DreamerTournamentRun::new(
                "run-early",
                2,
                2,
                vec![
                    DreamerTournamentRound::new(
                        vec![
                            accept_branch(left, groundedness, "early_left_grounded")?,
                            accept_branch(right, groundedness, "early_right_grounded")?,
                        ],
                        None,
                        vec![
                            DreamerTournamentBordaBallot::new("judge-a", vec![0, 1])?,
                            DreamerTournamentBordaBallot::new("judge-b", vec![0, 1])?,
                        ],
                    )?,
                    DreamerTournamentRound::new(
                        vec![accept_branch(late.clone(), groundedness, "late_grounded")?],
                        None,
                        vec![DreamerTournamentBordaBallot::new("judge-a", vec![0])?],
                    )?,
                ],
                Vec::new(),
                envelope,
                occurred(20),
                21,
            )?,
        )?;
        assert_eq!(result.rounds_executed, 1);
        assert_eq!(result.stop_reason, DreamerTournamentStopReason::Consensus);
        assert!(vault.get_claim(&late.claim_id)?.is_none());
        Ok(())
    }

    #[test]
    fn two_partial_survivors_use_lmx_weave_candidate() -> Result<()> {
        let (_dir, vault) = open_vault();
        let (_actor, subject, envelope) = test_envelope(&vault)?;
        let catalog = LensCatalog::of366_seed()?;
        let overreach = catalog.lens("overreach", "claim_authoring").unwrap();

        let left = candidate(
            subject,
            "partial-left",
            JobId::now(),
            EntityId::now(),
            "Left partial claim.",
            "seed-a",
            1,
        )?;
        let left_refined = candidate(
            subject,
            "partial-left-refined",
            left.branch_job,
            EntityId::now(),
            "Left refined claim.",
            "synthesis",
            1,
        )?;
        let right = candidate(
            subject,
            "partial-right",
            JobId::now(),
            EntityId::now(),
            "Right partial claim.",
            "seed-b",
            1,
        )?;
        let right_refined = candidate(
            subject,
            "partial-right-refined",
            right.branch_job,
            EntityId::now(),
            "Right refined claim.",
            "synthesis",
            1,
        )?;
        let weave = candidate(
            subject,
            "lmx-weave",
            JobId::now(),
            EntityId::now(),
            "LMX two-parent weave claim.",
            "lmx",
            1,
        )?;
        let weave_id = weave.claim_id;

        let run = DreamerTournamentRun::new(
            "run-weave",
            2,
            2,
            vec![DreamerTournamentRound::new(
                vec![
                    DreamerTournamentBranch::new(
                        left.clone(),
                        vec![critique(
                            &left,
                            overreach,
                            "left_overreach",
                            CritiqueVerdict::Revise,
                            CritiqueSeverity::Medium,
                            None,
                        )?],
                        Some(left_refined),
                    )?,
                    DreamerTournamentBranch::new(
                        right.clone(),
                        vec![critique(
                            &right,
                            overreach,
                            "right_overreach",
                            CritiqueVerdict::Revise,
                            CritiqueSeverity::Medium,
                            None,
                        )?],
                        Some(right_refined),
                    )?,
                ],
                Some(weave),
                vec![DreamerTournamentBordaBallot::new("judge", vec![2, 0, 1])?],
            )?],
            Vec::new(),
            envelope,
            occurred(20),
            21,
        )?;

        let result = run_dreamer_claim_tournament(&vault, run)?;
        assert_eq!(result.winner.claim_id, weave_id);
        assert!(result.branch_evidence.iter().any(|evidence| {
            evidence.candidate_ref == "lmx-weave"
                && evidence.verdict == DreamerTournamentBranchVerdict::Weaved
        }));
        assert!(vault.get_claim(&weave_id)?.is_some());
        Ok(())
    }
}
