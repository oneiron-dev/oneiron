//! OF-366 tournament claim-authoring runner primitives.
//!
//! The tournament is modeled as extra Dreamer run-tree steps. This module
//! keeps the steps deterministic and fixture-friendly: callers supply an
//! explicit OF-267 author fork artifact, MC-1 critique artifacts, typed
//! synthesis outputs, optional LMX weave output, and blind Borda ballots. The
//! winner is persisted through the normal claim-candidate write path.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::critic::{
    CriticReliability, CritiqueArtifact, CritiqueTriage, CritiqueVerdict, LensCatalog,
    triage_critiques,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::job_queue::JobId;
use crate::temporal::TimeRange;
use crate::write_envelope::ClaimCandidate;
use crate::write_envelope::WriteEnvelope;

pub const DREAMER_TOURNAMENT_BRANCH_EVIDENCE_SCHEMA_VERSION: u64 = 1;
pub const DREAMER_TOURNAMENT_MAX_ROUNDS_K: u16 = 2;
pub const DREAMER_TOURNAMENT_MIN_FANOUT_M: u16 = 2;
pub const DREAMER_TOURNAMENT_MAX_FANOUT_M: u16 = 3;

const DREAMER_TOURNAMENT_EVIDENCE_PREFIX: &[u8] = b"dreamer:tournament:v1:";
const CRITIQUE_PRIVATE_ARTIFACT_PREFIX: &[u8] = b"dreamer:critic:v1:";
const MAX_TOURNAMENT_RUN_ID_BYTES: usize = 128;
const MAX_TOURNAMENT_CANDIDATE_REF_BYTES: usize = 128;
const MAX_TOURNAMENT_ARTIFACT_ID_BYTES: usize = 128;
const MAX_TOURNAMENT_STRATEGY_BYTES: usize = 128;
const MAX_TOURNAMENT_JUDGE_TEXT_BYTES: usize = 8192;
const MAX_TOURNAMENT_EVIDENCE_REFS: usize = 64;
const MAX_TOURNAMENT_EVIDENCE_REF_BYTES: usize = 256;
const MAX_TOURNAMENT_BALLOTS: usize = 32;
const OF366_CLAIM_AUTHORING_LENSES: [(&str, &str); 4] = [
    ("groundedness", "claim_authoring"),
    ("overreach", "claim_authoring"),
    ("temporal", "claim_authoring"),
    ("redundancy", "claim_authoring"),
];

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DreamerTournamentCandidateIdentity {
    pub candidate_ref: String,
    pub branch_job: JobId,
    pub claim_id: String,
    pub round: u16,
}

impl DreamerTournamentCandidateIdentity {
    #[must_use]
    pub fn from_candidate(candidate: &DreamerTournamentCandidate) -> Self {
        Self {
            candidate_ref: candidate.candidate_ref.clone(),
            branch_job: candidate.branch_job,
            claim_id: candidate.claim_id.to_hex(),
            round: candidate.round,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerTournamentAuthorFork {
    pub seed_ref: String,
    pub author_job: JobId,
    pub sibling_branch_jobs: Vec<JobId>,
}

impl DreamerTournamentAuthorFork {
    pub fn new(
        seed_ref: impl Into<String>,
        author_job: JobId,
        sibling_branch_jobs: Vec<JobId>,
    ) -> Result<Self> {
        let fork = Self {
            seed_ref: seed_ref.into(),
            author_job,
            sibling_branch_jobs,
        };
        validate_author_fork(&fork)?;
        Ok(fork)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DreamerTournamentSynthesisVerdict {
    Survivor,
    Refined,
    Discarded,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DreamerTournamentSynthesisArtifact {
    pub artifact_id: String,
    pub source_candidate_ref: String,
    pub branch_job: JobId,
    pub round: u16,
    pub verdict: DreamerTournamentSynthesisVerdict,
    pub refined: Option<DreamerTournamentCandidate>,
}

impl DreamerTournamentSynthesisArtifact {
    pub fn survivor(
        artifact_id: impl Into<String>,
        source: &DreamerTournamentCandidate,
    ) -> Result<Self> {
        Self::new(
            artifact_id,
            source.candidate_ref.clone(),
            source.branch_job,
            source.round,
            DreamerTournamentSynthesisVerdict::Survivor,
            None,
        )
    }

    pub fn discarded(
        artifact_id: impl Into<String>,
        source: &DreamerTournamentCandidate,
    ) -> Result<Self> {
        Self::new(
            artifact_id,
            source.candidate_ref.clone(),
            source.branch_job,
            source.round,
            DreamerTournamentSynthesisVerdict::Discarded,
            None,
        )
    }

    pub fn refined(
        artifact_id: impl Into<String>,
        source: &DreamerTournamentCandidate,
        refined: DreamerTournamentCandidate,
    ) -> Result<Self> {
        Self::new(
            artifact_id,
            source.candidate_ref.clone(),
            source.branch_job,
            source.round,
            DreamerTournamentSynthesisVerdict::Refined,
            Some(refined),
        )
    }

    fn new(
        artifact_id: impl Into<String>,
        source_candidate_ref: impl Into<String>,
        branch_job: JobId,
        round: u16,
        verdict: DreamerTournamentSynthesisVerdict,
        refined: Option<DreamerTournamentCandidate>,
    ) -> Result<Self> {
        let artifact = Self {
            artifact_id: artifact_id.into(),
            source_candidate_ref: source_candidate_ref.into(),
            branch_job,
            round,
            verdict,
            refined,
        };
        validate_synthesis(&artifact)?;
        Ok(artifact)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DreamerTournamentBranch {
    pub author: DreamerTournamentCandidate,
    pub critiques: Vec<CritiqueArtifact>,
    pub synthesis: DreamerTournamentSynthesisArtifact,
}

impl DreamerTournamentBranch {
    pub fn new(
        author: DreamerTournamentCandidate,
        critiques: Vec<CritiqueArtifact>,
        synthesis: DreamerTournamentSynthesisArtifact,
    ) -> Result<Self> {
        let branch = Self {
            author,
            critiques,
            synthesis,
        };
        validate_branch(&branch)?;
        Ok(branch)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DreamerTournamentWeaveArtifact {
    pub artifact_id: String,
    pub parents: Vec<DreamerTournamentCandidateIdentity>,
    pub candidate: DreamerTournamentCandidate,
}

impl DreamerTournamentWeaveArtifact {
    pub fn new(
        artifact_id: impl Into<String>,
        parents: Vec<DreamerTournamentCandidateIdentity>,
        candidate: DreamerTournamentCandidate,
    ) -> Result<Self> {
        let artifact = Self {
            artifact_id: artifact_id.into(),
            parents,
            candidate,
        };
        validate_weave_artifact(&artifact)?;
        Ok(artifact)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DreamerTournamentRound {
    pub branches: Vec<DreamerTournamentBranch>,
    pub two_parent_weave: Option<DreamerTournamentWeaveArtifact>,
    pub ballots: Vec<DreamerTournamentBordaBallot>,
}

impl DreamerTournamentRound {
    pub fn new(
        branches: Vec<DreamerTournamentBranch>,
        two_parent_weave: Option<DreamerTournamentWeaveArtifact>,
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
    pub author_fork: DreamerTournamentAuthorFork,
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
        author_fork: DreamerTournamentAuthorFork,
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
            author_fork,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub synthesis_artifact_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parent_candidate_refs: Vec<DreamerTournamentCandidateIdentity>,
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
            evidence.round,
            evidence.verdict,
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
            branch_job: winner.branch_job,
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

fn tournament_evidence(
    run_id: &str,
    candidate: &DreamerTournamentCandidate,
    verdict: DreamerTournamentBranchVerdict,
    synthesis_artifact_id: Option<String>,
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
        synthesis_artifact_id,
        parent_candidate_refs: Vec::new(),
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
    weave: &DreamerTournamentWeaveArtifact,
) -> Result<DreamerTournamentBranchEvidence> {
    let evidence = DreamerTournamentBranchEvidence {
        schema_version: DREAMER_TOURNAMENT_BRANCH_EVIDENCE_SCHEMA_VERSION,
        run_id: run_id.to_owned(),
        candidate_ref: weave.candidate.candidate_ref.clone(),
        branch_job: weave.candidate.branch_job,
        claim_id: weave.candidate.claim_id.to_hex(),
        round: weave.candidate.round,
        verdict: DreamerTournamentBranchVerdict::Weaved,
        synthesis_artifact_id: Some(weave.artifact_id.clone()),
        parent_candidate_refs: weave.parents.clone(),
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

fn validate_run(run: &DreamerTournamentRun) -> Result<()> {
    validate_identifier(
        &run.run_id,
        MAX_TOURNAMENT_RUN_ID_BYTES,
        "tournament run id",
    )?;
    validate_author_fork(&run.author_fork)?;
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
    validate_author_fork_outputs(run)?;
    let rounds_to_execute = run
        .max_rounds_k
        .min(DREAMER_TOURNAMENT_MAX_ROUNDS_K)
        .min(u16::try_from(run.rounds.len()).unwrap_or(u16::MAX));
    for (round_index, round) in run.rounds.iter().enumerate() {
        validate_round(round)?;
        if round_index < usize::from(rounds_to_execute) {
            let round_number = u16::try_from(round_index + 1)
                .map_err(|_| Error::IndexOverflow("tournament round index"))?;
            validate_round_at(round, round_number)?;
        }
    }
    Ok(())
}

fn validate_author_fork(fork: &DreamerTournamentAuthorFork) -> Result<()> {
    validate_identifier(
        &fork.seed_ref,
        MAX_TOURNAMENT_CANDIDATE_REF_BYTES,
        "tournament author seed ref",
    )?;
    if !(DREAMER_TOURNAMENT_MIN_FANOUT_M as usize..=DREAMER_TOURNAMENT_MAX_FANOUT_M as usize)
        .contains(&fork.sibling_branch_jobs.len())
    {
        return Err(invalid_tournament(
            "tournament author fork must produce 2 or 3 sibling branches",
        ));
    }
    let mut branch_jobs = BTreeSet::new();
    for branch_job in &fork.sibling_branch_jobs {
        if *branch_job == fork.author_job || !branch_jobs.insert(*branch_job.as_bytes()) {
            return Err(invalid_tournament(
                "tournament author fork branch jobs must be unique siblings",
            ));
        }
    }
    Ok(())
}

fn validate_author_fork_outputs(run: &DreamerTournamentRun) -> Result<()> {
    if run.author_fork.sibling_branch_jobs.len() != usize::from(run.fanout_m) {
        return Err(invalid_tournament(
            "tournament fanout_m must match author fork sibling count",
        ));
    }
    let fork_jobs = run
        .author_fork
        .sibling_branch_jobs
        .iter()
        .map(|branch_job| *branch_job.as_bytes())
        .collect::<BTreeSet<_>>();
    let round_jobs = run.rounds[0]
        .branches
        .iter()
        .map(|branch| *branch.author.branch_job.as_bytes())
        .collect::<BTreeSet<_>>();
    if fork_jobs != round_jobs {
        return Err(invalid_tournament(
            "first tournament round branches must match author fork siblings",
        ));
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
        validate_weave_artifact(weave)?;
    }
    if round.ballots.is_empty() {
        return Err(invalid_tournament(
            "tournament round requires blind Borda ballots",
        ));
    }
    let mut judge_refs = BTreeSet::new();
    for ballot in &round.ballots {
        validate_identifier(
            &ballot.judge_ref,
            MAX_TOURNAMENT_CANDIDATE_REF_BYTES,
            "tournament judge ref",
        )?;
        if !judge_refs.insert(ballot.judge_ref.as_str()) {
            return Err(invalid_tournament(
                "duplicate tournament blind Borda judge_ref",
            ));
        }
    }
    Ok(())
}

fn validate_round_at(round: &DreamerTournamentRound, round_number: u16) -> Result<()> {
    for branch in &round.branches {
        validate_candidate_round(&branch.author, round_number, "author")?;
        if branch.synthesis.round != round_number {
            return Err(invalid_tournament(
                "synthesis artifact round must match enclosing tournament round",
            ));
        }
        if let Some(refined) = &branch.synthesis.refined {
            validate_candidate_round(refined, round_number, "refined")?;
        }
    }
    if let Some(weave) = &round.two_parent_weave {
        validate_candidate_round(&weave.candidate, round_number, "weave")?;
        for parent in &weave.parents {
            if parent.round != round_number {
                return Err(invalid_tournament(
                    "LMX weave parent round must match enclosing tournament round",
                ));
            }
        }
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
    validate_synthesis(&branch.synthesis)?;
    if branch.synthesis.branch_job != branch.author.branch_job
        || branch.synthesis.source_candidate_ref != branch.author.candidate_ref
        || branch.synthesis.round != branch.author.round
    {
        return Err(invalid_tournament(
            "tournament synthesis artifact must target its author branch",
        ));
    }
    let mut artifact_ids = BTreeSet::new();
    let mut lenses = BTreeSet::new();
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
        if !artifact_ids.insert(critique.artifact_id.as_str()) {
            return Err(invalid_tournament(
                "duplicate tournament critique artifact_id",
            ));
        }
        let lens_key = (critique.lens_id.as_str(), critique.domain.as_str());
        if !OF366_CLAIM_AUTHORING_LENSES.contains(&lens_key) {
            return Err(invalid_tournament(
                "tournament critique must use an OF-366 claim-authoring lens",
            ));
        }
        if !lenses.insert(lens_key) {
            return Err(invalid_tournament(
                "duplicate tournament MC-1 critique lens",
            ));
        }
    }
    for required_lens in OF366_CLAIM_AUTHORING_LENSES {
        if !lenses.contains(&required_lens) {
            return Err(invalid_tournament(
                "tournament branch requires all four OF-366 MC-1 lenses",
            ));
        }
    }
    if branch.critiques.len() != OF366_CLAIM_AUTHORING_LENSES.len() {
        return Err(invalid_tournament(
            "tournament branch requires exactly four OF-366 MC-1 critiques",
        ));
    }
    if let Some(refined) = &branch.synthesis.refined {
        validate_candidate(refined)?;
        if refined.branch_job != branch.author.branch_job {
            return Err(invalid_tournament(
                "refined tournament candidate must stay on its source branch",
            ));
        }
        if refined.round != branch.author.round {
            return Err(invalid_tournament(
                "refined tournament candidate round must match author round",
            ));
        }
    }
    Ok(())
}

fn validate_synthesis(synthesis: &DreamerTournamentSynthesisArtifact) -> Result<()> {
    validate_identifier(
        &synthesis.artifact_id,
        MAX_TOURNAMENT_ARTIFACT_ID_BYTES,
        "tournament synthesis artifact id",
    )?;
    validate_identifier(
        &synthesis.source_candidate_ref,
        MAX_TOURNAMENT_CANDIDATE_REF_BYTES,
        "tournament synthesis source candidate ref",
    )?;
    if synthesis.round == 0 || synthesis.round > DREAMER_TOURNAMENT_MAX_ROUNDS_K {
        return Err(invalid_tournament(
            "tournament synthesis round must be 1 or 2",
        ));
    }
    match synthesis.verdict {
        DreamerTournamentSynthesisVerdict::Refined => {
            let refined = synthesis.refined.as_ref().ok_or_else(|| {
                invalid_tournament("refined synthesis verdict requires a refined candidate")
            })?;
            validate_candidate(refined)?;
            if refined.branch_job != synthesis.branch_job || refined.round != synthesis.round {
                return Err(invalid_tournament(
                    "refined synthesis candidate must match synthesis branch and round",
                ));
            }
        }
        DreamerTournamentSynthesisVerdict::Survivor
        | DreamerTournamentSynthesisVerdict::Discarded => {
            if synthesis.refined.is_some() {
                return Err(invalid_tournament(
                    "non-refined synthesis verdict must not include refined candidate",
                ));
            }
        }
    }
    Ok(())
}

fn validate_weave_artifact(weave: &DreamerTournamentWeaveArtifact) -> Result<()> {
    validate_identifier(
        &weave.artifact_id,
        MAX_TOURNAMENT_ARTIFACT_ID_BYTES,
        "tournament weave artifact id",
    )?;
    validate_candidate(&weave.candidate)?;
    if weave.parents.len() != 2 {
        return Err(invalid_tournament(
            "LMX weave must reference exactly two parent candidates",
        ));
    }
    let mut parent_refs = BTreeSet::new();
    for parent in &weave.parents {
        validate_candidate_identity(parent)?;
        if !parent_refs.insert((*parent.branch_job.as_bytes(), parent.candidate_ref.as_str())) {
            return Err(invalid_tournament(
                "LMX weave parent candidates must be distinct",
            ));
        }
        if parent.round != weave.candidate.round {
            return Err(invalid_tournament(
                "LMX weave parent round must match weave candidate round",
            ));
        }
    }
    Ok(())
}

fn validate_weave_parents(
    partial_survivors: &[DreamerTournamentCandidate],
    weave: &DreamerTournamentWeaveArtifact,
) -> Result<()> {
    validate_weave_artifact(weave)?;
    let expected = partial_survivors
        .iter()
        .map(DreamerTournamentCandidateIdentity::from_candidate)
        .map(|identity| candidate_identity_key(&identity))
        .collect::<BTreeSet<_>>();
    let actual = weave
        .parents
        .iter()
        .map(candidate_identity_key)
        .collect::<BTreeSet<_>>();
    if expected != actual {
        return Err(invalid_tournament(
            "LMX weave parents must be exactly the two partial survivors",
        ));
    }
    Ok(())
}

fn candidate_identity_key(
    identity: &DreamerTournamentCandidateIdentity,
) -> ([u8; 16], String, String, u16) {
    (
        *identity.branch_job.as_bytes(),
        identity.candidate_ref.clone(),
        identity.claim_id.clone(),
        identity.round,
    )
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
    if candidate.claim.value_str() != Some(candidate.judge_claim.claim.as_str()) {
        return Err(invalid_tournament(
            "tournament judge claim must match candidate claim value",
        ));
    }
    Ok(())
}

fn validate_candidate_round(
    candidate: &DreamerTournamentCandidate,
    round_number: u16,
    role: &'static str,
) -> Result<()> {
    if candidate.round != round_number {
        return Err(match role {
            "refined" => {
                invalid_tournament("refined tournament candidate round must match enclosing round")
            }
            "weave" => invalid_tournament("LMX weave candidate round must match enclosing round"),
            _ => invalid_tournament("author candidate round must match enclosing round"),
        });
    }
    Ok(())
}

fn validate_candidate_identity(identity: &DreamerTournamentCandidateIdentity) -> Result<()> {
    validate_identifier(
        &identity.candidate_ref,
        MAX_TOURNAMENT_CANDIDATE_REF_BYTES,
        "tournament candidate ref",
    )?;
    validate_identifier(&identity.claim_id, 32, "tournament evidence claim id")?;
    if identity.round == 0 || identity.round > DREAMER_TOURNAMENT_MAX_ROUNDS_K {
        return Err(invalid_tournament(
            "tournament candidate identity round must be 1 or 2",
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
    if let Some(synthesis_artifact_id) = &evidence.synthesis_artifact_id {
        validate_identifier(
            synthesis_artifact_id,
            MAX_TOURNAMENT_ARTIFACT_ID_BYTES,
            "tournament synthesis artifact id",
        )?;
    }
    for parent in &evidence.parent_candidate_refs {
        validate_candidate_identity(parent)?;
    }
    if evidence.verdict == DreamerTournamentBranchVerdict::Weaved
        && evidence.parent_candidate_refs.len() != 2
    {
        return Err(invalid_tournament(
            "LMX weave evidence must include two parents",
        ));
    }
    if evidence.verdict != DreamerTournamentBranchVerdict::Weaved
        && !evidence.parent_candidate_refs.is_empty()
    {
        return Err(invalid_tournament(
            "non-weave tournament evidence must not include parents",
        ));
    }
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
    round: u16,
    verdict: DreamerTournamentBranchVerdict,
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
    key.extend_from_slice(&round.to_be_bytes());
    key.push(verdict_key_byte(verdict));
    key.extend_from_slice(&candidate_ref_len.to_be_bytes());
    key.extend_from_slice(candidate_ref.as_bytes());
    Ok(key)
}

fn verdict_key_byte(verdict: DreamerTournamentBranchVerdict) -> u8 {
    match verdict {
        DreamerTournamentBranchVerdict::Survivor => 1,
        DreamerTournamentBranchVerdict::Refined => 2,
        DreamerTournamentBranchVerdict::Discarded => 3,
        DreamerTournamentBranchVerdict::Weaved => 4,
    }
}

fn put_critique_artifact_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    artifact: &CritiqueArtifact,
) -> Result<()> {
    if artifact.out_of_scope {
        return Ok(());
    }
    let key = critique_artifact_key(artifact.branch_job, &artifact.artifact_id)?;
    let encoded = rmp_serde::to_vec_named(artifact)
        .map_err(|_| invalid_tournament("critique artifact MessagePack encode failed"))?;
    vault.store.vault_meta.put(wtxn, &key, &encoded)?;
    Ok(())
}

fn critique_artifact_key(branch_job: JobId, artifact_id: &str) -> Result<Vec<u8>> {
    validate_identifier(
        artifact_id,
        MAX_TOURNAMENT_ARTIFACT_ID_BYTES,
        "critique artifact id",
    )?;
    let artifact_id_len = u16::try_from(artifact_id.len())
        .map_err(|_| invalid_tournament("critique artifact id exceeds limit"))?;
    let mut key =
        Vec::with_capacity(CRITIQUE_PRIVATE_ARTIFACT_PREFIX.len() + 16 + 2 + artifact_id.len());
    key.extend_from_slice(CRITIQUE_PRIVATE_ARTIFACT_PREFIX);
    key.extend_from_slice(branch_job.as_bytes());
    key.extend_from_slice(&artifact_id_len.to_be_bytes());
    key.extend_from_slice(artifact_id.as_bytes());
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
mod tests;
