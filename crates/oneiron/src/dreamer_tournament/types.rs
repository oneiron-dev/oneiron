//! Tournament wire types, their validating constructors, and the pinned bounds.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::AttemptId;
use crate::critic::{CriticReliability, CritiqueArtifact};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteEnvelope};

use super::validate::{
    validate_author_fork, validate_branch, validate_candidate, validate_evidence_refs,
    validate_identifier, validate_round, validate_run, validate_synthesis, validate_text,
    validate_weave_artifact,
};

pub const DREAMER_TOURNAMENT_BRANCH_EVIDENCE_SCHEMA_VERSION: u64 = 1;

pub const DREAMER_TOURNAMENT_MAX_ROUNDS_K: u16 = 2;

pub const DREAMER_TOURNAMENT_MIN_FANOUT_M: u16 = 2;

pub const DREAMER_TOURNAMENT_MAX_FANOUT_M: u16 = 3;

pub(super) const MAX_TOURNAMENT_RUN_ID_BYTES: usize = 128;

pub(super) const MAX_TOURNAMENT_CANDIDATE_REF_BYTES: usize = 128;

pub(super) const MAX_TOURNAMENT_ARTIFACT_ID_BYTES: usize = 128;

pub(super) const MAX_TOURNAMENT_STRATEGY_BYTES: usize = 128;

pub(super) const MAX_TOURNAMENT_JUDGE_TEXT_BYTES: usize = 8192;

pub(super) const MAX_TOURNAMENT_EVIDENCE_REFS: usize = 64;

pub(super) const MAX_TOURNAMENT_EVIDENCE_REF_BYTES: usize = 256;

pub(super) const MAX_TOURNAMENT_BALLOTS: usize = 32;

pub(super) const OF366_CLAIM_AUTHORING_LENSES: [(&str, &str); 4] = [
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
    pub branch_attempt: AttemptId,
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
        branch_attempt: AttemptId,
        claim_id: EntityId,
        claim: ClaimCandidate,
        judge_claim: DreamerTournamentJudgeClaim,
        strategy: impl Into<String>,
        round: u16,
    ) -> Result<Self> {
        let candidate = Self {
            candidate_ref: candidate_ref.into(),
            branch_attempt,
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
    #[serde(rename = "branch_job")] // storage key pinned pre-rename (ONE-1714)
    pub branch_attempt: AttemptId,
    pub claim_id: String,
    pub round: u16,
}

impl DreamerTournamentCandidateIdentity {
    #[must_use]
    pub fn from_candidate(candidate: &DreamerTournamentCandidate) -> Self {
        Self {
            candidate_ref: candidate.candidate_ref.clone(),
            branch_attempt: candidate.branch_attempt,
            claim_id: candidate.claim_id.to_hex(),
            round: candidate.round,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerTournamentAuthorFork {
    pub seed_ref: String,
    pub author_attempt: AttemptId,
    pub sibling_branch_attempts: Vec<AttemptId>,
}

impl DreamerTournamentAuthorFork {
    pub fn new(
        seed_ref: impl Into<String>,
        author_attempt: AttemptId,
        sibling_branch_attempts: Vec<AttemptId>,
    ) -> Result<Self> {
        let fork = Self {
            seed_ref: seed_ref.into(),
            author_attempt,
            sibling_branch_attempts,
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
    pub branch_attempt: AttemptId,
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
            source.branch_attempt,
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
            source.branch_attempt,
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
            source.branch_attempt,
            source.round,
            DreamerTournamentSynthesisVerdict::Refined,
            Some(refined),
        )
    }

    fn new(
        artifact_id: impl Into<String>,
        source_candidate_ref: impl Into<String>,
        branch_attempt: AttemptId,
        round: u16,
        verdict: DreamerTournamentSynthesisVerdict,
        refined: Option<DreamerTournamentCandidate>,
    ) -> Result<Self> {
        let artifact = Self {
            artifact_id: artifact_id.into(),
            source_candidate_ref: source_candidate_ref.into(),
            branch_attempt,
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
    #[serde(rename = "branch_job")] // storage key pinned pre-rename (ONE-1714)
    pub branch_attempt: AttemptId,
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
    pub branch_attempt: AttemptId,
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

pub(super) struct SynthesizedCandidate {
    pub(super) candidate: DreamerTournamentCandidate,
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct RankedCandidate {
    pub(super) index: usize,
    pub(super) score: u64,
}
