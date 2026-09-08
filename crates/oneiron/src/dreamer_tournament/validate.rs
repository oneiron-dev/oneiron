//! Every structural predicate the tournament refuses on, and the one error constructor.

use std::collections::BTreeSet;

use crate::error::{Error, Result};

use super::types::{
    DREAMER_TOURNAMENT_BRANCH_EVIDENCE_SCHEMA_VERSION, DREAMER_TOURNAMENT_MAX_FANOUT_M,
    DREAMER_TOURNAMENT_MAX_ROUNDS_K, DREAMER_TOURNAMENT_MIN_FANOUT_M, DreamerTournamentAuthorFork,
    DreamerTournamentBordaBallot, DreamerTournamentBranch, DreamerTournamentBranchEvidence,
    DreamerTournamentBranchVerdict, DreamerTournamentCandidate, DreamerTournamentCandidateIdentity,
    DreamerTournamentRound, DreamerTournamentRun, DreamerTournamentSynthesisArtifact,
    DreamerTournamentSynthesisVerdict, DreamerTournamentWeaveArtifact,
    MAX_TOURNAMENT_ARTIFACT_ID_BYTES, MAX_TOURNAMENT_CANDIDATE_REF_BYTES,
    MAX_TOURNAMENT_EVIDENCE_REF_BYTES, MAX_TOURNAMENT_EVIDENCE_REFS,
    MAX_TOURNAMENT_JUDGE_TEXT_BYTES, MAX_TOURNAMENT_RUN_ID_BYTES, MAX_TOURNAMENT_STRATEGY_BYTES,
    OF366_CLAIM_AUTHORING_LENSES,
};

pub(super) fn validate_run(run: &DreamerTournamentRun) -> Result<()> {
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

pub(super) fn validate_author_fork(fork: &DreamerTournamentAuthorFork) -> Result<()> {
    validate_identifier(
        &fork.seed_ref,
        MAX_TOURNAMENT_CANDIDATE_REF_BYTES,
        "tournament author seed ref",
    )?;
    if !(DREAMER_TOURNAMENT_MIN_FANOUT_M as usize..=DREAMER_TOURNAMENT_MAX_FANOUT_M as usize)
        .contains(&fork.sibling_branch_attempts.len())
    {
        return Err(invalid_tournament(
            "tournament author fork must produce 2 or 3 sibling branches",
        ));
    }
    let mut branch_attempts = BTreeSet::new();
    for branch_attempt in &fork.sibling_branch_attempts {
        if *branch_attempt == fork.author_attempt
            || !branch_attempts.insert(*branch_attempt.as_bytes())
        {
            return Err(invalid_tournament(
                "tournament author fork branch attempts must be unique siblings",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_author_fork_outputs(run: &DreamerTournamentRun) -> Result<()> {
    if run.author_fork.sibling_branch_attempts.len() != usize::from(run.fanout_m) {
        return Err(invalid_tournament(
            "tournament fanout_m must match author fork sibling count",
        ));
    }
    let fork_attempts = run
        .author_fork
        .sibling_branch_attempts
        .iter()
        .map(|branch_attempt| *branch_attempt.as_bytes())
        .collect::<BTreeSet<_>>();
    let round_attempts = run.rounds[0]
        .branches
        .iter()
        .map(|branch| *branch.author.branch_attempt.as_bytes())
        .collect::<BTreeSet<_>>();
    if fork_attempts != round_attempts {
        return Err(invalid_tournament(
            "first tournament round branches must match author fork siblings",
        ));
    }
    Ok(())
}

pub(super) fn validate_round(round: &DreamerTournamentRound) -> Result<()> {
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

pub(super) fn validate_round_at(round: &DreamerTournamentRound, round_number: u16) -> Result<()> {
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

pub(super) fn validate_branch(branch: &DreamerTournamentBranch) -> Result<()> {
    validate_candidate(&branch.author)?;
    if branch.critiques.is_empty() {
        return Err(invalid_tournament(
            "tournament branch requires MC-1 critique artifacts",
        ));
    }
    validate_synthesis(&branch.synthesis)?;
    if branch.synthesis.branch_attempt != branch.author.branch_attempt
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
        if critique.branch_attempt != branch.author.branch_attempt {
            return Err(invalid_tournament(
                "tournament critique branch_attempt must match author branch",
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
        if refined.branch_attempt != branch.author.branch_attempt {
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

pub(super) fn validate_synthesis(synthesis: &DreamerTournamentSynthesisArtifact) -> Result<()> {
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
            if refined.branch_attempt != synthesis.branch_attempt
                || refined.round != synthesis.round
            {
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

pub(super) fn validate_weave_artifact(weave: &DreamerTournamentWeaveArtifact) -> Result<()> {
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
        if !parent_refs.insert((
            *parent.branch_attempt.as_bytes(),
            parent.candidate_ref.as_str(),
        )) {
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

pub(super) fn validate_weave_parents(
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

pub(super) fn candidate_identity_key(
    identity: &DreamerTournamentCandidateIdentity,
) -> ([u8; 16], String, String, u16) {
    (
        *identity.branch_attempt.as_bytes(),
        identity.candidate_ref.clone(),
        identity.claim_id.clone(),
        identity.round,
    )
}

pub(super) fn validate_candidate(candidate: &DreamerTournamentCandidate) -> Result<()> {
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

pub(super) fn validate_candidate_round(
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

pub(super) fn validate_candidate_identity(
    identity: &DreamerTournamentCandidateIdentity,
) -> Result<()> {
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

pub(super) fn validate_ballot(
    ballot: &DreamerTournamentBordaBallot,
    candidate_count: usize,
) -> Result<()> {
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

pub(super) fn validate_evidence(evidence: &DreamerTournamentBranchEvidence) -> Result<()> {
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

pub(super) fn validate_identifier(
    value: &str,
    max_bytes: usize,
    field: &'static str,
) -> Result<()> {
    validate_text(value, max_bytes, field)?;
    if value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(invalid_tournament(
            "tournament identifier contains control bytes",
        ));
    }
    Ok(())
}

pub(super) fn validate_text(value: &str, max_bytes: usize, field: &'static str) -> Result<()> {
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

pub(super) fn validate_evidence_refs(refs: &[String]) -> Result<()> {
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

pub(super) fn invalid_tournament(reason: &'static str) -> Error {
    Error::InvalidAttemptQueueRecord(reason)
}
