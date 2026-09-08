//! Branch-evidence and critique-artifact rows: keyspace, codec, and the read/write store.

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::critic::{CritiqueArtifact, CritiqueTriage};
use crate::error::{Error, Result};

use super::types::{
    DREAMER_TOURNAMENT_BRANCH_EVIDENCE_SCHEMA_VERSION, DreamerTournamentBranchEvidence,
    DreamerTournamentBranchVerdict, DreamerTournamentCandidate, DreamerTournamentWeaveArtifact,
    MAX_TOURNAMENT_ARTIFACT_ID_BYTES, MAX_TOURNAMENT_CANDIDATE_REF_BYTES,
    MAX_TOURNAMENT_RUN_ID_BYTES,
};

use super::validate::{invalid_tournament, validate_evidence, validate_identifier};
const DREAMER_TOURNAMENT_EVIDENCE_PREFIX: &[u8] = b"dreamer:tournament:v1:";

const CRITIQUE_PRIVATE_ARTIFACT_PREFIX: &[u8] = b"dreamer:critic:v1:";

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
            evidence.push(decode_tournament_evidence(&raw)?);
        }
        evidence.sort_by(|left, right| {
            (left.round, left.candidate_ref.as_str())
                .cmp(&(right.round, right.candidate_ref.as_str()))
        });
        Ok(evidence)
    }

    pub(super) fn put_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        evidence: &DreamerTournamentBranchEvidence,
    ) -> Result<()> {
        validate_evidence(evidence)?;
        let key = tournament_evidence_key(
            &evidence.run_id,
            evidence.branch_attempt,
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

pub(super) fn tournament_evidence(
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
        branch_attempt: candidate.branch_attempt,
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

pub(super) fn tournament_weave_evidence(
    run_id: &str,
    weave: &DreamerTournamentWeaveArtifact,
) -> Result<DreamerTournamentBranchEvidence> {
    let evidence = DreamerTournamentBranchEvidence {
        schema_version: DREAMER_TOURNAMENT_BRANCH_EVIDENCE_SCHEMA_VERSION,
        run_id: run_id.to_owned(),
        candidate_ref: weave.candidate.candidate_ref.clone(),
        branch_attempt: weave.candidate.branch_attempt,
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
    branch_attempt: AttemptId,
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
    key.extend_from_slice(branch_attempt.as_bytes());
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

pub(super) fn put_critique_artifact_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    artifact: &CritiqueArtifact,
) -> Result<()> {
    if artifact.out_of_scope {
        return Ok(());
    }
    let key = critique_artifact_key(artifact.branch_attempt, &artifact.artifact_id)?;
    let encoded = rmp_serde::to_vec_named(artifact)
        .map_err(|_| invalid_tournament("critique artifact MessagePack encode failed"))?;
    vault.store.vault_meta.put(wtxn, &key, &encoded)?;
    Ok(())
}

fn critique_artifact_key(branch_attempt: AttemptId, artifact_id: &str) -> Result<Vec<u8>> {
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
    key.extend_from_slice(branch_attempt.as_bytes());
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
