//! Branch-evidence and critique-artifact rows: keyspace, codec, and the read/write store.

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::critic::{CRITIQUE_ARTIFACT, CritiqueArtifact, CritiqueArtifactKey, CritiqueTriage};
use crate::error::Result;
use crate::side_table::{self, FixedSideKey, Named, SideKey, SideTable};

use super::types::{
    DREAMER_TOURNAMENT_BRANCH_EVIDENCE_SCHEMA_VERSION, DreamerTournamentBranchEvidence,
    DreamerTournamentBranchVerdict, DreamerTournamentCandidate, DreamerTournamentWeaveArtifact,
    MAX_TOURNAMENT_ARTIFACT_ID_BYTES, MAX_TOURNAMENT_CANDIDATE_REF_BYTES,
    MAX_TOURNAMENT_RUN_ID_BYTES,
};

use super::validate::{invalid_tournament, validate_evidence, validate_identifier};

/// One branch-evidence row: `run_id_len(u16 be) ++ run_id ++ branch_attempt(16) ++
/// round(u16 be) ++ verdict(1) ++ candidate_ref_len(u16 be) ++ candidate_ref`, exactly as
/// `tournament_evidence_key` spelled it. Every length was validated (`validate_identifier`)
/// before this key is constructed, so each fits its `u16`.
#[derive(Debug, Clone, PartialEq, Eq, SideKey)]
struct TournamentEvidenceKey {
    #[side_key(len = u16)]
    run_id: String,
    branch_attempt: AttemptId,
    round: u16,
    verdict: DreamerTournamentBranchVerdict,
    #[side_key(len = u16)]
    candidate_ref: String,
}

/// One [`TournamentEvidenceKey`] for `test_doors::side_key_pins`.
#[cfg(oneiron_test_support)]
pub(crate) fn tournament_evidence_key_pin_for_test(
    run_id: &str,
    branch_attempt: AttemptId,
    round: u16,
    verdict: DreamerTournamentBranchVerdict,
    candidate_ref: &str,
) -> crate::test_doors::side_key_pins::Pin {
    crate::test_doors::side_key_pins::Pin::of(&TournamentEvidenceKey {
        run_id: run_id.to_owned(),
        branch_attempt,
        round,
        verdict,
        candidate_ref: candidate_ref.to_owned(),
    })
}

const EVIDENCE: SideTable<TournamentEvidenceKey, DreamerTournamentBranchEvidence, Named> =
    SideTable::new(&side_table::DREAMER_TOURNAMENT_EVIDENCE);

pub struct DreamerTournamentEvidenceStore<'a> {
    vault: &'a Vault,
}

impl<'a> DreamerTournamentEvidenceStore<'a> {
    #[must_use]
    pub fn new(vault: &'a Vault) -> Self {
        Self { vault }
    }

    pub fn list_run(&self, run_id: &str) -> Result<Vec<DreamerTournamentBranchEvidence>> {
        let prefix = tournament_evidence_run_prefix(run_id)?;
        let rtxn = self.vault.store.env.read_txn()?;
        let mut evidence = Vec::new();
        for (_key, row) in EVIDENCE.scan_from(&self.vault.store, &rtxn, &prefix)? {
            validate_evidence(&row)?;
            evidence.push(row);
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
        validate_identifier(
            &evidence.candidate_ref,
            MAX_TOURNAMENT_CANDIDATE_REF_BYTES,
            "tournament candidate ref",
        )?;
        validate_identifier(
            &evidence.run_id,
            MAX_TOURNAMENT_RUN_ID_BYTES,
            "tournament run id",
        )?;
        let key = TournamentEvidenceKey {
            run_id: evidence.run_id.clone(),
            branch_attempt: evidence.branch_attempt,
            round: evidence.round,
            verdict: evidence.verdict,
            candidate_ref: evidence.candidate_ref.clone(),
        };
        EVIDENCE.put(&self.vault.store, wtxn, &key, evidence)?;
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
        auto_resolved: triage.auto_resolved,
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
        auto_resolved: false,
    };
    validate_evidence(&evidence)?;
    Ok(evidence)
}

/// The raw key-prefix bytes (after the table's own declared prefix) selecting one run's
/// evidence rows: `run_id_len(u16 be) ++ run_id`.
fn tournament_evidence_run_prefix(run_id: &str) -> Result<Vec<u8>> {
    validate_identifier(run_id, MAX_TOURNAMENT_RUN_ID_BYTES, "tournament run id")?;
    let run_id_len = u16::try_from(run_id.len())
        .map_err(|_| invalid_tournament("tournament run id exceeds limit"))?;
    let mut prefix = Vec::with_capacity(2 + run_id.len());
    prefix.extend_from_slice(&run_id_len.to_be_bytes());
    prefix.extend_from_slice(run_id.as_bytes());
    Ok(prefix)
}

/// A branch verdict, as its one key byte in `TournamentEvidenceKey`.
impl SideKey for DreamerTournamentBranchVerdict {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(match self {
            Self::Survivor => 1,
            Self::Refined => 2,
            Self::Discarded => 3,
            Self::Weaved => 4,
        });
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        match bytes {
            [1] => Some(Self::Survivor),
            [2] => Some(Self::Refined),
            [3] => Some(Self::Discarded),
            [4] => Some(Self::Weaved),
            _ => None,
        }
    }
}

impl FixedSideKey for DreamerTournamentBranchVerdict {
    const WIDTH: usize = 1;
}

pub(super) fn put_critique_artifact_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    artifact: &CritiqueArtifact,
) -> Result<()> {
    if artifact.out_of_scope {
        return Ok(());
    }
    validate_identifier(
        &artifact.artifact_id,
        MAX_TOURNAMENT_ARTIFACT_ID_BYTES,
        "critique artifact id",
    )?;
    let key = CritiqueArtifactKey {
        branch_attempt: artifact.branch_attempt,
        artifact_id: artifact.artifact_id.clone(),
    };
    CRITIQUE_ARTIFACT.put(vault, wtxn, &key, artifact)?;
    Ok(())
}
