//! Multi-critic review node primitives.
//!
//! OF-352 models critics as run-tree-scoped artifacts, not vault claims. This
//! module keeps that split explicit: critiques persist in private `vault_meta`
//! rows keyed by the Dreamer branch job, while learned reliability can be
//! surfaced separately as `critic_reliability.*` claims by callers that choose
//! to write the public calibration state.

use std::collections::{BTreeMap, BTreeSet};

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, MAX_PREDICATE_BYTES,
};
use crate::error::{Error, Result};
use crate::job_queue::JobId;
use crate::types::EntityId;

pub const CRITIQUE_ARTIFACT_SCHEMA_VERSION: u64 = 1;
pub const CRITIC_LENS_CATALOG_SCHEMA_VERSION: u64 = 1;
pub const CRITIC_RELIABILITY_CLAIM_SCHEMA_VERSION: u64 = 1;
pub const CRITIC_RELIABILITY_PREDICATE_PREFIX: &str = "critic_reliability";

const CRITIQUE_PRIVATE_ARTIFACT_PREFIX: &[u8] = b"dreamer:critic:v1:";
const MAX_CATALOG_LENSES: usize = 64;
const MAX_ID_BYTES: usize = 64;
const MAX_DOMAIN_BYTES: usize = 64;
const MAX_CONTRACT_BYTES: usize = 4096;
const MAX_OUTPUT_SCHEMA_BYTES: usize = 4096;
const MAX_ARTIFACT_ID_BYTES: usize = 128;
const MAX_RUN_ID_BYTES: usize = 128;
const MAX_CANDIDATE_REF_BYTES: usize = 256;
const MAX_PROVENANCE_REF_BYTES: usize = 256;
const MAX_EVIDENCE_REFS: usize = 64;
const MAX_EVIDENCE_REF_BYTES: usize = 256;
const MAX_SUGGESTED_EDIT_BYTES: usize = 8192;
const DEFAULT_UCB_EXPLORATION: f64 = 0.35;

pub const OF366_SEED_LENS_CATALOG_JSON: &str = r#"{
  "schema_version": 1,
  "lenses": [
    {
      "id": "groundedness",
      "prompt_contract": "Check that every asserted candidate token is grounded in the supplied evidence pack and supported by evidence refs.",
      "output_schema": "critique.v1 { verdict, severity, evidence_refs, suggested_edit, hard_check_passed }",
      "hard_check": true,
      "domain": "claim_authoring"
    },
    {
      "id": "overreach",
      "prompt_contract": "Check that the candidate scope and confidence do not exceed the supplied evidence scope.",
      "output_schema": "critique.v1 { verdict, severity, evidence_refs, suggested_edit }",
      "hard_check": false,
      "domain": "claim_authoring"
    },
    {
      "id": "temporal",
      "prompt_contract": "Check temporal validity: occurred_at, learned_at, and generalization freshness must match the evidence pack.",
      "output_schema": "critique.v1 { verdict, severity, evidence_refs, suggested_edit }",
      "hard_check": false,
      "domain": "claim_authoring"
    },
    {
      "id": "redundancy",
      "prompt_contract": "Check that the candidate is not a supersession duplicate of an existing claim in the evidence pack.",
      "output_schema": "critique.v1 { verdict, severity, evidence_refs, suggested_edit }",
      "hard_check": false,
      "domain": "claim_authoring"
    }
  ]
}"#;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CriticLens {
    pub id: String,
    pub prompt_contract: String,
    pub output_schema: String,
    pub hard_check: bool,
    pub domain: String,
}

impl CriticLens {
    pub fn new(
        id: impl Into<String>,
        prompt_contract: impl Into<String>,
        output_schema: impl Into<String>,
        hard_check: bool,
        domain: impl Into<String>,
    ) -> Result<Self> {
        let lens = Self {
            id: id.into(),
            prompt_contract: prompt_contract.into(),
            output_schema: output_schema.into(),
            hard_check,
            domain: domain.into(),
        };
        validate_lens(&lens)?;
        Ok(lens)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LensCatalog {
    pub schema_version: u64,
    pub lenses: Vec<CriticLens>,
}

impl LensCatalog {
    pub fn from_json_str(data: &str) -> Result<Self> {
        let catalog: Self = serde_json::from_str(data)
            .map_err(|_| invalid_critic_config("critic lens catalog is not valid JSON"))?;
        validate_catalog(&catalog)?;
        Ok(catalog)
    }

    pub fn of366_seed() -> Result<Self> {
        Self::from_json_str(OF366_SEED_LENS_CATALOG_JSON)
    }

    #[must_use]
    pub fn lens(&self, id: &str, domain: &str) -> Option<&CriticLens> {
        self.lenses
            .iter()
            .find(|lens| lens.id == id && lens.domain == domain)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CritiqueVerdict {
    Accept,
    Revise,
    Discard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CritiqueSeverity {
    Info,
    Low,
    Medium,
    High,
    Blocking,
}

impl CritiqueSeverity {
    const fn score_multiplier(self) -> f64 {
        match self {
            Self::Info => 0.25,
            Self::Low => 0.5,
            Self::Medium => 1.0,
            Self::High => 1.5,
            Self::Blocking => 2.0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CritiqueProvenance {
    pub critic_ref: String,
    pub model_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_revision: Option<String>,
}

impl CritiqueProvenance {
    pub fn new(
        critic_ref: impl Into<String>,
        model_id: impl Into<String>,
        model_revision: Option<String>,
    ) -> Result<Self> {
        let provenance = Self {
            critic_ref: critic_ref.into(),
            model_id: model_id.into(),
            model_revision,
        };
        validate_provenance(&provenance)?;
        Ok(provenance)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CritiqueArtifact {
    pub schema_version: u64,
    pub artifact_id: String,
    pub run_id: String,
    pub branch_job: JobId,
    pub candidate_ref: String,
    pub lens_id: String,
    pub domain: String,
    pub provenance: CritiqueProvenance,
    pub verdict: CritiqueVerdict,
    pub severity: CritiqueSeverity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hard_check_passed: Option<bool>,
    pub evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested_edit: Option<String>,
    #[serde(default)]
    pub out_of_scope: bool,
    pub created_at: u64,
}

impl CritiqueArtifact {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        artifact_id: impl Into<String>,
        run_id: impl Into<String>,
        branch_job: JobId,
        candidate_ref: impl Into<String>,
        lens: &CriticLens,
        provenance: CritiqueProvenance,
        verdict: CritiqueVerdict,
        severity: CritiqueSeverity,
        hard_check_passed: Option<bool>,
        evidence_refs: Vec<String>,
        suggested_edit: Option<String>,
        created_at: u64,
    ) -> Result<Self> {
        let artifact = Self {
            schema_version: CRITIQUE_ARTIFACT_SCHEMA_VERSION,
            artifact_id: artifact_id.into(),
            run_id: run_id.into(),
            branch_job,
            candidate_ref: candidate_ref.into(),
            lens_id: lens.id.clone(),
            domain: lens.domain.clone(),
            provenance,
            verdict,
            severity,
            hard_check_passed,
            evidence_refs,
            suggested_edit,
            out_of_scope: false,
            created_at,
        };
        validate_critique_artifact(&artifact)?;
        Ok(artifact)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CriticReliability {
    pub lens_id: String,
    pub domain: String,
    pub alpha: f64,
    pub beta: f64,
    pub observations: u64,
}

impl CriticReliability {
    pub fn prior(lens_id: impl Into<String>, domain: impl Into<String>) -> Result<Self> {
        Self::new(lens_id, domain, 1.0, 1.0, 0)
    }

    pub fn new(
        lens_id: impl Into<String>,
        domain: impl Into<String>,
        alpha: f64,
        beta: f64,
        observations: u64,
    ) -> Result<Self> {
        let reliability = Self {
            lens_id: lens_id.into(),
            domain: domain.into(),
            alpha,
            beta,
            observations,
        };
        validate_reliability(&reliability)?;
        Ok(reliability)
    }

    #[must_use]
    pub fn posterior_mean(&self) -> f64 {
        self.alpha / (self.alpha + self.beta)
    }

    #[must_use]
    pub fn ucb_bonus(&self, total_observations: u64, exploration: f64) -> f64 {
        let denominator = self.observations.max(1) as f64;
        let numerator = ((total_observations.max(1) + 1) as f64).ln();
        exploration * (2.0 * numerator / denominator).sqrt()
    }

    #[must_use]
    pub fn triage_weight(&self, total_observations: u64, exploration: f64) -> f64 {
        self.posterior_mean() + self.ucb_bonus(total_observations, exploration)
    }

    pub fn apply_outcome(&mut self, event: ReliabilityOutcomeEvent) -> Result<()> {
        if self.lens_id != event.lens_id || self.domain != event.domain {
            return Err(invalid_critic_config(
                "reliability outcome does not match posterior lens/domain",
            ));
        }
        if !event.source.is_anchored() {
            return Err(invalid_critic_config(
                "critic reliability updates require anchored outcomes",
            ));
        }
        if event.correct {
            self.alpha += 1.0;
        } else {
            self.beta += 1.0;
        }
        self.observations = self
            .observations
            .checked_add(1)
            .ok_or(Error::IndexOverflow("critic reliability observations"))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReliabilityOutcomeSource {
    HeldOutEval,
    OwnerVerdict,
    Beam,
    CriticAgreement,
}

impl ReliabilityOutcomeSource {
    #[must_use]
    pub const fn is_anchored(self) -> bool {
        matches!(self, Self::HeldOutEval | Self::OwnerVerdict | Self::Beam)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReliabilityOutcomeEvent {
    pub lens_id: String,
    pub domain: String,
    pub source: ReliabilityOutcomeSource,
    pub correct: bool,
    pub observed_at: u64,
}

impl ReliabilityOutcomeEvent {
    pub fn new(
        lens_id: impl Into<String>,
        domain: impl Into<String>,
        source: ReliabilityOutcomeSource,
        correct: bool,
        observed_at: u64,
    ) -> Result<Self> {
        let event = Self {
            lens_id: lens_id.into(),
            domain: domain.into(),
            source,
            correct,
            observed_at,
        };
        validate_identifier(&event.lens_id, MAX_ID_BYTES, "lens id")?;
        validate_identifier(&event.domain, MAX_DOMAIN_BYTES, "domain")?;
        Ok(event)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct CritiqueTriageScores {
    pub accept: f64,
    pub revise: f64,
    pub discard: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CritiqueTriage {
    pub verdict: CritiqueVerdict,
    pub scores: CritiqueTriageScores,
    pub acted_on_artifact_ids: Vec<String>,
    pub hard_veto_artifact_ids: Vec<String>,
    pub out_of_scope_artifact_ids: Vec<String>,
}

pub fn triage_critiques(
    catalog: &LensCatalog,
    critiques: &[CritiqueArtifact],
    reliabilities: &[CriticReliability],
) -> Result<CritiqueTriage> {
    triage_critiques_with_exploration(catalog, critiques, reliabilities, DEFAULT_UCB_EXPLORATION)
}

pub fn triage_critiques_with_exploration(
    catalog: &LensCatalog,
    critiques: &[CritiqueArtifact],
    reliabilities: &[CriticReliability],
    exploration: f64,
) -> Result<CritiqueTriage> {
    validate_catalog(catalog)?;
    validate_reliability_table(reliabilities)?;
    if !exploration.is_finite() || exploration < 0.0 {
        return Err(invalid_critic_config(
            "critic triage exploration coefficient must be finite and non-negative",
        ));
    }

    let total_observations = reliabilities.iter().try_fold(0_u64, |sum, reliability| {
        sum.checked_add(reliability.observations)
            .ok_or(Error::IndexOverflow("critic reliability observations"))
    })?;
    let reliability_by_lens = reliabilities
        .iter()
        .map(|reliability| {
            (
                (reliability.lens_id.as_str(), reliability.domain.as_str()),
                reliability,
            )
        })
        .collect::<BTreeMap<_, _>>();

    let mut scores = CritiqueTriageScores::default();
    let mut acted_on = Vec::new();
    let mut hard_vetoes = Vec::new();
    let mut out_of_scope = Vec::new();

    for critique in critiques {
        validate_critique_artifact(critique)?;
        let lens = catalog
            .lens(&critique.lens_id, &critique.domain)
            .ok_or_else(|| invalid_critic_config("critique references an unknown lens"))?;
        if critique.out_of_scope {
            out_of_scope.push(critique.artifact_id.clone());
            continue;
        }
        if lens.hard_check && critique.hard_check_passed != Some(true) {
            hard_vetoes.push(critique.artifact_id.clone());
            acted_on.push(critique.artifact_id.clone());
            continue;
        }

        let reliability = reliability_by_lens
            .get(&(critique.lens_id.as_str(), critique.domain.as_str()))
            .copied();
        let owned_prior;
        let reliability = if let Some(reliability) = reliability {
            reliability
        } else {
            owned_prior = CriticReliability::prior(&critique.lens_id, &critique.domain)?;
            &owned_prior
        };
        let weight = reliability.triage_weight(total_observations, exploration);
        match critique.verdict {
            CritiqueVerdict::Accept => scores.accept += weight,
            CritiqueVerdict::Revise => {
                scores.revise += weight * critique.severity.score_multiplier();
                acted_on.push(critique.artifact_id.clone());
            }
            CritiqueVerdict::Discard => {
                scores.discard += weight * critique.severity.score_multiplier();
                acted_on.push(critique.artifact_id.clone());
            }
        }
    }

    let verdict = if !hard_vetoes.is_empty() {
        CritiqueVerdict::Discard
    } else {
        soft_verdict(scores)
    };

    Ok(CritiqueTriage {
        verdict,
        scores,
        acted_on_artifact_ids: acted_on,
        hard_veto_artifact_ids: hard_vetoes,
        out_of_scope_artifact_ids: out_of_scope,
    })
}

pub struct CritiqueArtifactStore<'a> {
    vault: &'a Vault,
}

impl<'a> CritiqueArtifactStore<'a> {
    #[must_use]
    pub fn new(vault: &'a Vault) -> Self {
        Self { vault }
    }

    pub fn put(&self, artifact: &CritiqueArtifact) -> Result<()> {
        validate_critique_artifact(artifact)?;
        if artifact.out_of_scope {
            return Ok(());
        }
        let key = critique_artifact_key(artifact.branch_job, &artifact.artifact_id)?;
        let encoded = rmp_serde::to_vec_named(artifact)
            .map_err(|_| invalid_critic_config("critique artifact MessagePack encode failed"))?;
        let mut wtxn = self.vault.store.env.write_txn()?;
        self.vault.store.vault_meta.put(&mut wtxn, &key, &encoded)?;
        wtxn.commit()?;
        Ok(())
    }

    pub fn get(&self, branch_job: JobId, artifact_id: &str) -> Result<Option<CritiqueArtifact>> {
        validate_identifier(artifact_id, MAX_ARTIFACT_ID_BYTES, "critique artifact id")?;
        let key = critique_artifact_key(branch_job, artifact_id)?;
        let rtxn = self.vault.store.env.read_txn()?;
        let Some(raw) = self.vault.store.vault_meta.get(&rtxn, &key)? else {
            return Ok(None);
        };
        decode_stored_critique_artifact(raw).map(Some)
    }

    pub fn list_branch(&self, branch_job: JobId) -> Result<Vec<CritiqueArtifact>> {
        let rtxn = self.vault.store.env.read_txn()?;
        let prefix = critique_branch_prefix(branch_job);
        let mut artifacts = Vec::new();
        for row in self.vault.store.vault_meta.prefix_iter(&rtxn, &prefix)? {
            let (_key, raw) = row?;
            artifacts.push(decode_stored_critique_artifact(raw)?);
        }
        artifacts.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
        Ok(artifacts)
    }
}

pub fn critic_reliability_predicate(domain: &str, lens_id: &str) -> Result<String> {
    validate_identifier(domain, MAX_DOMAIN_BYTES, "domain")?;
    validate_identifier(lens_id, MAX_ID_BYTES, "lens id")?;
    let predicate = format!("{CRITIC_RELIABILITY_PREDICATE_PREFIX}.{domain}.{lens_id}");
    if predicate.len() > MAX_PREDICATE_BYTES {
        return Err(invalid_critic_config(
            "critic reliability predicate exceeds claim predicate limit",
        ));
    }
    Ok(predicate)
}

pub fn critic_reliability_claim_body(
    subject: EntityId,
    reliability: &CriticReliability,
    confidence: f32,
) -> Result<ClaimBody> {
    validate_reliability(reliability)?;
    let predicate = critic_reliability_predicate(&reliability.domain, &reliability.lens_id)?;
    let value = Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(CRITIC_RELIABILITY_CLAIM_SCHEMA_VERSION),
        ),
        (Value::from("alpha"), Value::F64(reliability.alpha)),
        (Value::from("beta"), Value::F64(reliability.beta)),
        (
            Value::from("observations"),
            Value::from(reliability.observations),
        ),
    ]);
    Ok(ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        value,
        confidence,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    ))
}

fn decode_stored_critique_artifact(raw: &[u8]) -> Result<CritiqueArtifact> {
    let artifact: CritiqueArtifact = rmp_serde::from_slice(raw)
        .map_err(|_| Error::CorruptedIndex("critic critique artifact"))?;
    validate_critique_artifact(&artifact)?;
    Ok(artifact)
}

fn soft_verdict(scores: CritiqueTriageScores) -> CritiqueVerdict {
    if scores.discard > 0.0 && scores.discard >= scores.revise && scores.discard >= scores.accept {
        CritiqueVerdict::Discard
    } else if scores.revise > 0.0 && scores.revise >= scores.accept {
        CritiqueVerdict::Revise
    } else {
        CritiqueVerdict::Accept
    }
}

fn critique_branch_prefix(branch_job: JobId) -> Vec<u8> {
    let mut out = Vec::with_capacity(CRITIQUE_PRIVATE_ARTIFACT_PREFIX.len() + 16);
    out.extend_from_slice(CRITIQUE_PRIVATE_ARTIFACT_PREFIX);
    out.extend_from_slice(branch_job.as_bytes());
    out
}

fn critique_artifact_key(branch_job: JobId, artifact_id: &str) -> Result<Vec<u8>> {
    validate_identifier(artifact_id, MAX_ARTIFACT_ID_BYTES, "critique artifact id")?;
    let mut out = critique_branch_prefix(branch_job);
    out.extend_from_slice(&(artifact_id.len() as u16).to_be_bytes());
    out.extend_from_slice(artifact_id.as_bytes());
    Ok(out)
}

fn validate_catalog(catalog: &LensCatalog) -> Result<()> {
    if catalog.schema_version != CRITIC_LENS_CATALOG_SCHEMA_VERSION {
        return Err(invalid_critic_config(
            "unsupported critic lens catalog schema_version",
        ));
    }
    if catalog.lenses.is_empty() || catalog.lenses.len() > MAX_CATALOG_LENSES {
        return Err(invalid_critic_config(
            "critic lens catalog must contain 1..=64 lenses",
        ));
    }
    let mut seen = BTreeSet::new();
    for lens in &catalog.lenses {
        validate_lens(lens)?;
        if !seen.insert((lens.domain.as_str(), lens.id.as_str())) {
            return Err(invalid_critic_config(
                "critic lens catalog contains duplicate domain/id",
            ));
        }
    }
    Ok(())
}

fn validate_lens(lens: &CriticLens) -> Result<()> {
    validate_identifier(&lens.id, MAX_ID_BYTES, "lens id")?;
    validate_identifier(&lens.domain, MAX_DOMAIN_BYTES, "domain")?;
    validate_text(&lens.prompt_contract, MAX_CONTRACT_BYTES, "prompt_contract")?;
    validate_text(
        &lens.output_schema,
        MAX_OUTPUT_SCHEMA_BYTES,
        "output_schema",
    )?;
    Ok(())
}

fn validate_critique_artifact(artifact: &CritiqueArtifact) -> Result<()> {
    if artifact.schema_version != CRITIQUE_ARTIFACT_SCHEMA_VERSION {
        return Err(invalid_critic_config(
            "unsupported critique artifact schema_version",
        ));
    }
    validate_identifier(
        &artifact.artifact_id,
        MAX_ARTIFACT_ID_BYTES,
        "critique artifact id",
    )?;
    validate_text(&artifact.run_id, MAX_RUN_ID_BYTES, "run_id")?;
    validate_text(
        &artifact.candidate_ref,
        MAX_CANDIDATE_REF_BYTES,
        "candidate_ref",
    )?;
    validate_identifier(&artifact.lens_id, MAX_ID_BYTES, "lens id")?;
    validate_identifier(&artifact.domain, MAX_DOMAIN_BYTES, "domain")?;
    validate_provenance(&artifact.provenance)?;
    if artifact.evidence_refs.len() > MAX_EVIDENCE_REFS {
        return Err(invalid_critic_config(
            "critique evidence_refs exceeds 64 entries",
        ));
    }
    for evidence_ref in &artifact.evidence_refs {
        validate_text(evidence_ref, MAX_EVIDENCE_REF_BYTES, "evidence_ref")?;
    }
    if let Some(suggested_edit) = &artifact.suggested_edit {
        validate_text(suggested_edit, MAX_SUGGESTED_EDIT_BYTES, "suggested_edit")?;
    }
    Ok(())
}

fn validate_provenance(provenance: &CritiqueProvenance) -> Result<()> {
    validate_text(
        &provenance.critic_ref,
        MAX_PROVENANCE_REF_BYTES,
        "critic_ref",
    )?;
    validate_text(&provenance.model_id, MAX_PROVENANCE_REF_BYTES, "model_id")?;
    if let Some(model_revision) = &provenance.model_revision {
        validate_text(model_revision, MAX_PROVENANCE_REF_BYTES, "model_revision")?;
    }
    Ok(())
}

fn validate_reliability_table(reliabilities: &[CriticReliability]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for reliability in reliabilities {
        validate_reliability(reliability)?;
        if !seen.insert((reliability.domain.as_str(), reliability.lens_id.as_str())) {
            return Err(invalid_critic_config(
                "critic reliability table contains duplicate domain/id",
            ));
        }
    }
    Ok(())
}

fn validate_reliability(reliability: &CriticReliability) -> Result<()> {
    validate_identifier(&reliability.lens_id, MAX_ID_BYTES, "lens id")?;
    validate_identifier(&reliability.domain, MAX_DOMAIN_BYTES, "domain")?;
    if !reliability.alpha.is_finite()
        || !reliability.beta.is_finite()
        || reliability.alpha <= 0.0
        || reliability.beta <= 0.0
    {
        return Err(invalid_critic_config(
            "critic reliability alpha/beta must be finite and positive",
        ));
    }
    Ok(())
}

fn validate_identifier(text: &str, max_bytes: usize, field: &'static str) -> Result<()> {
    validate_text(text, max_bytes, field)?;
    let mut bytes = text.bytes();
    let Some(first) = bytes.next() else {
        return Err(invalid_critic_config(format!("{field} must not be empty")));
    };
    if !first.is_ascii_lowercase() {
        return Err(invalid_critic_config(format!(
            "{field} must start with an ASCII lowercase letter"
        )));
    }
    if !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_') {
        return Err(invalid_critic_config(format!(
            "{field} must contain only ASCII lowercase letters, digits, or underscores"
        )));
    }
    Ok(())
}

fn validate_text(text: &str, max_bytes: usize, field: &'static str) -> Result<()> {
    if text.is_empty() {
        return Err(invalid_critic_config(format!("{field} must not be empty")));
    }
    if text.len() > max_bytes {
        return Err(invalid_critic_config(format!(
            "{field} exceeds {max_bytes} bytes"
        )));
    }
    Ok(())
}

fn invalid_critic_config(message: impl Into<String>) -> Error {
    Error::InvalidConfig(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ENTITY_TYPE_CLAIM, HnswConfig, TextAnalyzerConfig, TimeRange, VaultConfig};

    fn test_config() -> VaultConfig {
        let mut config = VaultConfig::device();
        config.map_size = 16 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = Some("test-model-v1".to_owned());
        config.max_readers = 16;
        config.hnsw = HnswConfig::default();
        config.text_analyzer = TextAnalyzerConfig::default();
        config
    }

    fn open_vault() -> (tempfile::TempDir, Vault) {
        crate::test_util::open_test_vault_with(test_config())
    }

    fn provenance() -> CritiqueProvenance {
        CritiqueProvenance::new("critic_groundedness", "model-a", Some("rev1".to_owned()))
            .expect("valid provenance")
    }

    fn critique(
        artifact_id: &str,
        lens: &CriticLens,
        verdict: CritiqueVerdict,
        severity: CritiqueSeverity,
        hard_check_passed: Option<bool>,
    ) -> CritiqueArtifact {
        CritiqueArtifact::new(
            artifact_id,
            "run-a",
            JobId::now(),
            "candidate-a",
            lens,
            provenance(),
            verdict,
            severity,
            hard_check_passed,
            vec!["evidence:1".to_owned()],
            Some("tighten scope".to_owned()),
            10,
        )
        .expect("valid critique")
    }

    #[test]
    fn of366_seed_catalog_loads_as_data() -> Result<()> {
        let catalog = LensCatalog::of366_seed()?;
        let ids = catalog
            .lenses
            .iter()
            .map(|lens| lens.id.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            ids,
            vec!["groundedness", "overreach", "temporal", "redundancy"]
        );
        assert!(
            catalog
                .lens("groundedness", "claim_authoring")
                .expect("seed lens")
                .hard_check
        );
        Ok(())
    }

    #[test]
    fn hard_check_failure_vetoes_to_discard() -> Result<()> {
        let catalog = LensCatalog::of366_seed()?;
        let groundedness = catalog.lens("groundedness", "claim_authoring").unwrap();
        let overreach = catalog.lens("overreach", "claim_authoring").unwrap();
        let critiques = vec![
            critique(
                "groundedness_fail",
                groundedness,
                CritiqueVerdict::Revise,
                CritiqueSeverity::Blocking,
                Some(false),
            ),
            critique(
                "overreach_accept",
                overreach,
                CritiqueVerdict::Accept,
                CritiqueSeverity::Info,
                None,
            ),
        ];

        let triage = triage_critiques(&catalog, &critiques, &[])?;

        assert_eq!(triage.verdict, CritiqueVerdict::Discard);
        assert_eq!(triage.hard_veto_artifact_ids, vec!["groundedness_fail"]);
        Ok(())
    }

    #[test]
    fn hard_check_missing_status_vetoes_to_discard() -> Result<()> {
        let catalog = LensCatalog::of366_seed()?;
        let groundedness = catalog.lens("groundedness", "claim_authoring").unwrap();
        let critiques = vec![critique(
            "groundedness_missing_status",
            groundedness,
            CritiqueVerdict::Accept,
            CritiqueSeverity::Info,
            None,
        )];

        let triage = triage_critiques(&catalog, &critiques, &[])?;

        assert_eq!(triage.verdict, CritiqueVerdict::Discard);
        assert_eq!(
            triage.hard_veto_artifact_ids,
            vec!["groundedness_missing_status"]
        );
        assert_eq!(
            triage.acted_on_artifact_ids,
            vec!["groundedness_missing_status"]
        );
        Ok(())
    }

    #[test]
    fn beta_weighted_soft_aggregation_uses_ucb_for_cold_lens() -> Result<()> {
        let catalog = LensCatalog::of366_seed()?;
        let overreach = catalog.lens("overreach", "claim_authoring").unwrap();
        let temporal = catalog.lens("temporal", "claim_authoring").unwrap();
        let critiques = vec![
            critique(
                "trusted_accept",
                overreach,
                CritiqueVerdict::Accept,
                CritiqueSeverity::Medium,
                None,
            ),
            critique(
                "cold_revise",
                temporal,
                CritiqueVerdict::Revise,
                CritiqueSeverity::High,
                None,
            ),
        ];
        let reliabilities = vec![CriticReliability::new(
            "overreach",
            "claim_authoring",
            19.0,
            1.0,
            20,
        )?];

        let triage = triage_critiques_with_exploration(&catalog, &critiques, &reliabilities, 0.75)?;

        assert_eq!(triage.verdict, CritiqueVerdict::Revise);
        assert!(triage.scores.revise > triage.scores.accept);
        assert_eq!(triage.acted_on_artifact_ids, vec!["cold_revise"]);
        Ok(())
    }

    #[test]
    fn soft_triage_accept_wins_when_accept_score_is_highest() -> Result<()> {
        let catalog = LensCatalog::of366_seed()?;
        let overreach = catalog.lens("overreach", "claim_authoring").unwrap();
        let temporal = catalog.lens("temporal", "claim_authoring").unwrap();
        let critiques = vec![
            critique(
                "trusted_accept",
                overreach,
                CritiqueVerdict::Accept,
                CritiqueSeverity::Info,
                None,
            ),
            critique(
                "weak_revise",
                temporal,
                CritiqueVerdict::Revise,
                CritiqueSeverity::Info,
                None,
            ),
        ];
        let reliabilities = vec![
            CriticReliability::new("overreach", "claim_authoring", 20.0, 1.0, 21)?,
            CriticReliability::new("temporal", "claim_authoring", 1.0, 20.0, 21)?,
        ];

        let triage = triage_critiques_with_exploration(&catalog, &critiques, &reliabilities, 0.0)?;

        assert_eq!(triage.verdict, CritiqueVerdict::Accept);
        assert!(triage.scores.accept > triage.scores.revise);
        Ok(())
    }

    #[test]
    fn reliability_updates_require_anchored_outcomes() -> Result<()> {
        let mut reliability = CriticReliability::prior("groundedness", "claim_authoring")?;
        let rejected = ReliabilityOutcomeEvent::new(
            "groundedness",
            "claim_authoring",
            ReliabilityOutcomeSource::CriticAgreement,
            true,
            10,
        )?;

        assert!(reliability.apply_outcome(rejected).is_err());
        assert_eq!(reliability.alpha, 1.0);
        assert_eq!(reliability.beta, 1.0);
        assert_eq!(reliability.observations, 0);

        reliability.apply_outcome(ReliabilityOutcomeEvent::new(
            "groundedness",
            "claim_authoring",
            ReliabilityOutcomeSource::Beam,
            false,
            11,
        )?)?;
        assert_eq!(reliability.alpha, 1.0);
        assert_eq!(reliability.beta, 2.0);
        assert_eq!(reliability.observations, 1);
        Ok(())
    }

    #[test]
    fn critique_artifacts_persist_branch_local_and_not_as_claims() -> Result<()> {
        let (_dir, vault) = open_vault();
        let catalog = LensCatalog::of366_seed()?;
        let lens = catalog.lens("groundedness", "claim_authoring").unwrap();
        let branch_job = JobId::now();
        let mut artifact = critique(
            "groundedness_ok",
            lens,
            CritiqueVerdict::Accept,
            CritiqueSeverity::Info,
            Some(true),
        );
        artifact.branch_job = branch_job;
        let before_claims = vault.count_entities_by_type(ENTITY_TYPE_CLAIM)?;

        let store = CritiqueArtifactStore::new(&vault);
        store.put(&artifact)?;

        assert_eq!(
            store.get(branch_job, "groundedness_ok")?,
            Some(artifact.clone())
        );
        assert_eq!(store.list_branch(branch_job)?, vec![artifact]);
        assert_eq!(
            vault.count_entities_by_type(ENTITY_TYPE_CLAIM)?,
            before_claims
        );
        Ok(())
    }

    #[test]
    fn out_of_scope_critique_artifacts_are_not_persisted() -> Result<()> {
        let (_dir, vault) = open_vault();
        let catalog = LensCatalog::of366_seed()?;
        let lens = catalog.lens("overreach", "claim_authoring").unwrap();
        let branch_job = JobId::now();
        let mut artifact = critique(
            "overreach_out_of_scope",
            lens,
            CritiqueVerdict::Revise,
            CritiqueSeverity::High,
            None,
        );
        artifact.branch_job = branch_job;
        artifact.out_of_scope = true;

        let store = CritiqueArtifactStore::new(&vault);
        store.put(&artifact)?;

        assert_eq!(store.get(branch_job, "overreach_out_of_scope")?, None);
        assert!(store.list_branch(branch_job)?.is_empty());
        Ok(())
    }

    #[test]
    fn two_candidate_four_lens_fixture_triages_independently() -> Result<()> {
        let catalog = LensCatalog::of366_seed()?;
        let reliability = catalog
            .lenses
            .iter()
            .map(|lens| CriticReliability::new(&lens.id, &lens.domain, 4.0, 2.0, 6))
            .collect::<Result<Vec<_>>>()?;

        let candidate_a = catalog
            .lenses
            .iter()
            .map(|lens| {
                critique(
                    &format!("candidate_a_{}", lens.id),
                    lens,
                    CritiqueVerdict::Accept,
                    CritiqueSeverity::Info,
                    lens.hard_check.then_some(true),
                )
            })
            .collect::<Vec<_>>();
        let candidate_b = catalog
            .lenses
            .iter()
            .map(|lens| {
                let verdict = if lens.id == "overreach" || lens.id == "temporal" {
                    CritiqueVerdict::Revise
                } else {
                    CritiqueVerdict::Accept
                };
                critique(
                    &format!("candidate_b_{}", lens.id),
                    lens,
                    verdict,
                    CritiqueSeverity::High,
                    lens.hard_check.then_some(true),
                )
            })
            .collect::<Vec<_>>();

        let triage_a = triage_critiques(&catalog, &candidate_a, &reliability)?;
        let triage_b = triage_critiques(&catalog, &candidate_b, &reliability)?;

        assert_eq!(triage_a.verdict, CritiqueVerdict::Accept);
        assert_eq!(triage_b.verdict, CritiqueVerdict::Revise);
        assert_eq!(triage_a.acted_on_artifact_ids, Vec::<String>::new());
        assert_eq!(
            triage_b.acted_on_artifact_ids,
            vec!["candidate_b_overreach", "candidate_b_temporal"]
        );
        Ok(())
    }

    #[test]
    fn reliability_claim_family_is_structured_under_critic_reliability() -> Result<()> {
        let subject = EntityId::now();
        let reliability = CriticReliability::new("temporal", "claim_authoring", 3.0, 1.0, 4)?;
        let body = critic_reliability_claim_body(subject, &reliability, 0.9)?;

        assert_eq!(
            body.predicate,
            "critic_reliability.claim_authoring.temporal"
        );
        assert_eq!(body.subject, ClaimSubject::Entity(subject));
        assert_eq!(body.approval, ClaimApprovalStatus::Auto);
        assert_eq!(body.lifecycle, ClaimLifecycleStatus::Active);
        assert_eq!(body.confidence, 0.9);

        let (_dir, vault) = open_vault();
        let anchor = EntityId::now();
        vault.put_entity(
            &anchor,
            crate::types::ENTITY_TYPE_TASK,
            TimeRange { start: 1, end: 1 },
            1,
            b"anchor",
        )?;
        let mut writable = body;
        writable.subject = ClaimSubject::Entity(anchor);
        vault.put_claim(
            &EntityId::now(),
            &writable,
            TimeRange { start: 2, end: 2 },
            2,
        )?;
        Ok(())
    }

    #[test]
    fn critic_reliability_predicate_rejects_claim_predicate_overflow() {
        let domain = "d".repeat(MAX_DOMAIN_BYTES);
        let lens_id = "l".repeat(MAX_ID_BYTES);

        assert!(critic_reliability_predicate(&domain, &lens_id).is_err());
    }
}
