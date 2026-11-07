//! Bounds and shape checks for critic lenses, artifacts and learned reliability.
use super::*;

pub(super) use crate::store::critic_lens::{validate_catalog, validate_lens};

pub(super) fn validate_critique_artifact(artifact: &CritiqueArtifact) -> Result<()> {
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
    artifact.calibration.validate()?;
    if artifact.calibration.predicate != LearningPredicate::Reliability
        || artifact.calibration.executor.as_deref()
            != Some(artifact.provenance.executor()?.as_str())
    {
        return Err(invalid_critic_config(
            "critique calibration must name its executor",
        ));
    }
    if let Some(prediction) = &artifact.prediction {
        prediction.validate(artifact.created_at)?;
    }
    // Every ref a critique cites is kept and checked; their count refuses
    // nothing (FIX 9939).
    for evidence_ref in &artifact.evidence_refs {
        validate_text(evidence_ref, MAX_EVIDENCE_REF_BYTES, "evidence_ref")?;
    }
    if let Some(suggested_edit) = &artifact.suggested_edit {
        validate_text(suggested_edit, MAX_SUGGESTED_EDIT_BYTES, "suggested_edit")?;
    }
    Ok(())
}

pub(super) fn validate_provenance(provenance: &CritiqueProvenance) -> Result<()> {
    validate_text(
        &provenance.critic_ref,
        MAX_PROVENANCE_REF_BYTES,
        "critic_ref",
    )?;
    // An erased critic's opaque ref names no actor (FIX 4477); a live one must.
    if !provenance.is_erased() {
        provenance.actor()?;
    }
    provenance.executor()?;
    validate_text(&provenance.model_id, MAX_PROVENANCE_REF_BYTES, "model_id")?;
    if let Some(model_revision) = &provenance.model_revision {
        validate_text(model_revision, MAX_PROVENANCE_REF_BYTES, "model_revision")?;
    }
    Ok(())
}

pub(super) fn validate_reliability_table(reliabilities: &[CriticReliability]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for reliability in reliabilities {
        validate_reliability(reliability)?;
        if !seen.insert(reliability.cell.digest()) {
            return Err(invalid_critic_config(
                "critic reliability table contains duplicate cells",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_reliability(reliability: &CriticReliability) -> Result<()> {
    reliability.cell.validate()?;
    reliability.estimate.validate()?;
    if reliability.cell.predicate != LearningPredicate::Reliability
        || reliability.estimate.form() != crate::learning::EstimateForm::Beta
    {
        return Err(invalid_critic_config(
            "critic weight requires learning.reliability in Beta form",
        ));
    }
    Ok(())
}

use crate::store::critic_lens::validate_text;
pub(super) use crate::store::critic_lens::{invalid_critic_config, validate_identifier};
