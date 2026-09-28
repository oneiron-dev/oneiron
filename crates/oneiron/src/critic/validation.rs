//! Bounds and shape checks for critic lenses, artifacts and learned reliability.
use super::*;

pub(super) fn validate_catalog(catalog: &LensCatalog) -> Result<()> {
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

pub(super) fn validate_lens(lens: &CriticLens) -> Result<()> {
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

pub(super) fn validate_provenance(provenance: &CritiqueProvenance) -> Result<()> {
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

pub(super) fn validate_reliability_table(reliabilities: &[CriticReliability]) -> Result<()> {
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

pub(super) fn validate_reliability(reliability: &CriticReliability) -> Result<()> {
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

pub(super) fn validate_identifier(text: &str, max_bytes: usize, field: &'static str) -> Result<()> {
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

pub(super) fn invalid_critic_config(message: impl Into<String>) -> Error {
    Error::InvalidConfig(message.into())
}
