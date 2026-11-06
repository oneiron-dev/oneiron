//! Critic lens catalogue vocabulary, seed catalogue and pure shape checks.

use oneiron_base::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const CRITIC_LENS_CATALOG_SCHEMA_VERSION: u64 = 1;
pub const MAX_CATALOG_LENSES: usize = 64;
pub const MAX_ID_BYTES: usize = 64;
pub const MAX_DOMAIN_BYTES: usize = 64;
pub const MAX_CONTRACT_BYTES: usize = 4096;
pub const MAX_OUTPUT_SCHEMA_BYTES: usize = 4096;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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

pub fn validate_catalog(catalog: &LensCatalog) -> Result<()> {
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

pub fn validate_lens(lens: &CriticLens) -> Result<()> {
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

pub fn validate_identifier(text: &str, max_bytes: usize, field: &'static str) -> Result<()> {
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

pub fn validate_text(text: &str, max_bytes: usize, field: &'static str) -> Result<()> {
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

pub fn invalid_critic_config(message: impl Into<String>) -> Error {
    Error::InvalidConfig(message.into())
}
