//! Host-injected HyDE query-expansion seam.

use std::collections::BTreeMap;

use crate::{EntityId, Error, Result};

pub mod host;

pub const HYDE_MAX_SUBQUERIES: usize = 3;
pub const HYDE_RETRY_LIMIT_MULTIPLIER: usize = 2;
pub const HYDE_RETRY_MAX_LIMIT: usize = 200;

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct GroundingContext {
    pub bindings: BTreeMap<String, String>,
}

/// Expands exact, single-level `${name}` placeholders from caller bindings.
pub fn ground_query(template: &str, context: &GroundingContext) -> Result<String> {
    let mut output = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("${") {
        output.push_str(&rest[..start]);
        let placeholder = &rest[start + 2..];
        let Some(end) = placeholder.find('}') else {
            return Err(Error::InvalidConfig(
                "malformed grounding placeholder".to_owned(),
            ));
        };
        let name = &placeholder[..end];
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(Error::InvalidConfig(
                "malformed grounding placeholder".to_owned(),
            ));
        }
        let Some(value) = context.bindings.get(name) else {
            return Err(Error::InvalidConfig(format!(
                "unknown grounding binding: {name}"
            )));
        };
        if value.contains("${") {
            return Err(Error::InvalidConfig(
                "recursive grounding binding".to_owned(),
            ));
        }
        output.push_str(value);
        rest = &placeholder[end + 1..];
    }
    output.push_str(rest);
    Ok(output)
}

pub(crate) fn retry_channel_limit(limit: usize) -> usize {
    let widened = limit
        .saturating_mul(HYDE_RETRY_LIMIT_MULTIPLIER)
        .min(HYDE_RETRY_MAX_LIMIT);
    widened.max(limit)
}

pub(crate) fn normalized_subqueries(subqueries: &[String]) -> Vec<String> {
    let mut normalized = Vec::new();
    for query in subqueries {
        if !query.is_empty() && !normalized.contains(query) {
            normalized.push(query.clone());
            if normalized.len() == HYDE_MAX_SUBQUERIES {
                break;
            }
        }
    }
    normalized
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct HydeRequest {
    pub query: String,
    pub max_subqueries: usize,
}
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct HydeExpansion {
    pub grounded_query: String,
    pub hypothetical_answer: String,
    pub embedding: Vec<f32>,
    pub subqueries: Vec<String>,
}
#[derive(Debug, Clone, PartialEq)]
pub struct CompletionCandidate {
    pub id: EntityId,
    pub score: f32,
    pub claim: Option<crate::claim::ClaimBody>,
}
#[derive(Debug, Clone, PartialEq)]
pub struct CompletionRequest {
    pub query: String,
    pub candidates: Vec<CompletionCandidate>,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub enum EvidenceVerdict {
    Sufficient,
    Insufficient { gaps: Vec<String> },
}
pub trait HydeExpander: Send + Sync {
    fn id(&self) -> &str;
    fn expand(&self, request: &HydeRequest) -> Result<HydeExpansion>;
    fn assess_evidence(&self, request: &CompletionRequest) -> Result<EvidenceVerdict>;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct HydeOptions {
    pub channel_limit: usize,
    pub retry_once: bool,
}

/// The host's expansion, grounding and options, bound outside the public recall input.
pub type HydeBinding<'a> = (&'a dyn HydeExpander, &'a GroundingContext, HydeOptions);

impl HydeOptions {
    pub fn validate(&self) -> Result<()> {
        if self.channel_limit == 0 {
            return Err(Error::InvalidConfig(
                "hyde channel_limit must be greater than zero".to_owned(),
            ));
        }
        Ok(())
    }
}

/// The same vector guards for a host completion and for the retrieval that consumes it.
pub fn validate_hyde_expansion(vault: &crate::Vault, expansion: &HydeExpansion) -> Result<()> {
    if expansion.embedding.is_empty() {
        return Err(Error::InvalidConfig("hyde embedding must not be empty".to_owned()));
    }
    if expansion.embedding.len() != vault.config.dimensions
        && vault.config.fast_dims.map(usize::from) != Some(expansion.embedding.len())
    {
        return Err(Error::DimensionMismatch {
            expected: vault.config.dimensions,
            got: expansion.embedding.len(),
        });
    }
    if let Some(error) = Error::invalid_vector_component(&expansion.embedding) {
        return Err(error);
    }
    Ok(())
}
