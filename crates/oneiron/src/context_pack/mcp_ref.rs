//! MCP protocol reference to a context pack, plus its validation.
//!
//! Protocol boundary only: consumed by `oneiron-server`'s MCP surface, not by
//! pack assembly. Assembly lives in [`super::builder`].

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;

pub const MCP_CONTEXT_PACK_REF_SCHEMA_VERSION: &str = "context_pack_ref.v1";

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpContextPackRef {
    pub schema_version: String,
    #[serde(default)]
    pub context_version: Option<String>,
    #[serde(default)]
    pub pack_ref: Option<String>,
    #[serde(default)]
    pub retrieval_run_id: Option<String>,
    #[serde(default)]
    pub result_ids: Vec<String>,
    #[serde(default)]
    pub budget_ref: Option<String>,
}

impl McpContextPackRef {
    pub fn validate(&self) -> std::result::Result<(), McpContextPackRefError> {
        if self.schema_version != MCP_CONTEXT_PACK_REF_SCHEMA_VERSION {
            return Err(McpContextPackRefError::UnsupportedSchemaVersion);
        }
        validate_optional_context_pack_ref_field(
            "context_version",
            self.context_version.as_deref(),
        )?;
        validate_optional_context_pack_ref_field("pack_ref", self.pack_ref.as_deref())?;
        validate_optional_context_pack_ref_field(
            "retrieval_run_id",
            self.retrieval_run_id.as_deref(),
        )?;
        validate_optional_context_pack_ref_field("budget_ref", self.budget_ref.as_deref())?;
        if self.pack_ref.is_none() && self.retrieval_run_id.is_none() && self.result_ids.is_empty()
        {
            return Err(McpContextPackRefError::MissingHandle);
        }
        for result_id in &self.result_ids {
            validate_context_pack_result_id(result_id)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
pub enum McpContextPackRefError {
    #[error("unsupported context-pack reference schema version")]
    UnsupportedSchemaVersion,
    #[error("context-pack reference requires pack_ref, retrieval_run_id, or result_ids")]
    MissingHandle,
    #[error("{0} must not be blank")]
    BlankField(&'static str),
    #[error("result_ids entries must be canonical entity ids")]
    InvalidResultId,
}

fn validate_optional_context_pack_ref_field(
    field: &'static str,
    value: Option<&str>,
) -> std::result::Result<(), McpContextPackRefError> {
    if value.is_some_and(|value| value.trim().is_empty()) {
        return Err(McpContextPackRefError::BlankField(field));
    }
    Ok(())
}

fn validate_context_pack_result_id(
    result_id: &str,
) -> std::result::Result<(), McpContextPackRefError> {
    let parsed =
        EntityId::from_hex(result_id).map_err(|_| McpContextPackRefError::InvalidResultId)?;
    if parsed.to_hex() != result_id {
        return Err(McpContextPackRefError::InvalidResultId);
    }
    Ok(())
}
