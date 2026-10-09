//! Small field validators shared by every MCP argument type.

use super::tool_catalog::{MCP_TOOL_ARGS_SCHEMA_VERSION, McpToolValidationError};
use oneiron::EntityId;

pub(super) fn validate_schema_version(
    tool: &'static str,
    version: &str,
) -> Result<(), McpToolValidationError> {
    if version == MCP_TOOL_ARGS_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(McpToolValidationError::field(
            tool,
            "schema_version",
            format!("must be {MCP_TOOL_ARGS_SCHEMA_VERSION}"),
        ))
    }
}

pub(super) fn validate_nonblank(
    tool: &'static str,
    field: &'static str,
    value: &str,
) -> Result<(), McpToolValidationError> {
    if value.trim().is_empty() {
        Err(McpToolValidationError::field(
            tool,
            field,
            "must not be blank",
        ))
    } else {
        Ok(())
    }
}

pub(super) fn validate_optional_nonblank(
    tool: &'static str,
    field: &'static str,
    value: Option<&str>,
) -> Result<(), McpToolValidationError> {
    match value {
        Some(value) => validate_nonblank(tool, field, value),
        None => Ok(()),
    }
}

pub(super) fn validate_optional_entity_ref(
    tool: &'static str,
    field: &'static str,
    value: Option<&str>,
) -> Result<(), McpToolValidationError> {
    match value {
        Some(value) => validate_entity_ref(tool, field, value),
        None => Ok(()),
    }
}

pub(super) fn validate_entity_ref(
    tool: &'static str,
    field: &'static str,
    value: &str,
) -> Result<(), McpToolValidationError> {
    let parsed = EntityId::from_hex(value).map_err(|_| {
        McpToolValidationError::field(tool, field, "must be a canonical 32-character entity id")
    })?;
    if parsed.to_hex() == value {
        Ok(())
    } else {
        Err(McpToolValidationError::field(
            tool,
            field,
            "must be a canonical 32-character entity id",
        ))
    }
}
