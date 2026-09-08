//! Small field validators shared by every MCP argument type.

use super::tool_catalog::{
    MCP_TOOL_ARGS_SCHEMA_VERSION, McpToolLabel, McpToolName, McpToolValidationError,
};
use oneiron::EntityId;
use oneiron::context_pack::McpContextPackRef;

pub(super) fn validate_schema_version(
    tool: impl McpToolLabel,
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

pub(super) fn validate_context_pack(
    tool: McpToolName,
    context_pack: &McpContextPackRef,
) -> Result<(), McpToolValidationError> {
    validate_context_pack_field(tool, "context_pack", context_pack)
}

pub(super) fn validate_context_pack_field(
    tool: McpToolName,
    field: &'static str,
    context_pack: &McpContextPackRef,
) -> Result<(), McpToolValidationError> {
    context_pack
        .validate()
        .map_err(|error| McpToolValidationError::field(tool, field, error.to_string()))
}

pub(super) fn validate_optional_context_pack(
    tool: McpToolName,
    context_pack: Option<&McpContextPackRef>,
) -> Result<(), McpToolValidationError> {
    match context_pack {
        Some(context_pack) => validate_context_pack(tool, context_pack),
        None => Ok(()),
    }
}

pub(super) fn validate_nonblank(
    tool: impl McpToolLabel,
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

pub(super) fn validate_short_ref(
    tool: McpToolName,
    field: &'static str,
    reference: &str,
) -> Result<(), McpToolValidationError> {
    validate_nonblank(tool, field, reference)?;
    let Some((short_id, content_hash)) = reference.split_once(':') else {
        return Err(McpToolValidationError::field(
            tool,
            field,
            "must be in shortId:contentHashHex form",
        ));
    };
    validate_short_ref_parts(tool, field, short_id, content_hash)
}

/// Validates the two halves of a short ref against the engine's presentation-id
/// grammar (`oneiron::parse_presentation_id`), the same door
/// `api/core.rs::parse_short_ref_parts` and `memory::resolve_entity_ref` use.
///
/// Syntax only: an undeclared prefix parses here and fails at resolution, and
/// prefix LENGTH is a registry fact rather than something this validator pins.
fn validate_short_ref_parts(
    tool: McpToolName,
    field: &'static str,
    short_id: &str,
    content_hash: &str,
) -> Result<(), McpToolValidationError> {
    if oneiron::parse_presentation_id(short_id).is_err() {
        return Err(McpToolValidationError::field(
            tool,
            field,
            "short id must be at least two lowercase letters followed by decimal digits",
        ));
    }
    if content_hash.len() != 2 || !content_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(McpToolValidationError::field(
            tool,
            field,
            "content hash must be exactly two hex digits",
        ));
    }
    u8::from_str_radix(content_hash, 16)
        .map_err(|_| McpToolValidationError::field(tool, field, "content hash must be hex"))?;
    Ok(())
}

pub(super) fn validate_optional_nonblank(
    tool: impl McpToolLabel,
    field: &'static str,
    value: Option<&str>,
) -> Result<(), McpToolValidationError> {
    match value {
        Some(value) => validate_nonblank(tool, field, value),
        None => Ok(()),
    }
}

pub(super) fn validate_confidence(
    tool: impl McpToolLabel,
    field: &'static str,
    value: f32,
) -> Result<(), McpToolValidationError> {
    if value.is_finite() && (0.0..=1.0).contains(&value) {
        Ok(())
    } else {
        Err(McpToolValidationError::field(
            tool,
            field,
            "must be a finite number in 0..=1",
        ))
    }
}

pub(super) fn validate_required_entity_ref(
    tool: impl McpToolLabel,
    field: &'static str,
    value: Option<&str>,
) -> Result<(), McpToolValidationError> {
    let value = value
        .ok_or_else(|| McpToolValidationError::field(tool, field, "is required for this verb"))?;
    validate_entity_ref(tool, field, value)
}

pub(super) fn validate_optional_entity_ref(
    tool: impl McpToolLabel,
    field: &'static str,
    value: Option<&str>,
) -> Result<(), McpToolValidationError> {
    match value {
        Some(value) => validate_entity_ref(tool, field, value),
        None => Ok(()),
    }
}

pub(super) fn validate_entity_ref(
    tool: impl McpToolLabel,
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

pub(super) fn validate_absent(
    tool: impl McpToolLabel,
    field: &'static str,
    present: bool,
) -> Result<(), McpToolValidationError> {
    if present {
        Err(McpToolValidationError::field(
            tool,
            field,
            "is not valid for this verb",
        ))
    } else {
        Ok(())
    }
}
