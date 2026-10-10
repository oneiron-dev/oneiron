//! Shared JSON-schema fragments: actors, scopes, consent, and envelope pieces.

use super::tool_catalog::{ENTITY_ID_PATTERN, MCP_SCHEMA_DRAFT, MCP_TOOL_ARGS_SCHEMA_VERSION};
use serde_json::Value;
use serde_json::json;

pub(super) fn closed_object_schema(required: &[&'static str], properties: Value) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties,
    })
}

pub(super) fn tool_schema_root(
    id: &'static str,
    properties: Value,
    required: &[&'static str],
) -> Value {
    json!({
        "$schema": MCP_SCHEMA_DRAFT,
        "$id": id,
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties,
    })
}

pub(super) fn schema_version_property() -> Value {
    json!({
        "type": "string",
        "const": MCP_TOOL_ARGS_SCHEMA_VERSION,
    })
}

pub(super) fn entity_id_schema() -> Value {
    json!({
        "type": "string",
        "pattern": ENTITY_ID_PATTERN,
    })
}

pub(super) fn nonblank_string_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "pattern": "\\S",
    })
}

fn actor_class_schema() -> Value {
    json!({
        "type": "string",
        "enum": ["human", "agent"],
    })
}

pub(super) fn actor_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["actor_ref", "actor_class", "gate_actor_class", "gate_actor_ref", "scope"],
        "oneOf": [
            {
                "properties": {
                    "actor_class": { "const": "human" },
                    "gate_actor_class": { "const": "human" },
                },
            },
            {
                "properties": {
                    "actor_class": { "const": "agent" },
                    "gate_actor_class": { "const": "agent" },
                },
            },
        ],
        "properties": {
            "actor_ref": entity_id_schema(),
            "actor_class": actor_class_schema(),
            "gate_actor_class": actor_class_schema(),
            "gate_actor_ref": entity_id_schema(),
            "scope": scope_schema(),
        },
    })
}

fn scope_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "world_ref": entity_id_schema(),
            "facet_ref": entity_id_schema(),
        },
    })
}

pub(super) fn consent_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["policy_ref", "purpose"],
        "properties": {
            "policy_ref": nonblank_string_schema(),
            "purpose": nonblank_string_schema(),
            "approval_ref": nonblank_string_schema(),
            "consent_receipt_ref": nonblank_string_schema(),
            "require_human_approval": { "type": "boolean" },
        },
    })
}
