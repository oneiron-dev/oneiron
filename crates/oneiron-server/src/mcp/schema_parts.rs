//! Shared JSON-schema fragments: actors, scopes, subjects, and envelope pieces.

use super::tool_catalog::{
    EDIT_ACTION_FIELDS, ENTITY_ID_PATTERN, MCP_SCHEMA_DRAFT, MCP_TOOL_ARGS_SCHEMA_VERSION,
    SHORT_REF_PATTERN,
};
use oneiron::context_pack::MCP_CONTEXT_PACK_REF_SCHEMA_VERSION;
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

pub(super) fn edit_forbidden_except(allowed: &[&str]) -> Value {
    let forbidden = EDIT_ACTION_FIELDS
        .iter()
        .copied()
        .filter(|field| !allowed.contains(field))
        .collect::<Vec<_>>();
    forbidden_properties_schema(&forbidden)
}

fn forbidden_properties_schema(properties: &[&str]) -> Value {
    let disallowed = properties
        .iter()
        .map(|field| json!({ "required": [field] }))
        .collect::<Vec<_>>();
    json!({ "anyOf": disallowed })
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

fn short_ref_schema() -> Value {
    json!({
        "type": "string",
        "pattern": SHORT_REF_PATTERN,
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

pub(super) fn context_pack_ref_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["schema_version"],
        "anyOf": [
            { "required": ["pack_ref"] },
            { "required": ["retrieval_run_id"] },
            {
                "required": ["result_ids"],
                "properties": {
                    "result_ids": { "minItems": 1 },
                },
            },
        ],
        "properties": {
            "schema_version": {
                "type": "string",
                "const": MCP_CONTEXT_PACK_REF_SCHEMA_VERSION,
            },
            "context_version": nonblank_string_schema(),
            "pack_ref": nonblank_string_schema(),
            "retrieval_run_id": nonblank_string_schema(),
            "result_ids": {
                "type": "array",
                "items": entity_id_schema(),
            },
            "budget_ref": nonblank_string_schema(),
        },
    })
}

pub(super) fn read_target_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "oneOf": [
            { "required": ["entity_ref"] },
            { "required": ["short_ref"] },
            { "required": ["context_pack"] },
        ],
        "properties": {
            "entity_ref": entity_id_schema(),
            "short_ref": short_ref_schema(),
            "context_pack": context_pack_ref_schema(),
        },
    })
}

pub(super) fn edit_subject_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "oneOf": [
            { "required": ["entity"] },
            { "required": ["edge"] },
        ],
        "properties": {
            "entity": entity_id_schema(),
            "edge": edit_edge_subject_schema(),
        },
    })
}

pub(super) fn edit_provenance_subject_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["edge"],
        "properties": {
            "edge": edit_provenance_edge_subject_schema(),
        },
    })
}

fn edit_edge_subject_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["source", "kind", "target"],
        "properties": {
            "source": entity_id_schema(),
            "kind": { "type": "integer", "minimum": 0, "maximum": 19 },
            "target": entity_id_schema(),
        },
    })
}

fn edit_provenance_edge_subject_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["source", "kind", "target"],
        "properties": {
            "source": entity_id_schema(),
            "kind": { "type": "integer", "minimum": 9, "maximum": 19 },
            "target": entity_id_schema(),
        },
    })
}

pub(super) fn occurred_range_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["start", "end"],
        "properties": {
            "start": { "type": "integer", "minimum": 0, "maximum": u64::MAX },
            "end": { "type": "integer", "minimum": 0, "maximum": u64::MAX },
        },
    })
}

pub(super) fn ask_effort_schema() -> Value {
    json!({
        "type": "string",
        "enum": ["minimal", "standard", "deep"],
    })
}

pub(super) fn citation_mode_schema() -> Value {
    json!({
        "type": "string",
        "enum": ["claim_refs", "claim_refs_and_spans"],
    })
}

pub(super) fn ask_route_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["model_tier"],
        "properties": {
            "model_tier": nonblank_string_schema(),
            "model_id": nonblank_string_schema(),
            "substrate_ref": nonblank_string_schema(),
            "reasoning_effort": ask_effort_schema(),
            "max_latency_ms": { "type": "integer", "minimum": 1, "maximum": u32::MAX },
        },
    })
}
