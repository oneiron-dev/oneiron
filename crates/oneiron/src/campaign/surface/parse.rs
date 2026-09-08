//! Request-body decoders and field-error helpers for the dispatch door.

use serde_json::Value;

use super::{
    CAMPAIGN_SCHEMA_VERSION, CreateCampaignRequest, MembershipReadRequest, UpdateCampaignRequest,
};
use crate::EntityId;
use crate::error::Error;
use crate::memory::{MemoryError, MemoryResult};
use crate::saved_query::{
    CreateSavedQueryRequest, EvalMode, EvalPolicy, FilterAst, MatcherSpec, QueryScope,
    SAVED_QUERY_SCHEMA_VERSION, UpdateSavedQueryRequest, parse_filter_ast,
};

pub(super) fn parse_create_campaign_request(body: &Value) -> MemoryResult<CreateCampaignRequest> {
    Ok(CreateCampaignRequest {
        schema_version: optional_u32(body, "schema_version")?.unwrap_or(CAMPAIGN_SCHEMA_VERSION),
        name: required_string(body, "name")?,
    })
}

pub(super) fn parse_update_campaign_request(body: &Value) -> MemoryResult<UpdateCampaignRequest> {
    Ok(UpdateCampaignRequest {
        expected_definition_version: required_u64(body, "expected_definition_version")?,
        name: required_string(body, "name")?,
    })
}

pub(super) fn parse_create_saved_query_request(
    body: &Value,
) -> MemoryResult<CreateSavedQueryRequest> {
    Ok(CreateSavedQueryRequest {
        schema_version: optional_u32(body, "schema_version")?.unwrap_or(SAVED_QUERY_SCHEMA_VERSION),
        scope: parse_scope(body)?,
        filter: parse_filter(body)?,
        matcher: parse_matcher(body)?,
        eval: parse_eval(body)?,
    })
}

pub(super) fn parse_update_saved_query_request(
    body: &Value,
) -> MemoryResult<UpdateSavedQueryRequest> {
    Ok(UpdateSavedQueryRequest {
        expected_definition_version: required_u64(body, "expected_definition_version")?,
        scope: parse_scope(body)?,
        filter: parse_filter(body)?,
        matcher: parse_matcher(body)?,
        eval: parse_eval(body)?,
    })
}

pub(super) fn parse_membership_request(
    body: &Value,
    ref_field: &str,
) -> MemoryResult<MembershipReadRequest> {
    Ok(MembershipReadRequest {
        owner_ref: required_entity_ref(body, ref_field)?,
        cursor: match body.get("cursor") {
            None | Some(Value::Null) => None,
            Some(value) => Some(
                value
                    .as_str()
                    .ok_or_else(|| field_error("cursor", "must be a string"))?
                    .to_owned(),
            ),
        },
        limit: optional_u32(body, "limit")?.unwrap_or(0),
        at_epoch: optional_u64(body, "at_epoch")?,
    })
}

pub(super) fn parse_scope(body: &Value) -> MemoryResult<QueryScope> {
    let Some(raw) = body.get("scope").filter(|value| !value.is_null()) else {
        return Ok(QueryScope::default());
    };
    // An empty axis means UNRESTRICTED in [`QueryScope`], so a non-object scope
    // cannot be read as "no fields present": `"scope": "sales"` would silently
    // widen the query to every world and facet instead of being refused.
    if !raw.is_object() {
        return Err(field_error("scope", "must be an object"));
    }
    let worlds = match raw.get("worlds") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .and_then(|hex| EntityId::from_hex(hex).ok())
                    .ok_or_else(|| field_error("scope.worlds", "must be 32-hex entity ids"))
            })
            .collect::<MemoryResult<Vec<_>>>()?,
        Some(_) => return Err(field_error("scope.worlds", "must be an array")),
    };
    let facets = match raw.get("facets") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| field_error("scope.facets", "must be strings"))
            })
            .collect::<MemoryResult<Vec<_>>>()?,
        Some(_) => return Err(field_error("scope.facets", "must be an array")),
    };
    Ok(QueryScope { worlds, facets })
}

/// Parses a stage-1 filter through CA-02's own door.
///
/// [`parse_filter_ast`] is the only place ranked and global-relative operators
/// are named and refused, so routing through it is what keeps a `top_k` filter
/// from entering by the SDK when it cannot enter by the engine.
fn parse_filter(body: &Value) -> MemoryResult<FilterAst> {
    let raw = body
        .get("filter")
        .ok_or_else(|| field_error("filter", "is required"))?;
    Ok(parse_filter_ast(raw)?)
}

fn parse_matcher(body: &Value) -> MemoryResult<MatcherSpec> {
    let raw = body
        .get("matcher")
        .ok_or_else(|| field_error("matcher", "is required"))?;
    let kind = raw
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| field_error("matcher.kind", "is required"))?;
    match kind {
        "hard" => Ok(MatcherSpec::Hard {
            expression: parse_filter_ast(
                raw.get("expression")
                    .ok_or_else(|| field_error("matcher.expression", "is required"))?,
            )?,
        }),
        "semantic_threshold" => Ok(MatcherSpec::SemanticThreshold {
            exemplar_ref: raw
                .get("exemplar_ref")
                .and_then(Value::as_str)
                .and_then(|hex| EntityId::from_hex(hex).ok())
                .ok_or_else(|| field_error("matcher.exemplar_ref", "must be a 32-hex entity id"))?,
            minimum_similarity_micros: raw
                .get("minimum_similarity_micros")
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| field_error("matcher.minimum_similarity_micros", "must be a u32"))?,
        }),
        "llm_judge" => Ok(MatcherSpec::LlmJudge {
            model_id: raw
                .get("model_id")
                .and_then(Value::as_str)
                .ok_or_else(|| field_error("matcher.model_id", "is required"))?
                .to_owned(),
            rubric: raw.get("rubric").cloned().unwrap_or(Value::Null),
            rubric_version: raw
                .get("rubric_version")
                .and_then(Value::as_str)
                .ok_or_else(|| field_error("matcher.rubric_version", "is required"))?
                .to_owned(),
        }),
        other => Err(field_error(
            "matcher.kind",
            &format!("{other:?} is not one of hard, semantic_threshold, llm_judge"),
        )),
    }
}

fn parse_eval(body: &Value) -> MemoryResult<EvalPolicy> {
    let raw = body
        .get("eval")
        .ok_or_else(|| field_error("eval", "is required"))?;
    Ok(EvalPolicy {
        mode: raw
            .get("mode")
            .and_then(Value::as_str)
            .and_then(EvalMode::parse)
            .ok_or_else(|| field_error("eval.mode", "must be reactive, wake, or manual"))?,
        max_entities_per_wake: required_u32(raw, "max_entities_per_wake")?,
        max_judges_per_wake: required_u32(raw, "max_judges_per_wake")?,
    })
}

pub(super) fn required_entity_ref(body: &Value, field: &str) -> MemoryResult<EntityId> {
    body.get(field)
        .and_then(Value::as_str)
        .and_then(|hex| EntityId::from_hex(hex).ok())
        .ok_or_else(|| field_error(field, "must be a 32-character hex entity id"))
}

fn required_string(body: &Value, field: &str) -> MemoryResult<String> {
    body.get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| field_error(field, "must be a string"))
}

pub(super) fn required_u64(body: &Value, field: &str) -> MemoryResult<u64> {
    body.get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| field_error(field, "must be a non-negative integer"))
}

fn required_u32(body: &Value, field: &str) -> MemoryResult<u32> {
    required_u64(body, field)?
        .try_into()
        .map_err(|_| field_error(field, "must fit in a u32"))
}

fn optional_u64(body: &Value, field: &str) -> MemoryResult<Option<u64>> {
    match body.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| field_error(field, "must be a non-negative integer")),
    }
}

fn optional_u32(body: &Value, field: &str) -> MemoryResult<Option<u32>> {
    optional_u64(body, field)?
        .map(|value| u32::try_from(value).map_err(|_| field_error(field, "must fit in a u32")))
        .transpose()
}

fn field_error(field: &str, requirement: &str) -> MemoryError {
    MemoryError::bad_request(format!("campaign surface field {field} {requirement}"))
}

pub(super) fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.to_owned())
}
