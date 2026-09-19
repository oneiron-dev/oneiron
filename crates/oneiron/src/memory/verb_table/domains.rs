//! Typed wire adapters for campaign and saved-query Memory operations.
//! Domain parsing and authorization remain in the existing campaign surface.
use super::{Memory, MemoryResult};
use crate::campaign::surface::{CampaignSurfaceVerb, SurfaceCall, invoke_campaign_surface};
use serde::{Deserialize, Serialize};

/// Campaign definition input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignCreateRequest {
    pub name: String,
    pub schema_version: Option<u32>,
}
/// Campaign identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignRefRequest {
    pub campaign_ref: String,
}
/// Campaign definition replacement under CAS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignUpdateRequest {
    pub campaign_ref: String,
    pub name: String,
    pub expected_definition_version: u64,
}
/// Campaign lifecycle transition under CAS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignArchiveRequest {
    pub campaign_ref: String,
    pub expected_definition_version: u64,
}
/// One bounded campaign membership page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignMembersRequest {
    pub campaign_ref: String,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    pub at_epoch: Option<u64>,
}
/// Engine campaign record wire form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignRecordDto {
    pub campaign_ref: String,
    pub definition: CampaignDefinitionDto,
    pub created_at: u64,
    pub updated_at: u64,
}
/// Owner-bound campaign definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignDefinitionDto {
    pub schema_version: u32,
    pub owner_actor: String,
    pub name: String,
    pub definition_version: u64,
    pub lifecycle: String,
}
/// A present or absent record; absence also covers an inaccessible record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordLookup<T> {
    pub found: bool,
    pub record: Option<T>,
}
/// Engine membership page wire form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipPageDto {
    pub rows: Vec<MembershipRowDto>,
    pub next_cursor: Option<String>,
}
/// Bitemporal membership projection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipRowDto {
    pub entity_ref: String,
    pub state: String,
    pub entered_valid: u64,
    pub entered_detected: u64,
    pub exited_valid: Option<u64>,
    pub exited_detected: Option<u64>,
    pub cause: Option<String>,
}
/// Saved-query scope, each empty axis meaning unrestricted.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueryScopeDto {
    #[serde(default)]
    pub worlds: Vec<String>,
    #[serde(default)]
    pub facets: Vec<String>,
}
/// Filter AST accepted by the existing domain parser.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum QueryFilterDto {
    All {
        terms: Vec<QueryFilterDto>,
    },
    Any {
        terms: Vec<QueryFilterDto>,
    },
    Not {
        term: Box<QueryFilterDto>,
    },
    Claim {
        predicate: String,
        cmp: String,
        value: serde_json::Value,
    },
    EdgeExists {
        edge_kind: String,
        target: Option<String>,
    },
}
/// Matcher accepted by the existing domain parser.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum QueryMatcherDto {
    Hard {
        expression: QueryFilterDto,
    },
    SemanticThreshold {
        exemplar_ref: String,
        minimum_similarity_micros: u32,
    },
    LlmJudge {
        model_id: String,
        rubric: serde_json::Value,
        rubric_version: String,
    },
}
/// Host-side query evaluation budget.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryEvalDto {
    pub mode: String,
    pub max_entities_per_wake: u32,
    pub max_judges_per_wake: u32,
}
/// Saved-query creation. No owner input is accepted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedQueryCreateRequest {
    pub schema_version: Option<u32>,
    pub scope: Option<QueryScopeDto>,
    pub filter: QueryFilterDto,
    pub matcher: QueryMatcherDto,
    pub eval: QueryEvalDto,
}
/// Saved-query identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedQueryRefRequest {
    pub query_ref: String,
}
/// Saved-query definition replacement under CAS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedQueryUpdateRequest {
    pub query_ref: String,
    pub expected_definition_version: u64,
    pub scope: Option<QueryScopeDto>,
    pub filter: QueryFilterDto,
    pub matcher: QueryMatcherDto,
    pub eval: QueryEvalDto,
}
/// Saved-query lifecycle transition under CAS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedQueryArchiveRequest {
    pub query_ref: String,
    pub expected_definition_version: u64,
}
/// One bounded saved-query membership page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedQueryMembersRequest {
    pub query_ref: String,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    pub at_epoch: Option<u64>,
}
/// Saved-query record wire form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedQueryRecordDto {
    pub query_ref: String,
    pub definition: SavedQueryDefinitionDto,
    pub created_at: u64,
    pub updated_at: u64,
}
/// Owner-bound query definition, preserving all domain fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedQueryDefinitionDto {
    pub schema_version: u32,
    pub owner_actor: String,
    pub scope: QueryScopeDto,
    pub definition_version: u64,
    pub filter: QueryFilterDto,
    pub matcher: QueryMatcherDto,
    pub eval: QueryEvalDto,
    pub lifecycle: QueryLifecycleDto,
}
/// Saved-query lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum QueryLifecycleDto {
    Active,
    Paused { error: String },
    Archived,
}

pub(super) fn call<Q: Serialize, R: serde::de::DeserializeOwned>(
    memory: &Memory<'_>,
    verb: CampaignSurfaceVerb,
    request: &Q,
) -> MemoryResult<R> {
    let reply = invoke_campaign_surface(
        memory,
        SurfaceCall {
            verb: verb.as_str().to_owned(),
            body: super::encode(request)?,
        },
    )?;
    serde_json::from_value(reply.body).map_err(|_| {
        super::MemoryError::new(
            super::MEMORY_CODE_INTERNAL,
            "campaign projection mismatch",
            &["Check the engine domain DTO."],
        )
    })
}
