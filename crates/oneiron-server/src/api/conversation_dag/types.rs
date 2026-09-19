//! Closed wire inputs for conversation topology and merge operations.

use super::super::{CoreEntityWriteResponse, CoreTextField, parse_entity_id_param};
use crate::auth::CoreAuth;
use crate::error::ApiError;
use crate::projection::View;
use oneiron::conversation_dag::{ScopePath, ScopeSelector};
use oneiron::{EdgeActorClass, EntityId, WriteActor};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DagActorClass {
    Human,
    Agent,
    System,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct DagActor {
    /// Required actor entity; no implicit machine/owner fallback.
    pub entity_ref: String,
    pub actor_class: DagActorClass,
}

impl DagActor {
    pub(super) fn parse(&self, auth: &CoreAuth) -> Result<WriteActor, ApiError> {
        let id = parse_entity_id_param(&self.entity_ref, "actor.entity_ref")?;
        let (class, name) = match self.actor_class {
            DagActorClass::Human => (EdgeActorClass::Human, "human"),
            DagActorClass::Agent => (EdgeActorClass::Agent, "agent"),
            DagActorClass::System => (EdgeActorClass::System, "system"),
        };
        // A delegated credential cannot overwrite the identity bound in its slip.
        if auth
            .principal_ref()
            .is_some_and(|bound| bound != id.to_hex())
            || auth.actor_class().is_some_and(|bound| bound != name)
        {
            return Err(ApiError::forbidden_scope("actor_binding"));
        }
        Ok(WriteActor::new(id, class))
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct DagAppendRequest {
    pub parent: Option<String>,
    pub advance: bool,
    pub body: Value,
    pub text: Option<Vec<CoreTextField>>,
    pub occurred_start: Option<u64>,
    pub occurred_end: Option<u64>,
    pub learned_at: Option<u64>,
    pub session: Option<String>,
    pub actor: DagActor,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DagScopePath {
    Canonical,
    Branch(String),
    SubSession(String),
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct DagScopeRequest {
    /// "canonical", {"branch": "id"}, or {"sub_session": "id"}.
    pub path: DagScopePath,
    #[serde(default)]
    pub include_forks: bool,
    pub session: Option<String>,
}

impl DagScopeRequest {
    pub(super) fn parse(&self, conversation: EntityId) -> Result<ScopeSelector, ApiError> {
        Ok(ScopeSelector {
            conversation,
            session: parse_optional(self.session.as_deref(), "session")?,
            path: match &self.path {
                DagScopePath::Canonical => ScopePath::Canonical,
                DagScopePath::Branch(id) => ScopePath::Branch(parse_entity_id_param(id, "branch")?),
                DagScopePath::SubSession(id) => {
                    ScopePath::SubSession(parse_entity_id_param(id, "sub_session")?)
                }
            },
            include_forks: self.include_forks,
        })
    }
}

pub(super) fn parse_optional(
    id: Option<&str>,
    field: &'static str,
) -> Result<Option<EntityId>, ApiError> {
    id.map(|id| parse_entity_id_param(id, field)).transpose()
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct DagHeadRequest {
    pub record: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct DagSpawnRequest {
    pub actor: DagActor,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct DagSummaryRequest {
    pub scope: DagScopeRequest,
    pub text: String,
    pub actor: DagActor,
    pub land_on: Option<String>,
    #[serde(default)]
    pub as_record: bool,
}

#[derive(Debug, Default, Deserialize, IntoParams, ToSchema)]
#[into_params(parameter_in = Query)]
pub(crate) struct DagPageQuery {
    pub after: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, IntoParams, ToSchema)]
#[into_params(parameter_in = Query)]
pub(crate) struct DagTurnQuery {
    pub view: Option<View>,
    /// Optional projection: reply_strip.
    pub with: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DagAppendResponse {
    #[serde(flatten)]
    pub entity: CoreEntityWriteResponse,
    pub head: Option<String>,
    pub parent: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DagPageResponse {
    pub head: Option<String>,
    pub root: Option<String>,
    pub main_line: Vec<String>,
    pub page: DagPageCursor,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DagPageCursor {
    pub next: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DagRecordsResponse {
    pub records: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DagSessionsResponse {
    pub sessions: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DagSpawnResponse {
    pub session: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DagHeadResponse {
    pub head: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DagMigrationResponse {
    pub migrated: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DagSummaryResponse {
    pub summary: String,
    pub claim: Option<String>,
    pub record: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DagCoversResponse {
    pub covers: Vec<String>,
}
