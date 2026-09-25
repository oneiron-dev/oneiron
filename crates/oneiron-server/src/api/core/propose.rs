//! Proposal-only cloud leg. No raw entities, caller ids, approvals, or authority rows.
use super::super::{core_engine_error, json_payload, scoped_read_for_core_auth};
use crate::{
    auth::{CoreAuth, CoreScope},
    error::{ApiError, ApiErrorEnvelope, EnvelopedApiError},
    server::SyncServer,
};
use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct CoreProposeRequest {
    subject: String,
    predicate: String,
    value: serde_json::Value,
}
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreProposeResponse {
    id: String,
    approval: &'static str,
}
#[utoipa::path(post,path="/v1/core/propose",request_body=CoreProposeRequest,
    responses((status=200,description="A new Proposed claim; no prior head closed.",body=CoreProposeResponse),
        (status=400,description="Invalid proposal.",body=ApiErrorEnvelope),
        (status=401,description="Authentication required.",body=ApiErrorEnvelope),
        (status=403,description="core:propose or core:write required.",body=ApiErrorEnvelope)))]
pub(crate) async fn core_propose(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<CoreProposeRequest>, JsonRejection>,
) -> Result<Json<CoreProposeResponse>, EnvelopedApiError> {
    if !auth.has_scope(CoreScope::Write) {
        auth.require(CoreScope::Propose)?;
    }
    let request = json_payload(payload)?;
    let subject = oneiron::EntityId::from_hex(&request.subject)
        .map_err(|_| ApiError::bad_request("invalid subject reference", Some("subject")))?;
    let readable = scoped_read_for_core_auth(server.vault().as_ref(), &auth)?
        .get(&subject)
        .map_err(|error| core_engine_error("proposal target lookup failed", error))?;
    if readable.value.is_none() {
        return Err(ApiError::forbidden_scope("proposal:subject").into());
    }
    let bytes = rmp_serde::to_vec_named(&request.value)
        .map_err(|_| ApiError::bad_request("invalid proposal value", Some("value")))?;
    let value = rmpv::decode::read_value(&mut bytes.as_slice())
        .map_err(|_| ApiError::bad_request("invalid proposal value", Some("value")))?;
    let mut body = oneiron::ClaimBody::new(
        request.predicate,
        oneiron::ClaimSubject::Entity(subject),
        value,
        1.0,
        oneiron::ClaimApprovalStatus::Proposed,
        oneiron::ClaimLifecycleStatus::Active,
    );
    body.source = Some(oneiron::ClaimSource::ToolOutput);
    body.scope = Some(rmpv::Value::Map(vec![(
        rmpv::Value::from("proposal_principal"),
        rmpv::Value::from(auth.principal()),
    )]));
    let id = oneiron::EntityId::now();
    let timestamps = super::write_shape::core_entity_timestamps(None, None, None)?;
    server
        .vault()
        .put_claim(&id, &body, timestamps.occurred, timestamps.learned_at)
        .map_err(|error| core_engine_error("proposal rejected", error))?;
    Ok(Json(CoreProposeResponse {
        id: id.to_hex(),
        approval: "proposed",
    }))
}
