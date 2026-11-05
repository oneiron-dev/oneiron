//! Exact owner review and confirmation of a shared proactivity-policy claim.

use std::sync::Arc;

use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::dreamer_runner::maintenance::digest::ProactivityPolicyRequest;
use serde::{Deserialize, Serialize};

use super::super::{OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::api::query_params;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyQuery {
    proposal: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct PolicyReview {
    proposal: String,
    revision: String,
    request: ProactivityPolicyRequest,
}

async fn review(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<PolicyQuery>, QueryRejection>,
) -> OwnerReply<PolicyReview> {
    let owner = owner(&auth, &server)?;
    let query = query_params(query)?;
    let review = blocking(move || -> OwnerResult<PolicyReview> {
        let proposal = entity_id("proposal", &query.proposal)?;
        let review = server
            .vault()
            .proactivity_policy_proposal(&owner, proposal)?;
        Ok(PolicyReview {
            proposal: proposal.to_hex(),
            revision: blake3::Hash::from_bytes(review.revision)
                .to_hex()
                .to_string(),
            request: review.request,
        })
    })
    .await?;
    Ok(Json(review))
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ConfirmPolicy {
    proposal: String,
    revision: String,
}

async fn confirm(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<ConfirmPolicy>,
) -> OwnerReply<()> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    blocking(move || -> OwnerResult<()> {
        let proposal = entity_id("proposal", &request.proposal)?;
        let revision = super::digest_id(&request.revision)
            .ok_or_else(|| OwnerError::Invalid("revision must be a 64-hex digest".into()))?;
        server
            .vault()
            .confirm_proactivity_policy_proposal(&owner, proposal, revision)?;
        Ok(())
    })
    .await?;
    Ok(Json(()))
}

fn review_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<PolicyReview>()
}

fn confirm_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ConfirmPolicy>()
}

fn confirmed_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<()>()
}

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/proactivity/policy",
                summary: "Review the exact pending shared digest policy named by proposal.",
                row: None,
                shape: Some(RestShape::no_body(review_schema)),
            },
            get(review),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/proactivity/policy/confirm",
                summary: "Confirm the exact reviewed shared digest policy revision.",
                row: None,
                shape: Some(RestShape::json(confirm_schema, confirmed_schema)),
            },
            post(confirm),
        ),
    ]
}
