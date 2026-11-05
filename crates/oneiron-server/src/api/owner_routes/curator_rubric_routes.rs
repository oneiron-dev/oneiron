//! The existing owner-set curator policy, without changing its rungs or defaults.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::dreamer_runner::maintenance::CuratorRubric;
use serde_json::{Value, json};

use super::{OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::OwnerResult;
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/dreamer/maintenance/curator-rubric",
                summary: "The current owner-set curator rubric, or validated shipped defaults when unset; not an evaluation result.",
                row: None,
                shape: Some(RestShape::no_body(rubric_schema)),
            },
            get(read),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/dreamer/maintenance/curator-rubric",
                summary: "Replace the owner's existing curator rubric; returns the committed rubric, not a grading result or a newly scheduled pass.",
                row: None,
                shape: Some(RestShape::json(rubric_schema, rubric_schema)),
            },
            post(write),
        ),
    ]
}

fn rubric_schema() -> Value {
    let factor = json!({"type": "number", "minimum": 0, "exclusiveMaximum": 1});
    let question = json!({"type": "string", "minLength": 1, "description": "Non-blank policy text; wording is stored, not executed by a grading model."});
    json!({
        "type": "object", "additionalProperties": false,
        "required": ["minimum_age_secs", "edge_weight_factor", "confidence_factor", "cadence_secs", "questions"],
        "properties": {
            "minimum_age_secs": {"type": "integer", "minimum": 0},
            "edge_weight_factor": factor,
            "confidence_factor": factor,
            "cadence_secs": {"type": "integer", "minimum": 1},
            "questions": {
                "type": "object", "additionalProperties": false,
                "required": ["authorship", "freshness", "least_force"],
                "properties": {"authorship": question, "freshness": question, "least_force": question}
            }
        }
    })
}

async fn read(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<CuratorRubric> {
    let owner = owner(&auth, &server)?;
    let rubric = blocking(move || -> OwnerResult<CuratorRubric> {
        Ok(server.vault().curator_rubric_as(&owner)?)
    })
    .await?;
    Ok(Json(rubric))
}

async fn write(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<CuratorRubric>,
) -> OwnerReply<CuratorRubric> {
    let owner = owner(&auth, &server)?;
    let rubric = payload.read(&server).await?;
    let committed = blocking(move || -> OwnerResult<CuratorRubric> {
        server.vault().set_curator_rubric(&owner, &rubric)?;
        Ok(rubric)
    })
    .await?;
    Ok(Json(committed))
}
