//! OF-537 report execution and owner triage. No triage prompt or repair policy lives here.
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use oneiron::authority::VerifiedSlip;
use oneiron::claim::CallerLocality;
use oneiron::feedback::{
    ReportDisclosureChoice, ReportIssue, ReportReceipt, ReportRequest, ReportReview, ReportRoute,
    ReportRoutedPayload,
};
use oneiron::memory::{MEMORY_CODE_INTERNAL, MemoryError, MemoryResult};
use oneiron::{EdgeActorClass, EntityId};
use serde::Deserialize;

use super::error_map::core_engine_error;
use crate::auth::CoreAuth;
use crate::error::ApiError;
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/v1/owner/reports", get(inbox))
        .route("/v1/owner/reports/route", post(set_route))
        .route("/v1/owner/reports/{issue}/review", post(review))
        .route("/v1/owner/reports/{issue}/disclosure", post(disclosure))
        .route("/v1/owner/reports/{issue}/outbound", get(outbound))
}

impl SyncServer {
    /// Every hosted report uses the host's embedder, never the caller's budget.
    /// A missing/unready embedder cannot keep a report out of the inbox.
    pub(crate) async fn report_off_runtime(
        self: &Arc<Self>,
        actor: EntityId,
        class: EdgeActorClass,
        proof: Option<VerifiedSlip>,
        locality: CallerLocality,
        room: Option<EntityId>,
        input: ReportRequest,
    ) -> MemoryResult<ReportReceipt> {
        self.report_off_runtime_listing(actor, class, proof, locality, room, input)
            .await
            .0
    }

    pub(crate) async fn report_off_runtime_listing(
        self: &Arc<Self>,
        actor: EntityId,
        class: EdgeActorClass,
        proof: Option<VerifiedSlip>,
        locality: CallerLocality,
        room: Option<EntityId>,
        input: ReportRequest,
    ) -> (MemoryResult<ReportReceipt>, Vec<EntityId>) {
        let server = Arc::clone(self);
        let output = tokio::task::spawn_blocking(move || {
            input.validate().map_err(MemoryError::from)?;
            let vector = input
                .embedding_text()
                .and_then(|text| server.embed_query(&text).ok());
            let memory = server.vault().memory(actor, class).at(locality);
            let memory = match proof.as_ref() {
                Some(proof) => memory.with_read_proof(proof),
                None => memory,
            };
            // report reads none of its quoted refs. It grants no read outside
            // the room or the credential, and loads no cited vault text.
            match room {
                Some(room) => memory
                    .for_room_turn(room)?
                    .report_with_embedding(input, vector.as_deref()),
                None => memory.report_with_embedding(input, vector.as_deref()),
            }
        })
        .await
        .unwrap_or_else(|_| {
            Err(MemoryError::new(
                MEMORY_CODE_INTERNAL,
                "report did not finish",
                &["Retry the same report."],
            ))
        });
        (output, Vec::new())
    }
}

#[derive(Default, Deserialize)]
struct InboxQuery {
    after_at: Option<u64>,
    after_ref: Option<String>,
    limit: Option<usize>,
}

async fn inbox(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Query(query): Query<InboxQuery>,
) -> Result<Json<Vec<ReportIssue>>, ApiError> {
    let _owner = super::owner_routes::owner(&auth, &server)?;
    let after = match (query.after_at, query.after_ref) {
        (None, None) => None,
        (Some(at), Some(reference)) => Some((at, parse_id(&reference)?)),
        _ => {
            return Err(ApiError::bad_request(
                "both report cursor fields are required",
                None,
            ));
        }
    };
    server
        .vault()
        .report_inbox(after, query.limit.unwrap_or(100))
        .map(Json)
        .map_err(|error| core_engine_error("report inbox failed", error))
}

async fn review(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(reference): Path<String>,
    Json(input): Json<ReportReview>,
) -> Result<Json<ReportIssue>, ApiError> {
    let owner = super::owner_routes::owner(&auth, &server)?;
    server
        .vault()
        .review_report(&owner, &parse_id(&reference)?, input)
        .map(Json)
        .map_err(|error| core_engine_error("report review failed", error))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DisclosureInput {
    choice: ReportDisclosureChoice,
}

async fn disclosure(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(reference): Path<String>,
    Json(input): Json<DisclosureInput>,
) -> Result<Json<ReportIssue>, ApiError> {
    let owner = super::owner_routes::owner(&auth, &server)?;
    server
        .vault()
        .decide_report_disclosure(&owner, &parse_id(&reference)?, input.choice)
        .map(Json)
        .map_err(|error| core_engine_error("report disclosure failed", error))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteInput {
    subject_ref: String,
    route: ReportRoute,
}

async fn set_route(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Json(input): Json<RouteInput>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let owner = super::owner_routes::owner(&auth, &server)?;
    server
        .vault()
        .set_report_route(&owner, &input.subject_ref, input.route)
        .map_err(|error| core_engine_error("report routing failed", error))?;
    Ok(Json(serde_json::json!({"updated": true})))
}

async fn outbound(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(reference): Path<String>,
) -> Result<Json<Option<ReportRoutedPayload>>, ApiError> {
    let _owner = super::owner_routes::owner(&auth, &server)?;
    server
        .vault()
        .report_routed_payload(&parse_id(&reference)?)
        .map(Json)
        .map_err(|error| core_engine_error("report payload failed", error))
}

fn parse_id(reference: &str) -> Result<EntityId, ApiError> {
    EntityId::from_hex(reference)
        .map_err(|_| ApiError::bad_request("invalid issue reference", Some("issue")))
}
