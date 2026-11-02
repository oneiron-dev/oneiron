use super::*;

#[utoipa::path(
    get,
    path = "/v1/core/memory/{id}/watch",
    params(("id" = String, Path, description = "Hex claim id to watch.")),
    responses(
        (status = 200, description = "Read the owner's durable per-entry watch flag.", body = CoreMemoryWatchResponse),
        (status = 400, description = "Invalid id or SAVED_QUERY kind not registered.", body = ApiErrorEnvelope),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope),
        (status = 403, description = "Human owner binding or required scope absent.", body = ApiErrorEnvelope),
        (status = 404, description = "Claim not found or not readable.", body = ApiErrorEnvelope)
    )
)]
pub(in crate::api) async fn core_memory_watch_read(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(id_hex): Path<String>,
) -> Result<Json<CoreMemoryWatchResponse>, super::facade::FacadeApiError> {
    // FIX 8185: a GET reads the anchor through the caller's own lane at its
    // verified destination first, so a withheld anchor answers the same
    // not-found an absent one does, before any watch metadata is read.
    let (owner, anchor) = watch_identity(&auth, &server, &id_hex, CoreScope::Read, true)?;
    let watch = oneiron::saved_query::memory_watch(&server.vault, owner, anchor)
        .map_err(|error| core_engine_error("memory watch read failed", error))?;
    Ok(Json(watch_response(watch)))
}

#[utoipa::path(
    put,
    path = "/v1/core/memory/{id}/watch",
    params(("id" = String, Path, description = "Hex claim id to watch.")),
    responses(
        (status = 200, description = "Enable the owner's durable per-entry watch flag.", body = CoreMemoryWatchResponse),
        (status = 400, description = "Invalid id or SAVED_QUERY kind not registered.", body = ApiErrorEnvelope),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope),
        (status = 403, description = "Human owner binding or required scope absent.", body = ApiErrorEnvelope),
        (status = 404, description = "Claim not found or not readable.", body = ApiErrorEnvelope)
    )
)]
pub(in crate::api) async fn core_memory_watch_enable(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(id_hex): Path<String>,
) -> Result<Json<CoreMemoryWatchResponse>, super::facade::FacadeApiError> {
    set_core_memory_watch(auth, server, id_hex, true)
}

#[utoipa::path(
    delete,
    path = "/v1/core/memory/{id}/watch",
    params(("id" = String, Path, description = "Hex claim id to watch.")),
    responses(
        (status = 200, description = "Disable the owner's durable per-entry watch flag.", body = CoreMemoryWatchResponse),
        (status = 400, description = "Invalid id or SAVED_QUERY kind not registered.", body = ApiErrorEnvelope),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope),
        (status = 403, description = "Human owner binding or required scope absent.", body = ApiErrorEnvelope),
        (status = 404, description = "Claim not found or not readable.", body = ApiErrorEnvelope)
    )
)]
pub(in crate::api) async fn core_memory_watch_disable(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(id_hex): Path<String>,
) -> Result<Json<CoreMemoryWatchResponse>, super::facade::FacadeApiError> {
    set_core_memory_watch(auth, server, id_hex, false)
}

fn set_core_memory_watch(
    auth: CoreAuth,
    server: Arc<SyncServer>,
    id_hex: String,
    enabled: bool,
) -> Result<Json<CoreMemoryWatchResponse>, super::facade::FacadeApiError> {
    let (owner, anchor) = watch_identity(&auth, &server, &id_hex, CoreScope::Write, enabled)?;
    let watch = oneiron::saved_query::set_memory_watch(
        &server.vault,
        owner,
        anchor,
        enabled,
        unix_seconds_now(),
    )?;
    Ok(Json(watch_response(watch)))
}

fn watch_identity(
    auth: &CoreAuth,
    server: &SyncServer,
    id_hex: &str,
    scope: CoreScope,
    require_visible: bool,
) -> Result<(oneiron::EntityId, oneiron::EntityId), super::facade::FacadeApiError> {
    auth.require(scope)?;
    auth.require_unrestricted_record_scope()?;
    if !auth.is_owner_grade() || auth.actor_class() != Some("human") {
        return Err(ApiError::forbidden_scope("owner+human").into());
    }
    let principal = auth.require_registered_principal()?;
    let owner = parse_entity_id_param(principal, "principal_ref")?;
    server
        .vault
        .memory(owner, oneiron::EdgeActorClass::Human)
        .verify_owner()?;
    let anchor = parse_entity_id_param(id_hex, "id")?;
    if !require_visible {
        return Ok((owner, anchor));
    }
    let read = scoped_read_for_core_auth(&server.vault, auth)?;
    let result = read
        .memory_timeline(&anchor)
        .map_err(|error| core_engine_error("memory watch visibility failed", error))?;
    if !result.value.records.iter().any(|record| {
        record.id == anchor && record.entity_type == Some(oneiron::registry::ENTITY_TYPE_CLAIM)
    }) {
        return Err(ApiError::not_found("claim", Some(id_hex)).into());
    }
    Ok((owner, anchor))
}

/// The response for `watch`, with its health when a wake recorded one.
fn watch_response(watch: Option<oneiron::saved_query::MemoryWatch>) -> CoreMemoryWatchResponse {
    CoreMemoryWatchResponse {
        watched: watch.is_some(),
        query_ref: watch.as_ref().map(|watch| watch.query_ref.to_hex()),
        health: watch
            .and_then(|watch| watch.health)
            .map(CoreMemoryWatchHealth::from),
    }
}

/// A watch's health as the evaluator's last wake of it left it (FIX 11250):
/// when it ended, which pass ran it, what it came to, its failures in a row
/// and how far it ended behind the change it answered.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreMemoryWatchHealth {
    /// Unix seconds the last wake ended at.
    last_evaluated_at: u64,
    /// `reactive` (a re-check of what a write moved) or `paged`.
    pass: String,
    /// `evaluated` or `failed`.
    outcome: String,
    /// The candidates the wake evaluated, when it ran to its end.
    #[serde(skip_serializing_if = "Option::is_none")]
    evaluated: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    memo_hits: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    judges_run: Option<u32>,
    /// Whether one of the watch's own bounds stopped the wake early.
    #[serde(skip_serializing_if = "Option::is_none")]
    stopped_at_bound: Option<bool>,
    /// The failed wake's error kind.
    #[serde(skip_serializing_if = "Option::is_none")]
    failure: Option<String>,
    consecutive_failures: u32,
    /// Unix seconds of the oldest change the wake answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    triggered_at: Option<u64>,
    /// Seconds the wake ended behind that change.
    #[serde(skip_serializing_if = "Option::is_none")]
    lag_secs: Option<u64>,
}

impl From<oneiron::saved_query::SavedQueryHealth> for CoreMemoryWatchHealth {
    fn from(health: oneiron::saved_query::SavedQueryHealth) -> Self {
        use oneiron::saved_query::{SavedQueryPass, SavedQueryWakeOutcome};
        let mut view = Self {
            last_evaluated_at: health.last_evaluated_at,
            pass: match health.pass {
                SavedQueryPass::Reactive => "reactive",
                SavedQueryPass::Paged => "paged",
            }
            .to_owned(),
            outcome: "evaluated".to_owned(),
            evaluated: None,
            memo_hits: None,
            judges_run: None,
            stopped_at_bound: None,
            failure: None,
            consecutive_failures: health.consecutive_failures,
            triggered_at: health.triggered_at,
            lag_secs: health.lag_secs,
        };
        match health.outcome {
            SavedQueryWakeOutcome::Evaluated {
                evaluated,
                memo_hits,
                judges_run,
                stopped_at_bound,
            } => {
                view.evaluated = Some(evaluated);
                view.memo_hits = Some(memo_hits);
                view.judges_run = Some(judges_run);
                view.stopped_at_bound = Some(stopped_at_bound);
            }
            SavedQueryWakeOutcome::Failed { kind } => {
                view.outcome = "failed".to_owned();
                view.failure = Some(kind);
            }
        }
        view
    }
}
