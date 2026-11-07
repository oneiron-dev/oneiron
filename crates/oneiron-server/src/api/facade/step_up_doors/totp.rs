//! Authenticator-app ceremonies on the same admitted own-person slip.

use super::*;
use axum::http::header::{CACHE_CONTROL, HeaderValue};
use axum::response::{IntoResponse, Response};
use oneiron::authority::{EnrolledTotp, StepUpTotpReset, StepUpTotpResetRequest, TotpCode};

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/v1/core/step-up/totp/enrollment", post(begin))
        .route("/v1/core/step-up/totp/confirm", post(confirm))
        .route("/v1/core/step-up/totp", get(enrollments).post(step_up))
        .route("/v1/core/step-up/totp/remove", post(remove))
}

async fn begin(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> Result<Response, FacadeApiError> {
    auth.require(CoreScope::Read)?;
    let slip = own_slip(&server, &auth)?;
    let vault = Arc::clone(&server.vault);
    let enrollment =
        super::super::clock_ingress::run_blocking(move || vault.begin_step_up_totp(&slip))
            .await
            .map_err(|_| internal())?
            .map_err(engine)?;
    let mut response = Json(enrollment).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

async fn confirm(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<serde_json::Value>, JsonRejection>,
) -> Result<Json<StepUpDone>, FacadeApiError> {
    auth.require(CoreScope::Read)?;
    let input: TotpCode = facade_input(facade_json(payload)?)?;
    let slip = own_slip(&server, &auth)?;
    let vault = Arc::clone(&server.vault);
    let done = super::super::clock_ingress::run_blocking(move || {
        vault.confirm_step_up_totp(&slip, &input)
    })
    .await
    .map_err(|_| internal())?
    .map_err(engine)?;
    Ok(Json(done))
}

async fn step_up(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<serde_json::Value>, JsonRejection>,
) -> Result<Json<StepUpDone>, FacadeApiError> {
    auth.require(CoreScope::Read)?;
    let input: TotpCode = facade_input(facade_json(payload)?)?;
    let slip = own_slip(&server, &auth)?;
    let vault = Arc::clone(&server.vault);
    let done =
        super::super::clock_ingress::run_blocking(move || vault.step_up_with_totp(&slip, &input))
            .await
            .map_err(|_| internal())?
            .map_err(engine)?;
    Ok(Json(done))
}

async fn enrollments(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> Result<Json<Vec<EnrolledTotp>>, FacadeApiError> {
    auth.require(CoreScope::Read)?;
    let slip = own_slip(&server, &auth)?;
    let vault = Arc::clone(&server.vault);
    let rows =
        super::super::clock_ingress::run_blocking(move || vault.step_up_totp_enrollments(&slip))
            .await
            .map_err(|_| internal())?
            .map_err(engine)?;
    Ok(Json(rows))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoveTotp {
    enrollment_id: String,
}

async fn remove(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<serde_json::Value>, JsonRejection>,
) -> Result<Json<Removed>, FacadeApiError> {
    auth.require(CoreScope::Read)?;
    let input: RemoveTotp = facade_input(facade_json(payload)?)?;
    let slip = own_slip(&server, &auth)?;
    let vault = Arc::clone(&server.vault);
    let removed = super::super::clock_ingress::run_blocking(move || {
        vault.remove_step_up_totp(&slip, &input.enrollment_id)
    })
    .await
    .map_err(|_| internal())?
    .map_err(engine)?;
    Ok(Json(Removed { removed }))
}

pub(crate) async fn vault_step_up_totp_reset(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: StepUpTotpResetRequest,
) -> Listed<StepUpTotpReset> {
    const VERB: &str = "vault.step_up.totp.reset";
    as_owner_naming(
        server,
        auth,
        VERB,
        move |server, owner| {
            oneiron::task_verb::sdk::reset_step_up_totp_as(server.vault(), owner, input)
        },
        |answer| {
            EntityId::from_hex(&answer.person)
                .ok()
                .into_iter()
                .collect()
        },
    )
    .await
}
