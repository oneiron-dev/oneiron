//! FIX 11694: a person's MFA step-up on their own credential (MFA-1 A: a
//! passkey first). The browser runs the WebAuthn ceremonies; these doors
//! hand out the engine's challenge and pass the answer to the engine, which
//! verifies it and records the step-up on the exact slip the request was
//! admitted on (`oneiron::authority::step_up`). The weave Admin's doors read
//! that record through `Vault::admin_step_up`; nothing here mints a witness.
//!
//! - `POST /v1/core/step-up/challenge` `{ "ceremony": "enroll" | "assert" }`
//!   opens a ceremony and answers its challenge, the person's id and their
//!   enrolled passkeys.
//! - `POST /v1/core/step-up/passkeys` enrolls the passkey a `create` answered.
//! - `GET /v1/core/step-up/passkeys` lists the person's passkeys.
//! - `POST /v1/core/step-up/passkeys/remove` `{ "credential_id": .. }` removes
//!   one, after a current step-up.
//! - `POST /v1/core/step-up/passkey` steps up with the assertion a `get`
//!   answered.
//!
//! Authenticator-app doors under `/v1/core/step-up/totp` open a sealed-seed
//! enrollment, confirm its first code, list/remove enrollments and verify
//! later codes. The provisioning response is `no-store`.
//!
//! Each runs on the caller's own verified slip, at read scope: a step-up is
//! the person's own sign-in strength, not a write into the vault's records.
//! The owner's reset of a person's passkeys is the verb row
//! `vault.step_up.passkeys.reset` (FIX 17553), under the owner proof.

mod totp;

pub(crate) use totp::vault_step_up_totp_reset;

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::EntityId;
use oneiron::authority::{
    EnrolledPasskey, PasskeyAssertion, PasskeyRegistration, StepUpCeremony, StepUpChallenge,
    StepUpDone, StepUpPasskeysReset, StepUpPasskeysResetRequest, VerifiedSlip,
};
use oneiron::memory::MEMORY_CODE_INTERNAL;
use serde::{Deserialize, Serialize};

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use super::{FacadeApiError, facade_input, facade_json};
use crate::auth::{CoreAuth, CoreScope};
use crate::server::SyncServer;

pub(crate) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/v1/core/step-up/challenge", post(challenge))
        .route("/v1/core/step-up/passkeys", get(passkeys).post(enroll))
        .route("/v1/core/step-up/passkeys/remove", post(remove))
        .route("/v1/core/step-up/passkey", post(step_up))
        .merge(totp::routes())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenCeremony {
    ceremony: StepUpCeremony,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemovePasskey {
    /// The passkey's credential id, base64url.
    credential_id: String,
}

#[derive(Serialize)]
struct Removed {
    removed: bool,
}

/// `POST /v1/core/step-up/challenge`: a fresh challenge for one ceremony on
/// the caller's own slip.
async fn challenge(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<serde_json::Value>, JsonRejection>,
) -> Result<Json<StepUpChallenge>, FacadeApiError> {
    auth.require(CoreScope::Read)?;
    let request: OpenCeremony = facade_input(facade_json(payload)?)?;
    let slip = own_slip(&server, &auth)?;
    let vault = Arc::clone(&server.vault);
    let opened = super::clock_ingress::run_blocking(move || {
        vault.open_step_up_ceremony(&slip, request.ceremony)
    })
    .await
    .map_err(|_| internal())?
    .map_err(engine)?;
    Ok(Json(opened))
}

/// `POST /v1/core/step-up/passkeys`: enrolls the passkey a
/// `navigator.credentials.create` answered for an `enroll` challenge.
async fn enroll(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<serde_json::Value>, JsonRejection>,
) -> Result<Json<EnrolledPasskey>, FacadeApiError> {
    auth.require(CoreScope::Read)?;
    let registration: PasskeyRegistration = facade_input(facade_json(payload)?)?;
    let slip = own_slip(&server, &auth)?;
    let vault = Arc::clone(&server.vault);
    let enrolled = super::clock_ingress::run_blocking(move || {
        vault.enroll_step_up_passkey(&slip, &registration)
    })
    .await
    .map_err(|_| internal())?
    .map_err(engine)?;
    Ok(Json(enrolled))
}

/// `GET /v1/core/step-up/passkeys`: the caller's own enrolled passkeys.
async fn passkeys(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> Result<Json<Vec<EnrolledPasskey>>, FacadeApiError> {
    auth.require(CoreScope::Read)?;
    let slip = own_slip(&server, &auth)?;
    let vault = Arc::clone(&server.vault);
    let listed = super::clock_ingress::run_blocking(move || vault.step_up_passkeys(&slip))
        .await
        .map_err(|_| internal())?
        .map_err(engine)?;
    Ok(Json(listed))
}

/// `POST /v1/core/step-up/passkeys/remove`: removes one of the caller's
/// passkeys, after a current step-up on this slip.
async fn remove(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<serde_json::Value>, JsonRejection>,
) -> Result<Json<Removed>, FacadeApiError> {
    auth.require(CoreScope::Read)?;
    let request: RemovePasskey = facade_input(facade_json(payload)?)?;
    let slip = own_slip(&server, &auth)?;
    let vault = Arc::clone(&server.vault);
    let removed = super::clock_ingress::run_blocking(move || {
        vault.remove_step_up_passkey(&slip, &request.credential_id)
    })
    .await
    .map_err(|_| internal())?
    .map_err(engine)?;
    Ok(Json(Removed { removed }))
}

/// `POST /v1/core/step-up/passkey`: steps up the caller's slip with the
/// assertion a `navigator.credentials.get` answered for an `assert`
/// challenge.
async fn step_up(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<serde_json::Value>, JsonRejection>,
) -> Result<Json<StepUpDone>, FacadeApiError> {
    auth.require(CoreScope::Read)?;
    let assertion: PasskeyAssertion = facade_input(facade_json(payload)?)?;
    let slip = own_slip(&server, &auth)?;
    let vault = Arc::clone(&server.vault);
    let done =
        super::clock_ingress::run_blocking(move || vault.step_up_with_passkey(&slip, &assertion))
            .await
            .map_err(|_| internal())?
            .map_err(engine)?;
    Ok(Json(done))
}

/// The verified slip this request was admitted on: a step-up is made on
/// that exact credential. A hosted operator's root is refused first, typed,
/// as at every facade door.
fn own_slip(server: &SyncServer, auth: &CoreAuth) -> Result<VerifiedSlip, FacadeApiError> {
    super::owner_binding::host_preflight(server, auth)?;
    auth.verified_slip().cloned().ok_or_else(|| {
        FacadeApiError::forbidden(
            "a step-up is made on the verified slip its request was admitted on",
            ["Present your own verified human credential."],
        )
    })
}

/// An engine refusal answers 403 with the engine's own words; any other
/// fault as the core plane maps it.
fn engine(error: oneiron::Error) -> FacadeApiError {
    if let oneiron::Error::Record(oneiron::error::RecordError::AuthorityRefused(reason)) = &error {
        return FacadeApiError::forbidden(
            *reason,
            ["Step up on your own live credential, with a passkey you enrolled on this vault."],
        );
    }
    crate::api::error_map::core_engine_error("step-up", error).into()
}

fn internal() -> FacadeApiError {
    FacadeApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        MEMORY_CODE_INTERNAL,
        "the step-up worker did not finish",
        ["Retry the request."],
    )
}

/// `vault.step_up.passkeys.reset` (FIX 17553): the vault owner removes every
/// passkey a person enrolled, and their step-ups, so a person who lost each
/// one can enroll again. Under the owner proof, revalidated in the writer;
/// it names the person.
pub(crate) async fn vault_step_up_passkeys_reset(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: StepUpPasskeysResetRequest,
) -> Listed<StepUpPasskeysReset> {
    const VERB: &str = "vault.step_up.passkeys.reset";
    as_owner_naming(
        server,
        auth,
        VERB,
        move |server, owner| {
            oneiron::task_verb::sdk::reset_step_up_passkeys_as(server.vault(), owner, input)
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
