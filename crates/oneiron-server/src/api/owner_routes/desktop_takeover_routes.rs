//! `/v1/owner/desktops*`: the owner takes a run's desktop over (CUA-001).
//! A run's agent asks with `self.desktop.handover`, or the owner takes it
//! unasked. While the owner holds it, the run's desktop verbs refuse
//! `desktop_taken_over` and take no screenshot; the owner sees the whole
//! display and drives the same guest through its driver. Handing it back
//! writes the takeover's record to the run's sandbox receipts, and the
//! agent's next desktop answer carries it. Each act re-proves the owner, and
//! each waits for the agent's call in flight to end.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::header;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use oneiron_browser::{BrowserError, DesktopSession, PersonInput, Takeover, TakeoverRecord};
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::json_payload;
use crate::auth::CoreAuth;
use crate::error::EnvelopedApiError;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/desktops", get(list))
        .route("/desktops/take", post(take))
        .route("/desktops/screen", post(screen))
        .route("/desktops/input", post(input))
        .route("/desktops/return", post(hand_back))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunRequest {
    run: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputRequest {
    run: String,
    action: PersonInput,
}

#[derive(Serialize)]
struct DesktopView {
    run: String,
    /// A call holds the desktop right now; its state shows once it ends.
    busy: bool,
    #[serde(flatten)]
    takeover: Option<Takeover>,
}

#[derive(Serialize)]
struct DesktopList {
    desktops: Vec<DesktopView>,
}

#[derive(Serialize)]
struct InputReply {
    inputs: u64,
}

#[derive(Serialize)]
struct ReturnReply {
    record: TakeoverRecord,
    receipt: String,
}

/// `GET /v1/owner/desktops`: each bound run desktop whose guest started,
/// with who has it, the agent's ask while it waits, and the holder's count
/// of inputs.
async fn list(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<DesktopList> {
    let owner = owner(&auth, &server)?;
    let list = blocking(move || -> OwnerResult<DesktopList> {
        owner.actor_for_read(server.vault())?;
        let mut desktops = Vec::new();
        for (run, seat) in server.desktop_seats.live() {
            let (busy, takeover) = match seat.try_lock() {
                Ok(session) => match session.as_ref() {
                    Some(session) => (false, Some(session.takeover().clone())),
                    None => continue,
                },
                Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                    match poisoned.into_inner().as_ref() {
                        Some(session) => (false, Some(session.takeover().clone())),
                        None => continue,
                    }
                }
                Err(std::sync::TryLockError::WouldBlock) => (true, None),
            };
            desktops.push(DesktopView {
                run: run.to_hex(),
                busy,
                takeover,
            });
        }
        Ok(DesktopList { desktops })
    })
    .await?;
    Ok(Json(list))
}

/// `POST /v1/owner/desktops/take` with `{"run"}`: the owner holds the run's
/// desktop, asked or not, once the agent's call in flight ends.
async fn take(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<RunRequest>, JsonRejection>,
) -> OwnerReply<Takeover> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let state = blocking(move || -> OwnerResult<Takeover> {
        let by = owner.revalidate_principal_ref(server.vault())?;
        on_desktop(&server, &request.run, |session| {
            session.take_over(by).cloned()
        })
    })
    .await?;
    Ok(Json(state))
}

/// `POST /v1/owner/desktops/screen` with `{"run"}`: the whole display as a
/// PNG, unmasked, for the owner only: never kept, never a receipt.
async fn screen(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<RunRequest>, JsonRejection>,
) -> Result<Response, EnvelopedApiError> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let png = blocking(move || -> OwnerResult<Vec<u8>> {
        owner.revalidate_principal_ref(server.vault())?;
        on_desktop(&server, &request.run, DesktopSession::person_screen)
    })
    .await?;
    Ok((
        [
            (header::CONTENT_TYPE, "image/png"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        png,
    )
        .into_response())
}

/// `POST /v1/owner/desktops/input` with `{"run", "action"}`: one click,
/// type, key, hotkey or scroll from the owner who holds the desktop, at the
/// pixels of the screen they were last shown.
async fn input(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<InputRequest>, JsonRejection>,
) -> OwnerReply<InputReply> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let reply = blocking(move || -> OwnerResult<InputReply> {
        let by = owner.revalidate_principal_ref(server.vault())?;
        let action = request.action;
        on_desktop(&server, &request.run, |session| {
            session.person_input(by, action)
        })
        .map(|inputs| InputReply { inputs })
    })
    .await?;
    Ok(Json(reply))
}

/// `POST /v1/owner/desktops/return` with `{"run"}`: the owner hands the
/// desktop back, from holding it or from the agent's ask unanswered. Its
/// record lands as the run's `desktop_takeover` receipt.
async fn hand_back(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<RunRequest>, JsonRejection>,
) -> OwnerReply<ReturnReply> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let reply = blocking(move || -> OwnerResult<ReturnReply> {
        let by = owner.revalidate_principal_ref(server.vault())?;
        let run = run_of(&request.run)?;
        let record = on_desktop(&server, &request.run, |session| session.hand_back(by))?;
        let body = serde_json::to_value(&record).map_err(|e| OwnerError::Host(e.into()))?;
        let receipt = server.vault().append_desktop_takeover_receipt(run, &body)?;
        Ok(ReturnReply { record, receipt })
    })
    .await?;
    Ok(Json(reply))
}

fn run_of(run: &str) -> OwnerResult<oneiron::EntityId> {
    oneiron::EntityId::from_hex(run)
        .map_err(|_| OwnerError::Invalid(format!("run {run} is not an entity id")))
}

/// Runs `act` on run `run`'s started desktop, under its lock.
fn on_desktop<T>(
    server: &SyncServer,
    run: &str,
    act: impl FnOnce(&mut DesktopSession) -> Result<T, BrowserError>,
) -> OwnerResult<T> {
    let not_found = || OwnerError::NotFound("run desktop", run.to_owned());
    let seat = server
        .desktop_seats
        .get(run_of(run)?)
        .ok_or_else(not_found)?;
    let mut session = seat
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let session = session.as_mut().ok_or_else(not_found)?;
    act(session).map_err(|error| match error {
        BrowserError::Input(message) => OwnerError::Invalid(message),
        other => OwnerError::Refused(other.to_string()),
    })
}
