//! `/v1/owner/browsers*`: the owner takes a run's browser over (CUA-001), to
//! sign in or pay inside the same guest, so its cart and login survive. A
//! run's agent asks with `self.browser.handover`, or the owner takes it
//! unasked. While the owner holds it, the run's browser verbs refuse
//! `browser_taken_over` and take no screenshot; the owner sees the viewport
//! and drives the same page through its driver. Handing it back writes the
//! takeover's record to the run's sandbox receipts, and the agent's next
//! browser answer carries it. Each act re-proves the owner, and each waits
//! for the agent's call in flight to end. The agent's ask raises the
//! owners' inbox Ask, and the owner's take or return clears it.
//!
//! The browser is the run's, not one door's: its seat outlives each door of
//! the run, as the desktop's does. The owner sees every tab: a popup or a
//! tab a link opens is followed, `tab` names one to the screen and input,
//! and the tab the owner leaves in front is the one the agent reads after.
//! The owner watches the front tab as a stream of frames
//! (`GET /v1/owner/browsers/stream`), the desktop's stream with the tabs
//! beside it.

use std::convert::Infallible;
use std::sync::{Arc, PoisonError, TryLockError};

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::http::header;
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use futures_util::Stream;
use oneiron_browser::{
    BrowserError, BrowserPersonInput, BrowserSession, BrowserTab, Takeover, TakeoverRecord,
};
use serde::{Deserialize, Serialize};

use super::desktop_takeover_routes::frame_stream;
use super::{OwnerReply, blocking, owner};
use crate::api::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::error::EnvelopedApiError;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/browsers", get(list))
        .route("/browsers/take", post(take))
        .route("/browsers/screen", post(screen))
        .route("/browsers/stream", get(stream))
        .route("/browsers/input", post(input))
        .route("/browsers/return", post(hand_back))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunRequest {
    run: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScreenRequest {
    run: String,
    /// The tab to show, which comes to the front; the front tab without.
    #[serde(default)]
    tab: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamQuery {
    run: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputRequest {
    run: String,
    /// The tab the input goes to, which comes to the front first; the front
    /// tab without.
    #[serde(default)]
    tab: Option<String>,
    action: BrowserPersonInput,
}

#[derive(Serialize)]
struct BrowserView {
    run: String,
    /// A call holds the browser right now; its state shows once it ends.
    busy: bool,
    #[serde(flatten)]
    takeover: Option<Takeover>,
    /// The browser's tabs, the one in front marked; none while busy.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tabs: Vec<BrowserTab>,
}

#[derive(Serialize)]
struct BrowserList {
    browsers: Vec<BrowserView>,
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

/// `GET /v1/owner/browsers`: each run browser whose guest started, its
/// run's door bound or parked, with who has it, the agent's ask while it
/// waits, the holder's count of inputs, and its tabs (a tab opened while the
/// owner holds the browser comes to the front).
async fn list(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<BrowserList> {
    let owner = owner(&auth, &server)?;
    let list = blocking(move || -> OwnerResult<BrowserList> {
        owner.actor_for_read(server.vault())?;
        let mut browsers = Vec::new();
        for (run, seat) in server.browser_seats.live() {
            let mut session = match seat.try_lock() {
                Ok(session) => session,
                Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
                Err(TryLockError::WouldBlock) => {
                    browsers.push(BrowserView {
                        run: run.to_hex(),
                        busy: true,
                        takeover: None,
                        tabs: Vec::new(),
                    });
                    continue;
                }
            };
            let Some(session) = session.as_mut() else {
                continue;
            };
            // A browser whose tabs do not read still lists who has it.
            let tabs = session.tabs().unwrap_or_default();
            browsers.push(BrowserView {
                run: run.to_hex(),
                busy: false,
                takeover: Some(session.takeover().clone()),
                tabs,
            });
        }
        Ok(BrowserList { browsers })
    })
    .await?;
    Ok(Json(list))
}

/// `POST /v1/owner/browsers/take` with `{"run"}`: the owner holds the run's
/// browser, asked or not, once the agent's call in flight ends.
async fn take(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<RunRequest>, JsonRejection>,
) -> OwnerReply<Takeover> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let state = blocking(move || -> OwnerResult<Takeover> {
        let by = owner.revalidate_principal_ref(server.vault())?;
        let state = on_browser(&server, &request.run, |session| {
            session.take_over(by).cloned()
        })?;
        server.browser_seats.answered(run_of(&request.run)?);
        Ok(state)
    })
    .await?;
    Ok(Json(state))
}

/// `POST /v1/owner/browsers/screen` with `{"run", "tab"?}`: the front
/// tab's viewport as a PNG, or the named tab's, which the owner who holds
/// the browser brings to the front; unmasked, for the owner only: never
/// kept, never a receipt.
async fn screen(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ScreenRequest>, JsonRejection>,
) -> Result<Response, EnvelopedApiError> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let png = blocking(move || -> OwnerResult<Vec<u8>> {
        owner.revalidate_principal_ref(server.vault())?;
        on_browser(&server, &request.run, |session| {
            session.person_screen(request.tab.as_deref())
        })
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

/// `POST /v1/owner/browsers/input` with `{"run", "tab"?, "action"}`: one
/// click, type, key, hotkey, scroll or navigate from the owner who holds the
/// browser, at the pixels of the screen they were last shown, in the front
/// tab or the named one, which comes to the front.
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
        on_browser(&server, &request.run, |session| {
            session.person_input(by, request.tab.as_deref(), action)
        })
        .map(|inputs| InputReply { inputs })
    })
    .await?;
    Ok(Json(reply))
}

/// `POST /v1/owner/browsers/return` with `{"run"}`: the owner hands the
/// browser back, from holding it or from the agent's ask unanswered. Its
/// record lands as the run's `browser_takeover` receipt.
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
        let record = on_browser(&server, &request.run, |session| session.hand_back(by))?;
        server.browser_seats.answered(run);
        let body = serde_json::to_value(&record).map_err(|e| OwnerError::Host(e.into()))?;
        let receipt = server.vault().append_browser_takeover_receipt(run, &body)?;
        Ok(ReturnReply { record, receipt })
    })
    .await?;
    Ok(Json(reply))
}

/// `GET /v1/owner/browsers/stream?run=<hex>`: the run browser's front tab
/// as server-sent events while the owner watches or holds it, as the
/// desktop's stream sends its display (`state`, `frame`, `error`, `ended`,
/// `refused`, at the same pace), and `tabs` (the tabs, at the start and when
/// they change; a popup the owner opened comes to the front). Input still
/// goes through `POST /v1/owner/browsers/input`; watching keeps no parked
/// browser up.
async fn stream(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<StreamQuery>, QueryRejection>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, EnvelopedApiError> {
    let owner = owner(&auth, &server)?;
    let request = query_params(query)?;
    frame_stream::<BrowserSession>(server, owner, request.run).await
}

fn run_of(run: &str) -> OwnerResult<oneiron::EntityId> {
    oneiron::EntityId::from_hex(run)
        .map_err(|_| OwnerError::Invalid(format!("run {run} is not an entity id")))
}

/// Runs `act` on run `run`'s started browser, under its lock.
fn on_browser<T>(
    server: &SyncServer,
    run: &str,
    act: impl FnOnce(&mut BrowserSession) -> Result<T, BrowserError>,
) -> OwnerResult<T> {
    let not_found = || OwnerError::NotFound("run browser", run.to_owned());
    let seat = server
        .browser_seats
        .get(run_of(run)?)
        .ok_or_else(not_found)?;
    let mut session = seat.lock().unwrap_or_else(PoisonError::into_inner);
    let session = session.as_mut().ok_or_else(not_found)?;
    act(session).map_err(|error| match error {
        BrowserError::Input(message) | BrowserError::Url(message) => OwnerError::Invalid(message),
        other => OwnerError::Refused(other.to_string()),
    })
}
