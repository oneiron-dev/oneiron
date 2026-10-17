//! `/v1/owner/desktops*`: the owner takes a run's desktop over (CUA-001).
//! A run's agent asks with `self.desktop.handover`, or the owner takes it
//! unasked. While the owner holds it, the run's desktop verbs refuse
//! `desktop_taken_over` and take no screenshot; the owner sees the whole
//! display and drives the same guest through its driver. Handing it back
//! writes the takeover's record to the run's sandbox receipts, and the
//! agent's next desktop answer carries it. Each act re-proves the owner, and
//! each waits for the agent's call in flight to end.
//!
//! An agent's ask is the owners' inbox Ask; taking the desktop or handing it
//! back clears it. The owner watches a desktop as a stream of frames
//! (`GET /v1/owner/desktops/stream`), re-proved at each frame.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::{Arc, PoisonError, TryLockError};
use std::time::Duration;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::http::header;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use futures_util::{Stream, stream};
use oneiron::consent::AuthenticatedOwner;
use oneiron_browser::{BrowserError, DesktopSession, PersonInput, Takeover, TakeoverRecord};
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::error::EnvelopedApiError;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::{DesktopSeat, DesktopSeats, SyncServer};

/// The pace of the owner's frame stream (CALLS, open): one look at the
/// display every 500 ms, sent only when it changed. A look skips a desktop
/// a call or another act holds, rather than wait for it.
const FRAME_EVERY: Duration = Duration::from_millis(500);

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/desktops", get(list))
        .route("/desktops/take", post(take))
        .route("/desktops/screen", post(screen))
        .route("/desktops/stream", get(stream))
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
struct StreamQuery {
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

/// `GET /v1/owner/desktops`: each run desktop whose guest started, its
/// run's door bound or parked, with who has it, the agent's ask while it
/// waits, and the holder's count of inputs.
async fn list(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<DesktopList> {
    let owner = owner(&auth, &server)?;
    let list = blocking(move || -> OwnerResult<DesktopList> {
        owner.actor_for_read(server.vault())?;
        let mut desktops = Vec::new();
        for (run, seat) in server.desktop_seats.live() {
            let (busy, takeover) =
                match DesktopSeats::peek(&seat, |session| session.map(|s| s.takeover().clone())) {
                    Some(Some(takeover)) => (false, Some(takeover)),
                    Some(None) => continue,
                    None => (true, None),
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
/// desktop, asked or not, once the agent's call in flight ends. The agent's
/// inbox Ask clears.
async fn take(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<RunRequest>, JsonRejection>,
) -> OwnerReply<Takeover> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let state = blocking(move || -> OwnerResult<Takeover> {
        let by = owner.revalidate_principal_ref(server.vault())?;
        let taken = on_desktop(&server, &request.run, |session| {
            session.take_over(by).cloned()
        })?;
        server.desktop_seats.answered(run_of(&request.run)?);
        Ok(taken)
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
/// record lands as the run's `desktop_takeover` receipt, and the agent's
/// inbox Ask clears.
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
        server.desktop_seats.answered(run);
        let body = serde_json::to_value(&record).map_err(|e| OwnerError::Host(e.into()))?;
        let receipt = server.vault().append_desktop_takeover_receipt(run, &body)?;
        Ok(ReturnReply { record, receipt })
    })
    .await?;
    Ok(Json(reply))
}

/// `GET /v1/owner/desktops/stream?run=<hex>`: the run desktop's whole
/// display as server-sent events while the owner watches or holds it, paced
/// by [`FRAME_EVERY`]. Events: `state` (the takeover, at the start and when
/// it changes), `frame` (`{seq, png_base64}`, the display when it changed;
/// unmasked, never kept, never a receipt), `error` (a look that failed, by
/// its code, once until it changes), `ended` (the run's desktop went away)
/// and `refused` (the owner's proof no longer holds). Input still goes
/// through `POST /v1/owner/desktops/input`; watching is no act, so it keeps
/// no parked desktop up.
async fn stream(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<StreamQuery>, QueryRejection>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, EnvelopedApiError> {
    let owner = owner(&auth, &server)?;
    let request = query_params(query)?;
    let seat = {
        let (server, owner) = (Arc::clone(&server), owner.clone());
        let run = request.run.clone();
        blocking(move || -> OwnerResult<Arc<DesktopSeat>> {
            owner.revalidate_principal_ref(server.vault())?;
            let not_found = || OwnerError::NotFound("run desktop", run.clone());
            let seat = server
                .desktop_seats
                .watch(run_of(&run)?)
                .ok_or_else(not_found)?;
            // A desktop a call holds is starting or started.
            if DesktopSeats::peek(&seat, |session| session.is_none()) == Some(true) {
                return Err(not_found());
            }
            Ok(seat)
        })
        .await?
    };
    let watch = Watch {
        server,
        owner,
        seat,
        run: request.run,
        takeover: None,
        frame: None,
        failing: None,
        seq: 0,
        queued: VecDeque::new(),
        first: true,
        done: false,
    };
    let events = stream::unfold(watch, |mut watch| async move {
        loop {
            if let Some(event) = watch.queued.pop_front() {
                return Some((Ok(event), watch));
            }
            if watch.done {
                return None;
            }
            if !watch.first {
                tokio::time::sleep(FRAME_EVERY).await;
            }
            watch.first = false;
            let (server, owner, seat) = (
                Arc::clone(&watch.server),
                watch.owner.clone(),
                Arc::clone(&watch.seat),
            );
            let seen = tokio::task::spawn_blocking(move || look(&server, &owner, &seat))
                .await
                .unwrap_or(Look::Ended);
            watch.saw(seen);
        }
    });
    Ok(Sse::new(events).keep_alive(KeepAlive::default()))
}

/// One owner's watch on one run desktop.
struct Watch {
    server: Arc<SyncServer>,
    owner: AuthenticatedOwner,
    seat: Arc<DesktopSeat>,
    run: String,
    /// The takeover last sent.
    takeover: Option<Takeover>,
    /// The digest of the frame last sent.
    frame: Option<[u8; 32]>,
    /// The code of the failed look last sent, until a look succeeds.
    failing: Option<&'static str>,
    seq: u64,
    queued: VecDeque<Event>,
    first: bool,
    done: bool,
}

#[derive(Serialize)]
struct Frame {
    seq: u64,
    png_base64: String,
}

/// What one look at a watched desktop found.
enum Look {
    Refused,
    Ended,
    /// A call or another act holds the desktop now.
    Busy,
    Seen {
        takeover: Takeover,
        png: Result<Vec<u8>, BrowserError>,
    },
}

/// One look, on a blocking thread: the owner is re-proved, and a desktop a
/// call or an act holds is skipped, never waited for.
fn look(server: &SyncServer, owner: &AuthenticatedOwner, seat: &DesktopSeat) -> Look {
    if owner.revalidate_principal_ref(server.vault()).is_err() {
        return Look::Refused;
    }
    let mut session = match seat.try_lock() {
        Ok(session) => session,
        Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        Err(TryLockError::WouldBlock) => return Look::Busy,
    };
    let Some(session) = session.as_mut() else {
        return Look::Ended;
    };
    Look::Seen {
        takeover: session.takeover().clone(),
        png: session.person_screen(),
    }
}

impl Watch {
    /// Queues the events a look calls for.
    fn saw(&mut self, look: Look) {
        let (takeover, png) = match look {
            Look::Busy => return,
            Look::Refused => return self.last(Event::default().event("refused").data("owner")),
            Look::Ended => return self.last(Event::default().event("ended").data(&self.run)),
            Look::Seen { takeover, png } => (takeover, png),
        };
        if self.takeover.as_ref() != Some(&takeover) {
            if let Ok(state) = serde_json::to_string(&takeover) {
                self.queued
                    .push_back(Event::default().event("state").data(state));
            }
            self.takeover = Some(takeover);
        }
        let png = match png {
            Ok(png) => png,
            Err(BrowserError::Abandoned | BrowserError::GuestLost) => {
                return self.last(Event::default().event("ended").data(&self.run));
            }
            Err(error) => {
                if self.failing != Some(error.code()) {
                    self.failing = Some(error.code());
                    self.queued
                        .push_back(Event::default().event("error").data(error.code()));
                }
                return;
            }
        };
        self.failing = None;
        let digest = *blake3::hash(&png).as_bytes();
        if self.frame == Some(digest) {
            return;
        }
        self.frame = Some(digest);
        self.seq += 1;
        let frame = Frame {
            seq: self.seq,
            png_base64: base64::engine::general_purpose::STANDARD.encode(&png),
        };
        if let Ok(frame) = serde_json::to_string(&frame) {
            self.queued.push_back(
                Event::default()
                    .event("frame")
                    .id(self.seq.to_string())
                    .data(frame),
            );
        }
    }

    /// Queues the watch's last event.
    fn last(&mut self, event: Event) {
        self.queued.push_back(event);
        self.done = true;
    }
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
    let mut session = seat.lock().unwrap_or_else(PoisonError::into_inner);
    let session = session.as_mut().ok_or_else(not_found)?;
    act(session).map_err(|error| match error {
        BrowserError::Input(message) => OwnerError::Invalid(message),
        other => OwnerError::Refused(other.to_string()),
    })
}
