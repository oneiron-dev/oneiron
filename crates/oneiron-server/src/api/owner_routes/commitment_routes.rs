//! Owner doors for where commitment reminders go (OF-187).
//!
//! A promise the owner made is reminded on the route the owner sets here, and
//! nowhere else: canon picks no default channel. The same record carries the
//! owner's civil clock, which every approved reminder freezes so its delivery
//! window reads local time. Setting it approves nothing: each reminder still
//! waits for the owner in run review.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use axum::routing::get;
use oneiron::commitment_wake::CommitmentReminderRoute;
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::json_payload;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route(
        "/commitments/reminder-route",
        get(reminder_route).put(set_reminder_route),
    )
}

/// The route as the owner sees it; `route: null` when none is set.
#[derive(Serialize)]
struct ReminderRouteReply {
    route: Option<CommitmentReminderRoute>,
}

/// `PUT` body: the new route, or `null` to stop reminding the owner.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetReminderRoute {
    route: Option<CommitmentReminderRoute>,
}

/// `GET /v1/owner/commitments/reminder-route`.
async fn reminder_route(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<ReminderRouteReply> {
    let _owner = owner(&auth, &server)?;
    let route = blocking(move || Ok(server.vault().commitment_reminder_route()?)).await?;
    Ok(Json(ReminderRouteReply { route }))
}

/// `PUT /v1/owner/commitments/reminder-route`.
async fn set_reminder_route(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<SetReminderRoute>, JsonRejection>,
) -> OwnerReply<ReminderRouteReply> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let route = blocking(move || {
        server
            .vault()
            .set_commitment_reminder_route(&owner, request.route.as_ref())?;
        Ok(server.vault().commitment_reminder_route()?)
    })
    .await?;
    Ok(Json(ReminderRouteReply { route }))
}
