//! `/v1/owner/roots/requests`: the owner decides a change to one install's
//! recovery root from any surface he is authenticated on, and that exact
//! install, the target, makes it (FIX 4736, 4530; WILL L04 row 02).
//!
//! - `POST /roots/requests` records his request on this install, naming the
//!   target as its executor (`Vault::request_root_change`). Ids only: no
//!   seed, piece, passphrase, enrolment code or carry list is asked for or
//!   kept. A target this install cannot name (itself, or one not linked) is
//!   no error: nothing is written, and the receipt says why.
//! - `GET /roots/requests` is the target's read: the root requests naming
//!   this install that have no result yet (`Vault::pending_root_requests`).
//! - The material a change needs goes to the target's own call alone,
//!   `POST /roots/requests/run` (`recovery_kit_target_routes`).
//! - `POST /roots/requests/cancel` records his cancel of one root request on
//!   this install (`Vault::cancel_root_request`, FIX 4739): ids only, and it
//!   takes effect on the target whenever it syncs, offline or not. The
//!   target never runs a request it holds cancelled, or superseded by a
//!   newer request on it; one it answered first keeps that answer, and the
//!   cancel says it came too late. Nothing is undone.
//!
//! Each answer is the request's owner work receipt (`owner_work_routes`),
//! polled at `GET /v1/owner/owner-work/{request}`. Where he spoke from is
//! the request's own (`machine_routes::act_surface`): audit only. The cancel
//! runs its `vault.roots.requests.cancel` row's verb hooks once around the
//! one engine operation, as the facade and MCP doors do (OF-580, FIX 5599).

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::authority::{RecoveryRootId, RootChange};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::machine_routes::{act_surface, parse_revision, revision_hex};
use super::owner_work_routes::{OwnerWorkView, request_entry};
use super::{OwnerReply, blocking, hooked_owner, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, entity_id, hooked_row};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/roots/requests", get(pending).post(request))
        .route("/roots/requests/cancel", post(cancel))
}

/// One root change as a surface shows it: its kind, and the ids it binds,
/// as [`RootRequest`] names them.
#[derive(Debug, Serialize)]
struct RootChangeWire {
    change: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    machine: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootRequest {
    /// The install that is to make the change, 32 hex.
    target: String,
    /// `pin`, `activate`, `restore` or `anchor`.
    change: String,
    /// The root the change binds, 64 hex: every change but `activate`.
    #[serde(default)]
    root: Option<String>,
    /// The machine an `anchor` marks, 32 hex.
    #[serde(default)]
    machine: Option<String>,
}

impl RootRequest {
    /// The change, each field present exactly when the change states it.
    fn change(&self) -> OwnerResult<RootChange> {
        let root = self
            .root
            .as_deref()
            .map(|root| parse_revision("root", root).map(RecoveryRootId))
            .transpose()?;
        let machine = self
            .machine
            .as_deref()
            .map(|machine| entity_id("machine", machine))
            .transpose()?;
        Ok(match (self.change.as_str(), root, machine) {
            ("pin", Some(root), None) => RootChange::Pin { root },
            ("activate", None, None) => RootChange::Activate,
            ("restore", Some(root), None) => RootChange::Restore { root },
            ("anchor", Some(root), Some(machine)) => RootChange::Anchor { root, machine },
            _ => {
                return Err(OwnerError::Invalid(
                    "a root change is pin, restore (each with root), anchor (with root and \
                     machine) or activate (with neither)"
                        .to_owned(),
                ));
            }
        })
    }
}

impl From<RootChange> for RootChangeWire {
    fn from(change: RootChange) -> Self {
        let machine = match change {
            RootChange::Anchor { machine, .. } => Some(machine.to_hex()),
            RootChange::Pin { .. } | RootChange::Activate | RootChange::Restore { .. } => None,
        };
        Self {
            change: change.as_str().to_owned(),
            root: change.root().map(|root| revision_hex(&root.0)),
            machine,
        }
    }
}

/// The owner's cancel of one root request: `vault.roots.requests.cancel`'s
/// input, as its verb hooks read it.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CancelRootRequest {
    /// The request, 64 hex: its receipt's `request`.
    request: String,
}

/// One root request pending on this install, as its target's surface shows
/// it.
#[derive(Debug, Serialize)]
struct PendingRootRequest {
    change: RootChangeWire,
    receipt: OwnerWorkView,
}

/// `POST /v1/owner/roots/requests`: records the owner's root change for the
/// target install. Its answer is the request's receipt: "recorded, awaiting
/// a holder" until the target makes the change, or, when nothing could be
/// recorded, why.
async fn request(
    auth: CoreAuth,
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<RootRequest>,
) -> OwnerReply<OwnerWorkView> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface(&server, &auth, &headers);
    let body = payload.read(&server).await?;
    let receipt = blocking(move || -> OwnerResult<OwnerWorkView> {
        let target = entity_id("target", &body.target)?;
        let change = body.change()?;
        Ok(server
            .vault()
            .request_root_change(&owner, surface, target, change)?
            .into())
    })
    .await?;
    Ok(Json(receipt))
}

/// `POST /v1/owner/roots/requests/cancel`: records the owner's cancel of one
/// root request (FIX 4739). Its answer is the request's receipt: cancelled,
/// or the answer its target gave before it had the cancel, which stands,
/// with the cancel marked "already enacted" or "already refused". A request
/// this install does not fold as a root request is refused, and nothing is
/// written. The `vault.roots.requests.cancel` row's verb hooks run around
/// it as on the facade and MCP (FIX 5599): its post chain reads this answer.
async fn cancel(
    auth: CoreAuth,
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<CancelRootRequest>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let surface = act_surface(&server, &auth, &headers);
    let body = payload.read(&server).await?;
    let receipt = blocking(move || {
        hooked_row(
            server.vault(),
            actor,
            "vault.roots.requests.cancel",
            body,
            |body: CancelRootRequest| -> OwnerResult<OwnerWorkView> {
                let request = request_entry("request", &body.request)?;
                Ok(server
                    .vault()
                    .cancel_root_request(&owner, surface, request)?
                    .into())
            },
        )
    })
    .await?;
    Ok(Json(receipt))
}

/// `GET /v1/owner/roots/requests`: the root requests naming this install
/// with no result yet, ascending by entry, but those the owner cancelled or
/// a newer request superseded. Ids only.
async fn pending(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Vec<PendingRootRequest>> {
    let owner = owner(&auth, &server)?;
    let pending = blocking(move || -> OwnerResult<Vec<PendingRootRequest>> {
        Ok(server
            .vault()
            .pending_root_requests(&owner)?
            .into_iter()
            .map(|(_, change, receipt)| PendingRootRequest {
                change: change.into(),
                receipt: receipt.into(),
            })
            .collect())
    })
    .await?;
    Ok(Json(pending))
}
