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
//!
//! Each answer is the request's owner work receipt (`owner_work_routes`),
//! polled at `GET /v1/owner/owner-work/{request}`. Where he spoke from is
//! the request's own (`machine_routes::act_surface`): audit only.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::HeaderMap;
use axum::response::Json;
use axum::routing::get;
use oneiron::authority::{RecoveryRootId, RootChange};
use serde::{Deserialize, Serialize};

use super::machine_routes::{act_surface, parse_revision, revision_hex};
use super::owner_work_routes::OwnerWorkView;
use super::{OwnerReply, blocking, owner};
use crate::api::json_payload;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route("/roots/requests", get(pending).post(request))
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
    payload: Result<Json<RootRequest>, JsonRejection>,
) -> OwnerReply<OwnerWorkView> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface(&server, &auth, &headers);
    let body = json_payload(payload)?;
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

/// `GET /v1/owner/roots/requests`: the root requests naming this install
/// with no result yet, ascending by entry. Ids only.
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
