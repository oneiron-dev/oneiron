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
//! - `GET /roots` is the roots this install sees (`Vault::owner_root_view`,
//!   FIX 4955): the one it pins, a page of the foreign roots with how many
//!   machines each admits, and `next` to read the page after, the root a pin
//!   awaits, and this install's machine.
//! - `POST /roots/pin` pins a root here from the fingerprint the owner
//!   carried (`Vault::pin_owner_root`): the change `request_root_change`
//!   answers is this install's own to make. No kit; the other changes made
//!   here carry one (`recovery_kit_target_routes`).
//!
//! Each request answer is the request's owner work receipt (`owner_work_routes`),
//! polled at `GET /v1/owner/owner-work/{request}`. Where he spoke from is
//! the request's own (`machine_routes::act_surface`): audit only. The cancel
//! runs its `vault.roots.requests.cancel` row's verb hooks once around the
//! one engine operation, as the facade and MCP doors do (OF-580, FIX 5599).

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::authority::{RecoveryRootId, RootChange};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::machine_routes::{act_surface, parse_revision, revision_hex};
use super::owner_work_routes::{OwnerWorkView, request_entry};
use super::recovery_kit_target_routes::RepinView;
use super::{OwnerReply, blocking, hooked_owner, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::api::query_params;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, entity_id, hooked_row};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/roots", get(roots))
        .route("/roots/pin", post(pin))
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

/// A page of foreign roots when the caller names no `limit` (CALLS "4955
/// local root routes"): the caller may ask for more; `next` reads on.
const ROOT_PAGE_DEFAULT: usize = 100;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootsQuery {
    /// The last foreign root of the page before, 64 hex: its `next`.
    #[serde(default)]
    after: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

/// A foreign root this install sees and never trusts, and how many live
/// machines its anchor admits.
#[derive(Debug, Serialize)]
struct ForeignRootWire {
    root: String,
    machines: usize,
}

/// The root a pin awaits, and whether it has arrived: pinning it again then
/// finishes.
#[derive(Debug, Serialize)]
struct AwaitedRootWire {
    root: String,
    arrived: bool,
}

/// `GET /v1/owner/roots`'s answer.
#[derive(Debug, Serialize)]
struct RootsView {
    /// This install's machine, 32 hex: the `target` its kit calls name.
    machine: Option<String>,
    /// The root this install pins, 64 hex.
    pinned: Option<String>,
    /// One page of foreign roots, by id.
    foreign: Vec<ForeignRootWire>,
    /// The `after` of the next page; none on the last.
    next: Option<String>,
    /// Every foreign root that admits a machine, across all pages.
    foreign_total: u64,
    /// Foreign roots that admit no machine.
    inert_foreign: u64,
    awaiting: Option<AwaitedRootWire>,
}

/// `GET /v1/owner/roots`: the roots this install sees, one page of foreign
/// roots at a time after `after`, ascending by id.
async fn roots(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<RootsQuery>, QueryRejection>,
) -> OwnerReply<RootsView> {
    owner(&auth, &server)?;
    let query = query_params(query)?;
    let view = blocking(move || -> OwnerResult<RootsView> {
        let after = query
            .after
            .as_deref()
            .map(|after| parse_revision("after", after).map(RecoveryRootId))
            .transpose()?;
        let limit = query.limit.unwrap_or(ROOT_PAGE_DEFAULT).max(1);
        let vault = server.vault();
        let mut view = vault.owner_root_view(after, limit.saturating_add(1))?;
        let more = view.foreign.len() > limit;
        while view.foreign.len() > limit {
            view.foreign.pop_last();
        }
        let next = more
            .then(|| {
                view.foreign
                    .last_key_value()
                    .map(|(root, _)| revision_hex(&root.0))
            })
            .flatten();
        Ok(RootsView {
            machine: vault.local_machine()?.map(|machine| machine.id.to_hex()),
            pinned: view.pinned.map(|root| revision_hex(&root.0)),
            foreign: view
                .foreign
                .iter()
                .map(|(root, machines)| ForeignRootWire {
                    root: revision_hex(&root.0),
                    machines: *machines,
                })
                .collect(),
            next,
            foreign_total: view.foreign_total,
            inert_foreign: view.inert_foreign,
            awaiting: view.awaiting.map(|awaited| AwaitedRootWire {
                root: revision_hex(&awaited.root.0),
                arrived: awaited.arrived,
            }),
        })
    })
    .await?;
    Ok(Json(view))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinRoot {
    /// The root's fingerprint, 64 hex, read on one of the owner's machines
    /// that pins it.
    root: String,
}

/// `POST /v1/owner/roots/pin`: pins the root on this install and re-wraps
/// the keys this machine may still read under it. A root this install does
/// not store yet, or one this machine is not mine under yet, is awaited: the
/// answer names it, and `GET /roots` says when it has arrived.
async fn pin(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<PinRoot>,
) -> OwnerReply<RepinView> {
    let owner = owner(&auth, &server)?;
    let body = payload.read(&server).await?;
    let report = blocking(move || -> OwnerResult<RepinView> {
        let root = RecoveryRootId(parse_revision("root", &body.root)?);
        let report = server.vault().pin_owner_root(&owner, root)?;
        Ok(RepinView::from(&report))
    })
    .await?;
    Ok(Json(report))
}
