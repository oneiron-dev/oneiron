//! `POST /v1/owner/secrets/bind`: the owner binds a secret to an effector, so
//! an agent's `self.use` can hand it to that effector's operation (OF-560).
//! A secret the mask on write found holds no binding, and `self.use` names
//! this door when it refuses one. `POST /v1/owner/secrets/unbind` withdraws
//! one binding, and every other stays (FIX 2620). Each reply names the
//! handle and the bindings, never the value.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use axum::routing::post;
use oneiron::secret_custody::SecretBindRequest;
use serde::Deserialize;

use super::{OwnerReply, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::OwnerResult;
use crate::owner::secret_bindings::{self, BoundView};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/secrets/bind", post(bind))
        .route("/secrets/unbind", post(unbind))
}

/// The OpenAPI schema of `POST /v1/owner/secrets/bind`'s body (FIX 11611): [`BindBody`].
pub(crate) fn bind_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<BindBody>()
}

/// The OpenAPI schema of `POST /v1/owner/secrets/unbind`'s body (FIX 11611): [`UnbindBody`].
pub(crate) fn unbind_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<UnbindBody>()
}

/// The OpenAPI schema of `POST /v1/owner/secrets/bind`'s answer (FIX 11611),
/// shared with `POST /v1/owner/secrets/unbind`: [`BoundView`].
pub(crate) fn bound_view_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<BoundView>()
}

/// The secret by exactly one of its handle or its name, the effector, and
/// the binding's rung and scopes.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct BindBody {
    #[serde(default)]
    handle: Option<String>,
    #[serde(default)]
    name: Option<String>,
    effector: String,
    /// The custody ladder's rung: 0 doored (the default), 1 leased, 2
    /// local-registered.
    #[serde(default)]
    tier_ceiling: Option<u8>,
    /// What the binding grants; `["read"]` when absent.
    #[serde(default)]
    scopes: Option<Vec<String>>,
}

/// The secret by exactly one of its handle or its name, and the effector
/// whose binding is withdrawn.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct UnbindBody {
    #[serde(default)]
    handle: Option<String>,
    #[serde(default)]
    name: Option<String>,
    effector: String,
}

/// `POST /v1/owner/secrets/bind` with `{"handle"}` or `{"name"}`,
/// `"effector"`, and optionally `"tier_ceiling"` and `"scopes"`. A portable
/// record's rewrap records where this request reached this install
/// (`machine_routes::act_surface_admitted`): audit only (FIX 4650).
async fn bind(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<BindBody>,
) -> OwnerReply<BoundView> {
    let owner = owner(&auth, &server)?;
    let surface =
        super::machine_routes::act_surface_admitted(&server, &auth, &headers, &extensions);
    let body = payload.read(&server).await?;
    let bound = blocking(move || -> OwnerResult<BoundView> {
        let request = SecretBindRequest {
            target: secret_bindings::target(body.handle, body.name)?,
            effector: body.effector,
            tier_ceiling: secret_bindings::rung(body.tier_ceiling)?,
            scopes: body
                .scopes
                .unwrap_or_else(SecretBindRequest::default_scopes),
        };
        secret_bindings::bind(server.vault(), &owner, surface, &request)
    })
    .await?;
    Ok(Json(bound))
}

/// `POST /v1/owner/secrets/unbind` with `{"handle"}` or `{"name"}` and
/// `"effector"`: the owner's withdrawal of that one binding. The reply is
/// the bind's, with the bindings the record still holds; the rewrap records
/// where the request reached this install, audit only.
async fn unbind(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<UnbindBody>,
) -> OwnerReply<BoundView> {
    let owner = owner(&auth, &server)?;
    let surface =
        super::machine_routes::act_surface_admitted(&server, &auth, &headers, &extensions);
    let body = payload.read(&server).await?;
    let unbound = blocking(move || -> OwnerResult<BoundView> {
        let target = secret_bindings::target(body.handle, body.name)?;
        secret_bindings::unbind(server.vault(), &owner, surface, &target, &body.effector)
    })
    .await?;
    Ok(Json(unbound))
}
