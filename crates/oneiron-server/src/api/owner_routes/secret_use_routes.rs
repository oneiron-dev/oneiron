//! `POST /v1/owner/secrets/bind`: the owner binds a secret to an effector, so
//! an agent's `self.use` can hand it to that effector's operation (OF-560).
//! A secret the mask on write found holds no binding, and `self.use` names
//! this door when it refuses one. The reply names the handle and the
//! bindings, never the value.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use axum::routing::post;
use oneiron::secret_custody::{CustodyTier, RevealTarget, SecretBindRequest, SecretBound};
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::json_payload;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route("/secrets/bind", post(bind))
}

/// The secret by exactly one of its handle or its name, the effector, and
/// the binding's rung and scopes.
#[derive(Debug, Deserialize)]
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

#[derive(Debug, Serialize)]
struct BindingView {
    effector: String,
    tier_ceiling: u8,
    scopes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct BoundView {
    secret_id: String,
    handle: String,
    name: String,
    bindings: Vec<BindingView>,
    /// The Gate record that keeps the binding, `gate:<hex>`.
    receipt_ref: String,
}

impl From<SecretBound> for BoundView {
    fn from(bound: SecretBound) -> Self {
        Self {
            secret_id: bound.secret_id.to_hex(),
            handle: bound.handle,
            name: bound.name,
            bindings: bound
                .bindings
                .into_iter()
                .map(|binding| BindingView {
                    effector: binding.effector,
                    tier_ceiling: binding.tier_ceiling.as_u8(),
                    scopes: binding.scopes,
                })
                .collect(),
            receipt_ref: format!("gate:{}", bound.receipt.to_hex()),
        }
    }
}

/// `POST /v1/owner/secrets/bind` with `{"handle"}` or `{"name"}`,
/// `"effector"`, and optionally `"tier_ceiling"` and `"scopes"`.
async fn bind(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<BindBody>, JsonRejection>,
) -> OwnerReply<BoundView> {
    let owner = owner(&auth, &server)?;
    let body = json_payload(payload)?;
    let bound = blocking(move || -> OwnerResult<BoundView> {
        let target = match (body.handle, body.name) {
            (Some(handle), None) => RevealTarget::Handle(handle),
            (None, Some(name)) => RevealTarget::Name(name),
            _ => {
                return Err(OwnerError::Invalid(
                    "name the secret by exactly one of handle or name".to_owned(),
                ));
            }
        };
        let tier_ceiling = match body.tier_ceiling {
            None => CustodyTier::T0Doored,
            Some(grade) => CustodyTier::from_u8(grade).ok_or_else(|| {
                OwnerError::Invalid(
                    "a rung is 0 (doored), 1 (leased) or 2 (local-registered)".to_owned(),
                )
            })?,
        };
        let request = SecretBindRequest {
            target,
            effector: body.effector,
            tier_ceiling,
            scopes: body
                .scopes
                .unwrap_or_else(SecretBindRequest::default_scopes),
        };
        let vault = server.vault();
        Ok(vault
            .bind_secret_as_owner(&owner, &request, vault.now_recorded_at())?
            .into())
    })
    .await?;
    Ok(Json(bound))
}
