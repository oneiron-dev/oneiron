//! What the owner's authorization-code exchanges share (Gmail's, Microsoft
//! 365's): the code and the client enter only through credential custody,
//! and the grant the provider returns is stored, answered and checked as the
//! pack connection's credential.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use oneiron::authority::ActSurface;
use oneiron::connector_key::{AuthorizationCodeGrant, ProviderConnectionChecks};
use oneiron::consent::AuthenticatedOwner;
use oneiron::error::{Error, SecretError};
use oneiron::secret_custody::{
    CustodyClass, CustodyPlan, CustodyTier, OwnerSecretRegistration, RequestedBinding,
};
use oneiron::skill_hub::pack_catalog::{PackSetupAnswer, PackSetupView};
use serde::{Deserialize, Serialize};

use super::super::{OwnerReply, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::builtin_host::HostConnectionChecks;
use crate::owner::OwnerError;
use crate::server::SyncServer;

/// Credential names only. Code, verifier and client-secret values never
/// enter this DTO.
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ExchangeRequest {
    client_secret: String,
    authorization_secret: String,
    #[serde(default)]
    source: Option<String>,
    class: String,
    device_only: bool,
    rung: u8,
    /// Explicit permission to rotate an existing credential of the
    /// connection's grant name (gmail.oauth, microsoft365.oauth).
    replace_existing: bool,
}

#[derive(Serialize, schemars::JsonSchema)]
pub(super) struct ExchangeReply {
    setup: PackSetupView,
    /// False means the provider issued access only; no older refresh token
    /// is borrowed.
    refreshable: bool,
}

/// The pack connection one exchange stores its grant for.
pub(super) struct ExchangeTarget {
    pub(super) pack: &'static str,
    pub(super) connection: &'static str,
    /// The effector both input credentials are read through and the stored
    /// grant is bound to, with read.
    pub(super) effector: &'static str,
    /// The stored grant's custody name.
    pub(super) grant: &'static str,
    /// The provider, as an error names it: `Google`, `Microsoft`.
    pub(super) provider: &'static str,
}

/// A provider's code exchange: the stored client and the stored completed
/// authorization, read inside their credential doors, to the grant.
pub(super) type CodeExchange =
    fn(&ProviderConnectionChecks, &[u8], &[u8]) -> oneiron::Result<AuthorizationCodeGrant>;

pub(super) fn request_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ExchangeRequest>()
}

pub(super) fn reply_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ExchangeReply>()
}

/// The route body of an exchange for `target` through `exchange`.
pub(super) async fn exchange_route(
    target: &'static ExchangeTarget,
    exchange: CodeExchange,
    auth: CoreAuth,
    headers: axum::http::HeaderMap,
    extensions: axum::http::Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<ExchangeRequest>,
) -> OwnerReply<ExchangeReply> {
    let owner = owner(&auth, &server)?;
    let surface =
        super::super::machine_routes::act_surface_admitted(&server, &auth, &headers, &extensions);
    let request = payload.read(&server).await?;
    let reply =
        blocking(move || exchange_admitted(&server, &owner, surface, target, exchange, &request))
            .await?;
    Ok(Json(reply))
}

fn exchange_admitted(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    target: &ExchangeTarget,
    exchange: CodeExchange,
    request: &ExchangeRequest,
) -> Result<ExchangeReply, OwnerError> {
    let class = CustodyClass::parse(&request.class)
        .ok_or_else(|| OwnerError::Invalid("unknown custody class".to_owned()))?;
    let rung = CustodyTier::from_u8(request.rung)
        .ok_or_else(|| OwnerError::Invalid("unknown custody rung".to_owned()))?;
    let vault = server.vault();
    // Resolve the real setup before consuming a single-use code.
    vault.pack_setup(owner, target.pack, request.source.as_deref())?;
    if !request.replace_existing && vault.resolve_secret_ref(target.grant)?.is_some() {
        return Err(Error::Secret(SecretError::SecretNameInUse {
            name: target.grant.to_owned(),
        })
        .into());
    }
    let checks = ProviderConnectionChecks::new()?;
    let mut grant = None;
    vault.inject_secret_at_door(
        &request.client_secret,
        target.effector,
        &mut |client_bytes| {
            vault.inject_secret_at_door(
                &request.authorization_secret,
                target.effector,
                &mut |authorization_bytes| {
                    grant = Some(exchange(&checks, client_bytes, authorization_bytes)?);
                    Ok(())
                },
            )?;
            Ok(())
        },
    )?;
    let grant = grant.ok_or_else(|| {
        Error::InvalidConfig(format!("the {} code exchange did not run", target.provider))
    })?;
    let refreshable = grant.has_refresh_token();
    let registration = OwnerSecretRegistration {
        name: target.grant,
        class,
        device_only: request.device_only,
        rung,
        bindings: vec![RequestedBinding {
            effector: target.effector.to_owned(),
            tier_ceiling: None,
            scopes: vec!["read".to_owned()],
        }],
        manifest: None,
        value: grant.as_bytes(),
    };
    let plan = CustodyPlan::default();
    let at = vault.now_recorded_at();
    match vault.register_secret_with_custody(owner, surface, &registration, &plan, at) {
        Ok(_) => {}
        Err(Error::Secret(SecretError::SecretNameInUse { .. })) if request.replace_existing => {
            let rotated = vault.rotate_secret_with_custody(
                owner,
                surface,
                target.grant,
                grant.as_bytes(),
                &plan,
                at,
            )?;
            if rotated.rotation.is_none() {
                return Err(invalid("the rotation is recorded for its holder to perform").into());
            }
        }
        Err(error) => return Err(error.into()),
    }
    drop(grant);
    vault.answer_pack_setup(
        owner,
        target.pack,
        request.source.as_deref(),
        &PackSetupAnswer::SecretStored {
            connection: target.connection.to_owned(),
            secret: target.grant.to_owned(),
        },
    )?;
    let checks = HostConnectionChecks::new(server)?;
    let setup = vault.verify_pack_connection(
        owner,
        target.pack,
        request.source.as_deref(),
        target.connection,
        &checks,
    )?;
    Ok(ExchangeReply { setup, refreshable })
}

pub(super) fn invalid(message: &'static str) -> Error {
    Error::InvalidConfig(message.to_owned())
}
