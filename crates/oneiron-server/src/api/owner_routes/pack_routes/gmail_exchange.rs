//! Owner-admitted Google authorization codes enter only through credential custody.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::post;
use oneiron::authority::ActSurface;
use oneiron::connector_key::{GoogleAuthorizationCode, ProviderConnectionChecks};
use oneiron::consent::AuthenticatedOwner;
use oneiron::error::{Error, SecretError};
use oneiron::secret_custody::{
    CustodyClass, CustodyPlan, CustodyTier, OwnerSecretRegistration, RequestedBinding,
};
use oneiron::skill_hub::pack_catalog::{PackSetupAnswer, PackSetupView};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::super::{OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::builtin_host::HostConnectionChecks;
use crate::owner::OwnerError;
use crate::server::SyncServer;

const PACK: &str = "oneiron.email";
const CONNECTION: &str = "gmail";
const EFFECTOR: &str = "connector:gmail";
const GRANT: &str = "gmail.oauth";

/// Credential names only. Code, verifier and client-secret values never enter this DTO.
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ExchangeRequest {
    client_secret: String,
    authorization_secret: String,
    #[serde(default)]
    source: Option<String>,
    class: String,
    device_only: bool,
    rung: u8,
    /// Explicit permission to rotate an existing gmail.oauth credential.
    replace_existing: bool,
}

#[derive(Serialize, schemars::JsonSchema)]
struct ExchangeReply {
    setup: PackSetupView,
    /// False means Google issued access only; no older refresh token is borrowed.
    refreshable: bool,
}

pub(super) fn owner_table() -> OwnerTable {
    vec![(
        OwnerRoute {
            method: "post",
            path: "/packs/gmail/exchange",
            summary: "Exchange an owner-admitted Google authorization code and store its Gmail grant.",
            row: None,
            shape: Some(RestShape::json(request_schema, reply_schema)),
        },
        post(exchange),
    )]
}

fn request_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ExchangeRequest>()
}

fn reply_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ExchangeReply>()
}

async fn exchange(
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
    let reply = blocking(move || exchange_admitted(&server, &owner, surface, &request)).await?;
    Ok(Json(reply))
}

fn exchange_admitted(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    request: &ExchangeRequest,
) -> Result<ExchangeReply, OwnerError> {
    let class = CustodyClass::parse(&request.class)
        .ok_or_else(|| OwnerError::Invalid("unknown custody class".to_owned()))?;
    let rung = CustodyTier::from_u8(request.rung)
        .ok_or_else(|| OwnerError::Invalid("unknown custody rung".to_owned()))?;
    let vault = server.vault();
    // Resolve the real setup before consuming a single-use Google code.
    vault.pack_setup(owner, PACK, request.source.as_deref())?;
    if !request.replace_existing && vault.resolve_secret_ref(GRANT)?.is_some() {
        return Err(Error::Secret(SecretError::SecretNameInUse {
            name: GRANT.to_owned(),
        })
        .into());
    }
    let checks = ProviderConnectionChecks::new()?;
    let mut grant = None;
    vault.inject_secret_at_door(&request.client_secret, EFFECTOR, &mut |client_bytes| {
        let client: ClientCredential = serde_json::from_slice(client_bytes)
            .map_err(|_| invalid("the stored Google client credential is not JSON"))?;
        vault.inject_secret_at_door(
            &request.authorization_secret,
            EFFECTOR,
            &mut |authorization_bytes| {
                let authorization: Authorization = serde_json::from_slice(authorization_bytes)
                    .map_err(|_| invalid("the stored Google authorization is not JSON"))?;
                grant = Some(checks.exchange_google_authorization_code(
                    GoogleAuthorizationCode {
                        client_id: &client.client_id,
                        client_secret: &client.client_secret,
                        code: &authorization.code,
                        redirect_uri: &authorization.redirect_uri,
                        code_verifier: authorization.code_verifier.as_deref(),
                    },
                )?);
                Ok(())
            },
        )?;
        Ok(())
    })?;
    let grant = grant.ok_or_else(|| invalid("the Google code exchange did not run"))?;
    let refreshable = grant.has_refresh_token();
    let registration = OwnerSecretRegistration {
        name: GRANT,
        class,
        device_only: request.device_only,
        rung,
        bindings: vec![RequestedBinding {
            effector: EFFECTOR.to_owned(),
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
                GRANT,
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
        PACK,
        request.source.as_deref(),
        &PackSetupAnswer::SecretStored {
            connection: CONNECTION.to_owned(),
            secret: GRANT.to_owned(),
        },
    )?;
    let checks = HostConnectionChecks::new(server)?;
    let setup = vault.verify_pack_connection(
        owner,
        PACK,
        request.source.as_deref(),
        CONNECTION,
        &checks,
    )?;
    Ok(ExchangeReply { setup, refreshable })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientCredential {
    client_id: String,
    client_secret: String,
}

impl Drop for ClientCredential {
    fn drop(&mut self) {
        self.client_secret.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Authorization {
    code: String,
    redirect_uri: String,
    #[serde(default)]
    code_verifier: Option<String>,
}

impl Drop for Authorization {
    fn drop(&mut self) {
        self.code.zeroize();
        self.code_verifier.zeroize();
    }
}

fn invalid(message: &'static str) -> Error {
    Error::InvalidConfig(message.to_owned())
}
