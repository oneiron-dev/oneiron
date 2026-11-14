//! Owner-admitted Google authorization codes enter only through credential custody.

use std::sync::Arc;

use axum::extract::State;
use axum::routing::post;
use oneiron::connector_key::{
    AuthorizationCodeGrant, GoogleAuthorizationCode, ProviderConnectionChecks,
};
use serde::Deserialize;
use zeroize::Zeroize;

use super::super::{OwnerReply, OwnerRoute, OwnerTable, RestShape};
use super::code_exchange::{
    CodeExchange, ExchangeReply, ExchangeRequest, ExchangeTarget, exchange_route, invalid,
    reply_schema, request_schema,
};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

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

async fn exchange(
    auth: CoreAuth,
    headers: axum::http::HeaderMap,
    extensions: axum::http::Extensions,
    server: State<Arc<SyncServer>>,
    payload: OwnerJsonBody<ExchangeRequest>,
) -> OwnerReply<ExchangeReply> {
    exchange_route::<GoogleCode>(auth, headers, extensions, server, payload).await
}

/// Google's code exchange for the stored web client and the stored completed
/// authorization.
enum GoogleCode {}

impl CodeExchange for GoogleCode {
    type Client = ClientCredential;
    const TARGET: ExchangeTarget = ExchangeTarget {
        pack: "oneiron.email",
        connection: "gmail",
        effector: "connector:gmail",
        grant: "gmail.oauth",
        provider: "Google",
    };

    fn client(bytes: &[u8]) -> oneiron::Result<ClientCredential> {
        serde_json::from_slice(bytes)
            .map_err(|_| invalid("the stored Google client credential is not JSON"))
    }

    fn exchange(
        checks: &ProviderConnectionChecks,
        client: &ClientCredential,
        authorization_bytes: &[u8],
    ) -> oneiron::Result<AuthorizationCodeGrant> {
        let authorization: Authorization = serde_json::from_slice(authorization_bytes)
            .map_err(|_| invalid("the stored Google authorization is not JSON"))?;
        checks.exchange_google_authorization_code(GoogleAuthorizationCode {
            client_id: &client.client_id,
            client_secret: &client.client_secret,
            code: &authorization.code,
            redirect_uri: &authorization.redirect_uri,
            code_verifier: authorization.code_verifier.as_deref(),
        })
    }
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
