//! Owner-admitted Microsoft authorization codes enter only through
//! credential custody ([MICROSOFT365-OAUTH-EXCHANGE]). The grant is stored
//! as the Microsoft 365 pack's `microsoft365.oauth`, bound to
//! `connector:microsoft365`: the Excel connection reads it, and a Microsoft
//! 365 mailbox source may name the same record (RULING
//! L3-17-EXCEL-CONNECTION = B).

use std::sync::Arc;

use axum::extract::State;
use axum::routing::post;
use oneiron::connector_key::{
    AuthorizationCodeGrant, MicrosoftAuthorizationCode, ProviderConnectionChecks,
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
            path: "/packs/microsoft365/exchange",
            summary: "Exchange an owner-admitted Microsoft authorization code and store its Microsoft 365 grant.",
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
    exchange_route::<MicrosoftCode>(auth, headers, extensions, server, payload).await
}

/// Microsoft's code exchange for the stored client and the stored completed
/// authorization, at the client's tenant.
enum MicrosoftCode {}

impl CodeExchange for MicrosoftCode {
    type Client = ClientCredential;
    const TARGET: ExchangeTarget = ExchangeTarget {
        pack: "oneiron.microsoft365",
        connection: "microsoft365",
        effector: "connector:microsoft365",
        grant: "microsoft365.oauth",
        provider: "Microsoft",
    };

    fn client(bytes: &[u8]) -> oneiron::Result<ClientCredential> {
        serde_json::from_slice(bytes)
            .map_err(|_| invalid("the stored Microsoft client credential is not JSON"))
    }

    fn exchange(
        checks: &ProviderConnectionChecks,
        client: &ClientCredential,
        authorization_bytes: &[u8],
    ) -> oneiron::Result<AuthorizationCodeGrant> {
        let authorization: Authorization = serde_json::from_slice(authorization_bytes)
            .map_err(|_| invalid("the stored Microsoft authorization is not JSON"))?;
        checks.exchange_microsoft_authorization_code(MicrosoftAuthorizationCode {
            client_id: &client.client_id,
            client_secret: client.client_secret.as_deref(),
            tenant: &client.tenant,
            code: &authorization.code,
            redirect_uri: &authorization.redirect_uri,
            code_verifier: authorization.code_verifier.as_deref(),
        })
    }
}

/// The app registration the sign-in ran on: its client id, its secret (a
/// web application's; none for a public client) and the tenant it signs in
/// against.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientCredential {
    client_id: String,
    #[serde(default)]
    client_secret: Option<String>,
    tenant: String,
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
