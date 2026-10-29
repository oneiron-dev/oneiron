//! `/v1/owner/packs/setup` and `/v1/owner/packs/slack`: the owner's guided
//! setup of one pack (OF-378), and the Slack app's manifest and install link
//! (OF-519).

use std::sync::Arc;

use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::response::Json;
use oneiron::lens::{GeneratedUiCard, GeneratedUiStateSnapshot};
use oneiron::skill_hub::pack_catalog::{PackSetupAnswer, PackSetupCardAction, PackSetupView};
use serde::{Deserialize, Serialize};

use super::super::{OwnerReply, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::api::query_params;
use crate::auth::CoreAuth;
use crate::builtin_host::{
    HostConnectionChecks, ProviderSetup, public_origin, slack_app_manifest, start_slack_install,
};
use crate::owner::OwnerError;
use crate::server::SyncServer;

/// One pack's setup: by name, and by content hash when several sources wait.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct PackSetupKey {
    pack: String,
    /// One exact source; else the Active one, or the pack's one Candidate.
    #[serde(default)]
    source: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct PackSetupAnswerRequest {
    pack: String,
    #[serde(default)]
    source: Option<String>,
    /// A typed answer.
    #[serde(default)]
    answer: Option<PackSetupAnswer>,
    /// Or one action from the setup's cards, with the card's `$state`.
    #[serde(default)]
    card_action: Option<PackSetupCardActionRequest>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct PackSetupCardActionRequest {
    action_id: String,
    #[serde(default)]
    state: GeneratedUiStateSnapshot,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct PackSetupVerifyRequest {
    pack: String,
    #[serde(default)]
    source: Option<String>,
    connection: String,
}

/// The setup, its GenUI cards and its plain text.
#[derive(Serialize, schemars::JsonSchema)]
pub(super) struct PackSetupReply {
    setup: PackSetupView,
    cards: Vec<GeneratedUiCard>,
    text: String,
    /// A built-in channel's provider URLs at this host, and Slack's manifest.
    #[serde(flatten)]
    provider: ProviderSetup,
    /// Set when a card asked to store a credential: the owner secrets door
    /// takes the value, then a `secret_stored` answer pins its record.
    #[serde(skip_serializing_if = "Option::is_none")]
    store_secret: Option<PackSetupStoreSecret>,
}

#[derive(Serialize, schemars::JsonSchema)]
struct PackSetupStoreSecret {
    door: &'static str,
    connection: String,
    name: String,
    /// The binding the stored credential needs, with the read scope.
    effector: String,
}

impl PackSetupReply {
    fn new(setup: PackSetupView, server: &SyncServer) -> Result<Self, OwnerError> {
        let provider = ProviderSetup::for_pack(
            &setup.pack_name,
            server.config.oauth_resource_indicator.as_deref(),
        )?;
        Ok(Self {
            cards: setup.cards()?,
            text: setup.text() + &provider.text(),
            setup,
            provider,
            store_secret: None,
        })
    }
}

/// `GET /v1/owner/packs/setup?pack=&source=`: the owner's guided setup of one
/// pack (OF-378), readable while the pack is still a Candidate.
pub(super) async fn setup_view(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<PackSetupKey>, QueryRejection>,
) -> OwnerReply<PackSetupReply> {
    let owner = owner(&auth, &server)?;
    let key = query_params(query)?;
    let reply = blocking(move || {
        PackSetupReply::new(
            server
                .vault()
                .pack_setup(&owner, &key.pack, key.source.as_deref())?,
            &server,
        )
    })
    .await?;
    Ok(Json(reply))
}

/// `POST /v1/owner/packs/setup/prepare`: open, or resume, the setup. Opening
/// grants nothing.
pub(super) async fn setup_prepare(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<PackSetupKey>,
) -> OwnerReply<PackSetupReply> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let reply = blocking(move || {
        PackSetupReply::new(
            server
                .vault()
                .prepare_pack_setup(&owner, &request.pack, request.source.as_deref())?,
            &server,
        )
    })
    .await?;
    Ok(Json(reply))
}

/// `POST /v1/owner/packs/setup/answer`: one typed answer, or one card action.
/// A credential value never comes here: a card's store button answers with
/// the owner secrets door to open.
pub(super) async fn setup_answer(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<PackSetupAnswerRequest>,
) -> OwnerReply<PackSetupReply> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let reply = blocking(move || {
        let vault = server.vault();
        let source = request.source.as_deref();
        let answer = match (request.answer, request.card_action) {
            (Some(answer), None) => answer,
            (None, Some(card)) => {
                let view = vault.pack_setup(&owner, &request.pack, source)?;
                match view.card_action(&card.action_id, &card.state)? {
                    PackSetupCardAction::Answer(answer) => answer,
                    PackSetupCardAction::Verify { connection } => {
                        let checks = HostConnectionChecks::new(&server)?;
                        return PackSetupReply::new(
                            vault.verify_pack_connection(
                                &owner,
                                &request.pack,
                                source,
                                &connection,
                                &checks,
                            )?,
                            &server,
                        );
                    }
                    PackSetupCardAction::StoreSecret {
                        connection,
                        secret,
                        effector,
                    } => {
                        let mut reply = PackSetupReply::new(view, &server)?;
                        reply.store_secret = Some(PackSetupStoreSecret {
                            door: "/v1/owner/secrets/register",
                            connection,
                            name: secret,
                            effector,
                        });
                        return Ok(reply);
                    }
                }
            }
            _ => {
                return Err(OwnerError::Invalid(
                    "send exactly one of answer or card_action".to_owned(),
                ));
            }
        };
        PackSetupReply::new(
            vault.answer_pack_setup(&owner, &request.pack, source, &answer)?,
            &server,
        )
    })
    .await?;
    Ok(Json(reply))
}

/// `POST /v1/owner/packs/setup/verify`: check one connection before the pack
/// uses it. The check is the engine's fixed read-only provider call for the
/// declared check name; a pack never names a URL.
pub(super) async fn setup_verify(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<PackSetupVerifyRequest>,
) -> OwnerReply<PackSetupReply> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let reply = blocking(move || {
        let checks = HostConnectionChecks::new(&server)?;
        PackSetupReply::new(
            server.vault().verify_pack_connection(
                &owner,
                &request.pack,
                request.source.as_deref(),
                &request.connection,
                &checks,
            )?,
            &server,
        )
    })
    .await?;
    Ok(Json(reply))
}

/// `GET /v1/owner/packs/slack/manifest`: the Slack app manifest at this
/// host's public origin, to paste at api.slack.com/apps (OF-519). It needs
/// no checked connection, since the app is made first.
pub(super) async fn slack_manifest(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<serde_json::Value> {
    owner(&auth, &server)?;
    let manifest = blocking(move || {
        let origin =
            public_origin(server.config.oauth_resource_indicator.as_deref()).ok_or_else(|| {
                OwnerError::Invalid(
                    "this host has no public https origin; set oauth_resource_indicator to it first"
                        .to_owned(),
                )
            })?;
        Ok(slack_app_manifest(&origin)?)
    })
    .await?;
    Ok(Json(manifest))
}

/// The Slack setup to install for: by content hash when several wait.
#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct SlackInstallRequest {
    #[serde(default)]
    source: Option<String>,
}

/// `POST /v1/owner/packs/slack/install`: one link that installs the Slack
/// app to the owner's workspace (OF-519). Slack's redirect redeems it once,
/// within ten minutes, and the host stores and checks the bot token under
/// this owner's proof, recording where this request reached it (FIX 4650).
pub(super) async fn slack_install(
    auth: CoreAuth,
    headers: axum::http::HeaderMap,
    extensions: axum::http::Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<SlackInstallRequest>,
) -> OwnerReply<crate::builtin_host::SlackInstallLink> {
    let owner = owner(&auth, &server)?;
    let surface =
        super::super::machine_routes::act_surface_admitted(&server, &auth, &headers, &extensions);
    let request = payload.read(&server).await?;
    let link =
        blocking(move || start_slack_install(&server, owner, surface, request.source)).await?;
    Ok(Json(link))
}
