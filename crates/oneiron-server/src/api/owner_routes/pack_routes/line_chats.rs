//! `/v1/owner/packs/line/chats`: the LINE groups and rooms the served bot
//! was seen in, as optional offers to bind one to an agent, and the
//! owner's accept (FIX 3115). An accept provisions the chat's own route key
//! through the owner's ordinary provision door and answers with that
//! door's lifecycle receipt as it stands (pending fulfillment, held or
//! applied), never a bare "bound".

use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::channel_identity::{
    ChannelIdentityBinding, ChannelIdentityFulfillment, SelfHeldShape,
};
use oneiron::channel_identity_provider::{LINE_CHANNEL, LineChatBindingOffer};
use oneiron::memory::channel_doors::{
    ChannelIdentityLifecycleReceipt, ChannelIdentityProvisionRequest,
};
use oneiron::{EdgeActorClass, EntityId};
use serde::Deserialize;

use super::super::{OwnerReply, OwnerRoute, OwnerTable, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, memory_refusal};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/packs/line/chats",
                summary: "Every LINE group or room the served bot was seen in (FIX 3115), each an optional offer to bind it to an agent: the route key a bind provisions and the identity that already holds it, if any.",
                row: None,
                shape: None,
            },
            get(chat_offers),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/line/chats/bind",
                summary: "Bind one observed LINE chat to an agent (`observation_ref`, `agent_ref`; the chat comes from the stored observation, never the request): provisions the chat's own route key through the owner's provision door and answers that door's lifecycle receipt as it stands (pending fulfillment, held or applied).",
                row: None,
                shape: None,
            },
            post(bind_chat),
        ),
    ]
}

/// The owner's accept of one offer: which observed chat, and which agent.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindLineChat {
    observation_ref: EntityId,
    agent_ref: EntityId,
}

/// `GET /v1/owner/packs/line/chats`: every chat the served bot was seen
/// in, each with the route key a bind provisions and the identity that
/// already holds it, if any.
async fn chat_offers(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Vec<LineChatBindingOffer>> {
    owner(&auth, &server)?;
    let offers = blocking(move || -> OwnerResult<Vec<LineChatBindingOffer>> {
        let Some(line) = server.builtin_handles.line() else {
            return Err(no_line_bot());
        };
        Ok(server.vault().line_chat_binding_offers(&line.adapter)?)
    })
    .await?;
    Ok(Json(offers))
}

/// `POST /v1/owner/packs/line/chats/bind`: binds one observed chat to an
/// agent. The chat comes from the stored observation, never the request.
async fn bind_chat(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<BindLineChat>,
) -> OwnerReply<ChannelIdentityLifecycleReceipt> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let locality = auth.locality();
    let receipt = blocking(move || -> OwnerResult<ChannelIdentityLifecycleReceipt> {
        let Some(line) = server.builtin_handles.line() else {
            return Err(no_line_bot());
        };
        let vault = server.vault();
        let observation = vault
            .line_chat_observation(&request.observation_ref)?
            .ok_or_else(|| {
                OwnerError::NotFound("LINE chat observation", request.observation_ref.to_hex())
            })?;
        if observation.destination != line.destination {
            return Err(OwnerError::Invalid(
                "the chat was seen on another LINE bot than the one this host serves".to_owned(),
            ));
        }
        let input = ChannelIdentityProvisionRequest {
            channel: LINE_CHANNEL.to_owned(),
            address_or_handle: line.adapter.address_for_line_chat(&observation.chat)?,
            shape: SelfHeldShape::SharedPresence,
            binding: ChannelIdentityBinding::agent(request.agent_ref),
            fulfillment_mode: ChannelIdentityFulfillment::Manual,
            request_ref: None,
        };
        let actor = owner.revalidate(vault)?;
        vault
            .memory(actor, EdgeActorClass::Human)
            .at(locality)
            .channel_identity_provision_as(&owner, input)
            .map_err(memory_refusal)
    })
    .await?;
    Ok(Json(receipt))
}

fn no_line_bot() -> OwnerError {
    OwnerError::NotFound("served LINE bot", "line".to_owned())
}
