//! `/v1/owner/packs/native_mail/identities`: the owner provisions an
//! agent's native mail identity end to end (FIX 2096) through the native
//! mail pack this host serves. The identity's lifecycle request passes the
//! pack's provision door, whose ExternalEffect gate decides; an admitted one
//! takes its mailbox on the mail server and is fulfilled. A provision whose
//! mailbox work failed stays pending fulfillment, and
//! `.../identities/complete` retries that work for the admitted row.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::response::Json;
use axum::routing::post;
use oneiron::channel_identity::{ChannelIdentityFulfillment, ChannelIdentityState};
use oneiron::channel_identity_lifecycle::{
    ChannelIdentityLifecycleActor, ChannelIdentityLifecycleGate, ChannelIdentityLifecycleIntent,
    ChannelIdentityLifecycleRequest, ChannelIdentityLifecycleResult, ProvisionIntent,
};
use oneiron::channel_identity_provider::native_mail::NativeMailPack;
use oneiron::{EntityId, Vault};
use serde::{Deserialize, Serialize};

use super::super::{OwnerReply, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/packs/native_mail/identities", post(provision_identity))
        .route(
            "/packs/native_mail/identities/complete",
            post(complete_identity),
        )
}

/// The agent a new native mail identity speaks for, and its address.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvisionNativeMail {
    agent_ref: EntityId,
    /// A chosen local part on the managed domain (`eiri@`); absent, the
    /// identity takes its derived `mail-<id>` address.
    #[serde(default)]
    local_part: Option<String>,
}

/// The pending identity whose mailbox work is retried.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteNativeMail {
    identity_ref: EntityId,
}

/// Where one provision stands: the lifecycle receipt as the door answered
/// it, or, when the mailbox work failed after admission, the pending row and
/// why, for `.../complete` to retry.
#[derive(Debug, Serialize)]
struct NativeMailProvisionReply {
    identity_ref: EntityId,
    address: String,
    state: ChannelIdentityState,
    outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gate_receipt_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    reason_codes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fulfillment_error: Option<String>,
}

/// `POST /v1/owner/packs/native_mail/identities`: requests the agent's
/// identity through the pack's provision door, which fulfills an admitted
/// one on the mail server.
async fn provision_identity(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<ProvisionNativeMail>,
) -> OwnerReply<NativeMailProvisionReply> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let reply = blocking(move || -> OwnerResult<NativeMailProvisionReply> {
        let vault = server.vault();
        owner.revalidate(vault)?;
        server
            .builtin_handles
            .with_native_mail_pack(|pack| provision(vault, pack, &request))
            .unwrap_or_else(|| Err(no_native_mail()))
    })
    .await?;
    Ok(Json(reply))
}

/// `POST /v1/owner/packs/native_mail/identities/complete`: retries the
/// mailbox work of an identity the gate admitted and the mail server has
/// not fulfilled, as the agent it is bound to requested it.
async fn complete_identity(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<CompleteNativeMail>,
) -> OwnerReply<NativeMailProvisionReply> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let reply = blocking(move || -> OwnerResult<NativeMailProvisionReply> {
        let vault = server.vault();
        owner.revalidate(vault)?;
        server
            .builtin_handles
            .with_native_mail_pack(|pack| complete(vault, pack, request.identity_ref))
            .unwrap_or_else(|| Err(no_native_mail()))
    })
    .await?;
    Ok(Json(reply))
}

fn provision(
    vault: &Vault,
    pack: &NativeMailPack,
    request: &ProvisionNativeMail,
) -> OwnerResult<NativeMailProvisionReply> {
    let identity_id = EntityId::now();
    let now = vault.now_recorded_at();
    let identity = match request.local_part.as_deref() {
        Some(local_part) => pack.adapter().requested_named_identity(
            identity_id,
            local_part,
            request.agent_ref,
            now,
        )?,
        None => pack
            .adapter()
            .requested_identity(identity_id, request.agent_ref, now),
    };
    let lifecycle = ChannelIdentityLifecycleRequest {
        actor: ChannelIdentityLifecycleActor::agent(request.agent_ref),
        // The ExternalEffect gate still decides; these flags only say the
        // owner asked.
        gate: ChannelIdentityLifecycleGate::allow_when_policy_grants(),
        requested_at: now,
        intent: ChannelIdentityLifecycleIntent::Provision(ProvisionIntent {
            identity_id,
            identity,
            fulfillment_mode: ChannelIdentityFulfillment::Api,
        }),
    };
    match pack.provision_identity(vault, lifecycle) {
        Ok(result) => Ok(lifecycle_reply(vault, identity_id, &result)?),
        Err(error) => pending_reply(vault, identity_id, &error).ok_or_else(|| error.into()),
    }
}

fn complete(
    vault: &Vault,
    pack: &NativeMailPack,
    identity_id: EntityId,
) -> OwnerResult<NativeMailProvisionReply> {
    let not_found = || OwnerError::NotFound("native mail identity", identity_id.to_hex());
    let identity = vault
        .get_channel_identity(&identity_id)?
        .ok_or_else(not_found)?;
    let agent = identity
        .binding()
        .actor_ref()
        .ok_or_else(|| OwnerError::Invalid("the identity is bound to no agent".to_owned()))?;
    let intent = ProvisionIntent {
        identity_id,
        identity,
        fulfillment_mode: ChannelIdentityFulfillment::Api,
    };
    let at = vault.now_recorded_at();
    match pack.complete_provision(
        vault,
        &intent,
        ChannelIdentityLifecycleActor::agent(agent),
        at,
    ) {
        Ok((_, result)) => Ok(lifecycle_reply(vault, identity_id, &result)?),
        Err(error) => pending_reply(vault, identity_id, &error).ok_or_else(|| error.into()),
    }
}

/// The reply for a lifecycle the door answered, the identity's state read
/// from its facts.
fn lifecycle_reply(
    vault: &Vault,
    identity_id: EntityId,
    result: &ChannelIdentityLifecycleResult,
) -> oneiron::Result<NativeMailProvisionReply> {
    let facts = vault.channel_identity_facts(&identity_id)?;
    let address = result
        .identity
        .as_ref()
        .map(|identity| identity.address_or_handle().to_owned())
        .or_else(|| facts.as_ref().map(|facts| facts.address_or_handle.clone()))
        .unwrap_or_default();
    let state = facts.map_or_else(
        || {
            result
                .identity
                .as_ref()
                .map_or(ChannelIdentityState::Requested, |identity| identity.state())
        },
        |facts| facts.state,
    );
    Ok(NativeMailProvisionReply {
        identity_ref: identity_id,
        address,
        state,
        outcome: result.outcome.clone(),
        receipt_id: Some(result.receipt_id.clone()),
        gate_receipt_id: result.gate_receipt_id.clone(),
        reason_codes: result.reason_codes.clone(),
        fulfillment_error: None,
    })
}

/// The reply for an identity the gate admitted whose mailbox work failed:
/// the row stays pending fulfillment for `.../complete`. `None` when the
/// identity is not pending, so the failure is the answer.
fn pending_reply(
    vault: &Vault,
    identity_id: EntityId,
    error: &oneiron::Error,
) -> Option<NativeMailProvisionReply> {
    let facts = vault.channel_identity_facts(&identity_id).ok()??;
    (facts.state == ChannelIdentityState::PendingFulfillment).then(|| NativeMailProvisionReply {
        identity_ref: identity_id,
        address: facts.address_or_handle,
        state: facts.state,
        outcome: ChannelIdentityState::PendingFulfillment.as_str().to_owned(),
        receipt_id: None,
        gate_receipt_id: None,
        reason_codes: Vec::new(),
        fulfillment_error: Some(error.to_string()),
    })
}

fn no_native_mail() -> OwnerError {
    OwnerError::NotFound("served native mail pack", "native_mail".to_owned())
}
