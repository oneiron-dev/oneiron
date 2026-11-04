//! `/v1/owner/weave/digest-channels`: where each reader's weave digest is
//! sent (FIX 1262). With no row, the vault's companion agent sends a
//! reader's digest to the reader's primary route; the owner's row for a
//! reader turns that send off, or redirects it to another of the vault's
//! channel identities the reader has a live contact on. The inbox notice
//! is the same either way.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::{get, put};
use oneiron::outbound::WeaveDigestChannelSetting;

use super::{OwnerReply, OwnerRoute, OwnerTable, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::OwnerResult;
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/weave/digest-channels",
                summary: "Every reader's digest channel override, in reader order. A reader with no row has the default: the companion agent sends the digest to the reader's primary route.",
                row: None,
            },
            get(overrides),
        ),
        (
            OwnerRoute {
                method: "put",
                path: "/weave/digest-channels",
                summary: "One reader's digest channel: `route` {kind: off} sends nothing, {kind: identity, channel_identity_ref} sends from that channel identity to the reader's live contact on it, null removes the row and restores the default. The inbox notice stays either way.",
                row: None,
            },
            put(set_override),
        ),
    ]
}

/// The OpenAPI schema of `PUT /v1/owner/weave/digest-channels`'s body and
/// answer: [`WeaveDigestChannelSetting`].
pub(crate) fn weave_digest_channel_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<WeaveDigestChannelSetting>()
}

/// `GET /v1/owner/weave/digest-channels`: every reader's override.
async fn overrides(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Vec<WeaveDigestChannelSetting>> {
    let owner = owner(&auth, &server)?;
    let rows = blocking(move || -> OwnerResult<Vec<WeaveDigestChannelSetting>> {
        Ok(server.vault().weave_digest_channel_overrides(&owner)?)
    })
    .await?;
    Ok(Json(rows))
}

/// `PUT /v1/owner/weave/digest-channels`: one reader's override, stored or
/// removed, answered as stored.
async fn set_override(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<WeaveDigestChannelSetting>,
) -> OwnerReply<WeaveDigestChannelSetting> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let set = blocking(move || -> OwnerResult<WeaveDigestChannelSetting> {
        Ok(server
            .vault()
            .set_weave_digest_channel_override(&owner, &request)?)
    })
    .await?;
    Ok(Json(set))
}
