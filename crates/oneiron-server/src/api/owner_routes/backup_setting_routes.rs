//! `/v1/owner/settings/backup`: the owner's backup setting (FIX 5621),
//! whether this server takes backups on its own, how many hours apart and
//! how many it keeps, stored in the vault. The schedule reads it at its next
//! tick, over the deployment's `[backup]` section, which decides while no
//! choice is stored; where backups go stays the deployment's. Both routes
//! answer the stored choice and the policy in force.

use std::io::BufReader;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Json;
use axum::routing::get;
use oneiron::settings::backup::BackupPolicy;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use super::{OwnerReply, blocking, owner};
use crate::api::has_json_content_type;
use crate::api::transfer::{self, BodyReader};
use crate::auth::CoreAuth;
use crate::error::ApiError;
use crate::owner::OwnerResult;
use crate::server::SyncServer;

/// The pieces a PUT body reaches its reader in: they bound what is held at
/// once, never the body's length.
const BODY_PIECE: usize = 16 * 1024;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route("/settings/backup", get(read).put(put))
}

/// The OpenAPI schema of `PUT /v1/owner/settings/backup`'s body (FIX 11611): [`BackupPolicy`].
pub(crate) fn backup_policy_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<BackupPolicy>()
}

/// The OpenAPI schema of `PUT /v1/owner/settings/backup`'s answer (FIX 11611): [`BackupSetting`].
pub(crate) fn backup_setting_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<BackupSetting>()
}

/// The owner's backup setting and the policy in force.
#[derive(Debug, Serialize, schemars::JsonSchema)]
struct BackupSetting {
    /// The owner's stored choice; `null` while he has made none.
    stored: Option<BackupPolicy>,
    /// What the schedule follows now: the stored choice whole, else this
    /// server's `[backup]` section. `null` on a server started without its
    /// vault's backup storage, which takes no backups.
    effective: Option<BackupPolicy>,
}

impl BackupSetting {
    fn of(server: &SyncServer, stored: Option<BackupPolicy>) -> Self {
        Self {
            stored,
            effective: server
                .owner_host
                .as_ref()
                .map(|host| host.effective(stored)),
        }
    }
}

/// `GET /v1/owner/settings/backup`.
async fn read(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<BackupSetting> {
    owner(&auth, &server)?;
    let setting = blocking(move || -> OwnerResult<BackupSetting> {
        let stored = server.vault().backup_policy()?;
        Ok(BackupSetting::of(&server, stored))
    })
    .await?;
    Ok(Json(setting))
}

/// `PUT /v1/owner/settings/backup` with the whole `{enabled, every_hours,
/// keep}`: stored at once, read by the schedule's next tick. It prunes
/// nothing and stops no backup already being written; a smaller `keep`
/// prunes after the next backup. The body is read after the owner door.
async fn put(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    headers: HeaderMap,
    body: Body,
) -> OwnerReply<BackupSetting> {
    let owner = owner(&auth, &server)?;
    if !has_json_content_type(&headers) {
        return Err(ApiError::bad_request("invalid JSON request body", None).into());
    }
    let policy = read_policy(&server, body).await?;
    let setting = blocking(move || -> OwnerResult<BackupSetting> {
        server.vault().set_backup_policy(&owner, policy)?;
        Ok(BackupSetting::of(&server, Some(policy)))
    })
    .await?;
    Ok(Json(setting))
}

/// The body as one policy, decoded as it streams in on a transfer worker:
/// the triple, then nothing but whitespace to the body's clean end. Nothing
/// refuses it for its length.
async fn read_policy(server: &SyncServer, body: Body) -> Result<BackupPolicy, ApiError> {
    let (sender, receiver) = mpsc::channel(2);
    let mut worker = transfer::spawn_worker(move || -> Result<BackupPolicy, serde_json::Error> {
        let mut json =
            serde_json::Deserializer::from_reader(BufReader::new(BodyReader::new(receiver)));
        let policy = BackupPolicy::deserialize(&mut json)?;
        json.end()?;
        Ok(policy)
    });
    // A body that is not a policy ends the worker before the client sends
    // the rest, so its answer is taken without waiting for the body to end.
    let early = tokio::select! {
        biased;
        joined = &mut worker => Some(joined),
        () = transfer::feed_body(body, sender, server.transfers.idle, BODY_PIECE) => None,
    };
    let joined = match early {
        Some(joined) => joined,
        None => worker.await,
    };
    match joined {
        Ok(Ok(policy)) => Ok(policy),
        Ok(Err(error)) if !error.is_io() => {
            Err(ApiError::bad_request("invalid JSON request body", None))
        }
        Ok(Err(_)) | Err(_) => Err(ApiError::bad_request(
            "the request body did not arrive whole",
            None,
        )),
    }
}
