//! `/v1/owner/origin-authority`: the owner's origin cutover (ARCH-0068 RA7).
//!
//! A served repository with no authority row is this vault's alone and takes
//! pushes with no lease. The owner's cutover installs one: the epoch it
//! expects, the residence, the writer host (this install's machine unless the
//! owner names another) and whether this copy is a read-only mirror. The
//! engine refuses a cutover until the repository's publications are drained,
//! and refuses one whose expected epoch moved. The git route then pushes
//! under the lease this host holds, or refuses the push when it holds none.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::get;
use oneiron::origin::residence::{OriginAuthority, OriginResidence};
use serde::{Deserialize, Serialize};

use super::owner_routes::{blocking, owner};
use super::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::error::EnvelopedApiError;
use crate::owner::{OwnerError, entity_id};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route(
        "/origin-authority",
        get(origin_authority).post(cut_origin_authority),
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepoQuery {
    /// The repository's served name, as `/git/{repo}` names it.
    repo: String,
}

/// One served repository's authority and the host reading it.
#[derive(Debug, Serialize)]
struct OriginAuthorityState {
    repo: String,
    /// This install's machine: the writer to name to make this host the
    /// repository's origin. `None` before the install has a machine id.
    host: Option<String>,
    /// `None`: no cutover yet, so this vault is the origin with no lease.
    authority: Option<OriginAuthority>,
}

async fn origin_authority(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<RepoQuery>, QueryRejection>,
) -> Result<Json<OriginAuthorityState>, EnvelopedApiError> {
    owner(&auth, &server)?;
    let RepoQuery { repo } = query_params(query)?;
    let state = blocking(move || {
        let vault = server.vault();
        Ok(OriginAuthorityState {
            authority: vault.served_origin_authority(&repo)?,
            host: vault.local_machine()?.map(|machine| machine.id.to_hex()),
            repo,
        })
    })
    .await?;
    Ok(Json(state))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CutOriginAuthority {
    repo: String,
    /// The epoch the owner read; `None` for a repository with no authority
    /// yet. A cutover whose epoch moved since is refused.
    expected_epoch: Option<u64>,
    residence: OriginResidence,
    /// The writer host's machine id; this install's machine when absent.
    writer: Option<String>,
    /// This copy serves reads only, at every ref.
    #[serde(default)]
    mirror: bool,
}

async fn cut_origin_authority(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<CutOriginAuthority>, JsonRejection>,
) -> Result<Json<OriginAuthority>, EnvelopedApiError> {
    owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let row = blocking(move || {
        let vault = server.vault();
        let writer = match request.writer.as_deref() {
            Some(writer) => entity_id("writer", writer)?,
            None => {
                vault
                    .local_machine()?
                    .ok_or_else(|| {
                        OwnerError::Invalid(
                            "this install has no machine id yet; name the writer".to_owned(),
                        )
                    })?
                    .id
            }
        };
        Ok(vault.set_served_origin_authority(
            &request.repo,
            request.expected_epoch,
            request.residence,
            writer,
            request.mirror,
        )?)
    })
    .await?;
    Ok(Json(row))
}
