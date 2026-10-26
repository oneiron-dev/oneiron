//! `/v1/owner/origin-authority`: the owner's origin cutover (ARCH-0068 RA7).
//!
//! A served repository with no authority row is this vault's alone and takes
//! pushes with no lease. The owner's cutover installs one: the epoch it
//! expects, the residence, the writer host (this install's machine unless the
//! owner names another) and whether this copy is a read-only mirror. The
//! engine refuses a cutover until the repository's publications are drained,
//! and refuses one whose expected epoch moved. The git route then pushes
//! under the lease this host holds, or refuses the push when it holds none.
//!
//! `/v1/owner/origin-mirror`: the repository's outbound mirror (ARCH-0068
//! RA8). The owner names an https URL, the custody record of its push token
//! (bound to `origin:mirror-push`) and a cadence in seconds; the origin host
//! pushes its published refs there on that cadence, which is the real RPO.
//! `POST /v1/owner/origin-mirror/push` pushes now.
//!
//! Each mirror carries a sync strategy (FIX 6866): `schedule` is that
//! cadenced push; `full_auto` pushes each new green head as soon as the
//! published refs move; `ask_me`, the default, sends nothing whole, so its
//! push refuses with `publish_request_required` and exact reviewed commits
//! go out through `vault.code.origin.publish.*`. `POST
//! /v1/owner/origin-mirror/strategy` changes the strategy alone.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::origin::mirror::{OriginMirrorRun, OriginMirrorTarget, OriginMirrorTargetInput};
use oneiron::origin::mirror_strategy::OriginMirrorSyncStrategy;
use oneiron::origin::residence::{OriginAuthority, OriginResidence};
use oneiron::origin::secret_publication::RepoDestinationVisibility;
use serde::{Deserialize, Serialize};

use super::owner_routes::{blocking, owner};
use super::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::error::EnvelopedApiError;
use crate::owner::{OwnerError, entity_id};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route(
            "/origin-authority",
            get(origin_authority).post(cut_origin_authority),
        )
        .route(
            "/origin-mirror",
            get(origin_mirror)
                .post(set_origin_mirror)
                .delete(clear_origin_mirror),
        )
        .route("/origin-mirror/push", post(push_origin_mirror))
        .route("/origin-mirror/strategy", post(set_origin_mirror_strategy))
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

/// One served repository's mirror; `None` when the owner set none.
#[derive(Debug, Serialize)]
struct OriginMirrorState {
    repo: String,
    mirror: Option<OriginMirrorTarget>,
}

async fn origin_mirror(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<RepoQuery>, QueryRejection>,
) -> Result<Json<OriginMirrorState>, EnvelopedApiError> {
    owner(&auth, &server)?;
    let RepoQuery { repo } = query_params(query)?;
    let state = blocking(move || {
        Ok(OriginMirrorState {
            mirror: server.vault().served_origin_mirror(&repo)?,
            repo,
        })
    })
    .await?;
    Ok(Json(state))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetOriginMirror {
    repo: String,
    /// The mirror's https URL, with no credential in it.
    url: String,
    /// The custody record of the mirror's push token.
    secret_ref: String,
    /// The basic-auth user the token goes with; `x-access-token` when absent.
    user: Option<String>,
    /// Seconds between pushes: the repository's RPO.
    every_secs: u64,
    /// `ask_me`, `schedule` or `full_auto`; absent, the same URL keeps its
    /// strategy and a new one asks first.
    #[serde(default)]
    sync_strategy: Option<OriginMirrorSyncStrategy>,
    /// `public`, `private` or `unknown`; absent, the same URL keeps its own
    /// and a new one is `unknown`, held as public.
    #[serde(default)]
    visibility: Option<RepoDestinationVisibility>,
}

async fn set_origin_mirror(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<SetOriginMirror>, JsonRejection>,
) -> Result<Json<OriginMirrorTarget>, EnvelopedApiError> {
    owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let row = blocking(move || {
        Ok(server.vault().set_served_origin_mirror(
            &request.repo,
            OriginMirrorTargetInput {
                url: request.url,
                secret_ref: request.secret_ref,
                user: request.user,
                every_secs: request.every_secs,
                sync_strategy: request.sync_strategy,
                visibility: request.visibility,
            },
        )?)
    })
    .await?;
    Ok(Json(row))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetOriginMirrorStrategy {
    repo: String,
    /// `ask_me`, `schedule` or `full_auto`.
    sync_strategy: OriginMirrorSyncStrategy,
}

/// Changes one mirror's sync strategy and its revision, nothing else.
async fn set_origin_mirror_strategy(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<SetOriginMirrorStrategy>, JsonRejection>,
) -> Result<Json<OriginMirrorTarget>, EnvelopedApiError> {
    owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let row = blocking(move || {
        Ok(server
            .vault()
            .set_served_origin_mirror_strategy(&request.repo, request.sync_strategy)?)
    })
    .await?;
    Ok(Json(row))
}

#[derive(Debug, Serialize)]
struct ClearedOriginMirror {
    repo: String,
    /// Whether a mirror was set.
    cleared: bool,
}

async fn clear_origin_mirror(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<RepoQuery>, QueryRejection>,
) -> Result<Json<ClearedOriginMirror>, EnvelopedApiError> {
    owner(&auth, &server)?;
    let RepoQuery { repo } = query_params(query)?;
    let cleared = blocking(move || {
        Ok(ClearedOriginMirror {
            cleared: server.vault().clear_served_origin_mirror(&repo)?,
            repo,
        })
    })
    .await?;
    Ok(Json(cleared))
}

async fn push_origin_mirror(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<RepoQuery>, JsonRejection>,
) -> Result<Json<OriginMirrorRun>, EnvelopedApiError> {
    owner(&auth, &server)?;
    let RepoQuery { repo } = json_payload(payload)?;
    let run = blocking(move || Ok(server.vault().push_served_origin_mirror(&repo)?)).await?;
    Ok(Json(run))
}
