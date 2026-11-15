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
//! `GET /v1/owner/origin-mirror`: the repository's outbound mirror (ARCH-0068
//! RA8). The owner sets it through `vault.settings.set` as the catalogue key
//! `origin.mirror` at the repository's scope: an https URL, the custody record
//! of its push token (bound to `origin:mirror-push`), a cadence in seconds and
//! a sync strategy; the origin host pushes its published refs there on that
//! cadence, which is the real RPO. `POST /v1/owner/origin-mirror/push` pushes
//! now.
//!
//! Each mirror carries a sync strategy (FIX 6866): `schedule` is that
//! cadenced push; `full_auto` pushes each new green head as soon as the
//! published refs move; `ask_me`, the default, sends nothing whole, so its
//! push refuses with `publish_request_required` and exact reviewed commits
//! go out through `vault.code.origin.publish.*`.

use std::sync::Arc;

use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::origin::mirror::{OriginMirrorRun, OriginMirrorTarget};
use oneiron::origin::residence::{OriginAuthority, OriginResidence};
use serde::{Deserialize, Serialize};

use super::openapi::{OwnerRoute, RestShape};
use super::owner_routes::{OwnerTable, blocking, owner};
use super::query_params;
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::error::EnvelopedApiError;
use crate::owner::{OwnerError, entity_id};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/origin-authority",
                summary: "Origin authority.",
                row: None,
                shape: None,
            },
            get(origin_authority),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/origin-authority",
                summary: "Cut origin authority.",
                row: None,
                shape: Some(RestShape::json(
                    cut_origin_authority_body_schema,
                    origin_authority_schema,
                )),
            },
            post(cut_origin_authority),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/origin-mirror",
                summary: "Origin mirror.",
                row: None,
                shape: None,
            },
            get(origin_mirror),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/origin-mirror/push",
                summary: "Push origin mirror.",
                row: None,
                shape: Some(RestShape::json(
                    push_origin_mirror_body_schema,
                    origin_mirror_run_schema,
                )),
            },
            post(push_origin_mirror),
        ),
    ]
}

/// The OpenAPI schema of `POST /v1/owner/origin-authority`'s body (FIX 11617): [`CutOriginAuthority`].
pub(crate) fn cut_origin_authority_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<CutOriginAuthority>()
}

/// The OpenAPI schema of `POST /v1/owner/origin-authority`'s answer (FIX 11617): [`OriginAuthority`].
pub(crate) fn origin_authority_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<OriginAuthority>()
}

/// The OpenAPI schema of `POST /v1/owner/origin-mirror/push`'s body (FIX 11617): [`RepoQuery`].
pub(crate) fn push_origin_mirror_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<RepoQuery>()
}

/// The OpenAPI schema of `POST /v1/owner/origin-mirror/push`'s answer (FIX 11617): [`OriginMirrorRun`].
pub(crate) fn origin_mirror_run_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<OriginMirrorRun>()
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
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

#[derive(Debug, Deserialize, schemars::JsonSchema)]
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
    payload: OwnerJsonBody<CutOriginAuthority>,
) -> Result<Json<OriginAuthority>, EnvelopedApiError> {
    let owner = owner(&auth, &server)?;
    // Where the owner's cut came from, for the act each cut it signs records
    // (FIX 15740): the host's own reading of the request, never its input.
    let surface = crate::api::facade::owner_binding::act_surface(&auth);
    let request = payload.read(&server).await?;
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
        // The proof is revalidated where the row commits (FIX 8214).
        Ok(vault.set_served_origin_authority_as_owner(
            &owner,
            surface,
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

async fn push_origin_mirror(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<RepoQuery>,
) -> Result<Json<OriginMirrorRun>, EnvelopedApiError> {
    let owner = owner(&auth, &server)?;
    let RepoQuery { repo } = payload.read(&server).await?;
    let run = blocking(move || {
        Ok(server
            .vault()
            .push_served_origin_mirror_as_owner(&owner, &repo)?)
    })
    .await?;
    Ok(Json(run))
}
