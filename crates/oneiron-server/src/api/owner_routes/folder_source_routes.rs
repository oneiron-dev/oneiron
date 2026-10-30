//! `/v1/owner/imports/folders`: an attached folder of notes while `serve`
//! runs (OF-554, FIX 1364), behind the same owner door as every other owner
//! route. Attach, rescan and detach run what the `import folder` command
//! runs; the list reads the attached folders.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::{get, post};
use serde::Deserialize;

use super::{OwnerReply, OwnerRoute, OwnerTable, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::files_intake::Rescanned;
use crate::owner::folder_sources::{self, AttachedFolder, DetachedFolder, ListedFolder};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/imports/folders",
                summary: "Every attached folder, with its ledger's counts.",
                row: None,
            },
            get(list),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/imports/folders/attach",
                summary: "Attaches a folder and lands its notes; serve rescans it every few minutes from then on.",
                row: None,
            },
            post(attach),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/imports/folders/rescan",
                summary: "Rescans one attached folder now, or every attached folder.",
                row: None,
            },
            post(rescan),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/imports/folders/detach",
                summary: "Detaches a folder: no rescan reads it again. Its notes stay.",
                row: None,
            },
            post(detach),
        ),
    ]
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachFolder {
    /// The folder. Only this path is read: symbolic links and hidden
    /// entries under it are skipped.
    path: String,
    /// Only notes whose path under the folder matches (`*` within a name,
    /// `**` across folders, `?` one character). Repeatable; none is every
    /// markdown file.
    #[serde(default)]
    include: Vec<String>,
    /// The note kind of a note whose frontmatter `type` names no kind the
    /// vault knows.
    #[serde(default = "default_kind")]
    kind: String,
}

/// The `import folder attach` default `--kind`: [`AttachFolder::kind`] when
/// the body names none.
fn default_kind() -> String {
    "observation".to_owned()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RescanFolders {
    /// The attached folder; none rescans every attached folder.
    #[serde(default)]
    path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DetachFolder {
    /// The attached folder.
    path: String,
}

/// `POST /v1/owner/imports/folders/attach`: attaches a folder and lands its
/// notes; `oneiron serve` rescans it every few minutes from then on.
async fn attach(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<AttachFolder>,
) -> OwnerReply<AttachedFolder> {
    let owner = owner(&auth, &server)?;
    let AttachFolder {
        path,
        include,
        kind,
    } = payload.read(&server).await?;
    let attached =
        blocking(move || folder_sources::attach(server.vault(), &owner, &path, include, &kind))
            .await?;
    Ok(Json(attached))
}

/// `POST /v1/owner/imports/folders/rescan`: rescans one attached folder now,
/// or every attached folder.
async fn rescan(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<RescanFolders>,
) -> OwnerReply<Vec<Rescanned>> {
    let owner = owner(&auth, &server)?;
    let RescanFolders { path } = payload.read(&server).await?;
    let reports =
        blocking(move || folder_sources::rescan(server.vault(), &owner, path.as_deref())).await?;
    Ok(Json(reports))
}

/// `POST /v1/owner/imports/folders/detach`: detaches a folder; its notes stay.
async fn detach(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<DetachFolder>,
) -> OwnerReply<DetachedFolder> {
    let owner = owner(&auth, &server)?;
    let DetachFolder { path } = payload.read(&server).await?;
    let detached = blocking(move || folder_sources::detach(server.vault(), &owner, &path)).await?;
    Ok(Json(detached))
}

/// `GET /v1/owner/imports/folders`: every attached folder, with its ledger's
/// counts.
async fn list(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Vec<ListedFolder>> {
    owner(&auth, &server)?;
    let listed = blocking(move || folder_sources::list(server.vault())).await?;
    Ok(Json(listed))
}
