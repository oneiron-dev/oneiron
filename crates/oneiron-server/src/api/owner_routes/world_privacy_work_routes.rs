//! `/v1/owner/worlds/privacy/settings` and `/reassert`: a holder changes a
//! world's settings, or re-asserts them after a pin change, as his own act
//! from whichever linked surface he is on (FIX 4632, 4682). Each is the
//! engine's one settings transaction: the signed edit, its receipt, and the
//! world's key work done here when this install may read the world, or an
//! owner work request naming a holder when it may not. The answer is the
//! receipt as committed, with the engine's words for its owner work: never a
//! synchronous success while a holder still has to act. A surface polls the
//! request at `GET /v1/owner/owner-work/{request}`.
//!
//! Where he spoke from is the request's own (`machine_routes::act_surface_admitted`):
//! audit only, no rule reads it.

use std::sync::Arc;

use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::authority::EffectiveWorldPrivacy;
use oneiron::policy_model::{WorldPrivacyReceipt, WorldPrivacySetInput};
use serde::{Deserialize, Serialize};

use super::machine_routes::{act_surface_admitted, revision_hex};
use super::{OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::api::query_params;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/worlds/privacy/settings",
                summary: "A world's settings as this install folds them, and the revision a change names as its seen.",
                row: None,
                shape: None,
            },
            get(settings),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/worlds/privacy/settings",
                summary: "A holder sets a world's settings as his own act: the settings receipt, with its key work done here or its owner work awaiting a holder, and that work's words.",
                row: None,
                shape: Some(RestShape::json(
                    world_privacy_set_body_schema,
                    world_privacy_work_schema,
                )),
            },
            post(set),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/worlds/privacy/reassert",
                summary: "The owner re-asserts a world's complete settings at its current revision after a pin change: the settings receipt, with its key work done here or its owner work awaiting a holder, and that work's words.",
                row: None,
                shape: Some(RestShape::json(
                    world_privacy_set_body_schema,
                    world_privacy_work_schema,
                )),
            },
            post(reassert),
        ),
    ]
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorldQuery {
    /// The WORLD row, 32 hex.
    world: String,
}

/// One world's settings as this install folds them, and the revision a
/// change names as its `seen`.
#[derive(Debug, Serialize)]
struct WorldSettings {
    world: String,
    settings: EffectiveWorldPrivacy,
    /// The settings revision, 64 hex.
    revision: String,
}

/// What a settings change or re-assertion committed.
#[derive(Debug, Serialize, schemars::JsonSchema)]
struct WorldPrivacyWork {
    #[serde(flatten)]
    receipt: WorldPrivacyReceipt,
    /// `OwnerWorkStatus::text` of the receipt's owner work, when a holder
    /// has to do the key work.
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_work_status_text: Option<&'static str>,
}

impl From<WorldPrivacyReceipt> for WorldPrivacyWork {
    fn from(receipt: WorldPrivacyReceipt) -> Self {
        Self {
            owner_work_status_text: receipt.owner_work.as_ref().map(|work| work.status.text()),
            receipt,
        }
    }
}

/// The OpenAPI schema of `POST /v1/owner/worlds/privacy/settings`'s body
/// (FIX 11611), shared with `/worlds/privacy/reassert`:
/// [`WorldPrivacySetInput`].
pub(crate) fn world_privacy_set_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<WorldPrivacySetInput>()
}

/// The OpenAPI schema of `POST /v1/owner/worlds/privacy/settings`'s answer
/// (FIX 11611), shared with `/worlds/privacy/reassert`:
/// [`WorldPrivacyWork`].
pub(crate) fn world_privacy_work_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<WorldPrivacyWork>()
}

/// `GET /v1/owner/worlds/privacy/settings?world=<id>`: the world's settings
/// and their revision.
async fn settings(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<WorldQuery>, QueryRejection>,
) -> OwnerReply<WorldSettings> {
    owner(&auth, &server)?;
    let query = query_params(query)?;
    let read = blocking(move || -> OwnerResult<WorldSettings> {
        let world = entity_id("world", &query.world)?;
        let vault = server.vault();
        // The revision first: a change landing between the reads leaves a
        // revision older than the settings shown, which the next edit's
        // `seen` refuses as stale, never the other way round.
        let revision = vault.world_privacy_revision(world)?;
        let settings = vault.world_privacy(world)?;
        Ok(WorldSettings {
            world: world.to_hex(),
            settings,
            revision: revision_hex(&revision.0),
        })
    })
    .await?;
    Ok(Json(read))
}

/// `POST /v1/owner/worlds/privacy/settings`: the holder sets the world's
/// settings (`Vault::set_world_privacy_as`). `seen` is the revision the
/// surface showed him; none takes the current one. A widen the vault's
/// "widen needs every owner" setting puts to every owner is refused here,
/// nothing written.
async fn set(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<WorldPrivacySetInput>,
) -> OwnerReply<WorldPrivacyWork> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let input = payload.read(&server).await?;
    let receipt = blocking(move || -> OwnerResult<WorldPrivacyReceipt> {
        let (world, settings, seen) = input.parse()?;
        Ok(server
            .vault()
            .set_world_privacy_as(&owner, surface, world, settings, seen)?)
    })
    .await?;
    Ok(Json(WorldPrivacyWork::from(receipt)))
}

/// `POST /v1/owner/worlds/privacy/reassert`: the owner signs the world's
/// complete settings again after a pin change
/// (`Vault::reassert_world_privacy`). `seen` is required: the world's
/// current settings revision.
async fn reassert(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<WorldPrivacySetInput>,
) -> OwnerReply<WorldPrivacyWork> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let input = payload.read(&server).await?;
    let receipt = blocking(move || -> OwnerResult<WorldPrivacyReceipt> {
        let (world, settings, seen) = input.parse()?;
        let expected = seen.ok_or_else(|| {
            OwnerError::Invalid(
                "a re-assertion names the settings revision it read: seen, 64 hex".to_owned(),
            )
        })?;
        Ok(server
            .vault()
            .reassert_world_privacy(&owner, surface, world, settings, expected)?)
    })
    .await?;
    Ok(Json(WorldPrivacyWork::from(receipt)))
}
