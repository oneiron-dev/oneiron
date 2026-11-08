//! `/v1/owner/settings/board-layout`: the owner's board cap and board layout
//! layers (BOARD-LAYOUT = A, owner 2026-11-03 20:25: "better to just set the
//! cap and let the agent manage"). The cap is every board's harness default;
//! the default layout renders until an agent lays out its own board; the
//! override's sections win over every agent's own layout of them, and one
//! agent's override wins over both for that agent. Absent, each reads empty.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use axum::routing::{get, post};
use serde::Deserialize;

use super::machine_routes::act_surface_admitted;
use super::{OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;
use oneiron::EntityId;
use oneiron::context_board::BoardLayout;
use oneiron::settings::BoardLayoutSettings;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/settings/board-layout",
                summary: "The owner's board cap, default layout, override and per-agent overrides, as they read now.",
                row: None,
                shape: None,
            },
            get(read),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/settings/board-layout",
                summary: "Sets the board cap, the default layout, the override, one agent's override, or any of them, and answers them as they now read.",
                row: None,
                shape: Some(RestShape::json(
                    board_layout_change_body_schema,
                    board_layout_settings_schema,
                )),
            },
            post(put),
        ),
    ]
}

/// The OpenAPI schema of `POST /v1/owner/settings/board-layout`'s body:
/// [`BoardLayoutSettingsChange`].
pub(crate) fn board_layout_change_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<BoardLayoutSettingsChange>()
}

/// The OpenAPI schema of `POST /v1/owner/settings/board-layout`'s answer:
/// [`BoardLayoutSettings`].
pub(crate) fn board_layout_settings_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<BoardLayoutSettings>()
}

/// A change to the cap, a layout layer, one agent's override, or any of
/// them; an absent one stays as it is.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct BoardLayoutSettingsChange {
    /// The board cap in tokens; `null` clears it, so each harness's default
    /// applies again.
    #[serde(default, deserialize_with = "present")]
    #[schemars(with = "Option<u64>")]
    cap_tok: Option<Option<u64>>,
    /// The layout an agent's board renders under until it lays out its own.
    #[serde(default)]
    default_layout: Option<BoardLayout>,
    /// Sections whose layout the owner sets for every agent.
    #[serde(default)]
    override_layout: Option<BoardLayout>,
    /// Sections whose layout the owner sets for one agent alone.
    #[serde(default)]
    agent_override: Option<AgentBoardLayoutChange>,
}

/// The owner's override of one agent's board layout.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct AgentBoardLayoutChange {
    /// The agent whose board the override lays out.
    agent: EntityId,
    /// The sections the owner sets for this agent; `null`, omitted or empty
    /// clears the agent's override.
    #[serde(default)]
    layout: Option<BoardLayout>,
}

/// A field that is present, even as `null`; `#[serde(default)]` leaves an
/// omitted one `None`.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// `GET /v1/owner/settings/board-layout`.
async fn read(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<BoardLayoutSettings> {
    owner(&auth, &server)?;
    let settings = blocking(move || -> OwnerResult<BoardLayoutSettings> {
        Ok(server.vault().board_layout_settings()?)
    })
    .await?;
    Ok(Json(settings))
}

/// `POST /v1/owner/settings/board-layout`: sets the cap, a layout layer,
/// one agent's override, or any of them, and answers the settings as they now read; the next board
/// every harness renders reads them.
async fn put(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<BoardLayoutSettingsChange>,
) -> OwnerReply<BoardLayoutSettings> {
    let owner = owner(&auth, &server)?;
    // A change records where the owner spoke from (FIX 6465): audit only.
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let change = payload.read(&server).await?;
    let settings = blocking(move || -> OwnerResult<BoardLayoutSettings> {
        server
            .vault()
            .set_board_layout_settings(
                &owner,
                Some(surface),
                change.cap_tok,
                change.default_layout,
                change.override_layout,
                change
                    .agent_override
                    .map(|agent| (agent.agent, agent.layout)),
            )
            .map_err(|error| match error {
                oneiron::Error::InvalidConfig(reason) => OwnerError::Invalid(reason),
                error => error.into(),
            })
    })
    .await?;
    Ok(Json(settings))
}
