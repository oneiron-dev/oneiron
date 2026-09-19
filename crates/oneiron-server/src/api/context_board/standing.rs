//! Standing blocks are pinned before Context Board retrieval can fill the session.
use crate::auth::CoreAuth;
use crate::error::ApiError;
use crate::server::SyncServer;
use oneiron::persona_snapshot::standing::StandingBlockHandle;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct StandingSessionControls {
    /// Required when an actor has more than one configured world.
    world_ref: Option<String>,
    /// The complete context budget, not a way to lower the stored block floor.
    token_budget: usize,
    block_tokens: Option<usize>,
}
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct StandingSessionPrefix {
    pub(crate) handle: String,
    pub(crate) world_ref: String,
    pub(crate) compiled: String,
    pub(crate) reserved_tokens: usize,
    pub(crate) other_context_tokens: usize,
    pub(crate) total_tokens: usize,
    pub(crate) evicted_claims: Vec<String>,
}
fn bad() -> ApiError {
    ApiError::bad_request(
        "standing session needs a configured world and sufficient token budget",
        Some("standing"),
    )
}
pub(super) async fn standing_prefix(
    server: &SyncServer,
    auth: &CoreAuth,
    controls: Option<&StandingSessionControls>,
) -> Result<Option<StandingSessionPrefix>, ApiError> {
    let actor_ref = auth.principal_ref().unwrap_or(auth.principal());
    let Ok(actor) = oneiron::EntityId::from_hex(actor_ref) else {
        return if controls.is_some() {
            Err(bad())
        } else {
            Ok(None)
        };
    };
    let blocks = server.vault.standing_blocks(actor).map_err(|_| bad())?;
    if blocks.is_empty() && controls.is_none() {
        return Ok(None);
    }
    // A classless or mistyped slip cannot skip a configured agent floor.
    if auth.actor_class() != Some("agent") {
        return Err(bad());
    }
    // A registered floor cannot be bypassed by omitting the control block.
    let controls = controls.ok_or_else(bad)?;
    let handle: &StandingBlockHandle = match controls.world_ref.as_deref() {
        Some(world) => {
            let world = oneiron::EntityId::from_hex(world).map_err(|_| bad())?;
            blocks
                .iter()
                .find(|block| block.world() == world)
                .ok_or_else(bad)?
        }
        None if blocks.len() == 1 => &blocks[0],
        None => return Err(bad()),
    };
    let reader =
        oneiron::claim::ScopedReadActorKey::with_actor_class(actor_ref, "agent").ok_or_else(bad)?;
    let mut cache = server.standing_block_cache.lock().await;
    let pinned = server
        .vault
        .begin_standing_block_session(
            handle,
            reader,
            controls.token_budget,
            controls.block_tokens.unwrap_or(handle.token_floor()),
            &mut cache,
        )
        .map_err(|_| bad())?;
    Ok(Some(StandingSessionPrefix {
        handle: pinned.block,
        world_ref: handle.world().to_hex(),
        compiled: String::from_utf8(pinned.compiled).map_err(|_| bad())?,
        reserved_tokens: pinned.reserved_tokens,
        other_context_tokens: pinned.other_context_tokens,
        total_tokens: controls.token_budget,
        evicted_claims: pinned
            .eviction
            .claims
            .into_iter()
            .map(|id| id.to_hex())
            .collect(),
    }))
}
