//! `/v1/owner/free-time`: one agent's free-time policy, its cycles and one
//! cycle's sheet (FIX 4453), behind the same owner door as every other owner
//! route. Each route runs its `vault.free_time.*` row's verb hooks once
//! around the engine door, as the host doors do. A sheet carries the agent's
//! short note and the spending records, never its diary. A set records where
//! the owner spoke from (`machine_routes::act_surface_admitted`, FIX 5721): audit only.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use axum::routing::get;
use oneiron::dreamer_runner::{
    self, FreeTimeCycleRequest, FreeTimeCyclesRequest, FreeTimePolicyRequest,
    FreeTimePolicySetRequest,
};
use serde::Deserialize;
use serde_json::Value;

use super::machine_routes::act_surface_admitted;
use super::{OwnerReply, blocking, hooked_owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::api::query_params;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, hooked_row};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/free-time/policy", get(policy).post(set_policy))
        .route("/free-time/cycles", get(cycles))
        .route("/free-time/cycles/{cycle}", get(cycle))
}

/// The agent a cycle's sheet is read for.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentQuery {
    /// The agent definition, 32 hex.
    agent: String,
}

/// `GET /v1/owner/free-time/policy?agent=`: the agent's policy with its
/// revision, or Disabled.
async fn policy(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<FreeTimePolicyRequest>, QueryRejection>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = query_params(query)?;
    let view = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.free_time.policy.get",
            request,
            |request: FreeTimePolicyRequest| {
                Ok(dreamer_runner::free_time_policy_as_owner(
                    vault, &owner, &request,
                )?)
            },
        )
    })
    .await?;
    Ok(Json(view))
}

/// `POST /v1/owner/free-time/policy`: sets the agent's policy at the
/// revision the owner read, or clears it when `policy` is absent.
async fn set_policy(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<FreeTimePolicySetRequest>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let request = payload.read(&server).await?;
    let view = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.free_time.policy.set",
            request,
            |request: FreeTimePolicySetRequest| {
                Ok(dreamer_runner::free_time_policy_set_as_owner(
                    vault, &owner, surface, &request,
                )?)
            },
        )
    })
    .await?;
    Ok(Json(view))
}

/// `GET /v1/owner/free-time/cycles?agent=&cursor=&limit=`: one page of the
/// agent's cycles, newest first, with the cursor of the next.
async fn cycles(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<FreeTimeCyclesRequest>, QueryRejection>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = query_params(query)?;
    let page = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.free_time.cycles",
            request,
            |request: FreeTimeCyclesRequest| {
                Ok(dreamer_runner::free_time_cycles_as_owner(
                    vault, &owner, &request,
                )?)
            },
        )
    })
    .await?;
    Ok(Json(page))
}

/// `GET /v1/owner/free-time/cycles/{cycle}?agent=`: one cycle's sheet with
/// this server's spend records for it; `null` when the agent has no such
/// cycle, as the row answers.
async fn cycle(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(cycle): Path<String>,
    query: Result<Query<AgentQuery>, QueryRejection>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let AgentQuery { agent } = query_params(query)?;
    let sheet = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.free_time.cycle",
            FreeTimeCycleRequest { agent, cycle },
            |request: FreeTimeCycleRequest| {
                dreamer_runner::free_time_cycle_as_owner(vault, &owner, &request)?
                    .map(|sheet| {
                        crate::api::facade::free_time_doors::free_time_cycle_with_spend(
                            &server, sheet,
                        )
                        .map_err(|error| {
                            OwnerError::Host(anyhow::anyhow!(
                                "a free-time cycle's spend did not read: {error}"
                            ))
                        })
                    })
                    .transpose()
            },
        )
    })
    .await?;
    Ok(Json(sheet))
}
