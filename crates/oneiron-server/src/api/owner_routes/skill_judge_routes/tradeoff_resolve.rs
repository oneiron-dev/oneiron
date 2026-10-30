//! `/v1/owner/skills/judge/tradeoff-asks/resolve`: the owner's decision on
//! one exact pending tradeoff, with decision evidence (FIX 9125). An
//! approval writes an accepted-tradeoff permission (or a deferred row the
//! next scored cycle admits through); it learns no preference, which only an
//! A/B pick teaches.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::post;
use oneiron::skill_optimize::{TradeoffChoice, resolve_skill_edit_tradeoff};
use serde::Deserialize;

use super::super::{OwnerReply, OwnerRoute, OwnerTable, blocking, owner};
use super::{Settled, unix_seconds};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::{OwnerResult, entity_id};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![(
        OwnerRoute {
            method: "post",
            path: "/skills/judge/tradeoff-asks/resolve",
            summary: "The owner's decision on one exact pending tradeoff.",
            row: None,
        },
        post(tradeoff_resolve),
    )]
}

/// The OpenAPI schema of `POST /v1/owner/skills/judge/tradeoff-asks/resolve`'s body (FIX 9125):
/// [`TradeoffResolve`].
pub(crate) fn tradeoff_resolve_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<TradeoffResolve>()
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct TradeoffResolve {
    /// The open optimizer proposal, as 32 hex.
    proposal: String,
    /// The pending verdict the ask names, as 32 hex.
    pending: String,
    /// The bounded decision evidence reference.
    evidence: String,
    choice: TradeoffChoice,
}

/// `POST /v1/owner/skills/judge/tradeoff-asks/resolve`: the owner's decision
/// on one exact pending tradeoff, with decision evidence. An approval writes
/// an accepted-tradeoff permission (or a deferred row the next scored cycle
/// admits through); it learns no preference.
async fn tradeoff_resolve(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<TradeoffResolve>,
) -> OwnerReply<Settled> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let settled = blocking(move || -> OwnerResult<Settled> {
        let proposal = entity_id("proposal", &request.proposal)?;
        let pending = entity_id("pending", &request.pending)?;
        let verdict = resolve_skill_edit_tradeoff(
            server.vault(),
            &proposal,
            pending,
            &owner,
            &request.evidence,
            request.choice,
            unix_seconds(),
        )?;
        Ok(Settled {
            proposal: request.proposal,
            accepted: verdict.accepted,
            goal_revision: verdict.goal_revision,
        })
    })
    .await?;
    Ok(Json(settled))
}
