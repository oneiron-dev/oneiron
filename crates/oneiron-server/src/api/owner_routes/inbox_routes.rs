//! `/v1/owner/inbox`: the owner's view of the agent inbox lens (ARCH-0063 R4,
//! INB-03). One view across every agent identity: conversations by thread,
//! the "Waiting on you" pile and coordination updates, in impact order. The
//! lens stores nothing; this route only reads it.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::get;
use oneiron::agent_inbox_lens::{AgentInboxItemKind, AgentInboxLensQuery, InboxImpact};
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::query_params;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

/// Most rows one page returns.
const MAX_INBOX_PAGE: usize = 200;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route("/inbox", get(read))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InboxQuery {
    /// Only rows on this channel identity, as 32 hex.
    #[serde(default)]
    identity: Option<String>,
    /// Only rows addressed to this agent, as 32 hex: its own slice.
    #[serde(default)]
    agent: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    /// The last row of the previous page: impact, time and item id.
    #[serde(default)]
    before_impact: Option<u16>,
    #[serde(default)]
    before_at: Option<u64>,
    #[serde(default)]
    before_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct InboxPage {
    items: Vec<InboxRow>,
}

#[derive(Debug, Serialize)]
struct InboxRow {
    item_id: String,
    /// `conversation`, `waiting_on_you` or `coordination_update`.
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    thread_ref: Option<String>,
    identity: String,
    actor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    facet: Option<String>,
    participants: Vec<InboxParticipant>,
    impact: u16,
    occurred_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload_ref: Option<String>,
}

#[derive(Debug, Serialize)]
struct InboxParticipant {
    identity: String,
    actor: String,
}

/// `GET /v1/owner/inbox`: one page of the lens, filtered to an identity or
/// to one agent's slice when asked.
async fn read(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<InboxQuery>, QueryRejection>,
) -> OwnerReply<InboxPage> {
    owner(&auth, &server)?;
    let query = query_params(query)?;
    let page = blocking(move || -> OwnerResult<InboxPage> {
        let limit = query.limit.unwrap_or(50).min(MAX_INBOX_PAGE);
        let before = match (query.before_impact, query.before_at, query.before_id) {
            (Some(impact), Some(at), Some(id)) => Some((InboxImpact(impact), at, id)),
            (None, None, None) => None,
            _ => {
                return Err(OwnerError::Invalid(
                    "before_impact, before_at and before_id go together".to_owned(),
                ));
            }
        };
        let vault = server.vault();
        let items = match (query.identity, query.agent) {
            (Some(_), Some(_)) => {
                return Err(OwnerError::Invalid(
                    "filter by identity or by agent, not both".to_owned(),
                ));
            }
            (None, Some(agent)) => {
                vault.agent_inbox_slice(entity_id("agent", &agent)?, limit, before)?
            }
            (identity, None) => vault.agent_inbox_lens(AgentInboxLensQuery {
                identity_ref: identity
                    .as_deref()
                    .map(|identity| entity_id("identity", identity))
                    .transpose()?,
                limit,
                before,
            })?,
        };
        let items = items
            .into_iter()
            .map(|item| InboxRow {
                item_id: item.item_id,
                kind: match item.kind {
                    AgentInboxItemKind::Conversation => "conversation",
                    AgentInboxItemKind::ApprovalRequired => "waiting_on_you",
                    AgentInboxItemKind::CoordinationUpdate => "coordination_update",
                },
                thread_ref: item.thread_ref,
                identity: item.identity_ref.to_hex(),
                actor: item.actor_ref.to_hex(),
                facet: item.facet_ref.map(|facet| facet.to_hex()),
                participants: item
                    .participants
                    .into_iter()
                    .map(|participant| InboxParticipant {
                        identity: participant.identity_ref.to_hex(),
                        actor: participant.actor_ref.to_hex(),
                    })
                    .collect(),
                impact: item.impact.0,
                occurred_at: item.occurred_at,
                receipt_ref: item.receipt_ref,
                payload_ref: item.payload_ref,
            })
            .collect();
        Ok(InboxPage { items })
    })
    .await?;
    Ok(Json(page))
}
