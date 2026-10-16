//! `/v1/owner/diary`: the owner's doors to agent diaries (OF-490, AGM-1+8).
//! The owner mints the `diary.read` Grants that decide what a reader gets,
//! sets whether an agent reviews each read first, and reads a diary under
//! its own Grant, stating a reason the agent sees. Owning the vault reads
//! nothing by itself.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use axum::routing::post;
use oneiron::EdgeActorClass;
use oneiron::consent::{ConsentGrant, ConsentReceipt};
use oneiron::memory::DiaryReadOutcome;
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::json_payload;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/diary/review", post(review))
        .route("/diary/grants", post(grant))
        .route("/diary/read", post(read))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetReview {
    /// The agent, as 32 hex.
    agent: String,
    on: bool,
}

#[derive(Debug, Serialize)]
struct ReviewSet {
    agent: String,
    on: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantDiaryRead {
    /// Who reads, as 32 hex: the owner names itself to read.
    reader: String,
    /// `human`, `agent` or `system`.
    reader_class: String,
    /// Whose diary, as 32 hex.
    agent: String,
    /// Only these entries, as 32 hex; none grants the whole diary.
    #[serde(default)]
    entries: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DiaryReadGranted {
    grant_ref: Option<String>,
    receipt_ref: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadDiary {
    /// Whose diary, as 32 hex.
    agent: String,
    /// The reason the read states; the agent sees it.
    reason: String,
}

fn memory_refused(error: oneiron::memory::MemoryError) -> OwnerError {
    OwnerError::Refused(error.to_string())
}

/// `POST /v1/owner/diary/review`: whether an agent reviews each read first.
async fn review(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<SetReview>, JsonRejection>,
) -> OwnerReply<ReviewSet> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let locality = auth.locality();
    let set = blocking(move || -> OwnerResult<ReviewSet> {
        let agent = entity_id("agent", &request.agent)?;
        let vault = server.vault();
        let actor = owner.revalidate(vault)?;
        vault
            .memory(actor, EdgeActorClass::Human)
            .at(locality)
            .set_diary_read_review(&owner, agent, request.on)
            .map_err(memory_refused)?;
        Ok(ReviewSet {
            agent: agent.to_hex(),
            on: request.on,
        })
    })
    .await?;
    Ok(Json(set))
}

/// `POST /v1/owner/diary/grants`: a `diary.read` Grant for one reader.
async fn grant(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<GrantDiaryRead>, JsonRejection>,
) -> OwnerReply<DiaryReadGranted> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let locality = auth.locality();
    let granted = blocking(move || -> OwnerResult<DiaryReadGranted> {
        let reader = entity_id("reader", &request.reader)?;
        let class = match request.reader_class.as_str() {
            "human" => EdgeActorClass::Human,
            "agent" => EdgeActorClass::Agent,
            "system" => EdgeActorClass::System,
            _ => {
                return Err(OwnerError::Invalid(
                    "reader_class is human, agent or system".to_owned(),
                ));
            }
        };
        let agent = entity_id("agent", &request.agent)?;
        let entries = request
            .entries
            .iter()
            .map(|entry| entity_id("entries", entry))
            .collect::<OwnerResult<Vec<_>>>()?;
        let vault = server.vault();
        let actor = owner.revalidate(vault)?;
        let receipt = vault
            .memory(actor, EdgeActorClass::Human)
            .at(locality)
            .grant_diary_read(
                &owner,
                oneiron::WriteActor::new(reader, class),
                agent,
                &entries,
            )
            .map_err(memory_refused)?;
        let grant_ref = match &receipt {
            ConsentReceipt::Approved {
                grant: ConsentGrant::Standing(grant),
                ..
            } => Some(grant.bound().digest().to_hex()),
            _ => None,
        };
        Ok(DiaryReadGranted {
            grant_ref,
            receipt_ref: format!("gate:{}", receipt.decision_id().to_hex()),
        })
    })
    .await?;
    Ok(Json(granted))
}

/// `POST /v1/owner/diary/read`: the owner reads a diary under its Grant.
async fn read(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ReadDiary>, JsonRejection>,
) -> OwnerReply<DiaryReadOutcome> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let locality = auth.locality();
    let outcome = blocking(move || -> OwnerResult<DiaryReadOutcome> {
        let agent = entity_id("agent", &request.agent)?;
        let vault = server.vault();
        let actor = owner.revalidate(vault)?;
        vault
            .memory(actor, EdgeActorClass::Human)
            .at(locality)
            .read_agent_diary(Some(&owner), agent, &request.reason)
            .map_err(memory_refused)
    })
    .await?;
    Ok(Json(outcome))
}
