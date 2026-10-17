//! `/v1/owner/conflicts`: the contradictions the vault holds open, and the
//! owner's settlement of one (OF-023, ARCH-0003 `dr:H0636-4`). Keeping a
//! member supersedes the others with it; holding both leaves every member
//! active; dismissing answers the marker and changes no member. The Dreamer
//! settles them through its ladder in every vault from birth; the owner
//! holds its review on one subject or the whole vault, releases the hold,
//! and reverts any settlement it made.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::EdgeActorClass;
use oneiron::dreamer_consolidation::{
    ConflictReviewScope, ConflictSettlement, OpenConflict, SettledAnswer,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::{OwnerReply, blocking, owner};
use crate::api::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

/// The most conflicts one list returns unless the caller asks for fewer.
const DEFAULT_LIMIT: usize = 100;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/conflicts", get(list))
        .route("/conflicts/settle", post(settle))
        .route("/conflicts/settled", get(settled))
        .route("/conflicts/revert", post(revert))
        .route("/conflicts/review", post(resume_review))
        .route("/conflicts/review/revoke", post(hold_review))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConflictQuery {
    /// One subject's conflicts only, as 32 hex.
    subject: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct ConflictView {
    marker: String,
    subject: String,
    predicates: Vec<String>,
    /// Whether the marker still waits in its own review.
    proposed: bool,
    /// Whether the owner reverted a settlement of it: the Dreamer leaves it.
    reverted: bool,
    members: Vec<MemberView>,
}

#[derive(Debug, Serialize)]
struct MemberView {
    id: String,
    predicate: String,
    value: JsonValue,
    source: Option<&'static str>,
    approval: &'static str,
    lifecycle: &'static str,
    confidence: f32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SettleConflict {
    /// The open marker, as 32 hex.
    marker: String,
    /// `keep`, `hold_both` or `dismiss`.
    settlement: String,
    /// The member `keep` keeps, as 32 hex.
    #[serde(default)]
    keep: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevertSettlement {
    /// The settlement's `conflict.resolved` answer, as 32 hex.
    resolved: String,
}

#[derive(Debug, Serialize)]
struct SettledView {
    resolved: String,
    marker: String,
    subject: String,
    settlement: String,
    kept: Option<String>,
    superseded: Vec<String>,
    /// Whether the Dreamer made it.
    by_dreamer: bool,
}

#[derive(Debug, Serialize)]
struct SettlementReverted {
    resolved: String,
    /// The marker, open again for the owner.
    marker: String,
    /// Members standing again in place.
    restored: Vec<String>,
    /// The Dreamer's fresh copies of its own members, as `[member, copy]`.
    copied: Vec<[String; 2]>,
    /// Members a later write closed, left as they are.
    left_closed: Vec<String>,
    receipt_ref: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewScope {
    /// `subject` or `vault`.
    scope: String,
    /// The one subject `subject` covers, as 32 hex.
    #[serde(default)]
    subject: Option<String>,
}

#[derive(Debug, Serialize)]
struct ReviewResumed {
    /// False when no such hold was live.
    resumed: bool,
}

#[derive(Debug, Serialize)]
struct ReviewHeld {
    hold_ref: String,
}

#[derive(Debug, Serialize)]
struct ConflictSettled {
    marker: String,
    settlement: &'static str,
    resolved: String,
    superseded: Vec<String>,
    receipt_ref: String,
}

fn view(vault: &oneiron::Vault, conflict: OpenConflict) -> OwnerResult<ConflictView> {
    let mut members = Vec::with_capacity(conflict.members.len());
    for id in &conflict.members {
        let Some(body) = vault.get_claim(id)? else {
            continue;
        };
        members.push(MemberView {
            id: id.to_hex(),
            predicate: body.predicate,
            value: crate::commands::msgpack_value_json(&body.value),
            source: body.source.map(|source| source.as_str()),
            approval: body.approval.as_str(),
            lifecycle: body.lifecycle.as_str(),
            confidence: body.confidence,
        });
    }
    Ok(ConflictView {
        marker: conflict.marker.to_hex(),
        subject: conflict.subject.to_hex(),
        predicates: conflict.predicates,
        proposed: conflict.body.approval == oneiron::claim::ClaimApprovalStatus::Proposed,
        reverted: conflict.reverted,
        members,
    })
}

fn memory_refused(error: oneiron::memory::MemoryError) -> OwnerError {
    OwnerError::Refused(error.to_string())
}

/// `GET /v1/owner/conflicts`: every unanswered contradiction, oldest first.
async fn list(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<ConflictQuery>, QueryRejection>,
) -> OwnerReply<Vec<ConflictView>> {
    let owner = owner(&auth, &server)?;
    let query = query_params(query)?;
    let locality = auth.locality();
    let conflicts = blocking(move || -> OwnerResult<Vec<ConflictView>> {
        let subject = query
            .subject
            .as_deref()
            .map(|subject| entity_id("subject", subject))
            .transpose()?;
        let vault = server.vault();
        let actor = owner.revalidate(vault)?;
        let open = vault
            .memory(actor, EdgeActorClass::Human)
            .at(locality)
            .open_conflicts(Some(&owner), subject, query.limit.unwrap_or(DEFAULT_LIMIT))
            .map_err(memory_refused)?;
        open.into_iter()
            .map(|conflict| view(vault, conflict))
            .collect()
    })
    .await?;
    Ok(Json(conflicts))
}

/// `POST /v1/owner/conflicts/settle`: the owner's answer to one marker.
async fn settle(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<SettleConflict>, JsonRejection>,
) -> OwnerReply<ConflictSettled> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let locality = auth.locality();
    let settled = blocking(move || -> OwnerResult<ConflictSettled> {
        let marker = entity_id("marker", &request.marker)?;
        let settlement = match (request.settlement.as_str(), request.keep.as_deref()) {
            ("keep", Some(keep)) => ConflictSettlement::Keep(entity_id("keep", keep)?),
            ("hold_both", None) => ConflictSettlement::HoldBoth,
            ("dismiss", None) => ConflictSettlement::Dismiss,
            _ => {
                return Err(OwnerError::Invalid(
                    "settlement is keep with the kept member, hold_both or dismiss".to_owned(),
                ));
            }
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            });
        let vault = server.vault();
        let actor = owner.revalidate(vault)?;
        let receipt = vault
            .memory(actor, EdgeActorClass::Human)
            .at(locality)
            .settle_conflict(Some(&owner), marker, settlement, now)
            .map_err(memory_refused)?;
        Ok(ConflictSettled {
            marker: receipt.marker.to_hex(),
            settlement: receipt.settlement.label(),
            resolved: receipt.resolved.to_hex(),
            superseded: receipt.superseded.iter().map(|id| id.to_hex()).collect(),
            receipt_ref: receipt.receipt_ref,
        })
    })
    .await?;
    Ok(Json(settled))
}

fn settled_view(answer: SettledAnswer) -> SettledView {
    SettledView {
        resolved: answer.resolved.to_hex(),
        marker: answer.marker.to_hex(),
        subject: answer.subject.to_hex(),
        settlement: answer.settlement,
        kept: answer.kept.map(|id| id.to_hex()),
        superseded: answer.superseded.iter().map(|id| id.to_hex()).collect(),
        by_dreamer: answer.by_dreamer,
    }
}

/// `GET /v1/owner/conflicts/settled` (optionally `?subject=<32 hex>&limit=<n>`):
/// the standing settlements, the Dreamer's among them, newest first.
async fn settled(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<ConflictQuery>, QueryRejection>,
) -> OwnerReply<Vec<SettledView>> {
    let owner = owner(&auth, &server)?;
    let query = query_params(query)?;
    let locality = auth.locality();
    let settled = blocking(move || -> OwnerResult<Vec<SettledView>> {
        let subject = query
            .subject
            .as_deref()
            .map(|subject| entity_id("subject", subject))
            .transpose()?;
        let vault = server.vault();
        let actor = owner.revalidate(vault)?;
        let answers = vault
            .memory(actor, EdgeActorClass::Human)
            .at(locality)
            .settled_conflicts(&owner, subject, query.limit.unwrap_or(DEFAULT_LIMIT))
            .map_err(memory_refused)?;
        Ok(answers.into_iter().map(settled_view).collect())
    })
    .await?;
    Ok(Json(settled))
}

/// `POST /v1/owner/conflicts/revert`: the owner's revert of one settlement.
/// Its answer is retracted, the marker opens again for the owner, and each
/// member it superseded stands again.
async fn revert(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<RevertSettlement>, JsonRejection>,
) -> OwnerReply<SettlementReverted> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let locality = auth.locality();
    let reverted = blocking(move || -> OwnerResult<SettlementReverted> {
        let resolved = entity_id("resolved", &request.resolved)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            });
        let vault = server.vault();
        let actor = owner.revalidate(vault)?;
        let receipt = vault
            .memory(actor, EdgeActorClass::Human)
            .at(locality)
            .revert_conflict_settlement(&owner, resolved, now)
            .map_err(memory_refused)?;
        let hex = |ids: &[oneiron::EntityId]| -> Vec<String> {
            ids.iter().map(|id| id.to_hex()).collect()
        };
        Ok(SettlementReverted {
            resolved: receipt.resolved.to_hex(),
            marker: receipt.reverted.marker.to_hex(),
            restored: hex(&receipt.reverted.restored),
            copied: receipt
                .reverted
                .copied
                .iter()
                .map(|(member, copy)| [member.to_hex(), copy.to_hex()])
                .collect(),
            left_closed: hex(&receipt.reverted.left_closed),
            receipt_ref: receipt.receipt_ref,
        })
    })
    .await?;
    Ok(Json(reverted))
}

fn review_scope(request: &ReviewScope) -> OwnerResult<ConflictReviewScope> {
    match (request.scope.as_str(), request.subject.as_deref()) {
        ("subject", Some(subject)) => {
            Ok(ConflictReviewScope::Subject(entity_id("subject", subject)?))
        }
        ("vault", None) => Ok(ConflictReviewScope::Vault),
        _ => Err(OwnerError::Invalid(
            "scope is subject with the subject, or vault".to_owned(),
        )),
    }
}

/// `POST /v1/owner/conflicts/review`: ends the owner's hold on the
/// Dreamer's review of one subject or of every subject in the vault, so it
/// settles them through its ladder again. Ending the whole vault's leaves a
/// subject's own hold.
async fn resume_review(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ReviewScope>, JsonRejection>,
) -> OwnerReply<ReviewResumed> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let locality = auth.locality();
    let resumed = blocking(move || -> OwnerResult<ReviewResumed> {
        let scope = review_scope(&request)?;
        let vault = server.vault();
        let actor = owner.revalidate(vault)?;
        let resumed = vault
            .memory(actor, EdgeActorClass::Human)
            .at(locality)
            .release_dreamer_conflict_review(&owner, scope)
            .map_err(memory_refused)?;
        Ok(ReviewResumed { resumed })
    })
    .await?;
    Ok(Json(resumed))
}

/// `POST /v1/owner/conflicts/review/revoke`: holds the Dreamer's review on
/// exactly that scope; it leaves those conflicts here for the owner until
/// `/review` ends the hold.
async fn hold_review(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ReviewScope>, JsonRejection>,
) -> OwnerReply<ReviewHeld> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let locality = auth.locality();
    let held = blocking(move || -> OwnerResult<ReviewHeld> {
        let scope = review_scope(&request)?;
        let vault = server.vault();
        let actor = owner.revalidate(vault)?;
        let hold_ref = vault
            .memory(actor, EdgeActorClass::Human)
            .at(locality)
            .hold_dreamer_conflict_review(&owner, scope)
            .map_err(memory_refused)?;
        Ok(ReviewHeld { hold_ref })
    })
    .await?;
    Ok(Json(held))
}
