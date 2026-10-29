//! `/v1/owner/outbox/diverged`: a vault VM's outbox carrier members as the
//! owner sees them (FIX 11074, FIX 11242). Each copy the carrier keeps of a
//! member it never agreed on, as the member's origin retired the agreed
//! version, carries a card with his two answers, remove or keep; each file
//! the guest holds back as damaged at its source is listed beside them. Any
//! live vault Owner reads and answers. The answer goes to the carrier's
//! companion, which carries it out at its next turn: nothing removes a copy
//! without it. A vault with no companion lists nothing and takes no answer.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::response::Json;
use axum::routing::get;
use oneiron_vault_contract::vm_outbox::{VmOutboxKind, VmOutboxSide};
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::managed::{
    DIVERGED_ANSWER_ROUTE, DivergedAnswer, DivergedOwnerAnswer, VmOutboxMemberStatus,
    answer_diverged, companion_member_statuses,
};
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route("/outbox/diverged", get(members).post(answer))
}

/// The carrier's members as the owner sees them.
#[derive(Debug, Serialize)]
struct MembersPage {
    /// Whether the vault's outbox companion answered; `false` on a vault
    /// that runs outside a VM or whose companion is down.
    carrier: bool,
    members: Vec<MemberView>,
}

/// One member's typed status, and what a surface shows the owner for it.
#[derive(Debug, Serialize)]
struct MemberView {
    #[serde(flatten)]
    status: VmOutboxMemberStatus,
    card: OwnerCard,
}

/// A generic owner card: a headline, a body in plain words, and the
/// answers it offers.
#[derive(Debug, Serialize)]
struct OwnerCard {
    /// `outbox_diverged` or `outbox_source_damaged`.
    kind: &'static str,
    headline: String,
    body: String,
    actions: Vec<CardAction>,
}

/// One answer: its label, the `answer` the route takes and the route.
#[derive(Debug, Serialize)]
struct CardAction {
    label: &'static str,
    answer: DivergedAnswer,
    route: &'static str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnswerBody {
    kind: VmOutboxKind,
    member: String,
    /// The kept copy's digest, as the page lists it.
    held: String,
    /// `remove` or `keep`.
    answer: DivergedAnswer,
}

/// What the route did with the owner's answer.
#[derive(Debug, Serialize)]
struct AnswerReceipt {
    kind: VmOutboxKind,
    member: String,
    held: String,
    answer: DivergedAnswer,
    /// The companion took it for its carrier's next turn.
    queued: bool,
}

/// `GET /v1/owner/outbox/diverged`: every member the carrier keeps typed,
/// each with its card.
async fn members(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<MembersPage> {
    owner(&auth, &server)?;
    let page = blocking(move || -> OwnerResult<MembersPage> {
        let Some(statuses) = companion_member_statuses() else {
            return Ok(MembersPage {
                carrier: false,
                members: Vec::new(),
            });
        };
        Ok(MembersPage {
            carrier: true,
            members: statuses
                .into_iter()
                .map(|status| MemberView {
                    card: OwnerCard::of(&status),
                    status,
                })
                .collect(),
        })
    })
    .await?;
    Ok(Json(page))
}

/// `POST /v1/owner/outbox/diverged` with `{"kind", "member", "held",
/// "answer": "remove" | "keep"}`: passes the owner's answer to the copy the
/// page lists with that digest to the companion.
async fn answer(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<AnswerBody>,
) -> OwnerReply<AnswerReceipt> {
    owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let receipt = blocking(move || -> OwnerResult<AnswerReceipt> {
        answer_diverged(DivergedOwnerAnswer {
            kind: request.kind,
            member: request.member.clone(),
            held: request.held.clone(),
            answer: request.answer,
        })
        .map_err(|error| OwnerError::Changed(format!("{error:#}")))?;
        Ok(AnswerReceipt {
            kind: request.kind,
            member: request.member,
            held: request.held,
            answer: request.answer,
            queued: true,
        })
    })
    .await?;
    Ok(Json(receipt))
}

impl OwnerCard {
    fn of(status: &VmOutboxMemberStatus) -> Self {
        match status {
            VmOutboxMemberStatus::DivergedUnagreed {
                kind,
                member,
                held_by,
                answer,
                ..
            } => {
                let end = match held_by {
                    VmOutboxSide::Guest => "The vault VM",
                    VmOutboxSide::Host => "The vault's host",
                };
                let (headline, body, actions) = match answer {
                    None => (
                        format!("A {kind} outbox copy waits for your answer"),
                        format!(
                            "{end} keeps a copy of {member} that the carrier never agreed on, \
                             after the agreed version was retired. Nothing removes it without your \
                             answer: remove it, or keep it."
                        ),
                        vec![
                            CardAction {
                                label: "Remove this copy",
                                answer: DivergedAnswer::Remove,
                                route: DIVERGED_ANSWER_ROUTE,
                            },
                            CardAction {
                                label: "Keep it",
                                answer: DivergedAnswer::Keep,
                                route: DIVERGED_ANSWER_ROUTE,
                            },
                        ],
                    ),
                    Some(DivergedAnswer::Keep) => (
                        format!("A {kind} outbox copy kept"),
                        format!(
                            "You kept {end}'s copy of {member}, one the carrier never agreed on."
                        ),
                        vec![CardAction {
                            label: "Remove this copy",
                            answer: DivergedAnswer::Remove,
                            route: DIVERGED_ANSWER_ROUTE,
                        }],
                    ),
                    Some(DivergedAnswer::Remove) => (
                        format!("A {kind} outbox copy is being removed"),
                        format!(
                            "You had {end}'s copy of {member} removed; the carrier carries it out \
                             at its next session."
                        ),
                        Vec::new(),
                    ),
                };
                Self {
                    kind: "outbox_diverged",
                    headline,
                    body,
                    actions,
                }
            }
            VmOutboxMemberStatus::SourceDigestMismatch { kind, member, .. } => Self {
                kind: "outbox_source_damaged",
                headline: format!("A {kind} outbox file is held back"),
                body: format!(
                    "The vault VM's file {member} no longer matches its own recorded digest, so \
                     none of it is sent until it changes."
                ),
                actions: Vec::new(),
            },
        }
    }
}
