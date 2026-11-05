//! The owner's served handoff from a session-branch claim edit to its
//! native approve-once merge and the host's existing typed decision ladder.

use std::sync::Arc;

use axum::extract::{Path as UrlPath, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::EntityId;
use oneiron::consent::ConsentReceipt;
use oneiron::llm::decision::{AnswerContract, DecisionClass, DecisionQuestion};
use oneiron::skill_hub::{
    ClaimRefinementMergeDisposition, ClaimRefinementMergeReceipt, LocalClaimRefinement,
};
use serde::{Deserialize, Serialize};

use super::{OwnerReply, OwnerRoute, OwnerTable, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::OwnerError;
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/claims/refinements/{candidate}",
                summary: "The owner reads a local claim refinement and its stored merge ruling.",
                row: None,
                shape: None,
            },
            get(refinement),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/claims/refinements/{candidate}/approve",
                summary: "The owner approves one local claim refinement's bound merge and runs its typed decisions now.",
                row: None,
                shape: None,
            },
            post(approve),
        ),
    ]
}

#[derive(Serialize)]
struct RefinementDetail {
    refinement: LocalClaimRefinement,
    receipt: Option<ClaimRefinementMergeReceipt>,
}

async fn refinement(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    UrlPath(candidate): UrlPath<String>,
) -> OwnerReply<RefinementDetail> {
    owner(&auth, &server)?;
    let detail = blocking(move || {
        let candidate = candidate_id(&candidate)?;
        let vault = server.vault();
        let refinement = vault
            .local_claim_refinement(candidate)?
            .ok_or_else(|| OwnerError::NotFound("claim refinement", candidate.to_hex()))?;
        Ok(RefinementDetail {
            refinement,
            receipt: vault.claim_refinement_merge_receipt(candidate)?,
        })
    })
    .await?;
    Ok(Json(detail))
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct MergeApproval {
    /// The owner's configured useful-upstream question, not a server prompt.
    question: String,
    question_version: u32,
}

#[derive(Serialize)]
struct MergeConsent {
    outcome: &'static str,
    decision: String,
}

impl From<ConsentReceipt> for MergeConsent {
    fn from(receipt: ConsentReceipt) -> Self {
        Self {
            outcome: receipt.gate_outcome(),
            decision: receipt
                .decision_id()
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct MergeRuling {
    outcome: &'static str,
    consent: MergeConsent,
    receipt: Option<Box<ClaimRefinementMergeReceipt>>,
}

async fn approve(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    UrlPath(candidate): UrlPath<String>,
    payload: OwnerJsonBody<MergeApproval>,
) -> OwnerReply<MergeRuling> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let ruling = blocking(move || {
        let candidate = candidate_id(&candidate)?;
        let vault = server.vault();
        let delta = vault
            .local_claim_refinement(candidate)?
            .ok_or_else(|| OwnerError::NotFound("claim refinement", candidate.to_hex()))?;
        let resident = EntityId::from_hex(&delta.resident).map_err(oneiron::Error::from)?;
        let question = DecisionQuestion {
            id: candidate,
            version: request.question_version,
            text: request.question,
            class: DecisionClass::UsefulUpstream,
            contract: AnswerContract::Noul,
            accept_type: false,
        };
        let ask = vault.prepare_claim_refinement_merge(candidate, resident, question)?;
        let consent = MergeConsent::from(vault.approve_claim_refinement_merge(&ask, &owner)?);
        let merged =
            server
                .decision_host()
                .merge_claim_refinement(vault, &ask, vault.now_recorded_at())?;
        Ok(match merged {
            ClaimRefinementMergeDisposition::PendingConsent => MergeRuling {
                outcome: "pending_consent",
                consent,
                receipt: None,
            },
            ClaimRefinementMergeDisposition::Ruled(receipt) => MergeRuling {
                outcome: if receipt.accepted {
                    "admitted"
                } else {
                    "refused"
                },
                consent,
                receipt: Some(receipt),
            },
        })
    })
    .await?;
    Ok(Json(ruling))
}

fn candidate_id(hex: &str) -> Result<EntityId, OwnerError> {
    EntityId::from_hex(hex)
        .map_err(|_| OwnerError::Invalid("candidate is not an entity id".to_owned()))
}
