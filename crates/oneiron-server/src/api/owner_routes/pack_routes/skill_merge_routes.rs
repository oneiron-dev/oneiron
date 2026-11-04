//! `/v1/owner/packs/skills/merges`: the owner's ingress for shared-skill
//! merges (FIX 952). A delta offered to an active shared skill, by a
//! federation merge-back, a company pull request or the Dreamer's promote
//! step, is listed and read here. The owner's approve runs its merge now:
//! the useful-upstream question on the host's ladder, then the held-out
//! replay on the host's judge, with the owner's answer given in the same act
//! where the merge needs one. The owner's discard closes an offer.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Path as UrlPath, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::error::ArtifactError;
use oneiron::llm::decision::{AnswerContract, DecisionClass, DecisionQuestion};
use oneiron::registry::ENTITY_TYPE_AGENT_DEF;
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::skill_hub::{
    SharedSkillDelta, SharedSkillLane, SharedSkillMergeDisposition, SharedSkillMergeEntry,
    SharedSkillMergeReceipt, SharedSkillMergeState,
};
use oneiron::{EntityId, Vault};
use serde::{Deserialize, Serialize};

use super::super::{OwnerReply, OwnerRoute, OwnerTable, blocking, owner};
use super::entity_id;
use super::skill_routes::ConsentRow;
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::OwnerError;
use crate::server::SyncServer;

/// The clock the owner's useful-upstream question runs on, the Coach's own.
const USEFUL_UPSTREAM_BUDGET: Duration = Duration::from_secs(30);

/// The version of the host's useful-upstream wording; a changed wording
/// takes the next.
const QUESTION_VERSION: u32 = 1;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/packs/skills/merges",
                summary: "Every offered shared-skill delta no merge has ruled on (FIX 952).",
                row: None,
            },
            get(pending_merges),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/packs/skills/merges/{candidate}",
                summary: "One offered shared-skill delta, where it stands, whether its merge needs the owner's answer, and the last merge's receipt.",
                row: None,
            },
            get(merge_detail),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/skills/merges/{candidate}/approve",
                summary: "The owner runs one offered delta's merge now, answering its review where it needs one.",
                row: None,
            },
            post(approve_merge),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/skills/merges/{candidate}/discard",
                summary: "The owner discards one offered delta no merge has admitted.",
                row: None,
            },
            post(discard_merge),
        ),
    ]
}

/// `GET /v1/owner/packs/skills/merges`: every offered delta no merge has
/// ruled on, in candidate order.
async fn pending_merges(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Vec<SharedSkillDelta>> {
    owner(&auth, &server)?;
    let pending = blocking(move || Ok(server.vault().pending_shared_skill_merges()?)).await?;
    Ok(Json(pending))
}

/// One offered delta as the owner reads it.
#[derive(Serialize)]
struct MergeDetail {
    #[serde(flatten)]
    entry: SharedSkillMergeEntry,
    /// Whether its merge waits on the owner's answer: the delta widens the
    /// skill's permissions, or the scan of its bytes asks for review. Unset
    /// once admitted, or while it cannot merge.
    #[serde(skip_serializing_if = "Option::is_none")]
    needs_owner: Option<bool>,
    /// Why it cannot merge now: its base, baseline or held-out reserve
    /// moved, or it no longer revises its base.
    #[serde(skip_serializing_if = "Option::is_none")]
    unmergeable: Option<&'static str>,
    /// The last merge's ruling on it.
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt: Option<SharedSkillMergeReceipt>,
}

/// `GET /v1/owner/packs/skills/merges/{candidate}`
async fn merge_detail(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    UrlPath(candidate): UrlPath<String>,
) -> OwnerReply<MergeDetail> {
    owner(&auth, &server)?;
    let detail = blocking(move || {
        let vault = server.vault();
        let candidate = entity_id(&candidate, "candidate")?;
        let entry = vault
            .shared_skill_merge_entry(&candidate)?
            .ok_or_else(|| OwnerError::NotFound("shared skill delta", candidate.to_hex()))?;
        let (needs_owner, unmergeable) = if entry.state == SharedSkillMergeState::Admitted {
            (None, None)
        } else {
            match vault.shared_skill_merge_needs_owner(&candidate) {
                Ok(needs) => (Some(needs), None),
                Err(oneiron::Error::Artifact(ArtifactError::InvalidSkillBody(reason))) => {
                    (None, Some(reason))
                }
                Err(error) => return Err(error.into()),
            }
        };
        Ok(MergeDetail {
            entry,
            needs_owner,
            unmergeable,
            receipt: vault.shared_skill_merge_receipt(&candidate)?,
        })
    })
    .await?;
    Ok(Json(detail))
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct MergeApproval {
    /// The agent definition the useful-upstream question is asked for, as
    /// 32 hex; unset, the leader of the vault's root project.
    #[serde(default)]
    resident: Option<String>,
}

/// What the owner's approve did.
#[derive(Serialize)]
struct MergeRuling {
    /// `admitted`, `refused` or `pending_consent`.
    outcome: &'static str,
    /// The owner's answer, when this merge needed one and took it here.
    #[serde(skip_serializing_if = "Option::is_none")]
    consent: Option<ConsentRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt: Option<Box<SharedSkillMergeReceipt>>,
}

/// `POST /v1/owner/packs/skills/merges/{candidate}/approve`: the owner runs
/// one offered delta's merge now. A merge that needs the owner's answer
/// takes it from this act; the useful-upstream question and the held-out
/// replay still rule. A refused delta is asked again.
async fn approve_merge(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    UrlPath(candidate): UrlPath<String>,
    payload: OwnerJsonBody<MergeApproval>,
) -> OwnerReply<MergeRuling> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let ruling = blocking(move || {
        let vault = server.vault();
        let candidate = entity_id(&candidate, "candidate")?;
        let delta = vault
            .shared_skill_delta(&candidate)?
            .ok_or_else(|| OwnerError::NotFound("shared skill delta", candidate.to_hex()))?;
        let resident = match request.resident.as_deref() {
            Some(hex) => entity_id(hex, "resident")?,
            None => root_leader(vault)?.ok_or_else(|| {
                OwnerError::Invalid(
                    "the root project's leader is not an agent; send a resident".to_owned(),
                )
            })?,
        };
        let judge = crate::replay_judge::registered().ok_or_else(|| {
            OwnerError::Refused("no skill judge is registered on this server".to_owned())
        })?;
        let question = DecisionQuestion {
            id: candidate,
            version: QUESTION_VERSION,
            text: question_text(&delta, resident),
            class: DecisionClass::UsefulUpstream,
            contract: AnswerContract::Noul,
            accept_type: false,
        };
        let ask = vault.prepare_shared_skill_merge(candidate, resident, question)?;
        let deadline = RetrievalDeadline::hard(Instant::now(), USEFUL_UPSTREAM_BUDGET);
        let useful = server.decision_host().useful_upstream(&deadline)?;
        let at = vault.now_recorded_at();
        let occurred = oneiron::TimeRange { start: at, end: at };
        let merge = || vault.merge_shared_skill_delta(&ask, &useful, judge, occurred, at);
        // The merge reads the owner's answer before it asks anything, so a
        // merge that needs one stops there; this act gives it, and the merge
        // runs again on it.
        let (merged, consent) = match merge()? {
            SharedSkillMergeDisposition::PendingConsent => {
                let consent = ConsentRow::from(vault.approve_shared_skill_merge(&ask, &owner)?);
                (merge()?, Some(consent))
            }
            merged => (merged, None),
        };
        Ok(match merged {
            SharedSkillMergeDisposition::PendingConsent => MergeRuling {
                outcome: "pending_consent",
                consent,
                receipt: None,
            },
            SharedSkillMergeDisposition::Ruled(receipt) => MergeRuling {
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

/// `POST /v1/owner/packs/skills/merges/{candidate}/discard`: the owner
/// discards one offered delta no merge has admitted. No merge is asked on it
/// again; the candidate revision stays readable. An admitted merge rolls
/// back instead.
async fn discard_merge(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    UrlPath(candidate): UrlPath<String>,
) -> OwnerReply<()> {
    let owner = owner(&auth, &server)?;
    blocking(move || {
        let candidate = entity_id(&candidate, "candidate")?;
        if server
            .vault()
            .discard_shared_skill_delta(&owner, &candidate)?
        {
            Ok(())
        } else {
            Err(OwnerError::NotFound(
                "shared skill delta",
                candidate.to_hex(),
            ))
        }
    })
    .await?;
    Ok(Json(()))
}

/// The leader of the vault's root project, the agent the Coach's own
/// useful-upstream questions are asked for. `None` when that leader is not
/// an agent definition.
fn root_leader(vault: &Vault) -> oneiron::Result<Option<EntityId>> {
    let Some(root) = vault.project(vault.root_project()?)? else {
        return Ok(None);
    };
    let Ok(leader) = EntityId::from_hex(&root.leader) else {
        return Ok(None);
    };
    Ok((vault.get_entity_type(&leader)? == Some(ENTITY_TYPE_AGENT_DEF)).then_some(leader))
}

/// The host's useful-upstream question on an offered delta. The question
/// names the revision and its base; the ladder reads both texts and the
/// delta's provenance from the merge's own state.
fn question_text(delta: &SharedSkillDelta, resident: EntityId) -> String {
    let lane = match delta.lane {
        SharedSkillLane::FederationMergeBack => "a federation merge-back",
        SharedSkillLane::CompanyPullRequest => "a company pull request",
    };
    format!(
        "Useful upstream? Asked by the vault's owner, on behalf of {resident}. Candidate \
{candidate}, offered through {lane}, revises the active shared skill {base}. Answer yes if \
the shared skill should take this revision for everyone who uses it, no if it should not.",
        resident = resident.to_hex(),
        candidate = delta.candidate,
        base = delta.base,
    )
}
