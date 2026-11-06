//! Owner review and keep-held discard of one durable repo-manifest conflict.

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::memory::{MemoryError, MemoryResult};
use crate::origin::{RepoManifest, RepoPortableId};
use crate::sync::window::{
    RepoManifestConflictDiscard, RepoManifestConflictReview,
    discard_reviewed_repo_manifest_carrier_as, review_repo_manifest_conflict,
};
use crate::sync::{SyncQueue, WindowKey};
use crate::{EntityId, Vault};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoManifestConflictReviewRequest {
    pub window: String,
    pub portable_repo: String,
}

/// The durable conflict as reviewed, not a live window's contents.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepoManifestConflictReviewView {
    pub window: String,
    pub portable_repo: String,
    pub held: RepoManifest,
    pub carried: RepoManifest,
    /// Return unchanged to discard exactly this reviewed carrier.
    pub binding: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoManifestConflictDiscardRequest {
    pub binding: String,
}

/// Queue acceptance is not delivery or convergence.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RepoManifestConflictQueueView {
    Queued { sequence: u64 },
    Failed { error: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RepoManifestConflictDiscardView {
    Discarded {
        /// The exact ordinary delta, retained even when queueing fails.
        update_base64: String,
        queue: RepoManifestConflictQueueView,
    },
    Stale,
    WindowLive,
}

pub fn repo_manifest_conflict_review_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: RepoManifestConflictReviewRequest,
) -> MemoryResult<Option<RepoManifestConflictReviewView>> {
    owner.revalidate(vault)?;
    let window = WindowKey::try_new(input.window)
        .ok_or_else(|| MemoryError::bad_request("invalid window"))?;
    let portable = RepoPortableId::from_hex(&input.portable_repo)
        .ok_or_else(|| MemoryError::bad_request("invalid portable_repo"))?;
    review_repo_manifest_conflict(vault, &window, &portable)?
        .map(|review| {
            let binding =
                base64::engine::general_purpose::STANDARD.encode(review.encode_binding()?);
            Ok(RepoManifestConflictReviewView {
                window: review.window().as_str().to_owned(),
                portable_repo: review.portable().to_hex(),
                held: review.held().clone(),
                carried: review.carried().clone(),
                binding,
            })
        })
        .transpose()
}

pub fn repo_manifest_conflict_discard_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: RepoManifestConflictDiscardRequest,
) -> MemoryResult<RepoManifestConflictDiscardView> {
    repo_manifest_conflict_discard_listed_as_owner(vault, owner, input).map(|(view, _)| view)
}

/// Only a matched discard names CODE rows; Stale/WindowLive expose none.
pub fn repo_manifest_conflict_discard_listed_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: RepoManifestConflictDiscardRequest,
) -> MemoryResult<(RepoManifestConflictDiscardView, Vec<EntityId>)> {
    owner.revalidate(vault)?;
    let binding = base64::engine::general_purpose::STANDARD
        .decode(&input.binding)
        .map_err(|_| MemoryError::bad_request("invalid binding"))?;
    let review = RepoManifestConflictReview::decode_binding(&binding)
        .map_err(|_| MemoryError::bad_request("invalid binding"))?;
    match discard_reviewed_repo_manifest_carrier_as(vault, owner, &review)? {
        RepoManifestConflictDiscard::Discarded { update } => {
            let queue = match SyncQueue::push_for(vault, review.window().as_str(), &update) {
                Ok(sequence) => RepoManifestConflictQueueView::Queued { sequence },
                Err(error) => RepoManifestConflictQueueView::Failed {
                    error: error.to_string(),
                },
            };
            Ok((
                RepoManifestConflictDiscardView::Discarded {
                    update_base64: base64::engine::general_purpose::STANDARD.encode(update),
                    queue,
                },
                vec![review.held().code, review.carried().code],
            ))
        }
        RepoManifestConflictDiscard::Stale => {
            Ok((RepoManifestConflictDiscardView::Stale, Vec::new()))
        }
        RepoManifestConflictDiscard::WindowLive => {
            Ok((RepoManifestConflictDiscardView::WindowLive, Vec::new()))
        }
    }
}
