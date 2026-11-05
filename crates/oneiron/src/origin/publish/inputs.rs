//! Core half of `origin::publish::inputs`: its store-layer items live in `oneiron_store::origin::publish::inputs` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::origin::publish::inputs::*;

use super::types::{OriginPublishForce, OriginPublishReviewItem};
use crate::entity_id::EntityId;
use serde::{Deserialize, Serialize};

/// Asks to publish one exact commit to one branch of a repo's mirror.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OriginPublishRequestInput {
    pub repo: String,
    /// A full branch ref, `refs/heads/...`; never a short name or HEAD.
    pub ref_name: String,
    /// The exact commit, 40 lower hex; never resolved from a ref.
    pub commit: String,
    #[serde(default)]
    pub force: OriginPublishForce,
    /// The same key answers the same request; another tuple under it is
    /// refused.
    pub idempotency_key: Option<String>,
    pub expires_at: Option<u64>,
    /// A Grant holder's repo handle: the CODE anchor its Grant's repo
    /// bounds name. The owner names none.
    pub code_repo: Option<EntityId>,
}

/// One page of a review.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginPublishReviewView {
    pub request_id: EntityId,
    pub digest: String,
    pub page: u64,
    pub pages: u64,
    pub items: Vec<OriginPublishReviewItem>,
}
