//! Typed MRL vector reads and full-row uploads through the existing scoped lanes.
use serde::{Deserialize, Serialize};

use super::{Memory, MemoryError, MemoryResult, caps};
use crate::claim::{ClaimReadStatus, ScopedReadResult};
use crate::consent::AuthenticatedOwner;

/// The compatibility shape fixed when the vault opens. Changing a populated
/// graph's prefix is not an online operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct VectorSearchConfig {
    pub dimensions: usize,
    pub fast_dims: Option<u16>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum VectorSearchLane {
    #[default]
    Ordinary,
    /// Explicit speculative voice quality: prefix scores and a reduced limit.
    VoiceHot,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VectorSearchRequest {
    pub query_vector: Vec<f32>,
    pub limit: usize,
    #[serde(default)]
    pub lane: VectorSearchLane,
}

impl VectorSearchRequest {
    pub fn validate(&self) -> MemoryResult<()> {
        caps::check_limit_nonzero(self.limit)?;
        caps::check_dimensions(self.query_vector.len())?;
        if let Some(error) = crate::Error::invalid_vector_component(&self.query_vector) {
            return Err(error.into());
        }
        Ok(())
    }
}

/// The source revision is the same pin the ordinary dense lane retrieved.
/// It can be hydrated/cited without silently switching to newer text.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct VectorSearchHit {
    pub entity_ref: String,
    pub source_revision_ref: Option<String>,
    pub score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct VectorSearchResult {
    pub hits: Vec<VectorSearchHit>,
    pub lane: VectorSearchLane,
    pub effective_limit: usize,
    pub limit_clamped: bool,
    /// None if authority prevented the vector channel from running. Scores
    /// from different dimensional spaces are not cross-comparable.
    pub refinement: Option<crate::pipeline::VectorRefinement>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VectorPutRequest {
    pub entity_ref: String,
    /// Always the full stored width, never a truncated MRL prefix.
    pub vector: Vec<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct VectorPutReceipt {
    pub entity_ref: String,
    pub dimensions: usize,
}

impl Memory<'_> {
    /// Reads the open's persisted compatibility selection under this caller's proof.
    pub fn vector_search_config(&self) -> MemoryResult<ScopedReadResult<VectorSearchConfig>> {
        let lane = self.read_lane(ClaimReadStatus::Surfaceable)?;
        Ok(ScopedReadResult {
            value: VectorSearchConfig {
                dimensions: self.vault.config.dimensions,
                fast_dims: self.vault.config.fast_dims,
            },
            receipt: lane.read_receipt(None, 0)?,
        })
    }

    pub fn query_vector(
        &self,
        input: &VectorSearchRequest,
    ) -> MemoryResult<ScopedReadResult<VectorSearchResult>> {
        input.validate()?;
        let (mut limit, mut limit_clamped) = caps::clamp_search_limit(input.limit);
        let skip_rescore = input.lane == VectorSearchLane::VoiceHot;
        if skip_rescore {
            let reduced = limit.min(crate::speculative::SPECULATIVE_FIRE_LIMIT_DEFAULT);
            limit_clamped |= reduced != limit;
            limit = reduced;
        }
        let lane = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let found = lane.search_vector_revisioned_with_rescore(
            &input.query_vector,
            limit,
            None,
            skip_rescore,
        )?;
        self.produced_from(found.hits.iter().map(|hit| hit.id));
        Ok(ScopedReadResult {
            value: VectorSearchResult {
                hits: found
                    .hits
                    .into_iter()
                    .map(|hit| VectorSearchHit {
                        entity_ref: hit.id.to_hex(),
                        source_revision_ref: found.revisions.get(&hit.id).map(|pin| pin.to_hex()),
                        score: hit.score,
                    })
                    .collect(),
                lane: input.lane,
                effective_limit: limit,
                limit_clamped,
                refinement: found.vector_refinement,
            },
            receipt: found.receipt,
        })
    }

    /// Supplies one full-width vector as the caller's authenticated owner.
    /// The existing batch keeps model/transform, full-width, finite-vector,
    /// revision staging and graph admission. An accepted vector may be staged
    /// until that revision publishes; this receipt promises no immediate index.
    pub fn put_vector_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &VectorPutRequest,
    ) -> MemoryResult<VectorPutReceipt> {
        caps::check_dimensions(input.vector.len())?;
        let lane = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let id = self.resolve_ref_in_lane(&lane, &input.entity_ref)?;
        let mut refusal = None;
        self.vault
            .batch()
            .vector(&id, &input.vector)
            .commit_below_owner_with_guard(|txn| {
                let admitted = || -> MemoryResult<()> {
                    if owner.revalidate_in_txn(self.vault, txn)? != self.actor()
                        || self.actor_class() != crate::EdgeActorClass::Human
                    {
                        return Err(MemoryError::new(
                            super::MEMORY_CODE_FORBIDDEN,
                            "vector upload acts as the authenticated vault owner",
                            &["Present the owner's own verified, unattenuated credential."],
                        ));
                    }
                    self.verify_actor_write_in_txn(txn)?;
                    if lane.entity_raw_live_in(txn, &id)?.is_none() {
                        return Err(MemoryError::not_found("vector target is not readable"));
                    }
                    Ok(())
                };
                admitted().map_err(|error| {
                    refusal = Some(error);
                    crate::Error::InvariantViolation("vector upload caller or target refused")
                })
            })
            .map_err(|error| refusal.take().unwrap_or_else(|| error.into()))?;
        self.produced_from([id]);
        Ok(VectorPutReceipt {
            entity_ref: id.to_hex(),
            dimensions: self.vault.config.dimensions,
        })
    }
}
