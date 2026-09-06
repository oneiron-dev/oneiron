mod blend;
mod budget;
mod builder;
mod channels;
mod execution;
mod filters;
mod support;
mod trace;
mod types;
mod world_authority;

pub use self::builder::PipelineBuilder;
pub use self::types::{
    ActiveWorldSelection, DEFAULT_RECENCY_HALF_LIFE_DAYS, DreamerWorkingSet,
    DreamerWorkingSetBudget, DreamerWorkingSetCursor, DreamerWorkingSetStopReason, FacetMode,
    MAX_WORLD_ACCESS_MEMBERS, PREDICATE_WORLD_ACCESS_ALLOWED_SET,
    PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET, PendingVectorEmbedding, RelMode, ResolvedWorldAuthority,
    RetrievalWithPendingVectors, RetrievalWithTelemetry, ScoredEntity, Signal,
    WORLD_ACCESS_SCHEMA_VERSION, WorldAuthoritySet, WorldScope, decode_world_access_claim_value,
    world_access_claim_body,
};

pub(crate) use self::types::DEFAULT_RESULT_LIMIT;

#[cfg(test)]
mod tests;

// ONE-1402 read-side decay owns its own test module: the suite is a
// self-contained contract (one application, rank-not-survival, no writes,
// seed neutrality, own-factor rerank, attribution) and `tests.rs` is not
// its home.
#[cfg(test)]
mod decay_tests;

// The flat pipeline.rs module used to provide these names to the sibling test
// module through `use super::*`: its own private crate/std import header, and
// every pipeline-internal item the tests name bare. After the directory split
// the seam re-imports both so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::{blend::*, channels::*, trace::*, types::*};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::batch::LONG_INTERVAL_THRESHOLD_SECS;
#[cfg(test)]
use crate::codebase::{CodebaseScopeKey, RepoRef};
#[cfg(test)]
use crate::edge::EdgeKind;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::query_expansion::{
    CompletionRequest, EvidenceVerdict, GroundingContext, HydeExpander, HydeOptions, HydeRequest,
};
#[cfg(test)]
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_RELATIONSHIP, ENTITY_TYPE_SUMMARY};
#[cfg(test)]
use crate::rerank::{RerankCandidate, RerankOptions, Reranker};
#[cfg(test)]
use crate::store::{
    RetrievalAction, RetrievalRunId, RetrievalRunRecord, RetrievalScoreBreakdown,
    RetrievalScoreComponent, RetrievalSignal, RetrievalTrace, RetrievalTraceStage,
};
#[cfg(test)]
use crate::temporal::TemporalAnchorMode;
#[cfg(test)]
use crate::temporal::TemporalExpressionParseError;
#[cfg(test)]
use crate::temporal::TemporalGranularity;
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use std::collections::HashSet;
