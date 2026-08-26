mod blend;
mod budget;
mod builder;
mod channels;
mod execution;
mod filters;
mod support;
mod trace;
mod types;

pub use self::builder::PipelineBuilder;
pub use self::types::{
    DEFAULT_RECENCY_HALF_LIFE_DAYS, DreamerWorkingSet, DreamerWorkingSetBudget,
    DreamerWorkingSetCursor, DreamerWorkingSetStopReason, FacetMode, PendingVectorEmbedding,
    RelMode, RetrievalWithPendingVectors, RetrievalWithTelemetry, ScoredEntity, Signal, WorldScope,
};

pub(crate) use self::types::DEFAULT_RESULT_LIMIT;

// Declared below the production surface on purpose: the dreamer-ingress source
// oracle in tests.rs scans each child only up to its first cfg(test) marker, so
// this module's production re-exports must stay above the test declaration.
// Keep the literal marker text out of comments here — the oracle splits on the
// raw attribute string, and a comment mentioning it would truncate the scan.
#[cfg(test)]
mod tests;

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
